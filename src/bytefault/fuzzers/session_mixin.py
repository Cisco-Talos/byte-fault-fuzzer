# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Session lifecycle mixin for :class:`ProtocolFuzzer`.

Contains the current recorded transport lifecycle and pure schema construction
adapter. Campaign execution and continuation use the ordinary campaign route.

Usage::

    class ProtocolFuzzer(SessionMixin):
        def __init__(self, ...): ...

All methods access ``self`` attributes defined in
:meth:`ProtocolFuzzer.__init__`.  The mixin is **not** intended to be
instantiated directly.
"""

import logging
from dataclasses import replace
from typing import Dict, List, Optional, Set, Tuple

from bytefault.core.contracts import ContractError, TransportResult, TransportCleanup
from bytefault.fuzzers.packet_builder import (
    PacketBuilder,
    _apply_computed_fields,
    _length_spec_from_schema,
)

logger = logging.getLogger(__name__)


def build_session_factory(plugin):
    """Reject executable protocol factories at the passive boundary.

    Current execution interprets passive conversations through the ordinary engine.
    """
    raise ContractError('session_factory', 'unavailable',
                        'use passive declarations with execute_conversation')


class SessionMixin:
    """Recorded transport lifecycle and pure packet construction."""

    # ------------------------------------------------------------------
    # Packet building
    # ------------------------------------------------------------------

    def build_packet(
        self,
        field_bytes: Dict[str, bytes],
        auto_length: bool = True,
        skip_fields: Optional[Set[str]] = None,
        skip_ranges: Optional[List[Tuple[int, int]]] = None,
        length_override: Optional[int] = None,
    ) -> bytes:
        if not self.packet_schema:
            raise ValueError("Protocol schema is required to build packets")
        field_bytes = dict(field_bytes)
        combined_skip: Set[str] = set(getattr(self, "computed_skip_fields", set()))
        if skip_fields:
            combined_skip.update(skip_fields)
        self._apply_sequence_fields(field_bytes, skip_fields=combined_skip)
        packet = bytearray(
            PacketBuilder.build_from_schema(
                self.packet_schema,
                field_bytes,
                pad_byte=self.pad_byte,
            )
        )
        if auto_length or length_override is not None:
            if length_override is not None:
                length_spec = _length_spec_from_schema(self.packet_schema)
                length_field = length_spec.get("field") if length_spec else None
                if length_field and length_field in combined_skip:
                    combined_skip.remove(length_field)
            _apply_computed_fields(
                packet,
                self.packet_schema,
                field_bytes=field_bytes,
                pad_byte=self.pad_byte,
                skip_fields=combined_skip,
                skip_ranges=skip_ranges,
                length_override=length_override,
            )
        return bytes(packet)

    # ------------------------------------------------------------------
    # Connect / disconnect
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        raise ContractError('connect', 'unavailable', 'use execute_conversation')

    def _connect_conversation(self) -> bool:
        if (not self._executing_conversation or not self._case_recorded or self.storage_failure or
                not self._connection_permission):
            raise ContractError('connect', 'required_record', 'acknowledged case context required')
        self._connection_permission = False
        if self._should_stop:
            return False
        self._execution_state = 'connecting'
        prior_cleanup = getattr(self.transport, 'last_cleanup', None)
        if not self.transport.open():
            cleanup = getattr(self.transport, 'last_cleanup', None)
            if cleanup is not prior_cleanup:
                self.last_cleanup_result = cleanup
            self._execution_state = 'failed'
            return False
        self.socket = self.transport.stream
        self._connection_epoch = getattr(self, '_connection_epoch', 0) + 1
        self._connection_context = dict(self._record_context)
        self._session_close = self.transport.close
        self._execution_state = 'connected'
        self._reset_sequence_state()
        return True

    def open_session(self, *args, **kwargs):
        raise ContractError('open_session', 'unavailable',
                            'direct protocol sessions are unsupported; use execute_conversation')

    def disconnect(self, *, phase='conversation'):
        """Detach campaign use and retain the single local close attempt.

        This operation does not call required sinks: recording-stop teardown
        must remain usable after one of those sinks has already failed.
        """
        close = self._session_close
        self._session_close = None
        stream, self.socket = self.socket, None
        if close is not None or stream is not None:
            self.last_cleanup_result = TransportCleanup(phase, 'pending')
            try:
                # Existing injected adapters expose close() without keywords.
                # Attribution belongs to the engine; a None return still means
                # the local call returned, never proof of an OS/target effect.
                result = self.transport.close()
                self.last_cleanup_result = (replace(result, phase=phase)
                    if isinstance(result, TransportCleanup) else TransportCleanup(phase, 'completed'))
            except Exception as exc:
                # A custom adapter failure still has an explicit uncertainty;
                # do not retry its close through another resource reference.
                self.last_cleanup_result = TransportCleanup(phase, 'uncertain',
                    str(exc), type(exc).__name__)
            self.transport.stream = None
        elif self.last_cleanup_result is None:
            self.last_cleanup_result = TransportCleanup(phase)
        cleanup = self.last_cleanup_result
        if cleanup.outcome == 'uncertain' or cleanup.pacing_error:
            self._execution_state = 'cleanup_failed'
        else:
            self._execution_state = 'stopped' if self._should_stop else 'idle'
        return cleanup

    # ------------------------------------------------------------------
    # Send / receive
    # ------------------------------------------------------------------

    def send_packet(self, *args, **kwargs):
        raise ContractError('send_packet', 'unavailable', 'use execute_conversation')

    def send_raw_packet(self, *args, **kwargs):
        raise ContractError('send_raw_packet', 'unavailable', 'use execute_conversation')

    def _exchange_packet(self, packet, receive, *, probe=False, record_identity=None, acknowledged_probe=False):
        with self._action_lock:
            return self._exchange_recorded_packet(packet, receive, probe=probe,
                record_identity=record_identity,acknowledged_probe=acknowledged_probe)

    def _exchange_recorded_packet(self, packet, receive, *, probe=False, record_identity=None, acknowledged_probe=False):
        if not self._executing_conversation:
            raise ContractError('exchange', 'unavailable', 'use execute_conversation')
        if (not (self._case_recorded or acknowledged_probe) or self.storage_failure or self._offer_permission != packet):
            raise ContractError('exchange', 'required_record', 'acknowledged materialization required')
        self._offer_permission = None
        if self.continuation.stopped or (self.continuation.hold is not None and not probe):
            raise ContractError('exchange', 'monitoring_hold', 'next fuzz send is held/stopped')
        if self._should_stop or (not probe and self._check_ui_state()):
            self.last_transport_result = TransportResult(packet,
                receive_requested=receive.requested,
                receive_outcome='not_reached' if receive.requested else 'unrequested',
                error='stopped before offer', connection=getattr(self.transport, 'last_open', None))
            return None
        self._execution_state = 'executing'
        self._last_transport_context = dict(record_identity if record_identity is not None else self._record_context)
        self.last_transport_result = None
        self._transport_in_progress = True
        try:
            result = self.transport.exchange(packet, receive, stopped=self._stop_event.is_set)
        finally:
            self._transport_in_progress = False
        self.last_transport_result = result
        self._emit('on_transport_result', result=result)
        logger.info("Transport prepared=%s offered=%s accepted_prefix=%s acceptance=%s "
                    "received=%s receive_outcome=%s error=%s",
                    result.prepared.hex(), result.offered.hex(), result.accepted_prefix.hex(),
                    result.acceptance, result.received.hex(), result.receive_outcome, result.error)
        self.last_send_len = result.accepted_count
        self.last_recv_len = len(result.received) if result.receive_requested else None
        if result.offered:
            self.session_state.last_sent = result.offered
            self.session_state.total_bytes_sent += len(result.accepted_prefix)
            if result.acceptance == 'accepted':
                self._emit('on_packet_sent', iteration=self.current_iteration or 0,
                           packet_bytes=result.offered, length=len(result.offered))
        if result.received:
            self.session_state.last_received = result.received
            self.session_state.total_bytes_received += len(result.received)
            self._emit('on_response_received', iteration=self.current_iteration or 0,
                       response_bytes=result.received, length=len(result.received))
        if result.error:
            self._emit('on_connection_error', iteration=self.current_iteration or 0,
                       error_type='transport', message=result.error)
        self._execution_state = ('recording_failed' if self.storage_failure else
                                 'stopping' if self._should_stop else 'connected')
        return result.received or None
