#!/usr/bin/env python3
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

"""
TCP Protocol Fuzzer

Fuzzes protocol packets with configurable mutation strategies.
Supports auto-calculated or intentionally mismatched length fields.
Includes byte masking for targeted fuzzing.

Run from source through the public launcher:
    python bytefault.py fuzz raw HOST --port PORT --seed-hex 00ff

The direct engine class is an in-process application component.
"""

import sys
import select
import socket
import struct
import time
import os
import shutil
import argparse
import logging
import hashlib
import random
import secrets
import zlib
from bytefault.core.logging_utils import setup_logging, fmt_bytes
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set

from bytefault.core.logging_utils import resolve_log_path
from bytefault.fuzzers.session_state import FuzzSessionState
from bytefault.fuzzers.event_listener import FuzzEventListener
from bytefault.core.contracts import ControlOutcome, EngineStatus, TransportRequest, freeze
from bytefault.fuzzers.transport import EngineTransport
from bytefault.fuzzers.presentation import PresentationAttachment
import threading

logger = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[3]
ARTIFACTS_DIR = REPO_ROOT / "artifacts"

# ── Re-exports ───────────────────────────────────────────────────────
# Keep common symbols available from ``bytefault.fuzzers.fuzzer``.

from bytefault.fuzzers.byte_mask import ByteMask  # noqa: E402, F401
from bytefault.fuzzers.helpers import (  # noqa: E402, F401
    parse_hex_bytes,
    parse_hex_byte,
    _randbytes,
    _randlength,
    _parse_length_range,
    _parse_recovery_delays,
    _load_seed_file,
    _field_sizes_from_schema,
    _int_to_bytes,
    _field_default_lens_from_schema,
)
from bytefault.fuzzers.packet_builder import (  # noqa: E402, F401
    _length_spec_from_schema,
    _computed_specs_from_schema,
    _sequence_specs_from_schema,
    _field_offsets_from_schema,
    _apply_computed_fields,
    _apply_length_field,
    _apply_checksum_field,
    _apply_offset_injections,
    PacketBuilder,
)
from bytefault.fuzzers.session_mixin import SessionMixin
from bytefault.fuzzers.conversation import ConversationMixin
from bytefault.fuzzers.recording import RecordingMixin
from bytefault.fuzzers.campaign import CampaignMixin
from bytefault.core.contracts import ContractError
from bytefault.core.contracts import Calculation
from bytefault.core.calculations import calculation_bytes, sequence_value
from bytefault.core.validation import passive


class ProtocolFuzzer(RecordingMixin, CampaignMixin, ConversationMixin, SessionMixin):
    """Fuzzer for TCP protocols."""
    
    def __init__(
        self,
        host: str,
        port: int = 1234,
        timeout: int = 3,
        check_interval: int = 1,
        crash_delay: int = 5,
        persistent: bool = False,
        ssh_key: Optional[str] = None,
        tcp_pre_delay_s: float = 0.5,
        tcp_post_delay_s: float = 0.0,
        core_dump_wait_s: float = 5.0,
        delayed_crash_check_s: float = 2.0,
        recovery_delays: Optional[List[float]] = None,
        reconnect_attempts: int = 5,
        reconnect_retry_delay_s: float = 1.0,
        session_factory=None,
        handshake_checker=None,
        protocol: Optional[str] = None,
        packet_schema: Optional[dict] = None,
        test_banner: bool = True,
        health_check_mode: str = "new_connection",
        crash_throttle: int = 5,
        output_formatter=None,
        no_recv: bool = False,
        transport: Optional[EngineTransport] = None,
        presentation_capacity: int = 128,
        record_store=None,
        monitoring=None,
    ):
        """
        Initialize fuzzer.
        
        Args:
            host: Device IP address
            port: Protocol TCP port
            timeout: Socket timeout
            check_interval: Iterations between health checks
            crash_delay: Max seconds to wait for recovery
            persistent: Keep connection alive between selected tests
            ssh_key: Path to SSH private key for core dump retrieval
            tcp_pre_delay_s: Seconds to wait before each protocol TCP connection
            tcp_post_delay_s: Seconds to wait after each protocol TCP connection
            core_dump_wait_s: Seconds to wait before retrieving core dumps after a crash
            delayed_crash_check_s: Seconds to wait before the final delayed crash check
            recovery_delays: Sequence of delays (seconds) between recovery checks
            reconnect_attempts: Attempts to reconnect after crash
            reconnect_retry_delay_s: Seconds between reconnect attempts
        """
        if session_factory is not None or handshake_checker is not None:
            raise ContractError('engine', 'executable_value',
                                'client/factory/checker callbacks are not passive declarations')
        self._executing_conversation = False
        self.last_conversation_result = None
        self.host = host
        self.port = port
        self.timeout = timeout
        self.check_interval = check_interval
        self.crash_delay = crash_delay
        self.persistent = persistent
        self.ssh_key = ssh_key
        self.tcp_pre_delay_s = tcp_pre_delay_s
        self.tcp_post_delay_s = tcp_post_delay_s
        self.core_dump_wait_s = core_dump_wait_s
        self.delayed_crash_check_s = delayed_crash_check_s
        self.recovery_delays = recovery_delays or []
        self.reconnect_attempts = reconnect_attempts
        self.reconnect_retry_delay_s = reconnect_retry_delay_s
        self.session_factory = session_factory
        self._session_close = None
        self.protocol = protocol
        self.packet_schema = packet_schema
        self.pad_byte = 0x00
        self.handshake_checker = handshake_checker
        self.test_banner = test_banner
        self.progress = False  # Display state for direct ProtocolFuzzer callers.
        self.progress_only = False  # Suppress per-test display when progress-only.
        self.health_check_mode = health_check_mode
        self.computed_skip_fields: Set[str] = set()
        self.last_send_len: Optional[int] = None
        self.last_recv_len: Optional[int] = None
        self.last_payload_hex: Optional[str] = None
        self.crash_count = 0
        self.crash_throttle = crash_throttle
        self.consecutive_crashes = 0
        self.crash_throttled = False
        self.sequence_state: Dict[str, int] = {}
        self.output_formatter = output_formatter
        self.no_recv = no_recv
        self.current_iteration: Optional[int] = None
        self.total_iterations: Optional[int] = None
        
        # Independent services attach separately and are never initialized
        # as a side effect of constructing the engine.
        self.monitor = None
        self.socket: Optional[socket.socket] = None
        self.results: List[Dict] = []

        # Session state used by engine and presentation consumers.
        self.session_state = FuzzSessionState(
            protocol=protocol or "",
            host=host,
            port=port,
            health_check_mode=health_check_mode,
            packet_schema=packet_schema,
        )

        # Event listeners
        self._listeners: List[PresentationAttachment] = []

        self._should_stop = False
        self._paused = False
        self._stop_event = threading.Event()
        self._control_condition = threading.Condition()
        self._execution_state = 'idle'
        self.last_transport_result = None
        self.last_cleanup_result = None
        self.presentation_capacity = presentation_capacity
        self.transport = transport or EngineTransport(TransportRequest(
            host, port, timeout, tcp_pre_delay_s, tcp_post_delay_s))
        if isinstance(self.transport, EngineTransport):
            self.transport.bind_stop_event(self._stop_event)

        self.crash_manager = None
        self._initialize_recording(record_store, monitoring)
        self._reset_sequence_state()

    def _legacy_campaign_unavailable(self, *args, **kwargs):
        raise ContractError('campaign', 'unavailable',
                            'direct method is disconnected; use Application.generate/campaign with passive inputs')

    fuzz_offset = _legacy_campaign_unavailable
    fuzz_with_generators = _legacy_campaign_unavailable
    fuzz_field = _legacy_campaign_unavailable
    fuzz_field_pair = _legacy_campaign_unavailable
    fuzz_payload_mutations = _legacy_campaign_unavailable
    fuzz_raw_mutations = _legacy_campaign_unavailable
    fuzz_random_offset = _legacy_campaign_unavailable
    fuzz_random_field = _legacy_campaign_unavailable

    def add_listener(self, listener: FuzzEventListener) -> None:
        """Attach an optional bounded asynchronous presentation consumer."""
        self._listeners.append(PresentationAttachment(listener, self.presentation_capacity))

    def _emit(self, event_name: str, **kwargs) -> None:
        snapshot = freeze(kwargs)
        for attachment in self._listeners:
            attachment.offer(event_name, snapshot)

    # Retained schema-display helper for protocol and callable integrations.
    # The current UI uses ApplicationView._materialized and final_fields;
    # absence of Raw-only callers does not establish this helper is obsolete.
    def _display_fields_from_packet(
        self,
        packet: bytes,
        field_bytes: Optional[Dict[str, bytes]] = None,
    ) -> Dict[str, bytes]:
        """Extract all schema field values from a built packet.

        Returns *field_bytes* enriched with actual byte slices so the
        protocol diagram shows post-computed values (e.g. real length).

        When offset injections expand the packet beyond the sum of
        schema-mapped field sizes, the first ``var``-size field absorbs
        the excess bytes so the diagram reflects the actual payload.
        """
        display: Dict[str, bytes] = dict(field_bytes) if field_bytes else {}
        if self.packet_schema:
            try:
                offsets = _field_offsets_from_schema(
                    self.packet_schema, field_bytes or {},
                )

                # Adjust for packet expansion (offset injections).
                total_mapped = sum(flen for _, flen in offsets.values())
                if total_mapped < len(packet):
                    excess = len(packet) - total_mapped
                    field_sizes = _field_sizes_from_schema(self.packet_schema)
                    order = self.packet_schema.get(
                        "order",
                        [f.get("name") for f in self.packet_schema.get("fields", [])],
                    )
                    for name in order:
                        if not name:
                            continue
                        sz = field_sizes.get(name)
                        if sz == "var" or sz is None:
                            old_off, old_len = offsets[name]
                            offsets[name] = (old_off, old_len + excess)
                            # Shift all subsequent fields by the excess.
                            found = False
                            for n2 in order:
                                if n2 == name:
                                    found = True
                                    continue
                                if found and n2 in offsets:
                                    o2, l2 = offsets[n2]
                                    offsets[n2] = (o2 + excess, l2)
                            break

                for fname, (off, flen) in offsets.items():
                    if off + flen <= len(packet):
                        display[fname] = bytes(packet[off:off + flen])
            except Exception:
                pass
        return display

    # Retained interruptible delay API; TerminalController now owns UI refresh.
    def _sleep_with_ui_refresh(self, duration: float) -> None:
        """Compatibility name for interruptible engine delay, independent of UI."""
        self._stop_event.wait(max(0.0, duration))

    # Retained callable receive adapter. Normal recorded exchanges instead use
    # SessionMixin._exchange_recorded_packet and EngineTransport.
    def _recv_with_ui(self, sock, bufsize):
        return sock.recv(bufsize)

    # Retained callback adapter; presentation runs independently of this call.
    def _run_blocking_with_ui(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    def _check_ui_state(self) -> bool:
        with self._control_condition:
            while self._paused and not self._should_stop:
                self._control_condition.wait(0.1)
            return self._should_stop

    def status(self):
        return EngineStatus(self._execution_state, self._paused, self._should_stop,
            self.socket is not None, self.last_transport_result,
            sum(a.dropped for a in self._listeners), sum(a.failed for a in self._listeners),
            sum(a.discarded_on_close for a in self._listeners),
            self.continuation.hold.decision_id if self.continuation.hold else None,
            str(self.storage_failure['reason']) if self.storage_failure else None,
            self.last_cleanup_result)

    def control(self, command):
        with self._control_condition:
            if command not in ('stop', 'pause', 'resume'):
                return ControlOutcome(command, 'rejected', 'unsupported control')
            if self._should_stop and command != 'stop':
                return ControlOutcome(command, 'rejected', 'stop already requested')
            if command == 'stop':
                self._should_stop = True
                self._stop_event.set()
                self.session_state.exit_reason = 'user_quit'
                self._execution_state = 'stopping' if self.socket else 'stopped'
            else:
                self._paused = command == 'pause'
            self._control_condition.notify_all()
        self.continuation.wake()
        return ControlOutcome(command, 'completed')

    def close_observers(self):
        return tuple(attachment.close() for attachment in self._listeners)


    # Retained engine sampling hook for callable/protocol integrations.
    # Current Plain output samples in ApplicationPlainClient._should_log_test.
    def _should_log_test(self, index: int, total: int) -> bool:
        if self.progress and self.progress_only:
            return False
        if total <= 0:
            return index % 100 == 0
        if total <= 1000:
            return True
        return index % 1000 == 0

    # Retained cadence predicate; active campaigns use MonitoringConfig/policy.
    def _should_monitor_iteration(self, iteration: int) -> bool:
        if self.check_interval <= 1:
            return True
        return iteration % self.check_interval == 0

    def _reset_sequence_state(self) -> None:
        if not self.packet_schema:
            self.sequence_state = {}
            return
        state: Dict[str, int] = {}
        for spec in _sequence_specs_from_schema(self.packet_schema):
            field = spec.get("field")
            if not field:
                continue
            start = spec.get("start", 0)
            if type(start) is not int or start < 0:
                raise ContractError('schema.sequence.' + field, 'malformed', 'nonnegative integer start required')
            state[field] = start
        self.sequence_state = state

    def _apply_sequence_fields(
        self,
        field_bytes: Dict[str, bytes],
        skip_fields: Optional[Set[str]] = None,
    ) -> None:
        if not self.packet_schema:
            return
        skip_fields = skip_fields or set()
        defaults = self.packet_schema.get("defaults", {})
        for spec in _sequence_specs_from_schema(self.packet_schema):
            field = spec.get("field")
            if not field or field in skip_fields:
                continue
            # User-provided value wins: skip auto-sequence if the caller
            # supplied a value that differs from the schema default.
            if field in field_bytes and field_bytes[field] != defaults.get(field, b""):
                continue
            size = spec.get("size", 1)
            endian = spec.get("endian", "big")
            current = self.sequence_state.get(field, spec.get("start", 0))
            step = spec.get("step", 1)
            wrap = spec.get("wrap")
            calculation = Calculation(field, 'schema', 'sequence', size=size, endian=endian,
                sequence_start=current, sequence_step=step, sequence_wrap=wrap)
            passive(calculation, 'schema.sequence.' + field)
            field_bytes[field] = calculation_bytes(calculation, b'', size, 0, size)
            self.sequence_state[field] = sequence_value(current, step, wrap, 2)

    
    


# CLI is a client boundary and must never be imported by the engine.
if __name__ == '__main__':
    from bytefault.fuzzers.cli import main
    sys.exit(main())
