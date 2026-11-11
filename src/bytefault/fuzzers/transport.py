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

"""Engine-owned TCP lifecycle; injectable ports replace external I/O in tests."""
from __future__ import annotations

import socket
import time
from dataclasses import replace
from bytefault.core.contracts import ReceiveRequest, TransportRequest, TransportResult, TransportCleanup, freeze


class SendFailure(OSError):
    """Port failure with explicit progress for the failing call; None is uncertain."""
    def __init__(self, message, accepted_count=None):
        super().__init__(message)
        self.accepted_count = accepted_count


class EngineTransport:
    def __init__(self, request: TransportRequest, *, socket_factory=None,
                 sleep=None, clock=None):
        self.request = request
        self.socket_factory = socket_factory or socket.socket
        self.sleep = sleep or time.sleep
        self._injected_sleep = sleep is not None
        self._stop_event = None
        self.clock = clock or time.monotonic
        self.stream = None
        self.open_error = None
        self.last_cleanup = None
        self.last_open = None
        self.pacer = None

    def bind_stop_event(self, event):
        """The fuzzer owns cancellation; injected blocking ports retain theirs."""
        self._stop_event = event

    def _stopped(self):
        return self._stop_event is not None and self._stop_event.is_set()

    def _wait(self, seconds):
        if not self._stopped():
            if self._stop_event is not None and not self._injected_sleep:
                deadline = time.monotonic() + seconds
                while not self._stopped():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._stop_event.wait(remaining)
            else:
                self.sleep(seconds)

    def _pace(self, seconds):
        started = self.clock()
        self._wait(seconds)
        return freeze({'seconds': seconds, 'started_at': started, 'completed_at': self.clock(),
            'outcome': 'cancelled' if self._stopped() else 'completed'})

    def open(self):
        if self.stream is not None:
            raise RuntimeError("connection already open")
        self.open_error = None
        self.last_cleanup = None
        self.last_open = None
        throttle, pacing = (self.pacer.before_start(self.request.connection_delay,
            cancelled=self._stopped,
            sleep=self._wait,
            pre_delay=self.request.pre_delay, pre_wait=self._pace) if self.pacer is not None
            else (None, self._pace(self.request.pre_delay)))
        self.last_open = freeze({'outcome': 'not_attempted', 'pacing': pacing,
            'connection_throttle': throttle, 'connect_attempted': False})
        if self._stopped():
            self.open_error = 'stopped before connect'
            if self.pacer is not None and throttle is not None and throttle['outcome'] == 'completed':
                self.pacer.finished()
            return False
        stream = None
        attempted = False
        started = self.clock()
        try:
            stream = self.socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            stream.settimeout(self.request.timeout)
            if self._stopped():
                self.open_error = 'stopped before connect'
                self.last_open = freeze({'outcome': 'not_attempted', 'pacing': pacing, 'connection_throttle': throttle,
                    'connect_attempted': False, 'started_at': started, 'completed_at': self.clock()})
                self._close_stream(stream, phase='open_cancelled')
                return False
            attempted = True
            stream.connect((self.request.host, self.request.port))
            self.stream = stream
            self.last_open = freeze({'outcome': 'completed', 'pacing': pacing, 'connection_throttle': throttle,
                'connect_attempted': True, 'started_at': started, 'completed_at': self.clock()})
            return True
        except Exception as exc:
            self.open_error = str(exc)
            self.last_open = freeze({'outcome': 'failed', 'pacing': pacing, 'connection_throttle': throttle,
                'connect_attempted': attempted,
                'started_at': started, 'completed_at': self.clock(),
                'error': str(exc), 'error_type': type(exc).__name__})
            if stream is not None:
                self._close_stream(stream, phase='open_failure')
            elif self.pacer is not None:
                self.pacer.finished()
            return False

    def _close_stream(self, stream, *, phase):
        outcome, error, error_type, pacing_error, pacing = 'completed', None, None, None, None
        try:
            stream.close()
        except Exception as exc:
            outcome, error, error_type = 'uncertain', str(exc), type(exc).__name__
        try:
            pacing = self._pace(self.request.post_delay)
        except Exception as exc:
            pacing_error = f'{type(exc).__name__}: {exc}'
        self.last_cleanup = TransportCleanup(phase, outcome, error, error_type, pacing_error, pacing)
        if self.pacer is not None:
            self.pacer.finished()
        return self.last_cleanup

    def close(self, *, phase='conversation'):
        # Detach before calling the OS: an exception must not cause a blind
        # second close, since the original descriptor may already be released.
        stream, self.stream = self.stream, None
        if stream is not None:
            return self._close_stream(stream, phase=phase)
        return self.last_cleanup or TransportCleanup(phase)

    def exchange(self, data: bytes, receive: ReceiveRequest, *, stopped=lambda: False):
        data = bytes(data)
        result = TransportResult(prepared=data, receive_requested=receive.requested,
            receive_outcome="not_reached" if receive.requested else "unrequested", connection=self.last_open)
        stream = self.stream
        if stream is None:
            return replace(result, error="not connected")
        if receive.cap < 1 or receive.deadline <= 0:
            return replace(result, error="receive cap and deadline must be positive")
        if stopped():
            return replace(result, error="stopped before offer")
        accepted = 0
        offered = b""
        try:
            while accepted < len(data):
                if stopped():
                    return replace(result, offered=offered, accepted_prefix=data[:accepted],
                                   accepted_count=accepted, acceptance="partial", error="stopped")
                offered = data  # all remaining bytes are now offered to the local port
                count = stream.send(data[accepted:])
                if not isinstance(count, int) or count <= 0 or count > len(data) - accepted:
                    raise SendFailure("invalid local send count", accepted_count=0)
                accepted += count
        except Exception as exc:
            progress = getattr(exc, "accepted_count", None)
            known = progress is not None and 0 <= progress <= len(data) - accepted
            prefix = accepted + progress if known else accepted
            return replace(result, offered=offered, accepted_prefix=data[:prefix],
                           accepted_count=prefix if known else None,
                           acceptance="partial" if known else "uncertain", error=str(exc),
                           error_type=type(exc).__name__)
        result = replace(result, offered=offered, accepted_prefix=data,
                         accepted_count=accepted, acceptance="accepted", offer_completed_at=self.clock())
        if not receive.requested:
            return result
        deadline = self.clock() + receive.deadline
        chunks = bytearray()
        wanted = receive.cap
        boundary = "unknown"
        parsed_length = False
        outcome = "read_cap"
        try:
            while len(chunks) < wanted:
                if stopped():
                    outcome = "cancelled"
                    break
                remaining = deadline - self.clock()
                if remaining <= 0:
                    outcome = "deadline"
                    break
                stream.settimeout(min(remaining, 0.1))
                size = wanted - len(chunks)
                if receive.length_offset is not None and not parsed_length:
                    size = min(size, receive.length_offset + receive.length_size - len(chunks))
                try:
                    chunk = stream.recv(size)
                except socket.timeout:
                    continue
                if not chunk:
                    outcome = "eof"
                    break
                chunks.extend(chunk)
                if result.first_response_at is None:
                    result = replace(result, first_response_at=self.clock())
                if receive.length_offset is None:
                    outcome = "bounded_chunk" if len(chunks) < receive.cap else "read_cap"
                    break
                header = receive.length_offset + receive.length_size
                if not parsed_length and len(chunks) >= header:
                    length = int.from_bytes(chunks[receive.length_offset:header], receive.length_endian)
                    total = length if receive.length_counts in ("full", "packet") else header + length
                    wanted = min(receive.cap, max(header, total))
                    boundary = "declared" if total <= receive.cap else "unknown"
                    parsed_length = True
            if boundary == "declared" and len(chunks) == wanted:
                outcome = "complete"
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            outcome = "reset" if isinstance(exc, ConnectionResetError) else "error"
            return replace(result, received=bytes(chunks), receive_outcome=outcome,
                           response_boundary=boundary, error=str(exc), error_type=type(exc).__name__,
                           receive_completed_at=self.clock())
        finally:
            try:
                stream.settimeout(self.request.timeout)
            except OSError:
                pass  # independent stop/storage failure may have closed it
        return replace(result, received=bytes(chunks), receive_outcome=outcome,
                       response_boundary=boundary, receive_completed_at=self.clock())
