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

"""Rich UI event listener implementation.

``RichUIListener`` is the ``FuzzEventListener`` implementation that drives
the Rich Live display.  It receives events from the fuzzer, updates
private ``ViewState`` and the ring buffer, and appends sparkline / crash data.
An optional presentation worker delivers immutable engine events. The terminal
controller renders this owned view in its own loop; neither calls engine code
to render or receives authoritative mutable state.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from bytefault.fuzzers.event_listener import FuzzEventListener
from bytefault.ui.rich_renderables import RingBufferEntry
from bytefault.ui.state import ViewState as FuzzSessionState

logger = logging.getLogger(__name__)


class RichUIListener(FuzzEventListener):
    """Event listener that populates state for Rich Live rendering.

    Constructor args:
        state: A private mutable ``ViewState`` instance owned by this client.
        output_formatter: Optional protocol-specific formatter callback.
    """

    def __init__(
        self,
        state: FuzzSessionState,
        output_formatter=None,
    ) -> None:
        self.state = state
        self.output_formatter = output_formatter

        # Sparkline history (bytes per iteration for TX/RX)
        self.tx_history: Deque[float] = deque(maxlen=500)
        self.rx_history: Deque[float] = deque(maxlen=500)

        # Rolling average for tests_per_second
        self._rate_window: Deque[float] = deque(maxlen=50)
        self._last_test_time: float = 0.0

        # Track iteration field_bytes for test_complete
        self._current_field_bytes: Dict[str, bytes] = {}

    # ── Session lifecycle ───────────────────────────────────────────

    def on_session_start(self, state: FuzzSessionState) -> None:
        """Populate static session state fields."""
        # The state reference is already shared; static fields are set
        # by the fuzzer before this call.  Record the start time for
        # rate calculation and elapsed display.
        from collections.abc import Mapping
        for name, value in state.items():
            if isinstance(value, Mapping):
                value = dict(value)
            elif isinstance(value, tuple):
                value = list(value)
            setattr(self.state, name, value)
        self._last_test_time = time.monotonic()
        self.state.start_time = time.time()

    def on_session_complete(
        self,
        total_tests: int,
        total_crashes: int,
        elapsed_s: float,
    ) -> None:
        """Mark session complete for final render."""
        self.state.current_iteration = total_tests
        self.state.crash_count = total_crashes
        self.state.elapsed_seconds = elapsed_s

    # ── Per-iteration events ────────────────────────────────────────

    def on_test_start(
        self,
        iteration: int,
        total: Optional[int],
        field_bytes: Dict[str, bytes],
    ) -> None:
        """Update iteration counter and current field values."""
        self.state.current_iteration = iteration
        self.state.current_field_bytes = dict(field_bytes)
        self._current_field_bytes = dict(field_bytes)
        if total is not None:
            self.state.total_iterations = total

    def on_packet_sent(
        self,
        iteration: int,
        packet_bytes: bytes,
        length: int,
    ) -> None:
        """Update TX state and sparkline history."""
        self.state.last_sent = packet_bytes
        self.state.total_bytes_sent += length
        self.tx_history.append(float(length))

    def on_response_received(
        self,
        iteration: int,
        response_bytes: bytes,
        length: int,
    ) -> None:
        """Update RX state and sparkline history."""
        self.state.last_received = response_bytes
        self.state.total_bytes_received += length
        self.rx_history.append(float(length))

    def on_crash_detected(
        self,
        iteration: int,
        crash_info: Dict,
    ) -> None:
        """Increment crash count, record crash, add to ring buffer."""
        self.state.crash_count += 1

        # Build crash record for the crash table.
        # crash_info is now enriched by crash_manager with:
        #   core_dumps (list), crash_dir (str), report_path (str),
        #   recovery_time (float), crash_type (str).
        core_dumps = crash_info.get("core_dumps", [])
        crash_dir = crash_info.get("crash_dir", "")

        record = {
            "iteration": iteration,
            "timestamp": time.time(),
            "payload_hex": (
                self.state.last_sent.hex() if self.state.last_sent else ""
            ),
            "has_core": bool(core_dumps),
            "crash_dir": crash_dir,
            "recovery_time_s": crash_info.get("recovery_time", ""),
        }
        self.state.crash_records.append(record)

        # Add styled entry to ring buffer
        msg = crash_info.get(
            "message",
            f"Device crash detected at iteration {iteration}",
        )
        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=iteration,
            entry_type="crash",
            message=msg,
        )
        self.state.recent_tests.append(entry)

    def on_crash_recovered(
        self,
        iteration: int,
        recovery_time_s: float,
    ) -> None:
        """Add recovery entry to ring buffer."""
        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=iteration,
            entry_type="recovery",
            message=f"Device recovered after {recovery_time_s:.1f}s",
        )
        self.state.recent_tests.append(entry)

        # Update last crash record if available
        if self.state.crash_records:
            self.state.crash_records[-1]["recovery_time_s"] = recovery_time_s

    def on_test_complete(
        self,
        iteration: int,
        result: Dict,
    ) -> None:
        """Append test result to ring buffer, update rate."""
        now = time.monotonic()
        if self._last_test_time > 0:
            dt = now - self._last_test_time
            if dt > 0:
                self._rate_window.append(1.0 / dt)
                self.state.tests_per_second = (
                    sum(self._rate_window) / len(self._rate_window)
                )
        self._last_test_time = now

        # Update elapsed
        if self.state.start_time > 0:
            self.state.elapsed_seconds = time.time() - self.state.start_time

        # Build ring buffer entry
        sent = result.get("_sent_bytes") or self.state.last_sent
        recv = result.get("_response")
        if recv is None:
            recv = self.state.last_received

        # Capture conversation log snapshot (auth exchanges etc.)
        conv_log = None
        if self.state.conversation_log:
            conv_log = list(self.state.conversation_log)

        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=iteration,
            entry_type="test",
            sent_bytes=sent,
            recv_bytes=recv,
            sent_len=len(sent) if sent else 0,
            recv_len=len(recv) if recv else 0,
            field_bytes=dict(self._current_field_bytes),
            result=result,
            conversation_log=conv_log,
        )
        self.state.recent_tests.append(entry)

    def on_progress(
        self,
        iteration: int,
        total: Optional[int],
        target_label: str,
        outer_pos: Optional[Tuple[int, int]] = None,
        inner_pos: Optional[Tuple[int, int]] = None,
    ) -> None:
        """Update progress bar positions on state."""
        self.state.current_iteration = iteration
        self.state.current_fuzz_target = target_label
        if total is not None:
            self.state.total_iterations = total

        # Store progress positions for the progress bar renderable
        # These are transient attributes read by build_progress_bars
        self.state._outer_pos = outer_pos  # type: ignore[attr-defined]
        self.state._inner_pos = inner_pos  # type: ignore[attr-defined]

    def on_health_check(
        self,
        iteration: int,
        host: str,
        port: int,
        alive: bool,
    ) -> None:
        """Add health check entry to ring buffer if not alive."""
        if not alive:
            entry = RingBufferEntry(
                timestamp=time.time(),
                iteration=iteration,
                entry_type="health",
                message=f"Health check: {host}:{port} not responding",
            )
            self.state.recent_tests.append(entry)

    def on_connection_error(
        self,
        iteration: int,
        error_type: str,
        message: str,
    ) -> None:
        """Add connection error entry to ring buffer."""
        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=iteration,
            entry_type="error",
            message=f"{error_type}: {message}",
        )
        self.state.recent_tests.append(entry)
