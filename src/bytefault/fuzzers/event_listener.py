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

"""Fuzz event listener interface and plain-text implementation.

The ``FuzzEventListener`` base class defines the observer interface that
``ProtocolFuzzer`` emits events to during fuzzing.  All methods have
empty default implementations so listeners can subscribe selectively.

``PlainTextListener`` replicates the current (pre-Rich) stdout behavior:
progress line, test banners, and session-complete summary.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from bytefault.fuzzers.session_state import FuzzSessionState

logger = logging.getLogger(__name__)


# ── Base listener ────────────────────────────────────────────────────


class FuzzEventListener:
    """Abstract observer for fuzz session events.

    All methods have empty default implementations (not abstract) so
    listeners can subscribe selectively.
    """

    def on_transport_result(self, result) -> None:
        """Immutable local transport facts, including partial/uncertain outcomes."""

    def on_session_start(self, state: FuzzSessionState) -> None:
        """Session metadata available."""

    def on_test_start(
        self,
        iteration: int,
        total: Optional[int],
        field_bytes: Dict[str, bytes],
    ) -> None:
        """An iteration is about to begin."""

    def on_packet_sent(
        self,
        iteration: int,
        packet_bytes: bytes,
        length: int,
    ) -> None:
        """A packet was sent via ``sendall()``."""

    def on_response_received(
        self,
        iteration: int,
        response_bytes: bytes,
        length: int,
    ) -> None:
        """A response was received."""

    def on_crash_detected(
        self,
        iteration: int,
        crash_info: Dict,
    ) -> None:
        """A crash was detected."""

    def on_crash_recovered(
        self,
        iteration: int,
        recovery_time_s: float,
    ) -> None:
        """The device recovered from a crash."""

    def on_test_complete(
        self,
        iteration: int,
        result: Dict,
    ) -> None:
        """An iteration finished."""

    def on_session_complete(
        self,
        total_tests: int,
        total_crashes: int,
        elapsed_s: float,
    ) -> None:
        """The session is done."""

    def on_progress(
        self,
        iteration: int,
        total: Optional[int],
        target_label: str,
        outer_pos: Optional[Tuple[int, int]] = None,
        inner_pos: Optional[Tuple[int, int]] = None,
    ) -> None:
        """Progress update (drives progress bars / progress line)."""

    def on_health_check(
        self,
        iteration: int,
        host: str,
        port: int,
        alive: bool,
    ) -> None:
        """Health check result."""

    def on_connection_error(
        self,
        iteration: int,
        error_type: str,
        message: str,
    ) -> None:
        """A socket exception occurred."""

    def on_session_opened(
        self,
        fuzz_stage: str,
        conversation_log: List[Tuple[str, str, bytes]],
    ) -> None:
        """A session was opened successfully.

        The *conversation_log* contains ``(direction, stage, data)``
        tuples for every message exchanged during the session setup.
        """
