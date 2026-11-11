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

"""Tests for engine FuzzSessionState and terminal-owned ViewState.

Covers:
  - Default construction with sensible defaults
  - Field updates
  - Terminal deque maxlen for recent_tests
"""

import sys
from collections import deque
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pytest

from bytefault.fuzzers.session_state import FuzzSessionState
from bytefault.ui.state import ViewState


class TestFuzzSessionStateDefaults:
    """Verify default values on construction."""

    def test_static_defaults(self):
        state = FuzzSessionState()
        assert state.protocol == ""
        assert state.host == ""
        assert state.port == 0
        assert state.start_time == 0.0
        assert state.fuzz_mode == ""
        assert state.targets == []
        assert state.generator_type == ""
        assert state.strategy == ""
        assert state.schema_name == ""
        assert state.health_check_mode == ""
        assert state.total_iterations is None

    def test_dynamic_defaults(self):
        state = FuzzSessionState()
        assert state.current_iteration == 0
        assert state.crash_count == 0
        assert state.current_fuzz_target == ""
        assert state.current_field_bytes == {}
        assert state.last_sent is None
        assert state.last_received is None
        assert state.total_bytes_sent == 0
        assert state.total_bytes_received == 0
        assert state.elapsed_seconds == 0.0
        assert state.tests_per_second == 0.0

    def test_ui_state_defaults(self):
        state = ViewState()
        assert isinstance(state.recent_tests, deque)
        assert state.recent_tests.maxlen == 200
        assert state.crash_records == []
        assert state.verbosity_level == 0
        assert state.paused is False
        assert state.active_screen == "dashboard"
        assert state.hidden_fields == []


class TestFuzzSessionStateUpdates:
    """Verify field updates work correctly."""

    def test_static_fields_set_at_construction(self):
        state = FuzzSessionState(
            protocol="raw",
            host="192.0.2.1",
            port=1234,
            health_check_mode="new_connection",
        )
        assert state.protocol == "raw"
        assert state.host == "192.0.2.1"
        assert state.port == 1234
        assert state.health_check_mode == "new_connection"

    def test_dynamic_field_updates(self):
        state = FuzzSessionState()
        state.current_iteration = 42
        state.crash_count = 3
        state.last_sent = b"\x00\x01"
        state.last_received = b"\x02\x03"
        state.total_bytes_sent = 1024
        state.total_bytes_received = 512
        assert state.current_iteration == 42
        assert state.crash_count == 3
        assert state.last_sent == b"\x00\x01"
        assert state.last_received == b"\x02\x03"
        assert state.total_bytes_sent == 1024
        assert state.total_bytes_received == 512

    def test_recent_tests_maxlen(self):
        state = ViewState()
        for i in range(250):
            state.recent_tests.append({"iteration": i})
        assert len(state.recent_tests) == 200
        assert state.recent_tests[0]["iteration"] == 50

    def test_independent_mutable_defaults(self):
        """Each instance gets its own mutable containers."""
        a = ViewState()
        b = ViewState()
        a.targets.append("route")
        a.crash_records.append({"crash": True})
        assert b.targets == []
        assert b.crash_records == []
