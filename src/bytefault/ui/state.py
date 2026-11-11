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

"""Mutable presentation state owned by the terminal client."""
from dataclasses import dataclass, field
from collections import deque
from typing import Any, Deque, Dict, List, Optional
from bytefault.fuzzers.session_state import FuzzSessionState

@dataclass
class RingBufferEntry:
    timestamp: float
    iteration: int
    entry_type: str
    sent_bytes: Optional[bytes] = None
    recv_bytes: Optional[bytes] = None
    sent_len: int = 0
    recv_len: int = 0
    message: str = ''
    style: Any = None
    result: Optional[Dict] = None
    crash_info: Optional[Dict] = None
    field_bytes: Optional[Dict[str, bytes]] = None
    conversation_log: Optional[List] = None
    schema: Optional[Dict] = None

@dataclass
class ViewState(FuzzSessionState):
    # ── UI state ─────────────────────────────────────────────────────
    recent_tests: Deque = field(default_factory=lambda: deque(maxlen=200))
    crash_records: List[Dict] = field(default_factory=list)
    verbosity_level: int = 0
    rain_enabled: bool = False
    paused: bool = False
    show_help: bool = False
    active_screen: str = "dashboard"
    hidden_fields: List[str] = field(default_factory=list)
    run_id: str = ''
    case_id: str = ''
    conversation_id: str = ''
    variant_id: str = ''
    action_id: str = ''
    attempt_id: str = ''
    intended: Optional[bytes] = None
    acceptance: str = 'not_offered'
    accepted_count: Optional[int] = 0
    accepted_prefix: bytes = b''
    stage_id: str = ''
    receive_outcome: str = 'unrequested'
    response_meaning: str = 'uninterpreted'
    execution_state: str = 'initializing'
    monitoring_hold: Optional[str] = None
    current_fields: List[Dict] = field(default_factory=list)
    final_fields_available: bool = False
    degraded: str = ''
    projection_resets: int = 0
    followup_pending: int = 0
    heartbeat_error: str = ''
    control_outcome: str = ''
    test_banner: bool = True
    log_lines: List[str] = field(default_factory=list)
    log_issue: str = ''
    log_index_ready: bool = False
    log_index_pending: bool = False
    theme_name: str = ''
    progress: Dict = field(default_factory=dict)
    current_selected: bool = False
    tx_bytes_per_second: float = 0.0
    rx_bytes_per_second: float = 0.0
    formatted_output: str = ''
    run_active: bool = True
    resume: Dict = field(default_factory=dict)

    # ── Log viewer state ────────────────────────────────────────────
    log_file: str = ""
    cmd_args: str = ""
    log_scroll_offset: int = -1      # -1 = follow tail
    log_search_query: str = ""
    log_search_input: str = ""       # partial input while typing
    log_search_active: bool = False  # True while / prompt is open
    log_search_matches: List[int] = field(default_factory=list)
    log_search_index: int = 0        # current match index
    log_search_pending: bool = False
    log_search_issue: str = ''
    log_detail_rows: Any = None
    log_detail_scroll_offset: int = 0
    log_match_in_record: bool = False

    # ── Heartbeat (ICMP monitor) ────────────────────────────────────
    heartbeat_enabled: bool = False
    heartbeat_alive: Optional[bool] = None      # None = no result yet

