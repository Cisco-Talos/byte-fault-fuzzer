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

"""Engine-owned execution state; observers receive immutable value snapshots.

Mutable terminal view state lives in bytefault.ui.state and is never shared
with this object. This module has no dependency on that optional client.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple


@dataclass
class FuzzSessionState:
    """Observable state for a fuzz session.

    Static and dynamic execution facts remain independent of presentation.
    """

    # ── Static (set once) ───────────────────────────────────────────
    protocol: str = ""
    host: str = ""
    port: int = 0
    start_time: float = 0.0
    fuzz_mode: str = ""
    fuzz_stage: str = "connect"
    targets: List[str] = field(default_factory=list)
    generator_type: str = ""
    strategy: str = ""
    schema_name: str = ""
    health_check_mode: str = ""
    total_iterations: Optional[int] = None
    packet_schema: Optional[Dict[str, Any]] = None

    # ── Dynamic (updated per iteration) ─────────────────────────────
    current_iteration: int = 0
    crash_count: int = 0
    current_fuzz_target: str = ""
    current_field_bytes: Dict[str, bytes] = field(default_factory=dict)
    last_sent: Optional[bytes] = None
    last_received: Optional[bytes] = None
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    elapsed_seconds: float = 0.0
    tests_per_second: float = 0.0
    conversation_log: List[Tuple[str, str, bytes]] = field(default_factory=list)

    # ── Exit state ─────────────────────────────────────────────────
    exit_reason: str = ""  # completed | throttled | interrupted | unrecovered | error

