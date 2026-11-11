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
Pytest configuration for bytefault tests.

Adds snapshot helpers for deterministic regression checks.
Offline tests deny real network I/O. The separately invoked loopback tier uses
only fixture-owned 127.0.0.1 endpoints.
"""

import json
import sys
from pathlib import Path

import pytest

# Test root directories
TESTS_ROOT = Path(__file__).parent
SNAPSHOTS_DIR = TESTS_ROOT / "snapshots"
PROJECT_ROOT = TESTS_ROOT.parent

sys.path.insert(0, str(PROJECT_ROOT / "src"))

def pytest_addoption(parser):
    """Add custom pytest options."""
    parser.addoption(
        "--capture-snapshots",
        action="store_true",
        default=False,
        help="Capture new snapshots instead of comparing",
    )
    parser.addoption(
        "--compare-snapshots",
        action="store_true",
        default=False,
        help="Compare against existing snapshots (default mode)",
    )


@pytest.fixture
def snapshot_mode(request):
    """Determine if we're capturing or comparing snapshots."""
    if request.config.getoption("--capture-snapshots"):
        return "capture"
    return "compare"  # Default mode


@pytest.fixture
def snapshots_dir():
    """Return path to snapshots directory."""
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    return SNAPSHOTS_DIR


def save_snapshot(snapshot_name: str, data: dict, snapshots_dir: Path):
    """Save snapshot data to JSON file."""
    snapshot_path = snapshots_dir / f"{snapshot_name}.json"
    with open(snapshot_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved snapshot: {snapshot_path}")


def load_snapshot(snapshot_name: str, snapshots_dir: Path) -> dict:
    """Load snapshot data from JSON file."""
    snapshot_path = snapshots_dir / f"{snapshot_name}.json"
    if not snapshot_path.exists():
        raise FileNotFoundError(
            f"Snapshot not found: {snapshot_path}\n"
            f"Run with --capture-snapshots to create it."
        )
    with open(snapshot_path) as f:
        return json.load(f)


@pytest.fixture
def snapshot_helper(snapshot_mode, snapshots_dir):
    """Helper for snapshot testing."""
    class SnapshotHelper:
        def __init__(self, mode, snapshots_dir):
            self.mode = mode
            self.snapshots_dir = snapshots_dir
        
        def assert_matches(self, snapshot_name: str, actual_data: dict):
            """Compare actual data against snapshot or save new snapshot."""
            if self.mode == "capture":
                save_snapshot(snapshot_name, actual_data, self.snapshots_dir)
                pytest.skip(f"Captured snapshot: {snapshot_name}")
            else:
                expected_data = load_snapshot(snapshot_name, self.snapshots_dir)
                assert actual_data == expected_data, (
                    f"Snapshot mismatch for {snapshot_name}\n"
                    f"Run with --capture-snapshots to update."
                )

    return SnapshotHelper(snapshot_mode, snapshots_dir)
