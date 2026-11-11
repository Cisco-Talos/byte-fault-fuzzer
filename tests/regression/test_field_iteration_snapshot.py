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
Snapshot test: field iteration packet generation.

Captures packet sequences produced by build_packet() with varying field values.
Validates consistency before/after refactor. No network traffic.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pytest
from bytefault.fuzzers.fuzzer import ProtocolFuzzer, ByteMask

_NEUTRAL_SCHEMA = {
    "length": {"field": "length", "size": 2, "endian": "big", "counts": "body"},
    "fields": [{"name": name, "size": size} for name, size in (
        ("length", 2), ("kind", 1), ("ordinal", 2), ("marker", 1),
        ("mode", 1), ("payload", "var"))],
    "order": ["length", "kind", "ordinal", "marker", "mode", "payload"],
    "defaults": {"length": b"\x00\x00", "kind": b"\x5a", "ordinal": b"\x12\x34",
                 "marker": b"\x7e", "mode": b"\xc0", "payload": b""},
    "computed": [{"type": "sequence", "field": "ordinal", "size": 2,
                  "start": 0x1234, "step": 1, "wrap": 65536}],
}


@pytest.fixture
def fuzzer():
    return ProtocolFuzzer(
        host="127.0.0.1",
        port=1234,
        protocol="neutral-fixture",
        packet_schema=_NEUTRAL_SCHEMA,
    )


def test_field_iter_kind_full(fuzzer, snapshot_helper):
    """Iterate kind 0x00-0x09, capture packets."""
    mask = ByteMask([(0x00, 0x09)], [])
    packets = []
    for val in mask.get_values():
        pkt = fuzzer.build_packet({
            "kind": bytes([val]),
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"\x00\x00",
        })
        packets.append({"value": val, "packet": pkt.hex()})

    snapshot_helper.assert_matches("field_iter_kind_00_09", {
        "test": "field_iter_kind",
        "mask": "0x00-0x09",
        "count": len(packets),
        "packets": packets,
    })


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--capture-snapshots"])
