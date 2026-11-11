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
Unit tests for ByteMask class.

Tests mask construction, from_string parsing, value generation, exclude logic.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pytest
from bytefault.fuzzers.fuzzer import ByteMask


# --- Constructor tests ---

def test_single_range():
    mask = ByteMask([(0x00, 0x09)], [])
    assert mask.get_values() == list(range(10))


def test_multiple_ranges():
    mask = ByteMask([(0x00, 0x02), (0x10, 0x12)], [])
    assert mask.get_values() == [0, 1, 2, 0x10, 0x11, 0x12]


def test_full_byte():
    mask = ByteMask([(0x00, 0xFF)], [])
    values = mask.get_values()
    assert len(values) == 256
    assert values[0] == 0 and values[-1] == 0xFF


def test_single_value_range():
    mask = ByteMask([(0x42, 0x42)], [])
    assert mask.get_values() == [0x42]


def test_excludes():
    mask = ByteMask([(0x00, 0x0F)], [0x05])
    values = mask.get_values()
    assert 0x05 not in values
    assert len(values) == 15


def test_excludes_multiple():
    mask = ByteMask([(0x00, 0x0F)], [0x02, 0x03, 0x04, 0x05])
    values = mask.get_values()
    for v in [0x02, 0x03, 0x04, 0x05]:
        assert v not in values
    assert len(values) == 12


def test_exclude_outside_range():
    mask = ByteMask([(0x00, 0x05)], [0xFF])
    assert len(mask.get_values()) == 6


def test_boundary_values():
    mask = ByteMask([(0x00, 0x00), (0x7F, 0x80), (0xFF, 0xFF)], [])
    assert mask.get_values() == [0x00, 0x7F, 0x80, 0xFF]


def test_exclude_all_gives_empty():
    mask = ByteMask([(0x00, 0x02)], [0x00, 0x01, 0x02])
    assert mask.get_values() == []


def test_high_bit_range():
    mask = ByteMask([(0x80, 0xFF)], [])
    values = mask.get_values()
    assert len(values) == 128


# --- from_string tests ---

def test_from_string_simple_range():
    mask = ByteMask.from_string("0x00-0x0F")
    assert len(mask.get_values()) == 16


def test_from_string_single_value():
    mask = ByteMask.from_string("0x42")
    assert mask.get_values() == [0x42]


def test_from_string_comma_ranges():
    mask = ByteMask.from_string("0x00-0x02,0x10-0x12")
    assert mask.get_values() == [0, 1, 2, 0x10, 0x11, 0x12]


def test_from_string_mixed():
    mask = ByteMask.from_string("0x00-0x02,0x10,0x20-0x21")
    assert mask.get_values() == [0, 1, 2, 0x10, 0x20, 0x21]


def test_from_string_with_excludes():
    mask = ByteMask.from_string("0x00-0x0F", "0x02,0x03,0x04,0x05")
    values = mask.get_values()
    assert len(values) == 12
    assert 0x02 not in values


def test_from_string_exclude_none():
    mask = ByteMask.from_string("0x00-0x0F", None)
    assert len(mask.get_values()) == 16


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
