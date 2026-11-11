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

"""Tests for --gen-field CLI spec parser.

Covers:
  - parse_gen_field() for all generator types (iter, random, mutate, list)
  - Parameter parsing (exclude, width, start, fill, count, seed, max_len)
  - Error handling (malformed specs, unknown types, duplicates)
  - parse_gen_fields() multi-spec and duplicate detection
  - Field size inference from schema

No network traffic — all tests run locally against parsing logic only.
"""

import sys
import random
from pathlib import Path
from typing import Dict, Any, Iterator, Optional

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pytest

from bytefault.generators.cli_parser import (
    GenFieldParseError,
    parse_gen_field,
    parse_gen_fields,
    _split_params,
)
from bytefault.generators.iterator import IteratorGenerator
from bytefault.generators.random_bytes import RandomBytesGenerator
from bytefault.generators.mutator import MutatorGenerator
from bytefault.generators.list_gen import ListGenerator
from bytefault.generators.edge_case import EdgeCaseGenerator
from bytefault.generators.file_gen import FileGenerator


# ────────────────────────────────────────────────────────────────────────
# _split_params internal helper
# ────────────────────────────────────────────────────────────────────────


class TestSplitParams:
    """Verify the primary/kwarg tokeniser."""

    def test_empty(self):
        primary, kwargs = _split_params("")
        assert primary == ""
        assert kwargs == {}

    def test_primary_only(self):
        primary, kwargs = _split_params("0-255")
        assert primary == "0-255"
        assert kwargs == {}

    def test_primary_with_modifier(self):
        primary, kwargs = _split_params("0-255,exclude:2-5")
        assert primary == "0-255"
        assert kwargs == {"exclude": "2-5"}

    def test_multiple_modifiers(self):
        primary, kwargs = _split_params("0-255,exclude:2-5,width:2,start:0x50")
        assert primary == "0-255"
        assert kwargs == {"exclude": "2-5", "width": "2", "start": "0x50"}

    def test_bare_modifier(self):
        primary, kwargs = _split_params("0-255,fill")
        assert primary == "0-255"
        assert kwargs == {"fill": ""}

    def test_multi_range_primary(self):
        """Multi-range like 0-15,128-255 should stay in primary."""
        primary, kwargs = _split_params("0-15,128-255")
        assert primary == "0-15,128-255"
        assert kwargs == {}

    def test_multi_range_with_modifier(self):
        primary, kwargs = _split_params("0-15,128-255,exclude:3-5")
        assert primary == "0-15,128-255"
        assert kwargs == {"exclude": "3-5"}


# ────────────────────────────────────────────────────────────────────────
# Iterator generator specs
# ────────────────────────────────────────────────────────────────────────


class TestParseIter:
    """Verify iterator spec parsing."""

    def test_simple_range(self):
        field, gen = parse_gen_field("route:iter:0-255")
        assert field == "route"
        assert isinstance(gen, IteratorGenerator)
        assert gen.count() == 256

    def test_hex_range(self):
        field, gen = parse_gen_field("route:iter:0x00-0xFF")
        assert field == "route"
        assert gen.count() == 256

    def test_narrow_range(self):
        field, gen = parse_gen_field("op:iter:0x80-0x8F")
        assert field == "op"
        assert gen.count() == 16

    def test_single_value(self):
        field, gen = parse_gen_field("flags:iter:42")
        assert field == "flags"
        assert gen.count() == 1

    def test_exclude(self):
        field, gen = parse_gen_field("route:iter:0-9,exclude:3-5")
        assert field == "route"
        assert gen.count() == 7

    def test_width(self):
        field, gen = parse_gen_field("op:iter:0-3,width:2")
        values = list(gen.generate())
        assert all(len(v) == 2 for v in values)
        assert values[0] == b"\x00\x00"
        assert values[3] == b"\x00\x03"

    def test_width_from_schema(self):
        """Width inferred from field_sizes if not explicitly given."""
        field, gen = parse_gen_field(
            "op:iter:0-3",
            field_sizes={"op": 2},
        )
        values = list(gen.generate())
        assert all(len(v) == 2 for v in values)

    def test_explicit_width_overrides_schema(self):
        """Explicit width:N takes precedence over schema."""
        field, gen = parse_gen_field(
            "op:iter:0-3,width:1",
            field_sizes={"op": 2},
        )
        values = list(gen.generate())
        assert all(len(v) == 1 for v in values)

    def test_fill_mode(self):
        field, gen = parse_gen_field("route:iter:0-2,width:3,fill")
        values = list(gen.generate())
        assert len(values) == 3
        # fill mode fills all bytes with same value
        assert values[0] == b"\x00\x00\x00"
        assert values[1] == b"\x01\x01\x01"
        assert values[2] == b"\x02\x02\x02"

    def test_start_value(self):
        field, gen = parse_gen_field("route:iter:0-9,start:0x05")
        values = list(gen.generate())
        # Should start at 5, so values 5,6,7,8,9 = 5 items
        assert len(values) == 5
        assert values[0] == b"\x05"

    def test_no_range_raises(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'route:iter:'.*iterator range required"):
            parse_gen_field("route:iter:")

    def test_multi_range(self):
        field, gen = parse_gen_field("route:iter:0-3,8-9")
        # 0,1,2,3,8,9 = 6 values
        assert gen.count() == 6


# ────────────────────────────────────────────────────────────────────────
# Random generator specs
# ────────────────────────────────────────────────────────────────────────


class TestParseRandom:
    """Verify random spec parsing."""

    def test_length_range(self):
        field, gen = parse_gen_field("payload:random:10-100")
        assert field == "payload"
        assert isinstance(gen, RandomBytesGenerator)
        # Without count, it's infinite
        assert gen.count() is None

    def test_fixed_length(self):
        field, gen = parse_gen_field("payload:random:64")
        assert field == "payload"
        assert isinstance(gen, RandomBytesGenerator)

    def test_count_limit(self):
        field, gen = parse_gen_field("payload:random:10-100,count:50")
        assert gen.count() == 50

    def test_deterministic_seed(self):
        _, gen1 = parse_gen_field("payload:random:10-20,count:5,seed:42")
        _, gen2 = parse_gen_field("payload:random:10-20,count:5,seed:42")
        vals1 = list(gen1.generate())
        vals2 = list(gen2.generate())
        assert vals1 == vals2

    def test_no_length_raises(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'payload:random:'.*length range required"):
            parse_gen_field("payload:random:")

    def test_exclude_single_byte(self):
        """``exclude:0x00`` removes NULL bytes from random output."""
        _, gen = parse_gen_field(
            "payload:random:8-16,count:100,seed:42,exclude:0x00"
        )
        for payload in gen.generate():
            assert 0x00 not in payload


# ────────────────────────────────────────────────────────────────────────
# Mutate generator specs
# ────────────────────────────────────────────────────────────────────────


class TestParseMutate:
    """Verify mutate spec parsing."""

    def test_basic_seed(self):
        field, gen = parse_gen_field("payload:mutate:AABBCCDD")
        assert field == "payload"
        assert isinstance(gen, MutatorGenerator)
        # Default count is 100
        assert gen.count() == 100

    def test_count(self):
        _, gen = parse_gen_field("payload:mutate:AABB,count:50")
        assert gen.count() == 50

    def test_deterministic(self):
        _, gen1 = parse_gen_field("payload:mutate:AABB,count:10,seed:42")
        _, gen2 = parse_gen_field("payload:mutate:AABB,count:10,seed:42")
        vals1 = list(gen1.generate())
        vals2 = list(gen2.generate())
        assert vals1 == vals2

    def test_no_seed_raises(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'payload:mutate:'.*mutation seed required"):
            parse_gen_field("payload:mutate:")

    def test_invalid_hex_raises(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'payload:mutate:ZZZZ'.*non-hexadecimal"):
            parse_gen_field("payload:mutate:ZZZZ")


# ────────────────────────────────────────────────────────────────────────
# List generator specs
# ────────────────────────────────────────────────────────────────────────


class TestParseList:
    """Verify list spec parsing."""

    def test_basic_list(self):
        field, gen = parse_gen_field("op:list:00,01,0A,FF")
        assert field == "op"
        assert isinstance(gen, ListGenerator)
        assert gen.count() == 4

    def test_empty_raises(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'op:list:'.*hexadecimal list value required"):
            parse_gen_field("op:list:")

    def test_invalid_hex_raises(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'op:list:ZZ'.*non-hexadecimal"):
            parse_gen_field("op:list:ZZ")


# ────────────────────────────────────────────────────────────────────────
# edge generator
# ────────────────────────────────────────────────────────────────────────


class TestParseEdge:
    """Verify ``edge`` spec parsing."""

    def test_bare_defaults(self):
        """route:edge → EdgeCaseGenerator(width=1, endian='big')."""
        field, gen = parse_gen_field("route:edge")
        assert field == "route"
        assert isinstance(gen, EdgeCaseGenerator)
        assert gen._width == 1
        assert gen._endian == "big"

    def test_explicit_width(self):
        """op:edge:width:2 → width=2."""
        _, gen = parse_gen_field("op:edge:width:2")
        assert isinstance(gen, EdgeCaseGenerator)
        assert gen._width == 2

    def test_explicit_width_and_endian(self):
        _, gen = parse_gen_field("route:edge:width:4,endian:little")
        assert isinstance(gen, EdgeCaseGenerator)
        assert gen._width == 4
        assert gen._endian == "little"

    def test_width_inferred_from_schema(self):
        """When field_sizes provides size, edge should adopt it."""
        _, gen = parse_gen_field("op:edge", field_sizes={"op": 2})
        assert gen._width == 2

    def test_explicit_width_beats_schema(self):
        """Explicit width:4 overrides schema size of 1."""
        _, gen = parse_gen_field("route:edge:width:4", field_sizes={"route": 1})
        assert gen._width == 4


# ────────────────────────────────────────────────────────────────────────
# Error handling
# ────────────────────────────────────────────────────────────────────────


class TestErrors:
    """Verify error handling for malformed specs."""

    def test_no_type(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'route'.*expected TARGET:TYPE"):
            parse_gen_field("route")

    def test_empty_field(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field ':iter:0-255'.*nonempty target"):
            parse_gen_field(":iter:0-255")

    def test_unknown_type(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'route:bogus:0-255'.*unknown source type"):
            parse_gen_field("route:bogus:0-255")

    def test_type_case_insensitive(self):
        """Generator type should be case-insensitive."""
        field, gen = parse_gen_field("route:ITER:0-9")
        assert isinstance(gen, IteratorGenerator)


# ────────────────────────────────────────────────────────────────────────
# parse_gen_fields (multi-spec)
# ────────────────────────────────────────────────────────────────────────


class TestParseGenFields:
    """Verify multi-spec parsing and duplicate detection."""

    def test_single_spec(self):
        gens = parse_gen_fields(["route:iter:0-9"])
        assert len(gens) == 1
        assert "route" in gens

    def test_multiple_specs(self):
        gens = parse_gen_fields([
            "route:iter:0-9",
            "op:iter:0x80-0x8F",
            "payload:random:10-50,count:100",
        ])
        assert len(gens) == 3
        assert "route" in gens
        assert "op" in gens
        assert "payload" in gens

    def test_duplicate_field_raises(self):
        with pytest.raises(GenFieldParseError, match="duplicate --gen-field.*route"):
            parse_gen_fields([
                "route:iter:0-9",
                "route:iter:10-19",
            ])

    def test_mixed_types(self):
        gens = parse_gen_fields([
            "route:iter:0-255",
            "payload:mutate:AABB,count:50",
        ])
        assert isinstance(gens["route"], IteratorGenerator)
        assert isinstance(gens["payload"], MutatorGenerator)

    def test_field_sizes_propagated(self):
        """Field sizes should flow through to iter generators."""
        gens = parse_gen_fields(
            ["op:iter:0-3"],
            field_sizes={"op": 2},
        )
        values = list(gens["op"].generate())
        assert all(len(v) == 2 for v in values)

    def test_empty_list(self):
        gens = parse_gen_fields([])
        assert gens == {}


# ────────────────────────────────────────────────────────────────────────
# Integration: parsed generators produce valid output
# ────────────────────────────────────────────────────────────────────────


class TestGeneratorOutput:
    """Verify end-to-end: parse spec → generate values."""

    def test_iter_generates_expected_bytes(self):
        _, gen = parse_gen_field("route:iter:0-4")
        values = list(gen.generate())
        assert values == [b"\x00", b"\x01", b"\x02", b"\x03", b"\x04"]

    def test_list_generates_exact(self):
        _, gen = parse_gen_field("op:list:41,42,43")
        values = list(gen.generate())
        assert values == [b"\x41", b"\x42", b"\x43"]

    def test_file_generates_lines(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"alpha\nbeta\n")
        _, whole = parse_gen_field(f"payload:file:{f}")
        assert list(whole.generate()) == [b"alpha\nbeta\n"]
        _, gen = parse_gen_field(f"payload:file:{f},source_mode:lines")
        assert isinstance(gen, FileGenerator)
        assert list(gen.generate()) == [b"alpha", b"beta"]

    def test_file_missing_raises(self):
        with pytest.raises((GenFieldParseError, FileNotFoundError)):
            parse_gen_field("payload:file:/no/such/file.txt")

    def test_file_empty_path_raises(self):
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'payload:file:'.*nonempty file path"):
            parse_gen_field("payload:file:")


# ────────────────────────────────────────────────────────────────────────
# Offset target @N syntax
# ────────────────────────────────────────────────────────────────────────


class TestOffsetTarget:
    """Parse @N offset targets with optional mode:insert|overwrite."""

    def test_offset_random(self):
        """@6:random:10-200 → field='@6', RandomBytesGenerator."""
        field, gen = parse_gen_field("@6:random:10-200")
        assert field == "@6"
        assert isinstance(gen, RandomBytesGenerator)
        assert gen.injection_mode == "insert"

    def test_offset_overwrite(self):
        """mode:overwrite sets injection_mode attribute."""
        field, gen = parse_gen_field("@3:random:100,mode:overwrite")
        assert field == "@3"
        assert gen.injection_mode == "overwrite"

    def test_offset_insert_explicit(self):
        """mode:insert is the default but can be stated explicitly."""
        field, gen = parse_gen_field("@10:random:64,mode:insert")
        assert field == "@10"
        assert gen.injection_mode == "insert"

    def test_offset_list(self):
        """@0:list:DEADBEEF works with list generator."""
        field, gen = parse_gen_field("@0:list:DEADBEEF,CAFEBABE")
        assert field == "@0"
        assert isinstance(gen, ListGenerator)
        assert gen.injection_mode == "insert"

    def test_offset_iter(self):
        """@2:iter:0-255 works with iterator generator."""
        field, gen = parse_gen_field("@2:iter:0-255")
        assert field == "@2"
        assert isinstance(gen, IteratorGenerator)
        assert gen.injection_mode == "insert"

    def test_invalid_offset_raises(self):
        """@abc is not a valid offset."""
        with pytest.raises(GenFieldParseError, match=r"--gen-field '@abc:random:10'.*invalid literal"):
            parse_gen_field("@abc:random:10")

    def test_invalid_mode_raises(self):
        """mode:xxx rejects unknown modes."""
        with pytest.raises(GenFieldParseError, match=r"--gen-field '@6:random:10,mode:xxx'.*mode must be"):
            parse_gen_field("@6:random:10,mode:xxx")

    def test_mode_on_schema_field_raises(self):
        """mode: is only valid with @N targets."""
        with pytest.raises(GenFieldParseError, match=r"--gen-field 'payload:random:10,mode:overwrite'.*placement modifiers require"):
            parse_gen_field("payload:random:10,mode:overwrite")

    def test_parse_gen_fields_mixed(self):
        """Schema fields and offset targets coexist."""
        gens = parse_gen_fields([
            "route:iter:0-3",
            "@6:random:10-20",
        ])
        assert "route" in gens
        assert "@6" in gens

    def test_parse_gen_fields_duplicate_offset_rejected(self):
        """Two generators targeting the same offset key are rejected."""
        with pytest.raises(GenFieldParseError, match="duplicate --gen-field.*@6"):
            parse_gen_fields([
                "@6:random:10",
                "@6:random:20",
            ])

