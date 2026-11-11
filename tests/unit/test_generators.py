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

"""Tests for FuzzGenerator ABC and all generator implementations.

Covers:
  - FuzzGenerator interface contract
  - IteratorGenerator (byte mask iteration, width, endian, fill, start_value)
  - RandomBytesGenerator (determinism, length bounds, infinite vs finite)
  - MutatorGenerator (seed cycling, determinism, count limit)

No network traffic — all tests run locally against generator logic only.
"""

import sys
import random
from pathlib import Path
from typing import Dict, Any, Iterator, Optional

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pytest

from bytefault.fuzzers.fuzzer import ByteMask
from bytefault.generators.base import FuzzGenerator
from bytefault.generators.edge_case import EdgeCaseGenerator
from bytefault.generators.file_gen import FileGenerator
from bytefault.generators.iterator import IteratorGenerator
from bytefault.generators.random_bytes import RandomBytesGenerator
from bytefault.generators.mutator import Mutator, MutatorGenerator


# ────────────────────────────────────────────────────────────────────────
# FuzzGenerator ABC contract
# ────────────────────────────────────────────────────────────────────────

class TestFuzzGeneratorABC:
    """Verify the ABC cannot be instantiated directly."""

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            FuzzGenerator()  # type: ignore[abstract]

    def test_concrete_subclass(self):
        """A minimal concrete subclass satisfies the interface."""

        class StubGenerator(FuzzGenerator):
            def generate(self) -> Iterator[bytes]:
                yield b"\x00"

            def count(self) -> Optional[int]:
                return 1

            def metadata(self) -> Dict[str, Any]:
                return {"type": "stub"}

        gen = StubGenerator()
        assert list(gen.generate()) == [b"\x00"]
        assert gen.count() == 1
        assert gen.metadata()["type"] == "stub"

    def test_repr(self):
        class StubGenerator(FuzzGenerator):
            def generate(self) -> Iterator[bytes]:
                yield b""

            def count(self) -> Optional[int]:
                return 5

            def metadata(self) -> Dict[str, Any]:
                return {"type": "stub"}

        assert "stub" in repr(StubGenerator())
        assert "count=5" in repr(StubGenerator())


# ────────────────────────────────────────────────────────────────────────
# IteratorGenerator
# ────────────────────────────────────────────────────────────────────────

class TestIteratorGenerator:

    def test_basic_range(self):
        """Full range 0x00-0x09 yields 10 one-byte payloads."""
        mask = ByteMask([(0x00, 0x09)], [])
        gen = IteratorGenerator(mask, width=1)
        values = list(gen.generate())
        assert len(values) == 10
        assert values[0] == b"\x00"
        assert values[9] == b"\x09"
        assert gen.count() == 10

    def test_excludes(self):
        """Excludes are respected — excluded values never appear."""
        mask = ByteMask([(0x00, 0x05)], [0x02, 0x04])
        gen = IteratorGenerator(mask, width=1)
        values = list(gen.generate())
        assert b"\x02" not in values
        assert b"\x04" not in values
        assert len(values) == 4  # 0,1,3,5

    def test_width_2_big_endian(self):
        """Width=2, big-endian: value 0xFF -> b'\\x00\\xFF'."""
        mask = ByteMask([(0xFF, 0xFF)], [])
        gen = IteratorGenerator(mask, width=2, endian="big")
        values = list(gen.generate())
        assert values == [b"\x00\xFF"]

    def test_width_2_little_endian(self):
        """Width=2, little-endian: value 0xFF -> b'\\xFF\\x00'."""
        mask = ByteMask([(0xFF, 0xFF)], [])
        gen = IteratorGenerator(mask, width=2, endian="little")
        values = list(gen.generate())
        assert values == [b"\xFF\x00"]

    def test_fill_mode(self):
        """fill=True fills all width bytes with the same value."""
        mask = ByteMask([(0x41, 0x43)], [])
        gen = IteratorGenerator(mask, width=3, fill=True)
        values = list(gen.generate())
        assert values[0] == b"\x41\x41\x41"
        assert values[1] == b"\x42\x42\x42"
        assert values[2] == b"\x43\x43\x43"

    def test_start_value(self):
        """start_value skips earlier values (resume support)."""
        mask = ByteMask([(0x00, 0x09)], [])
        gen = IteratorGenerator(mask, width=1, start_value=0x05)
        values = list(gen.generate())
        assert len(values) == 5  # 5,6,7,8,9
        assert values[0] == b"\x05"

    def test_start_value_not_in_mask(self):
        """start_value not in mask — full list is used."""
        mask = ByteMask([(0x00, 0x03)], [])
        gen = IteratorGenerator(mask, width=1, start_value=0xFF)
        assert gen.count() == 4

    def test_invalid_width(self):
        mask = ByteMask([(0x00, 0x00)], [])
        with pytest.raises(ValueError, match="width"):
            IteratorGenerator(mask, width=0)

    def test_invalid_endian(self):
        mask = ByteMask([(0x00, 0x00)], [])
        with pytest.raises(ValueError, match="endian"):
            IteratorGenerator(mask, width=1, endian="middle")

    def test_empty_mask(self):
        """Empty mask produces zero values."""
        mask = ByteMask([], [])
        gen = IteratorGenerator(mask, width=1)
        assert list(gen.generate()) == []
        assert gen.count() == 0

    def test_metadata(self):
        mask = ByteMask([(0x00, 0xFF)], [0x11])
        gen = IteratorGenerator(mask, width=1)
        meta = gen.metadata()
        assert meta["type"] == "iterator"
        assert meta["width"] == 1
        assert meta["total_values"] == 255  # 256 - 1 excluded

    def test_generator_is_reusable(self):
        """Calling generate() twice yields the same sequence."""
        mask = ByteMask([(0x00, 0x03)], [])
        gen = IteratorGenerator(mask, width=1)
        first = list(gen.generate())
        second = list(gen.generate())
        assert first == second


# ────────────────────────────────────────────────────────────────────────
# RandomBytesGenerator
# ────────────────────────────────────────────────────────────────────────

class TestRandomBytesGenerator:

    def test_deterministic_with_seed(self):
        """Same seed + same params = same sequence."""
        gen1 = RandomBytesGenerator(4, 16, count_limit=20, rng=random.Random(42))
        gen2 = RandomBytesGenerator(4, 16, count_limit=20, rng=random.Random(42))
        assert list(gen1.generate()) == list(gen2.generate())

    def test_count_limit(self):
        """Generator stops after count_limit payloads."""
        gen = RandomBytesGenerator(1, 4, count_limit=10, rng=random.Random(0))
        values = list(gen.generate())
        assert len(values) == 10
        assert gen.count() == 10

    def test_infinite_when_zero(self):
        """count_limit=0 means infinite (count() returns None)."""
        gen = RandomBytesGenerator(1, 4, count_limit=0)
        assert gen.count() is None

    def test_infinite_when_none(self):
        gen = RandomBytesGenerator(1, 4, count_limit=None)
        assert gen.count() is None

    def test_length_bounds(self):
        """All payloads are within [min_len, max_len]."""
        gen = RandomBytesGenerator(3, 7, count_limit=100, rng=random.Random(99))
        for payload in gen.generate():
            assert 3 <= len(payload) <= 7

    def test_fixed_length(self):
        """min_len == max_len produces fixed-length payloads."""
        gen = RandomBytesGenerator(5, 5, count_limit=20, rng=random.Random(1))
        for payload in gen.generate():
            assert len(payload) == 5

    def test_zero_length(self):
        """min_len=0 can produce empty payloads."""
        gen = RandomBytesGenerator(0, 0, count_limit=5, rng=random.Random(1))
        for payload in gen.generate():
            assert payload == b""

    def test_invalid_min_len(self):
        with pytest.raises(ValueError, match="nonnegative integer length bounds"):
            RandomBytesGenerator(-1, 4)

    def test_invalid_max_lt_min(self):
        with pytest.raises(ValueError, match="nonnegative integer length bounds"):
            RandomBytesGenerator(10, 5)

    def test_metadata(self):
        gen = RandomBytesGenerator(4, 16, count_limit=100, rng=random.Random(42))
        meta = gen.metadata()
        assert meta["type"] == "random_bytes"
        assert meta["min_len"] == 4
        assert meta["max_len"] == 16
        assert meta["count"] == 100
        assert meta["deterministic"] is True

    def test_metadata_nondeterministic(self):
        gen = RandomBytesGenerator(1, 8, count_limit=10, rng=None)
        assert gen.metadata()["deterministic"] is False

    def test_generator_is_reentrant(self):
        """Two calls to generate() with seeded rng produce different output.

        This is expected — the rng state advances.  Verifying it doesn't
        crash or return stale data.
        """
        gen = RandomBytesGenerator(1, 4, count_limit=5, rng=random.Random(42))
        first = list(gen.generate())
        second = list(gen.generate())
        # Second call continues from advanced rng state — sequences differ
        assert len(second) == 5

    # -- exclude_bytes tests ---

    def test_exclude_bytes_basic(self):
        """Excluded byte values never appear in output."""
        excluded = {0x00, 0x0A, 0xFF}
        gen = RandomBytesGenerator(
            8, 32, count_limit=200, rng=random.Random(42),
            exclude_bytes=excluded,
        )
        for payload in gen.generate():
            for b in payload:
                assert b not in excluded, (
                    f"Excluded byte 0x{b:02X} found in payload"
                )

    def test_exclude_bytes_range(self):
        """Excluding a range of byte values works correctly."""
        # Exclude all control characters 0x00-0x1F
        excluded = set(range(0x00, 0x20))
        gen = RandomBytesGenerator(
            16, 16, count_limit=100, rng=random.Random(99),
            exclude_bytes=excluded,
        )
        for payload in gen.generate():
            assert len(payload) == 16
            for b in payload:
                assert b >= 0x20, f"Control byte 0x{b:02X} found in payload"

    def test_exclude_bytes_deterministic(self):
        """Seeded generator with excludes is deterministic."""
        excluded = {0x00, 0xFF}
        gen1 = RandomBytesGenerator(
            4, 16, count_limit=20, rng=random.Random(42),
            exclude_bytes=excluded,
        )
        gen2 = RandomBytesGenerator(
            4, 16, count_limit=20, rng=random.Random(42),
            exclude_bytes=excluded,
        )
        assert list(gen1.generate()) == list(gen2.generate())

    def test_exclude_bytes_metadata(self):
        """Metadata includes excluded bytes when present."""
        gen = RandomBytesGenerator(
            1, 8, count_limit=10, exclude_bytes={0x00, 0x0A},
        )
        meta = gen.metadata()
        assert meta["exclude_bytes"] == [0x00, 0x0A]

    def test_exclude_bytes_metadata_empty(self):
        """Metadata explicitly represents the empty exclusion choice."""
        gen = RandomBytesGenerator(1, 8, count_limit=10)
        assert gen.metadata()['exclude_bytes'] == []

    def test_exclude_all_bytes_raises(self):
        """Excluding all 256 values raises ValueError."""
        with pytest.raises(ValueError, match="remove a complete selectable alphabet"):
            RandomBytesGenerator(1, 8, exclude_bytes=set(range(256)))

    def test_exclude_bytes_empty_set_no_constraint(self):
        """Empty exclude set behaves like no exclusion."""
        gen = RandomBytesGenerator(
            4, 4, count_limit=5, rng=random.Random(42),
            exclude_bytes=set(),
        )
        # Should produce output identical to no-exclude version
        gen_ref = RandomBytesGenerator(
            4, 4, count_limit=5, rng=random.Random(42),
        )
        assert list(gen.generate()) == list(gen_ref.generate())

    def test_exclude_bytes_zero_length(self):
        """Excluding bytes still works when length is zero."""
        gen = RandomBytesGenerator(
            0, 0, count_limit=3, exclude_bytes={0x00},
        )
        for payload in gen.generate():
            assert payload == b""


# ────────────────────────────────────────────────────────────────────────
# MutatorGenerator
# ────────────────────────────────────────────────────────────────────────

class TestMutatorGenerator:

    def test_deterministic_with_seed(self):
        """Same rng seed + same seeds = same mutations."""
        gen1 = MutatorGenerator(
            seeds=[b"\x00\x01\x02\x03"],
            count_limit=20,
            rng=random.Random(42),
        )
        gen2 = MutatorGenerator(
            seeds=[b"\x00\x01\x02\x03"],
            count_limit=20,
            rng=random.Random(42),
        )
        assert list(gen1.generate()) == list(gen2.generate())

    def test_count_limit(self):
        gen = MutatorGenerator(
            seeds=[b"AAAA"],
            count_limit=10,
            rng=random.Random(0),
        )
        values = list(gen.generate())
        assert len(values) == 10
        assert gen.count() == 10

    def test_seed_cycling(self):
        """Multiple seeds are cycled round-robin."""
        seed_a = b"\xAA" * 4
        seed_b = b"\xBB" * 4
        gen = MutatorGenerator(
            seeds=[seed_a, seed_b],
            count_limit=4,
            rng=random.Random(42),
        )
        values = list(gen.generate())
        assert len(values) == 4
        # All should be bytes (mutations of the seeds)
        for v in values:
            assert isinstance(v, bytes)

    def test_empty_seeds_raises(self):
        with pytest.raises(ValueError, match="seed"):
            MutatorGenerator(seeds=[], count_limit=10)

    def test_metadata(self):
        gen = MutatorGenerator(
            seeds=[b"\x00\x01", b"\xFF\xFE\xFD"],
            count_limit=50,
            max_len=10,
        )
        meta = gen.metadata()
        assert meta["type"] == "mutator"
        assert meta["seed_count"] == 2
        assert meta["seed_sizes"] == [2, 3]
        assert meta["count"] == 50
        assert meta["max_len"] == 10


# ────────────────────────────────────────────────────────────────────────
# EdgeCaseGenerator
# ────────────────────────────────────────────────────────────────────────


class TestEdgeCaseGenerator:
    """Verify boundary-value generation."""

    def test_width_1_basic(self):
        gen = EdgeCaseGenerator(width=1)
        values = list(gen.generate())
        assert len(values) > 0
        assert all(len(v) == 1 for v in values)
        # Must include classic 1-byte boundaries
        assert b"\x00" in values
        assert b"\x01" in values
        assert b"\x7f" in values
        assert b"\x80" in values
        assert b"\xff" in values

    def test_width_2_includes_16bit(self):
        gen = EdgeCaseGenerator(width=2)
        values = list(gen.generate())
        assert all(len(v) == 2 for v in values)
        assert b"\x00\x00" in values
        assert b"\x7f\xff" in values
        assert b"\x80\x00" in values
        assert b"\xff\xff" in values

    def test_width_4_includes_32bit(self):
        gen = EdgeCaseGenerator(width=4)
        values = list(gen.generate())
        assert all(len(v) == 4 for v in values)
        assert b"\x00\x00\x00\x00" in values
        assert b"\x7f\xff\xff\xff" in values
        assert b"\x80\x00\x00\x00" in values
        assert b"\xff\xff\xff\xff" in values

    def test_count_is_finite(self):
        gen = EdgeCaseGenerator(width=1)
        cnt = gen.count()
        assert cnt is not None
        assert cnt > 0
        assert cnt == len(list(gen.generate()))

    def test_deterministic(self):
        gen1 = EdgeCaseGenerator(width=2)
        gen2 = EdgeCaseGenerator(width=2)
        assert list(gen1.generate()) == list(gen2.generate())

    def test_sorted(self):
        gen = EdgeCaseGenerator(width=1)
        values = [int.from_bytes(v, "big") for v in gen.generate()]
        assert values == sorted(values)

    def test_no_duplicates(self):
        gen = EdgeCaseGenerator(width=2)
        values = list(gen.generate())
        assert len(values) == len(set(values))

    def test_little_endian(self):
        gen = EdgeCaseGenerator(width=2, endian="little")
        values = list(gen.generate())
        # 0x0100 in little-endian is b"\x00\x01"
        assert b"\x00\x01" in values

    def test_metadata(self):
        gen = EdgeCaseGenerator(width=2)
        meta = gen.metadata()
        assert meta["type"] == "edge_case"
        assert meta["width"] == 2
        assert meta["count"] > 0

    def test_invalid_width(self):
        with pytest.raises(ValueError, match="width"):
            EdgeCaseGenerator(width=0)

    def test_invalid_endian(self):
        with pytest.raises(ValueError, match="endian"):
            EdgeCaseGenerator(endian="middle")


# ────────────────────────────────────────────────────────────────────────
# FileGenerator
# ────────────────────────────────────────────────────────────────────────


class TestFileGenerator:
    """Exact whole files and explicit lines/transforms preserve useful results."""

    def test_basic_read(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_bytes(b"hello\nworld\n")
        gen = FileGenerator(str(f))
        values = list(gen.generate())
        assert values == [b"hello\nworld\n"]
        assert list(FileGenerator(str(f), source_mode='lines').generate()) == [b'hello', b'world']

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / "payloads.txt"
        from bytefault.generators.transforms import MutationPipeline, TransformSpec
        f.write_bytes(b"aaa\n\nbbb\n\n")
        gen = FileGenerator(str(f), source_mode='lines')
        pipeline = MutationPipeline((TransformSpec('blank', 'filter_empty'),))
        outcomes = [pipeline.apply(data) for data in gen.generate()]
        assert [outcome.data for outcome in outcomes if outcome.disposition == 'accepted'] == [b'aaa', b'bbb']
        assert [outcome.disposition for outcome in outcomes] == ['accepted', 'excluded:empty', 'accepted', 'excluded:empty']
        assert outcomes[1].results[0].input_data == b''

    def test_skips_comments(self, tmp_path):
        f = tmp_path / "payloads.txt"
        from bytefault.generators.transforms import MutationPipeline, TransformSpec
        f.write_bytes(b"# comment\nreal_payload\n# another\n")
        gen = FileGenerator(str(f), source_mode='lines')
        pipeline = MutationPipeline((TransformSpec('comment', 'filter_comments'),))
        outcomes = [pipeline.apply(data) for data in gen.generate()]
        assert [outcome.data for outcome in outcomes if outcome.disposition == 'accepted'] == [b'real_payload']
        assert [outcome.disposition for outcome in outcomes] == ['excluded:comment', 'accepted', 'excluded:comment']
        assert outcomes[0].results[0].input_data == b'# comment'

    def test_count_matches_output(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_bytes(b"a\nb\nc\n")
        gen = FileGenerator(str(f), source_mode='lines')
        assert gen.count() == 3
        assert gen.count() == len(list(gen.generate()))

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            FileGenerator("/nonexistent/path/to/file.txt")

    def test_metadata(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_text("x\n")
        gen = FileGenerator(str(f))
        meta = gen.metadata()
        assert meta["type"] == "file"
        assert "path" in meta

    def test_preserves_whitespace_and_explicit_trim(self, tmp_path):
        from bytefault.generators.transforms import MutationPipeline, TransformSpec
        f = tmp_path / "payloads.txt"
        f.write_bytes(b"  spaced  \n")
        gen = FileGenerator(str(f), source_mode='lines')
        values = list(gen.generate())
        assert values == [b"  spaced  "]
        pipeline = MutationPipeline((TransformSpec('strip', 'text_trim'),))
        outcome = pipeline.apply(values[0])
        assert outcome.data == b'spaced'
        assert outcome.results[0].input_data == b'  spaced  '

    def test_unicode_content(self, tmp_path):
        f = tmp_path / "payloads.txt"
        from bytefault.generators.transforms import MutationPipeline, TransformSpec
        f.write_bytes("éàü\nñöä\n".encode('utf-8'))
        gen = FileGenerator(str(f), source_mode='lines')
        values = list(gen.generate())
        assert len(values) == 2
        assert values[0] == "éàü".encode("utf-8")
        pipeline = MutationPipeline((TransformSpec('transcode', 'text', {'from_encoding': 'utf-8', 'to_encoding': 'latin-1'}),))
        outcome = pipeline.apply(values[0])
        assert outcome.data == 'éàü'.encode('latin-1')
        assert outcome.results[0].input_data == 'éàü'.encode('utf-8')

    def test_deterministic_order(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_bytes(b"z\ny\nx\n")
        gen = FileGenerator(str(f), source_mode='lines')
        assert list(gen.generate()) == [b"z", b"y", b"x"]
