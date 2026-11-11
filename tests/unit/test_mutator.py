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
Unit tests for Mutator class.

Tests deterministic mutation with seeded RNG.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import random
import pytest
from bytefault.generators.mutator import Mutator


SEED_PACKET = bytes.fromhex("0006012c10000000")


def test_mutate_once_returns_bytes():
    m = Mutator(rng=random.Random(42))
    result = m.mutate_once(SEED_PACKET)
    assert isinstance(result, bytes)


def test_mutate_once_changes_something():
    """At least some mutations should differ from the seed."""
    m = Mutator(rng=random.Random(42))
    changed = 0
    for _ in range(20):
        result = m.mutate_once(SEED_PACKET)
        if result != SEED_PACKET:
            changed += 1
    assert changed > 0, "No mutations produced any change"


def test_deterministic_with_same_seed():
    """Same RNG seed → same mutation sequence."""
    m1 = Mutator(rng=random.Random(12345))
    m2 = Mutator(rng=random.Random(12345))
    for _ in range(10):
        assert m1.mutate_once(SEED_PACKET) == m2.mutate_once(SEED_PACKET)


def test_different_seeds_differ():
    """Different RNG seeds → different sequences (with high probability)."""
    m1 = Mutator(rng=random.Random(111))
    m2 = Mutator(rng=random.Random(999))
    results1 = [m1.mutate_once(SEED_PACKET) for _ in range(10)]
    results2 = [m2.mutate_once(SEED_PACKET) for _ in range(10)]
    assert results1 != results2


def test_generate_yields_count():
    """generate() produces exactly `count` mutations."""
    m = Mutator(rng=random.Random(42))
    results = list(m.generate(SEED_PACKET, 50))
    assert len(results) == 50


def test_generate_deterministic():
    """generate() with same seed gives same sequence."""
    m1 = Mutator(rng=random.Random(77))
    m2 = Mutator(rng=random.Random(77))
    r1 = list(m1.generate(SEED_PACKET, 10))
    r2 = list(m2.generate(SEED_PACKET, 10))
    assert r1 == r2


def test_max_len_respected():
    """Mutations don't exceed max_len."""
    m = Mutator(rng=random.Random(42), max_len=8)
    for _ in range(50):
        result = m.mutate_once(SEED_PACKET)
        assert len(result) <= 8


def test_empty_seed():
    """Empty seed doesn't crash."""
    m = Mutator(rng=random.Random(42))
    result = m.mutate_once(b"")
    assert isinstance(result, bytes)
    assert len(result) > 0  # Mutator converts empty to b"\x00" internally


def test_single_byte_seed():
    """Single byte seed doesn't crash."""
    m = Mutator(rng=random.Random(42))
    result = m.mutate_once(b"\xAA")
    assert isinstance(result, bytes)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
