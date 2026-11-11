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
Snapshot test: mutation-based packet generation.

Captures deterministic mutation sequences.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import random
import pytest
from bytefault.generators.mutator import Mutator


SEED_PACKET = bytes.fromhex("0006012c10000000")


def test_mutation_sequence(snapshot_helper):
    """20 mutations with seed=42 produce same sequence."""
    m = Mutator(rng=random.Random(42))
    mutations = []
    for i in range(20):
        mutated = m.mutate_once(SEED_PACKET)
        mutations.append({"index": i, "packet": mutated.hex()})

    snapshot_helper.assert_matches("mutation_seq_seed42", {
        "test": "mutation_sequence",
        "rng_seed": 42,
        "seed_packet": SEED_PACKET.hex(),
        "count": len(mutations),
        "mutations": mutations,
    })


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--capture-snapshots"])
