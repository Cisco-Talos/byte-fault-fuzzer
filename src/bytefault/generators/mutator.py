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

"""Retained mutation operations, traced decisions and a byte-generator facade."""

from __future__ import annotations

import random
from typing import Dict, Any, Iterable, Iterator, List, Optional

from bytefault.generators.base import FuzzGenerator

MUTATION_OPERATIONS = ('flip_bit', 'flip_byte', 'arith_byte',
    'insert_byte', 'delete_byte', 'duplicate_slice')


class Mutator:
    """Generate simple mutations from seed payloads."""

    def __init__(self, rng: Optional[random.Random] = None, max_len: Optional[int] = None,
                 *, draw=None, operations=None):
        if max_len is not None and (type(max_len) is not int or max_len < 0):
            raise ValueError('max_len must be a nonnegative integer')
        self.rng = rng or random.Random()
        self.max_len = max_len
        self.draw = draw
        self.operations = tuple(MUTATION_OPERATIONS if operations is None else operations)
        if not self.operations:
            raise ValueError('at least one mutation operation required')
        if any(name not in MUTATION_OPERATIONS for name in self.operations):
            raise ValueError('unknown mutation operation')
        self.last_operation = None
        self.selected_operation = None

    def _number(self, name, stop):
        return self.draw(name, 0, stop - 1) if self.draw is not None else self.rng.randrange(stop)

    def _select(self, name, values):
        return values[self.draw(name, 0, len(values) - 1)] if self.draw is not None else self.rng.choice(values)

    def generate(self, seed: bytes, count: int) -> Iterable[bytes]:
        for _ in range(count):
            yield self.mutate_once(seed)

    def mutate_once(self, data: bytes) -> bytes:
        if not data:
            data = b"\x00"
        self.last_operation = self.selected_operation = self._select('operation', self.operations)
        result = getattr(self, '_' + self.last_operation)(data)
        return result if self.max_len is None else result[:self.max_len]

    def _flip_bit(self, data: bytes) -> bytes:
        self.last_operation = 'flip_bit'
        buf = bytearray(data)
        idx = self._number('index', len(buf))
        bit = 1 << self._number('bit', 8)
        buf[idx] ^= bit
        return bytes(buf)

    def _flip_byte(self, data: bytes) -> bytes:
        self.last_operation = 'flip_byte'
        buf = bytearray(data)
        idx = self._number('index', len(buf))
        buf[idx] = self._number('value', 256)
        return bytes(buf)

    def _arith_byte(self, data: bytes) -> bytes:
        self.last_operation = 'arith_byte'
        buf = bytearray(data)
        idx = self._number('index', len(buf))
        delta = self._select('delta', [-3, -2, -1, 1, 2, 3])
        buf[idx] = (buf[idx] + delta) & 0xFF
        return bytes(buf)

    def _insert_byte(self, data: bytes) -> bytes:
        self.last_operation = 'insert_byte'
        if self.max_len is not None and len(data) >= self.max_len:
            return self._flip_byte(data)
        buf = bytearray(data)
        idx = self._number('index', len(buf) + 1)
        buf.insert(idx, self._number('value', 256))
        return bytes(buf)

    def _delete_byte(self, data: bytes) -> bytes:
        self.last_operation = 'delete_byte'
        if len(data) <= 1:
            return self._flip_byte(data)
        buf = bytearray(data)
        idx = self._number('index', len(buf))
        del buf[idx]
        return bytes(buf)

    def _duplicate_slice(self, data: bytes) -> bytes:
        self.last_operation = 'duplicate_slice'
        if len(data) <= 1:
            return self._insert_byte(data)
        max_len = len(data) if self.max_len is None else min(len(data), self.max_len)
        if max_len <= 1:
            return self._flip_byte(data)
        slice_len = 1 + self._number('slice_length', min(8, len(data)))
        start = self._number('slice_start', len(data) - slice_len + 1)
        chunk = data[start:start + slice_len]
        buf = bytearray(data)
        insert_at = self._number('insert_at', len(buf) + 1)
        buf[insert_at:insert_at] = chunk
        if self.max_len is not None and len(buf) > self.max_len:
            buf = buf[: self.max_len]
        return bytes(buf)


class MutatorGenerator(FuzzGenerator):
    """FuzzGenerator wrapper around the core ``Mutator``.

    Yields mutated payloads from one or more seed payloads.  Seeds are
    cycled round-robin and each is mutated once per cycle.

    Args:
        seeds: One or more seed payloads to mutate.
        count_limit: Total mutations to yield.  ``0`` or ``None`` means
                     infinite.
        rng: Seeded ``random.Random`` for deterministic mutations.
        max_len: Maximum output length (passed through to ``Mutator``).

    Example::

        gen = MutatorGenerator(
            seeds=[b"\\x00\\x01\\x02\\x03"],
            count_limit=50,
            rng=random.Random(42),
        )
        for payload in gen.generate():
            ...
    """

    def __init__(
        self,
        seeds: List[bytes],
        count_limit: Optional[int] = None,
        rng: Optional[random.Random] = None,
        max_len: Optional[int] = None,
        *, mutation_scope: str = 'per_test',
    ) -> None:
        seeds = tuple(seeds)
        if not seeds:
            raise ValueError("At least one seed payload is required")
        if any(type(seed) is not bytes for seed in seeds):
            raise ValueError('seed payloads must be exact bytes')
        if count_limit is not None and (type(count_limit) is not int or count_limit < 0):
            raise ValueError('count_limit must be nonnegative')
        if mutation_scope not in ('sample_once', 'per_test'):
            raise ValueError('mutation_scope must be sample_once or per_test')
        self._seeds = seeds
        self._count_limit = count_limit if count_limit else None
        self._mutator = Mutator(rng=rng, max_len=max_len)
        self._mutation_scope, self._pipeline = mutation_scope, None

    # -- FuzzGenerator interface ------------------------------------------

    def generate(self) -> Iterator[bytes]:
        if self._pipeline is None:
            # Local import avoids the transforms -> Mutator dependency cycle.
            from bytefault.generators.transforms import MutationPipeline, TransformSpec
            self._pipeline = MutationPipeline((TransformSpec('mutation', 'mutate', {
                'max_len': self._mutator.max_len, 'scope': self._mutation_scope}),))
            self._pipeline._rngs['mutation'] = self._mutator.rng
        i = 0
        while True:
            if self._count_limit is not None and i >= self._count_limit:
                return
            seed = self._seeds[i % len(self._seeds)]
            yield self._pipeline.apply(seed).data
            i += 1

    def count(self) -> Optional[int]:
        return self._count_limit

    def metadata(self) -> Dict[str, Any]:
        return {
            "type": "mutator",
            "seed_count": len(self._seeds),
            "seed_sizes": [len(s) for s in self._seeds],
            "count": self._count_limit,
            "max_len": self._mutator.max_len,
            "mutation_scope": self._mutation_scope,
        }
