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

"""Length-sweep generator.

Produces random byte payloads at sequentially increasing (or decreasing)
lengths.  Useful for finding the exact length threshold that triggers a
crash or behavioural change.

Example::

    gen = SweepGenerator(start=500, stop=4100, step=100,
                         rng=random.Random(42))
    for payload in gen.generate():
        # payload lengths: 500, 600, 700, ..., 4100
        ...
"""

from __future__ import annotations

import random
from typing import Dict, Any, Iterator, Optional

from bytefault.generators.base import FuzzGenerator
from bytefault.generators.random_bytes import RandomBytesGenerator


class SweepGenerator(FuzzGenerator):
    """Generate random byte strings at sequentially stepped lengths.

    Args:
        start: First payload length in bytes (inclusive).
        stop: Last payload length in bytes (inclusive).
        step: Length increment between payloads (default 1).
        rng: Seeded ``random.Random`` for reproducibility.
             If ``None``, uses ``secrets`` (non-deterministic).

    Yields payloads of lengths ``start, start+step, start+2*step, ...``
    up to and including ``stop``.
    """

    def __init__(
        self,
        start: int = 1,
        stop: int = 256,
        step: int = 1,
        rng: Optional[random.Random] = None,
        *, content_scope: str = 'per_test', range_scope: str = 'per_test',
        byte_range=(0, 255), range_choices=None, exclude_bytes=None,
    ) -> None:
        if start < 0:
            raise ValueError(f"start must be >= 0, got {start}")
        if stop < start:
            raise ValueError(f"stop ({stop}) < start ({start})")
        if step < 1:
            raise ValueError(f"step must be >= 1, got {step}")
        self._start = start
        self._stop = stop
        self._step = step
        self._rng = rng
        self._random = RandomBytesGenerator(start, stop, rng=rng,
            content_scope=content_scope, range_scope=range_scope,
            byte_range=byte_range, range_choices=range_choices, exclude_bytes=exclude_bytes,
            length_scope='sample_once')

    # -- FuzzGenerator interface ------------------------------------------

    def generate(self) -> Iterator[bytes]:
        for data, _ in self.samples():
            yield data

    def sample(self, *, index=1):
        length = self._start + (index - 1) * self._step
        if not 1 <= index <= self.count():
            raise IndexError('sweep index outside source bounds')
        return self._random.sample(length=length)

    def samples(self):
        for index in range(1, self.count() + 1):
            yield self.sample(index=index)

    def count(self) -> Optional[int]:
        if self._stop < self._start:
            return 0
        return ((self._stop - self._start) // self._step) + 1

    def metadata(self) -> Dict[str, Any]:
        return {
            "type": "sweep",
            "start": self._start,
            "stop": self._stop,
            "step": self._step,
            "deterministic": self._rng is not None,
            'random': self._random.metadata(),
        }
