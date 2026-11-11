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

"""Random payloads with independent length, content and alphabet scopes."""
from __future__ import annotations

import random
import secrets
from typing import Iterator

from bytefault.generators.base import FuzzGenerator


def _randbytes(rng, length: int, allowed: bytes | None = None) -> bytes:
    if length <= 0:
        return b''
    if allowed is None:
        return secrets.token_bytes(length) if rng is None else rng.randbytes(length)
    if rng is None:
        return bytes(allowed[secrets.randbelow(len(allowed))] for _ in range(length))
    return bytes(allowed[rng.randrange(len(allowed))] for _ in range(length))


class RandomBytesGenerator(FuzzGenerator):
    """A seed reproduces a stream; it is never reset for each payload.

    ``range_choices`` is an ordered set of inclusive byte alphabets, one of
    which is selected randomly for each payload (or once when held). Exclusions
    apply within each chosen alphabet. By default the complete byte alphabet is
    fixed. ``sample`` returns exact resolved choices alongside the bytes.
    """
    def __init__(self, min_len: int = 1, max_len: int = 256,
                 count_limit: int | None = None, rng: random.Random | None = None,
                 exclude_bytes: set[int] | None = None, *,
                 length_scope: str = 'per_test', content_scope: str = 'per_test',
                 range_scope: str = 'per_test', byte_range: tuple[int, int] = (0, 255),
                 range_choices=None):
        if type(min_len) is not int or min_len < 0 or type(max_len) is not int or max_len < min_len:
            raise ValueError('ordered nonnegative integer length bounds required')
        if count_limit is not None and (type(count_limit) is not int or count_limit < 0):
            raise ValueError('count_limit must be a nonnegative integer or None')
        for scope in (length_scope, content_scope, range_scope):
            if scope not in ('sample_once', 'per_test'):
                raise ValueError('random scopes must be sample_once or per_test')
        self._min_len, self._max_len = min_len, max_len
        self._count_limit = count_limit or None
        self._rng = rng
        self._length_scope, self._content_scope, self._range_scope = length_scope, content_scope, range_scope
        self._exclude = frozenset(exclude_bytes or ())
        if any(type(n) is not int or not 0 <= n <= 255 for n in self._exclude):
            raise ValueError('excluded bytes must be integers in 0..255')
        self._range_choices = tuple(tuple(pair) for pair in range_choices) if range_choices is not None else ()
        self._byte_range = tuple(byte_range)
        for pair in self._range_choices or (self._byte_range,):
            if len(pair) != 2 or any(type(n) is not int or not 0 <= n <= 255 for n in pair) or pair[0] > pair[1]:
                raise ValueError('byte alphabets require inclusive ordered bounds in 0..255')
            if not any(n not in self._exclude for n in range(pair[0], pair[1] + 1)):
                raise ValueError('excluded bytes remove a complete selectable alphabet')
        alphabets = {bytes(n for n in range(lo, hi + 1) if n not in self._exclude)
                     for lo, hi in self._range_choices}
        if content_scope == 'sample_once' and len(alphabets) > 1 and range_scope == 'per_test':
            raise ValueError('contradictory_scope: held content conflicts with a per_test variable alphabet')
        self._held = {}

    def _resolve(self, name, scope, draw):
        if scope == 'sample_once':
            if name not in self._held:
                self._held[name] = draw()
            return self._held[name]
        return draw()

    def _randint(self, lo, hi):
        if lo == hi:
            return lo
        return lo + secrets.randbelow(hi - lo + 1) if self._rng is None else self._rng.randint(lo, hi)

    def sample(self, *, length=None):
        if length is not None and (type(length) is not int or not self._min_len <= length <= self._max_len):
            raise ValueError('sample length outside configured payload bounds')
        choices = []
        if length is None:
            length = self._resolve('length', self._length_scope,
                lambda: self._randint(self._min_len, self._max_len))
            choices.append(('length', (self._min_len, self._max_len), self._length_scope, length))
        if self._range_choices:
            selected = self._resolve('range', self._range_scope,
                lambda: self._randint(0, len(self._range_choices) - 1))
            alphabet = self._range_choices[selected]
            choices.append(('range', (0, len(self._range_choices) - 1), self._range_scope,
                            {'index': selected, 'bounds': alphabet}))
        else:
            alphabet = self._byte_range
        allowed = (None if alphabet == (0, 255) and not self._exclude else
                   bytes(n for n in range(alphabet[0], alphabet[1] + 1) if n not in self._exclude))
        content_length = self._max_len if self._content_scope == 'sample_once' else length
        content = self._resolve('content', self._content_scope,
            lambda: _randbytes(self._rng, content_length, allowed))
        data = content[:length]
        choices.append(('content', alphabet, self._content_scope, content))
        return data, tuple(choices)

    def samples(self):
        index = 0
        while self._count_limit is None or index < self._count_limit:
            yield self.sample()
            index += 1

    def generate(self) -> Iterator[bytes]:
        for data, _ in self.samples():
            yield data

    def count(self):
        return self._count_limit

    def metadata(self):
        return {'type': 'random_bytes', 'min_len': self._min_len, 'max_len': self._max_len,
                'count': self._count_limit, 'deterministic': self._rng is not None,
                'exclude_bytes': sorted(self._exclude), 'byte_range': self._byte_range,
                'range_choices': self._range_choices, 'length_scope': self._length_scope,
                'content_scope': self._content_scope, 'range_scope': self._range_scope}
