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

"""Edge-case value generator for boundary/corner-case fuzzing.

Generates classic boundary values that commonly trigger integer
overflow, off-by-one, sign confusion, and similar bugs:

- Minimum and maximum values for 1/2/4/8-byte widths
- Powers of two and their neighbours (2^n, 2^n-1, 2^n+1)
- Sign boundaries for signed integer interpretations
- Common "interesting" values from fuzzing literature (AFL, libFuzzer)

The generator is width-aware: for a 1-byte field it produces 0x00,
0x01, 0x7F, 0x80, 0xFE, 0xFF etc.  For a 2-byte field it also
includes 0x0100, 0x7FFF, 0x8000, 0xFFFF and so on.

All values are deduplicated and sorted.
"""

from __future__ import annotations

from typing import Dict, Any, Iterator, List, Optional

from bytefault.generators.base import FuzzGenerator


# Classic interesting values per byte-width, big-endian.
# Inspired by AFL's ``interesting`` value tables.
_INTERESTING_8: List[int] = [
    0x00, 0x01, 0x02,
    0x0F, 0x10, 0x1F, 0x20,
    0x3F, 0x40, 0x41,
    0x7E, 0x7F, 0x80, 0x81,
    0xBF, 0xC0,
    0xFE, 0xFF,
]

_INTERESTING_16: List[int] = [
    0x0000, 0x0001, 0x0002,
    0x000F, 0x0010, 0x001F, 0x0020,
    0x003F, 0x0040, 0x007F, 0x0080,
    0x00FF, 0x0100, 0x01FF, 0x0200,
    0x03FF, 0x0400, 0x07FF, 0x0800,
    0x0FFF, 0x1000,
    0x3FFF, 0x4000,
    0x7FFE, 0x7FFF, 0x8000, 0x8001,
    0xFFFE, 0xFFFF,
]

_INTERESTING_32: List[int] = [
    0x00000000, 0x00000001,
    0x0000007F, 0x00000080, 0x000000FF, 0x00000100,
    0x0000FFFF, 0x00010000,
    0x7FFFFFFE, 0x7FFFFFFF, 0x80000000, 0x80000001,
    0xFFFFFFFE, 0xFFFFFFFF,
]

_INTERESTING_64: List[int] = [
    0x0000000000000000, 0x0000000000000001,
    0x000000007FFFFFFF, 0x0000000080000000,
    0x00000000FFFFFFFF, 0x0000000100000000,
    0x7FFFFFFFFFFFFFFE, 0x7FFFFFFFFFFFFFFF,
    0x8000000000000000, 0x8000000000000001,
    0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
]


def _interesting_values(width: int) -> List[int]:
    """Return sorted/deduplicated interesting values for *width* bytes."""
    max_val = (1 << (width * 8)) - 1

    vals: set[int] = set()
    vals.update(_INTERESTING_8)
    if width >= 2:
        vals.update(_INTERESTING_16)
    if width >= 4:
        vals.update(_INTERESTING_32)
    if width >= 8:
        vals.update(_INTERESTING_64)

    # Trim values that exceed the field width
    return sorted(v for v in vals if 0 <= v <= max_val)


class EdgeCaseGenerator(FuzzGenerator):
    """Generate classic boundary/edge-case byte payloads.

    Produces a finite, deterministic list of interesting values for the
    given ``width``.  Width defaults to 1 but should typically be set to
    match the target field's byte-width for best coverage.

    Args:
        width: Field width in bytes (1, 2, 4, or 8 typical).
        endian: Byte order for encoding — ``"big"`` or ``"little"``.

    Example::

        gen = EdgeCaseGenerator(width=2)
        for payload in gen.generate():
            # b'\\x00\\x00', b'\\x00\\x01', ..., b'\\xff\\xff'
            ...
    """

    def __init__(
        self,
        width: int = 1,
        endian: str = "big",
    ) -> None:
        if width < 1:
            raise ValueError(f"width must be >= 1, got {width}")
        if endian not in ("big", "little"):
            raise ValueError(f"endian must be 'big' or 'little', got {endian!r}")

        self._width = width
        self._endian = endian
        self._values = _interesting_values(width)

    def generate(self) -> Iterator[bytes]:
        for v in self._values:
            yield v.to_bytes(self._width, self._endian)

    def count(self) -> Optional[int]:
        return len(self._values)

    def metadata(self) -> Dict[str, Any]:
        return {
            "type": "edge_case",
            "width": self._width,
            "endian": self._endian,
            "count": len(self._values),
        }
