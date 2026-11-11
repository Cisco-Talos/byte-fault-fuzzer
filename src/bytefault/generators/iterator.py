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

"""Iterator-based generator that wraps ByteMask value enumeration.

Produces a finite sequence of byte payloads by iterating over every value
in a ByteMask, encoding each value into ``width`` bytes.

This captures the same value-generation semantics as the monolithic
``fuzz_field()`` loop, decoupled from send/crash handling.
"""

from __future__ import annotations

from typing import Dict, Any, Iterator, Optional

from bytefault.generators.base import FuzzGenerator

from bytefault.fuzzers.byte_mask import ByteMask


class IteratorGenerator(FuzzGenerator):
    """Iterate over every value in a byte mask.

    Each value is encoded as a ``width``-byte big-endian payload.

    Args:
        mask: A ``ByteMask`` instance whose values are enumerated lazily.
        width: Number of bytes per generated payload (default 1).
        endian: ``"big"`` or ``"little"`` — byte order for multi-byte
                encoding (default ``"big"``).
        start_value: If provided, skip all values before this one
                     (resume support).
        fill: If ``True``, fill all ``width`` bytes with the same value
              instead of encoding the integer.  Mirrors ``field_same``
              behaviour in the old fuzzer.

    Example::

        mask = ByteMask([(0x00, 0x09)], [])
        gen = IteratorGenerator(mask, width=1)
        list(gen.generate())
        # [b'\\x00', b'\\x01', ..., b'\\x09']
    """

    def __init__(
        self,
        mask: "ByteMask",
        width: int = 1,
        endian: str = "big",
        start_value: Optional[int] = None,
        fill: bool = False,
    ) -> None:
        if width < 1:
            raise ValueError(f"width must be >= 1, got {width}")
        if endian not in ("big", "little"):
            raise ValueError(f"endian must be 'big' or 'little', got {endian!r}")

        self._mask = ByteMask(mask.ranges, mask.excludes)
        self._width = width
        self._endian = endian
        self._fill = fill

        self._start_value = start_value

    # -- FuzzGenerator interface ------------------------------------------

    def generate(self) -> Iterator[bytes]:
        for val in self._mask.iter_values(self._start_value):
            if self._fill:
                yield bytes([val & 0xFF]) * self._width
            else:
                yield val.to_bytes(self._width, byteorder=self._endian)

    def count(self) -> Optional[int]:
        return self._mask.count_values(self._start_value)

    def metadata(self) -> Dict[str, Any]:
        return {
            "type": "iterator",
            "width": self._width,
            "endian": self._endian,
            "fill": self._fill,
            "total_values": self.count(),
            "mask_ranges": self._mask.ranges,
            "mask_excludes": list(self._mask.excludes),
        }
