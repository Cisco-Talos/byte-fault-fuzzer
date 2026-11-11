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

"""ByteMask — define allowed/excluded byte values for fuzzing."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple
from collections.abc import Sequence, Set as AbstractSet
from bisect import bisect_left, bisect_right


class ByteMask:
    """
    Define allowed/excluded bytes for fuzzing.

    Why ByteMask exists:
    Protocol fuzzing generates massive test spaces (e.g., 256 values for a single byte).
    ByteMask allows targeted fuzzing by:
    1. Focusing on specific value ranges (e.g., only high-bit-set values 0x80-0xFF)
    2. Operator-selected exclusion of known crashes (e.g., skip value=0x11)
    3. Testing interesting subsets (printable ASCII, control chars, boundary values)

    Common fuzzing strategies:
    - Full range: 0x00-0xFF (comprehensive but time-consuming)
    - High values: 0x80-0xFF (often trigger integer overflow bugs)
    - Low values: 0x00-0x7F (test normal range handling)
    - Boundaries: 0x00, 0x7F, 0x80, 0xFF (off-by-one errors)
    - Printable: 0x20-0x7E (test string handling)
    - Control chars: 0x00-0x1F (test parser robustness)

    Security relevance:
    - Known DoS values can be excluded to allow continued fuzzing
    - Ranges can be narrowed after discovering vulnerability patterns
    - Multiple masks can be combined to test specific hypotheses

    Example usage:
        # Test all bytes except observed crash
        mask = ByteMask([(0x00, 0xFF)], [0x11])

        # Test only high-bit values
        mask = ByteMask([(0x80, 0xFF)], [])

        # Test boundaries only
        mask = ByteMask([(0x00, 0x00), (0x7F, 0x80), (0xFF, 0xFF)], [])
    """

    def __init__(self, ranges: List[Tuple[int, int]], excludes: List[int]):
        """
        Initialize byte mask.

        Args:
            ranges: List of (start, end) inclusive byte ranges
            excludes: List of specific bytes to exclude
        """
        if not isinstance(ranges, Sequence) or not isinstance(excludes, (Sequence, AbstractSet)):
            raise ValueError('mask ranges/exclusions require finite supplied sequences or an exclusion set')
        ranges, excludes = tuple(ranges), frozenset(excludes)
        if any(not isinstance(pair, Sequence) or len(pair) != 2 or any(type(n) is not int or n < 0 for n in pair)
               or pair[0] > pair[1] for pair in ranges):
            raise ValueError('mask requires ordered nonnegative integer ranges')
        if any(type(n) is not int or n < 0 for n in excludes):
            raise ValueError('mask exclusions must be nonnegative integers')
        self.ranges = tuple(tuple(pair) for pair in ranges)
        self.excludes = set(excludes)

    def get_values(self) -> List[int]:
        """Explicitly materialize all valid values; use iter_values for streams."""
        return list(self.iter_values())

    def _selected_ranges(self, start_value=None):
        first = None
        if start_value is not None and start_value not in self.excludes:
            first = next((index for index, (lo, hi) in enumerate(self.ranges)
                          if lo <= start_value <= hi), None)
        for index, (lo, hi) in enumerate(self.ranges):
            if first is None or index >= first:
                yield (start_value if index == first else lo), hi

    def iter_values(self, start_value=None):
        """Lazy ordered enumeration, including duplicate overlapping ranges.

        Resume at the first allowed occurrence of start_value. An absent or
        excluded start retains the existing full-enumeration fallback.
        """
        for lo, hi in self._selected_ranges(start_value):
            for value in range(lo, hi + 1):
                if value not in self.excludes:
                    yield value

    def count_values(self, start_value=None):
        """Exact arithmetic cardinality without enumerating range members."""
        excluded = sorted(self.excludes)
        return sum(hi - lo + 1 - (bisect_right(excluded, hi) - bisect_left(excluded, lo))
                   for lo, hi in self._selected_ranges(start_value))

    @classmethod
    def from_string(cls, mask_str: str, exclude_str: Optional[str] = None):
        """
        Parse mask from string format.

        Examples:
            "0x00-0xFF" -> All bytes
            "0x20-0x7E" -> Printable ASCII
            "0x41-0x5A,0x61-0x7A" -> a-z, A-Z
        """
        ranges = []
        for part in mask_str.split(','):
            if '-' in part:
                start_str, end_str = part.split('-')
                start = int(start_str.strip(), 16)
                end = int(end_str.strip(), 16)
                ranges.append((start, end))
            else:
                val = int(part.strip(), 16)
                ranges.append((val, val))

        excludes = []
        if exclude_str:
            for part in exclude_str.split(','):
                excludes.append(int(part.strip(), 16))

        return cls(ranges, excludes)
