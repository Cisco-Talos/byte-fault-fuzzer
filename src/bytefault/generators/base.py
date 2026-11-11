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

"""Abstract base class for fuzz value generators.

All generators conform to the FuzzGenerator interface, making them
composable and pluggable into the fuzzer's orchestration layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Any, Iterator, Optional


class FuzzGenerator(ABC):
    """Abstract base for fuzz value generators.

    A generator yields byte payloads one at a time.  Generators may be
    finite (e.g. iterate over a byte mask) or infinite (e.g. random values
    with count=0).  They carry metadata used for crash attribution.

    Implementers must define:
        generate()  -> Iterator[bytes]
        count()     -> Optional[int]   (None = infinite)
        metadata()  -> Dict[str, Any]

    Example usage::

        gen = IteratorGenerator(ByteMask([(0x00, 0xFF)], []), width=1)
        for value in gen.generate():
            field_bytes["route"] = value
            pkt = fuzzer.build_packet(field_bytes)
            ...
    """

    @abstractmethod
    def generate(self) -> Iterator[bytes]:
        """Yield fuzz payloads until exhausted (or forever if infinite)."""

    @abstractmethod
    def count(self) -> Optional[int]:
        """Return the total number of payloads, or ``None`` if infinite."""

    @abstractmethod
    def metadata(self) -> Dict[str, Any]:
        """Return generator metadata for crash reporting and logging.

        At minimum should include ``{"type": "<generator_name>"}``.
        """

    def samples(self):
        """Yield bytes and resolved random choices; deterministic default."""
        values = self.generate()
        try:
            for data in values:
                yield data, ()
        finally:
            close = getattr(values, 'close', None)
            if close is not None:
                close()

    def __repr__(self) -> str:
        meta = self.metadata()
        cnt = self.count()
        cnt_str = str(cnt) if cnt is not None else "inf"
        return f"<{meta.get('type', type(self).__name__)} count={cnt_str}>"
