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

"""Simple generator that yields from a pre-computed list of payloads.

Useful for wrapping externally-generated payload lists (e.g. mutation
output, file-loaded values) into the FuzzGenerator interface.
"""

from __future__ import annotations

from typing import Dict, Any, Iterator, List, Optional
from collections.abc import Sequence

from bytefault.generators.base import FuzzGenerator


class ListGenerator(FuzzGenerator):
    """Yield payloads from an in-memory list.

    Args:
        payloads: Pre-computed byte payloads to yield in order.

    Example::

        gen = ListGenerator([b"\\x00", b"\\x01", b"\\xFF"])
        list(gen.generate())  # [b'\\x00', b'\\x01', b'\\xff']
    """

    def __init__(self, payloads: List[bytes]) -> None:
        if not isinstance(payloads, Sequence):
            raise ValueError('list payloads require a finite supplied sequence; use a generator source for streaming')
        payloads = tuple(payloads)
        if any(type(value) is not bytes for value in payloads):
            raise ValueError('list payloads must be exact bytes')
        self._payloads = tuple(payloads)

    def generate(self) -> Iterator[bytes]:
        yield from self._payloads

    def count(self) -> Optional[int]:
        return len(self._payloads)

    def metadata(self) -> Dict[str, Any]:
        return {
            "type": "list",
            "count": len(self._payloads),
        }
