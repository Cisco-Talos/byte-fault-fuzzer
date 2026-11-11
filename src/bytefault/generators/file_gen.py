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

"""Exact whole-file and incremental binary-record sources.

Decoding, trimming and filtering belong to explicitly selected mutators.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from bytefault.generators.base import FuzzGenerator


class FileGenerator(FuzzGenerator):
    """Read one exact whole file, or binary records excluding only delimiter.

    Whole mode materializes the file. Lines mode buffers at most one record
    plus one read chunk; an individual record can itself be arbitrarily large.
    Counting lines scans the file without retaining its records.
    """

    def __init__(self, path: str, *, source_mode: str = 'whole',
                 delimiter: bytes = b'\n', chunk_size: int = 65536):
        if source_mode not in ('whole', 'lines'):
            raise ValueError("source_mode must be 'whole' or 'lines'")
        if type(delimiter) is not bytes or not delimiter:
            raise ValueError('delimiter must be nonempty bytes')
        if type(chunk_size) is not int or chunk_size < 1:
            raise ValueError('chunk_size must be a positive integer')
        if source_mode == 'whole' and delimiter != b'\n':
            raise ValueError('delimiter is only meaningful with source_mode=lines')
        if not Path(path).is_file():
            raise FileNotFoundError(f'Payload file not found: {path}')
        self._path = str(path)
        self._source_mode = source_mode
        self._delimiter = delimiter
        self._chunk_size = chunk_size

    def generate(self) -> Iterator[bytes]:
        with open(self._path, 'rb') as source:
            if self._source_mode == 'whole':
                yield source.read()
                return
            pending = bytearray()
            search_from = 0
            while chunk := source.read(self._chunk_size):
                pending.extend(chunk)
                start = 0
                while (end := pending.find(self._delimiter, search_from)) >= 0:
                    yield bytes(pending[start:end])
                    start = end + len(self._delimiter)
                    search_from = start
                if start:
                    del pending[:start]
                search_from = max(0, len(pending) - len(self._delimiter) + 1)
            if pending:
                yield bytes(pending)

    def count(self) -> int:
        return 1 if self._source_mode == 'whole' else sum(1 for _ in self.generate())

    def metadata(self) -> dict:
        return {'type': 'file', 'path': self._path, 'source_mode': self._source_mode,
                'delimiter': self._delimiter, 'chunk_size': self._chunk_size,
                'materialization': 'whole_file' if self._source_mode == 'whole' else 'one_record_plus_chunk'}
