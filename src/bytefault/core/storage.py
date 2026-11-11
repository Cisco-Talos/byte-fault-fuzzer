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

"""Append-only local records, acknowledged after complete write, flush and fsync.

The supported guarantee is writer-process termination on a local filesystem.
This does not assert power-loss durability. Recovery never repairs/truncates an
invalid tail: valid earlier frames and an attributed suffix issue are returned.
Result-root attachment/ownership belongs to the separate shared-root service.
"""
import json
import os
from pathlib import Path
import struct
import threading
from uuid import uuid4
import zlib

from bytefault.core.records import (Record, RecordRef, RecordError, RecoveryIssue,
    RecoveryResult, encode_value, decode_value)

HEADER = struct.Struct('>4sII')
MAGIC = b'BFR1'


def frame_record(record):
    body = json.dumps(encode_value(record), ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')
    return HEADER.pack(MAGIC, len(body), zlib.crc32(body)) + body


def reopen_records(path):
    """Immutable reader snapshot. Missing input creates no file or directory."""
    path = Path(path).resolve()
    try:
        if not path.is_file():
            return RecoveryResult((), (), RecoveryIssue('not_found', 0, str(path)))
    except OSError as exc:
        return RecoveryResult((), (), RecoveryIssue('unreadable', 0, str(exc)))
    records, refs = [], []
    seen_ids = set()
    try:
        with path.open('rb') as stream:
            while True:
                offset = stream.tell()
                header = stream.read(HEADER.size)
                if not header:
                    break
                if len(header) != HEADER.size:
                    return RecoveryResult(tuple(records), tuple(refs),
                        RecoveryIssue('incomplete', offset, 'partial frame header'))
                magic, length, checksum = HEADER.unpack(header)
                if magic != MAGIC:
                    kind = 'unsupported_version' if magic.startswith(b'BFR') else 'corrupt'
                    return RecoveryResult(tuple(records), tuple(refs),
                        RecoveryIssue(kind, offset, 'unsupported frame version' if kind ==
                                      'unsupported_version' else 'invalid frame marker'))
                # Check remaining size before allocating an untrusted length.
                if length > os.fstat(stream.fileno()).st_size - stream.tell():
                    return RecoveryResult(tuple(records), tuple(refs),
                        RecoveryIssue('incomplete', offset, 'partial frame body'))
                body = stream.read(length)
                try:
                    if zlib.crc32(body) != checksum:
                        raise ValueError('frame checksum mismatch')
                    value = decode_value(json.loads(body))
                    if type(value.get('version')) is not int or value.get('version') != 1:
                        return RecoveryResult(tuple(records), tuple(refs),
                            RecoveryIssue('unsupported_version', offset, 'unsupported record version'))
                    record = Record(**value)
                    if not record.record_id or not record.kind:
                        raise ValueError('record identity/kind missing')
                    if record.record_id in seen_ids:
                        raise ValueError('duplicate record identity')
                except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
                    return RecoveryResult(tuple(records), tuple(refs),
                        RecoveryIssue('corrupt', offset, str(exc)))
                records.append(record)
                seen_ids.add(record.record_id)
                refs.append(RecordRef(str(path), record.record_id, offset, HEADER.size + length))
    except OSError as exc:
        return RecoveryResult(tuple(records), tuple(refs), RecoveryIssue('unreadable', 0, str(exc)))
    return RecoveryResult(tuple(records), tuple(refs))


class LocalRecordStore:
    """One attached writer's local append primitive; no deletion or rotation."""
    def __init__(self, path):
        self.path = Path(path).resolve()
        self._lock = threading.RLock()
        self.closed = False
        self.failed = False
        existing = reopen_records(self.path)
        if existing.issue and existing.issue.kind != 'not_found':
            raise RecordError(f'{existing.issue.kind} at {existing.issue.offset}: {existing.issue.reason}')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open('ab', buffering=0)

    def append(self, kind, identity, data):
        with self._lock:
            if self.closed:
                raise RecordError('record store closed')
            try:
                record = Record(str(uuid4()), kind, identity, data)
                frame = frame_record(record)
                offset = self._stream.tell()
                count = self._stream.write(frame)
                if count != len(frame):
                    raise RecordError(f'short required write: {count}/{len(frame)}')
                self._stream.flush()
                os.fsync(self._stream.fileno())
            except (OSError, ValueError, TypeError) as exc:
                self.failed = True
                self.closed = True
                try:
                    self._stream.close()
                except OSError:
                    pass
                raise RecordError(str(exc)) from exc
            # This return is the sole success acknowledgement point.
            return RecordRef(str(self.path), record.record_id, offset, len(frame))

    def snapshot(self):
        return reopen_records(self.path)

    def writer_stat(self):
        """Snapshot open-writer metadata under the append/close lock."""
        with self._lock:
            if self.closed or self.failed:
                return None
            try:
                return os.fstat(self._stream.fileno())
            except (OSError, ValueError):
                return None

    def close(self):
        with self._lock:
            if not self.closed:
                self.closed = True
                self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
