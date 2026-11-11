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

"""Required exact action retention, independent of terminal and result bundles."""
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from bytefault.core.storage import LocalRecordStore


@dataclass(frozen=True)
class AppendProgress:
    """One run-owned writer's contiguous acknowledged file boundary."""
    owner_token: str
    path: str
    device: int
    inode: int
    committed_end: int
    appended_bytes: int
    append_count: int
    mtime_ns: int


class ActionLog:
    """Attachment owns only resources declared run/application-owned.

    Caller stores are never closed by the application. No Python/root logger
    handler, level, formatter or embedding stream is modified.
    """
    def __init__(self, store, *, owner='caller'):
        if owner not in ('run', 'application', 'caller'):
            raise ValueError('log owner must be run, application or caller')
        self.store, self.owner = store, owner
        self.closed = False
        self._lock = threading.RLock()
        self._progress_token = str(uuid4()) if isinstance(store,LocalRecordStore) else None
        self._committed_end = store._stream.tell() if self._progress_token else 0
        self._appended_bytes = self._append_count = 0
        self._contiguous = True

    @classmethod
    def open(cls, path, *, owner='run'):
        if owner == 'caller':
            raise ValueError('caller ownership requires an explicitly supplied store')
        return cls(LocalRecordStore(path), owner=owner)

    def __call__(self, kind, identity, data, acknowledged_ref=None):
        with self._lock:
            if self.closed:
                raise OSError('action log attachment closed')
            # These envelopes can contain a whole case history and portable
            # recipe. Their acknowledged source record is exact; keep the log
            # independently navigable without copying that envelope again.
            if acknowledged_ref is not None and kind in ('report_context', 'report_result'):
                data = {'projection': 'reference_only', 'record_reference': acknowledged_ref,
                    'decision_id': data.get('decision_id') if kind == 'report_context' else None}
            ref=self.store.append(kind, identity,
                {'action': data, 'evidence_reference': acknowledged_ref,
                 'recorded_at_utc': datetime.now(timezone.utc).isoformat()})
            if self._progress_token:
                if ref.offset!=self._committed_end:
                    self._contiguous=False
                self._committed_end=ref.offset+ref.length
                self._appended_bytes+=ref.length
                self._append_count+=1
            return ref

    def append_progress(self):
        """Return a token only while this exact sole writer remains attached.

        The token accounts for all writes acknowledged through this ActionLog.
        It makes no claim about out-of-band same-length overwrites of its file.
        """
        with self._lock:
            if not self._progress_token or self.closed or self.store.failed or not self._contiguous:
                return None
            info=self.store.writer_stat()
            if info is None or info.st_size!=self._committed_end:
                return None
            return AppendProgress(self._progress_token,str(self.store.path),
                info.st_dev,info.st_ino,self._committed_end,self._appended_bytes,
                self._append_count,info.st_mtime_ns)

    def end(self, boundary):
        with self._lock:
            if self.owner == boundary and not self.closed:
                self.closed = True
                self.store.close()

    def close(self):
        """Explicit owner close; caller resources still belong to the caller."""
        self.end(self.owner if self.owner != 'caller' else 'explicit_caller_close')
