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

"""Owned run/event result storage and real report assembly."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import os
from pathlib import Path
import threading

from bytefault.core.contracts import freeze
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.logging import ActionLog


class WriterAttachedError(OSError):
    pass


class ResultRoot:
    """One logical writer per canonical root, explicit release, snapshot readers.

    Reserve in-process identity, then hold an OS file lock before opening any
    result journal. The persistent marker is never unlinked/replaced on release.
    """
    OWNER_FILE = '.bytefault-owner.lock'
    _owners = set()
    _owners_lock = threading.RLock()

    def __init__(self, path):
        self.path = Path(path).resolve()
        self.key = os.path.normcase(str(self.path))
        self.closed = False
        self._owner_fd = None
        self._layout_lock = threading.RLock()
        with self._owners_lock:
            if self.key in self._owners:
                raise WriterAttachedError(f'writable result root already attached: {self.path}')
            self._owners.add(self.key)
        try:
            self._claim_process()
            self.store = LocalRecordStore(self.path / 'results.bfr')
            self.action_log = ActionLog.open(self.path / 'reporting-actions.bfr', owner='application')
        except BaseException:
            try:
                if hasattr(self, 'store'):
                    self.store.close()
            finally:
                try:
                    self._release_process()
                finally:
                    with self._owners_lock:
                        self._owners.remove(self.key)
            raise

    def _claim_process(self):
        self.path.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path / self.OWNER_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.set_inheritable(fd, False)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException as error:
            os.close(fd)
            if isinstance(error, OSError):
                raise WriterAttachedError(f'writable result root unavailable: {self.path}: {error}') from error
            raise
        self._owner_fd = fd

    def _release_process(self):
        fd, self._owner_fd = self._owner_fd, None
        if fd is not None:
            os.close(fd)  # OS releases the claim on explicit close or process death.

    @staticmethod
    def read(path):
        return reopen_records(Path(path).resolve() / 'results.bfr')

    def append(self, kind, identity, data):
        if self.closed:
            raise OSError('result root released')
        ref = self.store.append(kind, identity, data)
        self.action_log(kind, identity, data, ref)
        return ref

    def register_run_log(self, run_id, log_path):
        """Keep a durable pointer even when the run never requests a report."""
        return self.append('run_action_log', {'run_id': run_id},
            {'log_path': str(Path(log_path).resolve()),
             'registered_at_utc': datetime.now(timezone.utc).isoformat()})

    def close(self):
        with self._owners_lock:
            if not self.closed:
                self.closed = True
                try:
                    self.store.close()
                finally:
                    try:
                        self.action_log.end('application')
                    finally:
                        try:
                            self._release_process()
                        finally:
                            self._owners.remove(self.key)


@dataclass(frozen=True)
class ReportRequest:
    report_id: str
    action: object
    collection_status: str
    artifacts: tuple = ()
    collection_error: str = ''
    context: object = None
    collection_items: tuple = ()
    collection_operations: tuple = ()
    collection_inventory_status: str = 'unknown'


@dataclass(frozen=True)
class ReportOutcome:
    report_id: str
    event_id: str
    action_id: str
    status: str
    location: str | None = None
    error: str = ''
    acquired_core_count: int = 0
    acquired_cores: tuple = ()


class Reporting:
    def __init__(self, root, *, port=None):
        from bytefault.reporting.layout import ReportLayout
        self.root = root
        self.layout = ReportLayout(root)
        self.port = port if port is not None else self.layout.report

    def report(self, request):
        from bytefault.core.validation import validate_followup_action
        from bytefault.core.contracts import ContractError
        if not isinstance(request, ReportRequest):
            raise ContractError('reporting.request', 'invalid', 'typed ReportRequest required')
        validate_followup_action(request.action)
        if (not isinstance(request.report_id, str) or not request.report_id or
                request.collection_status not in ('succeeded', 'failed', 'pending', 'disabled')):
            raise ContractError('reporting.request', 'invalid', 'report identity and explicit collection status required')
        action = request.action
        identity = dict(freeze(action.correlation))
        identity.update(event_id=action.event_id, followup_action_id=action.action_id,
                        report_id=request.report_id, observation_id=action.observation_id)
        reference = request.context.get('report_context_ref') if request.context else None
        recorded = (replace(request, context={'projection': 'reference_only',
            'record_reference': reference}) if reference is not None else request)
        self.root.append('report_request', identity, {'request': recorded})
        if self.port is not None:
            try:
                outcome = self.port(request)
                if (not isinstance(outcome, ReportOutcome) or
                    (outcome.report_id, outcome.event_id, outcome.action_id) !=
                    (request.report_id, action.event_id, action.action_id) or
                    outcome.status not in ('succeeded', 'failed', 'pending', 'unavailable')):
                    raise ValueError('report port returned invalid identity/status')
            except Exception as exc:
                outcome = ReportOutcome(request.report_id, action.event_id, action.action_id,
                                        'failed', error=str(exc))
        self.root.append('report_outcome', identity, {'outcome': outcome})
        return outcome
