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

"""Exact, passive required-evidence values and a closed value codec."""
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
import math
import sys

from bytefault.core.contracts import freeze


@dataclass(frozen=True)
class Record:
    record_id: str
    kind: str
    identity: Mapping
    data: Mapping
    version: int = 1

    def __post_init__(self):
        if type(self.version) is not int or self.version != 1:
            raise ValueError('unsupported record version')
        if not isinstance(self.record_id, str) or not self.record_id or not isinstance(self.kind, str) or not self.kind:
            raise ValueError('record identity/kind must be nonempty strings')
        if not isinstance(self.identity, Mapping) or not isinstance(self.data, Mapping):
            raise ValueError('record identity/data must be mappings')
        if self.kind in ('case_start', 'case_terminal', 'retry_case_resume', 'connection_attempt', 'materialization', 'action_result'):
            if any(not isinstance(self.identity.get(name), str) or not self.identity.get(name)
                   for name in ('run_id', 'case_id', 'conversation_id')):
                raise ValueError('case records require exact run/case/conversation identities')
        if self.kind == 'retry_case_resume':
            data = freeze(self.data)
            # ActionLog retains the same record kind/identity with its explicit
            # action envelope; the root journal carries the direct data.
            payload = data.get('action', {}) if 'evidence_reference' in data else data
            request = payload.get('request', {}) if isinstance(payload, Mapping) else {}
            if not isinstance(request, Mapping) or any(request.get(name) != self.identity[name]
                    for name in ('run_id', 'case_id', 'conversation_id')):
                raise ValueError('retry_case_resume must identify its exact original request: ' + repr({
                    name: (request.get(name), self.identity[name]) for name in
                    ('run_id', 'case_id', 'conversation_id')}))
        object.__setattr__(self, 'identity', freeze(self.identity))
        object.__setattr__(self, 'data', freeze(self.data))


@dataclass(frozen=True)
class RecordRef:
    path: str
    record_id: str
    offset: int
    length: int


@dataclass(frozen=True)
class RecoveryIssue:
    kind: str
    offset: int
    reason: str


@dataclass(frozen=True)
class RecoveryResult:
    records: tuple[Record, ...]
    refs: tuple[RecordRef, ...]
    issue: RecoveryIssue | None = None

    @property
    def incomplete_cases(self):
        """Recognition only; this never selects/repeats an interrupted case."""
        pending = {}
        for record in self.records:
            identity = record.identity
            key = tuple(identity.get(name) for name in ('run_id', 'case_id', 'conversation_id'))
            if record.kind in ('case_start', 'retry_case_resume'):
                pending[key] = record
            elif record.kind == 'case_terminal':
                pending.pop(key, None)
            elif key in pending:
                pending[key] = record
        return tuple(freeze({'identity': record.identity, 'state': 'incomplete',
            'last_record_id': record.record_id, 'last_record_kind': record.kind,
            'reason': 'no acknowledged terminal record; interrupted attempt outcome is uncertain'})
            for record in pending.values())


class RecordError(OSError):
    pass


class RequiredSaveFailure(RuntimeError):
    """Internal engine unwind after an independent storage-stop diagnostic."""


class RequiredServiceSaveFailure(OSError):
    """Independent service result withheld because required history was not saved."""
    status = 'recording_failed'

    def __init__(self, diagnostic, diagnostic_delivery_error=None):
        self.diagnostic = freeze(diagnostic)
        self.diagnostic_delivery_error = diagnostic_delivery_error
        super().__init__(self.diagnostic['reason'])


def emit_recording_diagnostic(diagnostic):
    """Direct headless delivery, independent of required sinks and consumers."""
    try:
        sys.stderr.write('BYTEFAULT REQUIRED RECORDING STOP ' + repr(encode_value(diagnostic)) + '\n')
        sys.stderr.flush()
    except Exception as exc:
        return str(exc)
    return None


def encode_value(value):
    """Tagged containers prevent user keys from colliding with byte/type tags."""
    from bytefault.core.provenance import is_view, export
    if is_view(value):
        return ['provenance', export(value)]
    if isinstance(value, bytes):
        return ['bytes', value.hex()]
    if is_dataclass(value):
        return ['mapping', [[f.name, encode_value(getattr(value, f.name))]
                            for f in fields(value)]]
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise ValueError('record mappings require string keys')
        return ['mapping', [[k, encode_value(v)] for k, v in value.items()]]
    if isinstance(value, (tuple, list)):
        return ['sequence', [encode_value(v) for v in value]]
    if value is None or isinstance(value, (str, int, float, bool)):
        return ['scalar', value]
    raise ValueError(f'unsupported record value: {type(value).__name__}')


def decode_value(value):
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError('invalid tagged record value')
    kind, data = value
    if kind == 'provenance':
        from bytefault.core.provenance import load
        return load(data)
    if kind == 'scalar' and (data is None or isinstance(data, (str, int, float, bool))):
        if isinstance(data, float) and not math.isfinite(data):
            raise ValueError('nonfinite scalar')
        return data
    if kind == 'bytes' and isinstance(data, str):
        return bytes.fromhex(data)
    if kind == 'sequence' and isinstance(data, list):
        return tuple(decode_value(v) for v in data)
    if kind == 'mapping' and isinstance(data, list):
        result = {}
        for entry in data:
            if not isinstance(entry, list) or len(entry) != 2:
                raise ValueError('invalid mapping entry')
            key, item = entry
            if not isinstance(key, str) or key in result:
                raise ValueError('invalid or duplicate mapping key')
            result[key] = decode_value(item)
        return result
    raise ValueError('invalid record tag or data')
