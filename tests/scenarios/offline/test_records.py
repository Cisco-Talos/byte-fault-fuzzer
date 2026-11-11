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

from dataclasses import replace
import json
from pathlib import Path
import struct
import time
import zlib

import pytest


class ShortWriter:
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        return self.stream.write(data[:len(data) // 2])
    def __getattr__(self, name):
        return getattr(self.stream, name)


class FailedWriter(ShortWriter):
    def write(self, data):
        raise OSError('controlled failed write')


def two_sends():
    from bytefault.core.contracts import ConversationRequest, ConversationAction, PassivePlan, PreparedRow
    return ConversationRequest(PassivePlan('record-fixture', 1,
        (ConversationAction('first', b'\x00\xff\x80'), ConversationAction('second', b'NEXT'))),
        PreparedRow('row', 1), ('first', 'second'), 'run-record', 'case-record', 'conversation-record',
        original_request={'password': 'marker-X', '$bytes': {'$type': 'literal-key'},
                          'binary': b'\x00\xff\x80'})


@pytest.mark.parametrize('write_mode', ['short', 'failed'])
def test_required_save_gates_and_reopen(engine_factory, capsys, write_mode):
    from bytefault.core.storage import reopen_records
    request = two_sends()
    engine, trace, _, _ = engine_factory()
    result = engine.execute_conversation(request)
    assert result.outcome == 'completed'
    snapshot = reopen_records(engine.record_store.path)
    assert snapshot.issue is None
    kinds = [r.kind for r in snapshot.records]
    assert kinds[0:2] == ['case_start', 'connection_attempt']
    assert kinds[-1] == 'case_terminal'
    start = snapshot.records[0]
    assert start.data['request']['original_request']['password'] == 'marker-X'
    assert start.data['request']['original_request']['$bytes']['$type'] == 'literal-key'
    assert start.data['request']['original_request']['binary'] == b'\x00\xff\x80'
    assert start.data['materialized'][0]['final_bytes'] == b'\x00\xff\x80'
    action = next(r for r in snapshot.records if r.kind == 'action_result')
    assert action.data['result']['transport']['accepted_prefix'] == b'\x00\xff\x80'
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x00\xff\x80', b'NEXT']
    # Each acknowledged materialization precedes its action result in the real store.
    assert kinds.index('materialization') < kinds.index('action_result')

    for failing_kind in ('case_start', 'materialization', 'action_result', 'case_terminal'):
        failed, trace, stream, _ = engine_factory()
        store = failed.record_store
        real_append = store.append
        def broken(kind, identity, data):
            if kind == failing_kind:
                store._stream = (ShortWriter if write_mode == 'short' else FailedWriter)(store._stream)
            return real_append(kind, identity, data)
        store.append = broken
        result = failed.execute_conversation(request)
        assert result.outcome == 'recording_failed'
        assert failed.status().required_record_failure
        assert failed.status().state == 'recording_failed'
        assert failed.session_state.exit_reason != 'user_quit'
        offered = [t for t in trace if t[0] == 'offer']
        assert len(offered) == (0 if failing_kind in ('case_start', 'materialization') else
                                1 if failing_kind == 'action_result' else 2)
        if failing_kind == 'case_start':
            assert not any(t[0] == 'open' for t in trace)
        else:
            assert stream.closed
        recovered = reopen_records(store.path)
        assert (recovered.issue.kind if recovered.issue else None) == ('incomplete' if write_mode == 'short' else None)
        assert store.failed and store.closed
        with pytest.raises(OSError, match='closed'):
            store.append('later', {}, {})
        before = list(trace)
        assert failed.execute_conversation(request).outcome == 'recording_failed'
        assert trace == before
        diagnostic = capsys.readouterr().err
        for exact in ('BYTEFAULT REQUIRED RECORDING STOP', 'run-record', 'case-record',
                      'offline.invalid', 'marker-X', failing_kind, 'last_retained_record'):
            assert exact in diagnostic
        assert '00ff80' in diagnostic or failing_kind == 'case_start'


def test_required_failure_independent_of_presentation_and_terminal_failure(engine_factory, monkeypatch):
    import threading
    import sys
    from bytefault.fuzzers.inputs import raw_request
    engine, trace, _, _ = engine_factory()
    entered, release = threading.Event(), threading.Event()
    class Blocked:
        def on_progress(self, **kwargs):
            entered.set()
            release.wait(2)
    engine.add_listener(Blocked())
    engine._emit('on_progress', iteration=0)
    assert entered.wait(1)
    class BadTerminal:
        def write(self, value):
            raise OSError('terminal unavailable')
    monkeypatch.setattr(sys, 'stderr', BadTerminal())
    engine.record_store.close()
    try:
        assert engine.execute_conversation(raw_request(b'ABC')).outcome == 'recording_failed'
        assert not trace
        assert engine.diagnostic_delivery_error == 'terminal unavailable'
        assert engine.storage_failure['missing_evidence']
    finally:
        release.set()


def test_no_store_or_private_transport_bypass(engine_factory):
    from bytefault.core.contracts import ContractError, ReceiveRequest
    from bytefault.fuzzers.inputs import raw_request
    engine, trace, _, _ = engine_factory()
    for operation in (engine._connect_conversation,
                      lambda: engine._exchange_packet(b'ABC', ReceiveRequest(requested=False))):
        with pytest.raises(ContractError):
            operation()
    assert not trace
    engine.record_store.close()
    engine.record_store = None
    assert engine.execute_conversation(raw_request(b'ABC')).outcome == 'recording_failed'
    assert not trace


def test_first_save_diagnostic_keeps_materialized_bytes_without_original_request(engine_factory, capsys):
    from bytefault.fuzzers.inputs import raw_request
    engine, trace, _, _ = engine_factory()
    engine.record_store.close()
    value = raw_request(b'\x00\xff\x80')
    assert not value.original_request
    assert engine.execute_conversation(value).outcome == 'recording_failed'
    assert not trace
    assert engine.storage_failure['available_materializations'][0]['final_bytes'] == b'\x00\xff\x80'
    assert engine.storage_failure['known_transport_progress'] is None
    assert engine.storage_failure['resolved_request']['plan']['actions'][0]['seed'] == b'\x00\xff\x80'
    assert '00ff80' in capsys.readouterr().err


def test_corrupt_unsupported_and_malformed_records_are_explicit(tmp_path):
    from bytefault.core.storage import LocalRecordStore, reopen_records, HEADER, MAGIC
    from bytefault.core.records import encode_value
    path = tmp_path / 'records.bfr'
    store = LocalRecordStore(path)
    store.append('intact', {'run': 'A'}, {'bytes': b'\x00\xff\x80'})
    store.close()
    prefix = path.read_bytes()
    for suffix, expected in ((b'BFR9' + b'\x00' * 8, 'unsupported_version'),
                             (b'junk' + b'\x00' * 8, 'corrupt'), (b'B', 'incomplete')):
        path.write_bytes(prefix + suffix)
        result = reopen_records(path)
        assert result.records[0].data['bytes'] == b'\x00\xff\x80'
        assert len(result.records) == 1 and result.issue.kind == expected
        with pytest.raises(OSError):
            LocalRecordStore(path)
    for change in ({'version': True}, {'record_id': 3}, {'kind': []}, {'identity': ()},
                   {'data': 'wrong'}, {'data': {'number': float('nan')}}):
        value = {'version': 1, 'record_id': 'malformed', 'kind': 'bad', 'identity': {}, 'data': {}}
        value.update(change)
        body = json.dumps(encode_value(value)).encode()
        path.write_bytes(prefix + HEADER.pack(MAGIC, len(body), zlib.crc32(body)) + body)
        result = reopen_records(path)
        assert len(result.records) == 1 and result.issue.kind in ('corrupt', 'unsupported_version')
    missing = tmp_path / 'missing' / 'records.bfr'
    assert reopen_records(missing).issue.kind == 'not_found'
    assert not missing.parent.exists()


@pytest.mark.parametrize('point', ['ack_start', 'ack_materialization', 'offer', 'ack_result', 'partial_tail'])
def test_actual_engine_process_termination(storage_child, point):
    from bytefault.core.storage import reopen_records
    process, root = storage_child(point)
    deadline = time.monotonic() + 10
    while not (root / 'ready').exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if not (root / 'ready').exists():
        process.kill()
        process.wait(timeout=5)
        pytest.fail('child did not reach actual boundary: ' + process.stderr.read().decode(errors='replace'))
    process.kill()
    process.wait(timeout=5)
    snapshot = reopen_records(root / 'required.bfr')
    assert snapshot.records[0].kind == 'previous_acknowledged'
    assert snapshot.records[0].data['bytes'] == b'\x00\xff\x80'
    kinds = [r.kind for r in snapshot.records]
    assert 'case_start' in kinds and 'case_terminal' not in kinds
    assert len(snapshot.incomplete_cases) == 1
    assert snapshot.incomplete_cases[0]['state'] == 'incomplete'
    assert 'uncertain' in snapshot.incomplete_cases[0]['reason']
    start = next(r for r in snapshot.records if r.kind == 'case_start')
    assert start.data['request']['original_request']['password'] == 'marker-X'
    if point in ('ack_materialization', 'offer', 'ack_result', 'partial_tail'):
        materialized = next(r for r in snapshot.records if r.kind == 'materialization')
        assert materialized.data['materialized']['final_bytes'] == b'\x00\xff\x80'
    if point in ('offer', 'ack_result', 'partial_tail'):
        assert (root / 'offered').read_bytes() == b'\x00\xff\x80'
    else:
        assert not (root / 'offered').exists()
    if point == 'ack_result':
        result = next(r for r in snapshot.records if r.kind == 'action_result')
        assert result.data['result']['transport']['accepted_prefix'] == b'\x00\xff\x80'
    else:
        assert 'action_result' not in kinds
        # A retained materialization without a result is uncertain/incomplete,
        # regardless of whether this fixture additionally observed a local offer.
    assert (snapshot.issue.kind if snapshot.issue else None) == ('incomplete' if point == 'partial_tail' else None)
