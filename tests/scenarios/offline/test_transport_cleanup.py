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

"""Ordinary adapter teardown remains visible in results and required history."""
from dataclasses import replace

import pytest

from bytefault.application import ApplicationRequest
from bytefault.core.contracts import ReceiveRequest, TransportRequest, freeze
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.fuzzers.inputs import positional_plan, raw_request


def request_at(tmp_path):
    return ApplicationRequest(raw_request(b'ABC', receive=ReceiveRequest(cap=4, deadline=10),
        original_request={'password': 'cleanup-marker-X'}),
        TransportRequest('offline.invalid', 1234, 10, 2, 3),
        str(tmp_path / 'case.bfr'), str(tmp_path / 'actions.bfr'))


@pytest.mark.parametrize('failure', ['none', 'close', 'send_and_close', 'open_and_close'])
def test_application_transport_cleanup_history(tmp_path, application_factory, failure):
    options = {}
    if failure != 'none':
        options['close_error'] = OSError('controlled socket close failure')
    if failure == 'send_and_close':
        options['sends'] = (OSError('preceding send failure'),)
    if failure == 'open_and_close':
        options['open_error'] = OSError('preceding open failure')
    app, traces = application_factory(stream_options=options)
    request = request_at(tmp_path)
    result = app.submit(request)
    status = app.status(result.run_id)
    trace, stream, _ = traces[0]
    assert len([t for t in trace if t[0] == 'close']) == 1
    expected = ('completed' if failure == 'none' else 'cleanup_failed'
                if failure == 'close' else 'transport_failed')
    assert result.outcome == expected and status['state'] == expected
    assert result.cleanup.outcome == ('completed' if failure == 'none' else 'uncertain')
    assert result.cleanup.phase == ('open_failure' if failure == 'open_and_close' else 'conversation')
    assert status['engine'].cleanup == freeze(result.cleanup)
    assert not status['engine'].connected
    if failure != 'none':
        assert result.cleanup.error == 'controlled socket close failure'
        assert result.cleanup.error_type == 'OSError'
        assert status['error']
    if failure in ('none', 'close'):
        fact = result.actions[0].transport
        assert fact.prepared == fact.offered == fact.accepted_prefix == b'ABC'
        assert fact.accepted_count == 3 and fact.received == b'\x00\xff'
        assert result.execution_outcome == 'completed'
    elif failure == 'send_and_close':
        assert result.reason == result.execution_reason == 'preceding send failure'
        assert result.execution_outcome == 'transport_failed'
        assert result.actions[0].transport.acceptance == 'uncertain'
    else:
        assert result.reason == result.execution_reason == 'preceding open failure'
        assert result.actions[0].transport.acceptance == 'not_offered'
        assert not any(t[0] == 'offer' for t in trace)
    case = reopen_records(request.record_path)
    actions = reopen_records(request.log_path)
    assert case.issue is actions.issue is None
    cleanup = [r for r in case.records if r.kind == 'transport_cleanup']
    assert len(cleanup) == 1
    assert cleanup[0].identity.run_id == result.run_id
    assert cleanup[0].identity.case_id == result.case_id
    assert cleanup[0].identity.conversation_id == result.conversation_id
    assert cleanup[0].data.cleanup.outcome == result.cleanup.outcome
    assert cleanup[0].data.execution_reason == result.execution_reason
    terminal = next(r for r in case.records if r.kind == 'case_terminal')
    assert terminal.data.result.cleanup == cleanup[0].data.cleanup
    assert terminal.data.result.outcome == expected
    logged = next(r for r in actions.records if r.kind == 'transport_cleanup')
    assert logged.data.action.cleanup == cleanup[0].data.cleanup
    assert logged.data.evidence_reference.record_id == cleanup[0].record_id
    recorded_action = next(r for r in case.records if r.kind == 'action_result')
    assert recorded_action.data.result.transport.offered == result.actions[0].transport.offered
    assert recorded_action.data.result.transport.received == result.actions[0].transport.received
    assert len(actions.records) == len(case.records)
    close_result = app.close()
    assert close_result.outcome == ('completed' if failure == 'none' else 'failed')
    if failure != 'none':
        assert close_result.cleanup_failures[0].cleanup == status['engine'].cleanup
    assert len([t for t in trace if t[0] == 'close']) == 1  # no blind retry


def test_recording_failure_keeps_cleanup_diagnostic(tmp_path, application_factory, monkeypatch, capsys):
    app, traces = application_factory(stream_options={'close_error': OSError('controlled socket close failure')})
    request = request_at(tmp_path)
    original = LocalRecordStore.append
    failures = []
    def append(store, kind, identity, data):
        if str(store.path) == str(request.record_path) and kind == 'action_result':
            failures.append(kind)
            raise OSError('preceding required history failure')
        return original(store, kind, identity, data)
    monkeypatch.setattr(LocalRecordStore, 'append', append)
    result = app.submit(request)
    status = app.status(result.run_id)
    assert result.outcome == result.execution_outcome == 'recording_failed'
    assert result.cleanup.outcome == 'uncertain' and result.cleanup.phase == 'recording_stop'
    assert status['engine'].state == 'recording_failed'
    assert status['storage_failure'].reason == 'preceding required history failure'
    assert status['storage_failure'].cleanup.error == 'controlled socket close failure'
    assert result.actions[0].transport.accepted_prefix == b'ABC'
    assert result.actions[0].transport.received == b'\x00\xff'
    diagnostic = capsys.readouterr().err
    assert 'preceding required history failure' in diagnostic
    assert 'controlled socket close failure' in diagnostic
    assert failures == ['action_result']
    assert not any(r.kind == 'transport_cleanup' for r in reopen_records(request.record_path).records)
    assert len([t for t in traces[0][0] if t[0] == 'close']) == 1


@pytest.mark.parametrize('failed_save', [None, 'transport_cleanup', 'case_terminal'])
def test_unexpected_execution_failure_keeps_cleanup_and_unwinds(
        tmp_path, application_factory, monkeypatch, capsys, failed_save):
    app, traces = application_factory(stream_options={'close_error': OSError('controlled socket close failure'),
        'reads': (b'\x00\xff', ValueError('preceding unexpected read failure'))})
    request = request_at(tmp_path)
    request = replace(request, conversation=replace(request.conversation,
        plan=positional_plan((b'ABC', b'NEXT'), receive=ReceiveRequest(cap=4, deadline=10)),
        selected_actions=('1', '2')))
    original = LocalRecordStore.append
    failures = []
    def append(store, kind, identity, data):
        if str(store.path) == request.record_path and kind == failed_save:
            failures.append(kind)
            raise OSError('subsequent required history failure')
        return original(store, kind, identity, data)
    monkeypatch.setattr(LocalRecordStore, 'append', append)
    with pytest.raises(ValueError, match='preceding unexpected read failure'):
        app.submit(request)
    status = app.status(request.conversation.run_id)
    assert status['state'] == ('recording_failed' if failed_save else 'failed') and not status['active']
    assert status['error'] == 'preceding unexpected read failure'
    assert status['result'].cleanup.error == 'controlled socket close failure'
    assert status['result'].execution_reason == 'ValueError: preceding unexpected read failure'
    assert status['result'].actions[0].transport.accepted_prefix == b'ABC'
    assert status['result'].actions[0].transport.received == b'\x00\xff'
    assert not app._run(request.conversation.run_id).engine._executing_conversation
    case = reopen_records(request.record_path)
    history = reopen_records(request.log_path)
    if failed_save:
        assert status['result'].outcome == 'recording_failed'
        assert status['storage_failure'].execution.reason == 'ValueError: preceding unexpected read failure'
        assert status['storage_failure'].cleanup.error == 'controlled socket close failure'
        assert failures == [failed_save]
        assert not any(r.kind == 'application_failure' for r in history.records)
        diagnostic = capsys.readouterr().err
        for error in ('preceding unexpected read failure', 'controlled socket close failure',
                      'subsequent required history failure'):
            assert error in diagnostic
    else:
        assert case.records[-1].kind == 'case_terminal'
        assert case.records[-1].data.result.cleanup.error == 'controlled socket close failure'
        failure = next(r for r in history.records if r.kind == 'application_failure')
        assert failure.data.action.error == 'preceding unexpected read failure'
        assert failure.data.action.cleanup.error == 'controlled socket close failure'
    assert len([t for t in traces[0][0] if t[0] == 'close']) == 1


@pytest.mark.parametrize('termination', ['stop', 'storage_failure'])
def test_no_connection_does_not_borrow_previous_cleanup(engine_factory, termination):
    engine, trace, _, _ = engine_factory(close_error=OSError('previous cleanup uncertainty'))
    first = engine.execute_conversation(raw_request(b'ABC'))
    assert first.cleanup.outcome == 'uncertain'
    if termination == 'stop':
        engine.control('stop')
    else:
        engine.record_store.close()
    previous_trace = list(trace)
    second = engine.execute_conversation(raw_request(b'NEXT'))
    assert second.cleanup.outcome == 'not_attempted' and second.cleanup.error is None
    assert engine.status().cleanup == second.cleanup
    assert trace == previous_trace


def test_existing_no_argument_close_port_is_invoked(engine_factory):
    engine, trace, _, _ = engine_factory()
    original = engine.transport.close
    calls = []
    def close():
        calls.append(True)
        original()  # supported existing ports may return None
    engine.transport.close = close
    result = engine.execute_conversation(raw_request(b'ABC'))
    assert calls == [True] and result.cleanup.outcome == 'completed'
    assert len([t for t in trace if t[0] == 'close']) == 1
