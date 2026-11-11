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

"""Initialization and recording failures, retained progress, root forwarding, and CLI field validation."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import threading

import pytest


@pytest.mark.parametrize('stop_operation', ['close', 'stop'])
def test_stop_retained_while_required_log_initializes(tmp_path, application_factory, monkeypatch, stop_operation):
    from bytefault.logging import ActionLog
    from bytefault.core.storage import LocalRecordStore
    from test_logging_lifetime import app_request
    entered, release = threading.Event(), threading.Event()
    caller_store = LocalRecordStore(tmp_path / 'caller.bfr')
    caller_log = ActionLog(caller_store)
    opened = []
    original_open = ActionLog.open
    def stalled_open(cls, path, *, owner='run'):
        if owner == 'run':
            entered.set()
            assert release.wait(5)
        log = original_open(path, owner=owner)
        opened.append(log)
        return log
    monkeypatch.setattr(ActionLog, 'open', classmethod(stalled_open))
    app, traces = application_factory(action_logs=(caller_log,))
    request = app_request(tmp_path)
    results, errors = [], []
    def submit():
        try:
            results.append(app.submit(request))
        except BaseException as exc:
            errors.append(exc)
    worker = threading.Thread(target=submit)
    worker.start()
    try:
        assert entered.wait(5)
        status = app.status(request.conversation.run_id)
        assert status['active'] and status['state'] == 'initializing' and status['engine'] is None
        pause = app.control(request.conversation.run_id, 'pause')
        assert pause.outcome == 'rejected' and 'initializing' in pause.reason
        if stop_operation == 'close':
            assert app.close()['outcome'] == 'pending'
        else:
            assert app.control(request.conversation.run_id, 'stop').outcome == 'completed'
        assert app.status(request.conversation.run_id)['stop_requested']
        release.set(); worker.join(5)
        assert not worker.is_alive() and not errors
        assert results[0].outcome == 'stopped'
        assert not any(item[0] in ('open', 'offer') for trace, _, _ in traces for item in trace)
        assert all(log.closed for log in opened)
        assert not caller_store.closed
        assert app.read_records(request.conversation.run_id).records[-1].kind == 'case_terminal'
    finally:
        release.set(); app.close(); worker.join(5); caller_store.close()


@pytest.mark.parametrize('failed_resource', ['action_log', 'case_store'])
def test_required_recording_initialization_diagnostic(tmp_path, application_factory, monkeypatch, capsys, failed_resource):
    import bytefault.application as application_module
    from bytefault.logging import ActionLog
    from bytefault.core.storage import LocalRecordStore
    from test_logging_lifetime import app_request
    caller_store = LocalRecordStore(tmp_path / 'caller.bfr')
    caller = ActionLog(caller_store)
    run_logs = []
    original = ActionLog.open
    def open_log(cls, path, *, owner='run'):
        if failed_resource == 'action_log':
            raise OSError('required run log cannot open')
        log = original(path, owner=owner)
        run_logs.append(log)
        return log
    monkeypatch.setattr(ActionLog, 'open', classmethod(open_log))
    if failed_resource == 'case_store':
        def fail_store(path):
            raise OSError('required case store cannot open')
        monkeypatch.setattr(application_module, 'LocalRecordStore', fail_store)
    app, traces = application_factory(action_logs=(caller,))
    request = app_request(tmp_path)
    try:
        with pytest.raises(OSError, match='cannot open'):
            app.submit(request)
        status = app.status(request.conversation.run_id)
        diagnostic = status['storage_failure']
        assert status['state'] == 'recording_failed' and not status['active']
        assert diagnostic['required_record_kind'] == failed_resource.replace('action_log', 'action_log_open').replace('case_store', 'case_store_open')
        assert diagnostic['identity']['run_id'] == request.conversation.run_id
        assert diagnostic['identity']['action_id'] is None
        assert diagnostic['original_request']['password'] == 'marker-X'
        assert diagnostic['resolved_request']['plan']['actions'][0]['seed'] == b'\x00\xff\x80'
        assert diagnostic['application_request']['record_path'] == request.record_path
        assert diagnostic['known_transport_progress'] is None
        assert diagnostic['transport_progress_state'] == 'not_observed'
        assert diagnostic['last_retained_record'] is None
        if failed_resource == 'action_log':
            assert not traces
            assert diagnostic['materialization_state'] == 'unresolved_not_materialized'
            assert not diagnostic['available_materializations']
        else:
            assert len(traces) == 1 and not traces[0][0]
            assert diagnostic['materialization_state'] == 'materialized_not_offered'
            assert diagnostic['available_materializations'][0]['final_bytes'] == b'\x00\xff\x80'
        terminal = capsys.readouterr().err
        assert 'BYTEFAULT REQUIRED RECORDING STOP' in terminal
        assert request.conversation.run_id in terminal and '00ff80' in terminal and 'marker-X' in terminal
        assert not caller_store.closed and all(log.closed for log in run_logs)
    finally:
        app.close(); caller_store.close()


def test_ordinary_initialization_errors_are_not_recording_failures(tmp_path, application_factory, capsys):
    from bytefault.application import Application
    from bytefault.core.contracts import ContractError, Capability
    from test_logging_lifetime import app_request
    def fail_adapter(request):
        raise OSError('ordinary adapter error')
    request = app_request(tmp_path)
    app = Application(transport_factory=fail_adapter)
    try:
        with pytest.raises(OSError, match='ordinary adapter'):
            app.submit(request)
        assert app.status(request.conversation.run_id)['storage_failure'] is None
        assert 'REQUIRED RECORDING STOP' not in capsys.readouterr().err
    finally:
        app.close()
    app, traces = application_factory()
    invalid = replace(app_request(tmp_path, 'invalid'), conversation=replace(request.conversation,
        plan=replace(request.conversation.plan, required_capabilities=(Capability('unsupported'),))))
    with pytest.raises(ContractError):
        app.submit(invalid)
    assert app.status(invalid.conversation.run_id)['storage_failure'] is None
    assert not traces[0][0]
    assert 'REQUIRED RECORDING STOP' not in capsys.readouterr().err


def test_root_forwarding_separator_retains_intent(tmp_path, application_factory, capsys):
    path = Path(__file__).resolve().parents[3] / 'bytefault.py'
    spec = importlib.util.spec_from_file_location('review_root_forwarder', path)
    entry = importlib.util.module_from_spec(spec); spec.loader.exec_module(entry)
    app, traces = application_factory()
    plain = ['fuzz', 'neutral', 'offline.invalid', '--target', 'offset', '--offset', '2', '--no-ui']
    separated = [*plain[:3], '--', *plain[3:]]
    expected = entry.resolve_arguments(plain, app)
    actual = entry.resolve_arguments(separated, app)
    assert actual.status == expected.status == 'pending'
    assert actual.options == expected.options and actual.resolved == expected.resolved
    assert actual.original_argv == tuple(separated) and expected.original_argv == tuple(plain)
    assert entry.main(separated) == 2
    terminal = capsys.readouterr()
    assert not terminal.err and 'pending' in terminal.out
    assert not traces
    # Only the root forwarding boundary is stripped; literal option values survive.
    literal = [*plain[:3], '--', '--log-file=--', *plain[3:]]
    assert entry.resolve_arguments(literal, app).options['log_file'] == '--'
    common = [*plain[:3], '--hide-field','payload','--debug','--',*plain[3:]]
    forwarded = entry.resolve_arguments(common, app)
    assert forwarded.status == 'pending' and forwarded.original_argv == tuple(common)
    assert forwarded.options['hide_field'] == ('payload',) and forwarded.options['debug']
    assert forwarded.options['offset'] == 2
    assert entry.main(common) == 2
    assert not capsys.readouterr().err and not traces


def test_failure_log_after_execution_keeps_retained_progress(tmp_path, application_factory, monkeypatch, capsys):
    from bytefault.logging import ActionLog
    from bytefault.fuzzers.fuzzer import ProtocolFuzzer
    from test_logging_lifetime import app_request
    original_execute = ProtocolFuzzer.execute_conversation
    original_log = ActionLog.__call__
    def interrupted(engine, request):
        original_execute(engine, request)
        raise RuntimeError('unexpected error after retained execution')
    def log(self, kind, identity, data, acknowledged_ref=None):
        if kind == 'application_failure':
            raise OSError('failure record unavailable')
        return original_log(self, kind, identity, data, acknowledged_ref)
    monkeypatch.setattr(ProtocolFuzzer, 'execute_conversation', interrupted)
    monkeypatch.setattr(ActionLog, '__call__', log)
    app, traces = application_factory()
    request = app_request(tmp_path)
    with pytest.raises(RuntimeError, match='unexpected error'):
        app.submit(request)
    status = app.status(request.conversation.run_id)
    diagnostic = status['storage_failure']
    assert status['state'] == 'recording_failed'
    assert diagnostic['transport_progress_state'] == 'retained_result'
    assert diagnostic['known_transport_progress']['offered'] == b'\x00\xff\x80'
    assert diagnostic['known_transport_progress']['acceptance'] == 'accepted'
    assert diagnostic['last_retained_record'] is not None
    assert diagnostic['available_materialized_bytes'] == b'\x00\xff\x80'
    assert 'no case evidence acknowledged' not in diagnostic['missing_evidence']
    assert 'BYTEFAULT REQUIRED RECORDING STOP' in capsys.readouterr().err
    assert any(item[0] == 'offer' for item in traces[0][0])


@pytest.mark.parametrize('operation', ['admit','inspect-declaration','export-declaration','request','saved-intent','service'])
def test_json_cli_paths_reject_duplicate_fields(tmp_path, application_factory, operation):
    from bytefault.core.contracts import ContractError
    from bytefault.fuzzers.cli import execute_arguments
    from bytefault.fuzzers.declarations import discover
    app, traces = application_factory()
    declaration = ('{"declaration_id":"neutral","version":1,"actions":'
                   '[{"action_id":"1","seed_hex":"41","seed_hex":"42"}]}')
    if operation in ('admit','inspect-declaration','export-declaration'):
        args = [operation, declaration]
    elif operation == 'request':
        args = ['offline.invalid','--port','1234','--records',str(tmp_path/'case.bfr'),
                '--request-json','{"$type":"ConversationRequest","fields":{"run_id":"A","run_id":"B"}}']
    elif operation == 'saved-intent':
        args = ['saved-intent','{"path":"case.bfr","record_id":"record",'
            '"steps":[{"action_id":"one","choice":"recorded","choice":"fresh_dynamic"}]}']
    else:
        args = ['service','management','["scalar",{"report":false,"report":true}]']
    with pytest.raises(ContractError) as error:
        execute_arguments(args, app)
    assert error.value.code == 'duplicate_field'
    assert error.value.path in ('declaration','cli.request_json','cli.saved_intent','cli.service')
    assert not traces and not (tmp_path/'case.bfr').exists()
    directory = tmp_path / 'declarations'; directory.mkdir()
    (directory/'duplicate.json').write_text(declaration, encoding='utf-8')
    assert discover(directory).issues[0].code == error.value.code
