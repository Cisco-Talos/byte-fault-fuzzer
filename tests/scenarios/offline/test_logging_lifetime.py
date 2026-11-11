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
import logging
import io
import threading

import pytest

from bytefault.application import ApplicationRequest
from bytefault.core.contracts import TransportRequest, Capability, ContractError
from bytefault.core.storage import reopen_records, LocalRecordStore
from bytefault.fuzzers.inputs import raw_request
from bytefault.logging import ActionLog


def app_request(tmp_path, label='A'):
    conversation = raw_request(b'\x00\xff\x80', original_request={'password': 'marker-X'})
    return ApplicationRequest(conversation, TransportRequest('offline.invalid', 1234, 10),
        str(tmp_path / f'{label}.bfr'), str(tmp_path / f'{label}.log.bfr'))


def test_run_owned_sinks(tmp_path, application_factory):
    root = logging.getLogger()
    before = (tuple(root.handlers), root.level)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.WARNING)
    formatter = logging.Formatter('caller %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)
    caller_store = LocalRecordStore(tmp_path / 'caller.bfr')
    caller = ActionLog(caller_store, owner='caller')
    application_store = ActionLog.open(tmp_path / 'application.bfr', owner='application')
    try:
        app, traces = application_factory(action_logs=(caller, application_store))
        a, b = app_request(tmp_path), app_request(tmp_path, 'B')
        assert app.submit(a).outcome == 'completed'
        snapshot_a = reopen_records(a.log_path)
        assert app.submit(b).outcome == 'completed'
        assert reopen_records(a.log_path) == snapshot_a
        for request in (a, b):
            actions = reopen_records(request.log_path)
            evidence = reopen_records(request.record_path)
            assert len(actions.records) == len(evidence.records)
            assert len({r.data['evidence_reference']['record_id'] for r in actions.records}) == len(actions.records)
            start = next(r for r in actions.records if r.kind == 'case_start')
            assert start.data['action']['request']['original_request']['password'] == 'marker-X'
            result = next(r for r in actions.records if r.kind == 'action_result')
            assert result.data['action']['result']['transport']['offered'] == b'\x00\xff\x80'
            # The product closed its owned file; independent writer can reopen.
            with LocalRecordStore(request.log_path):
                pass
        assert not caller_store.closed and not application_store.closed
        app.close()
        assert application_store.closed and not caller_store.closed
        assert tuple(root.handlers) == before[0] + (handler,)
        assert root.level == before[1] and handler.formatter is formatter
        assert handler.level == logging.WARNING and not stream.closed
    finally:
        root.removeHandler(handler)
        caller_store.close()


def test_closed_caller_store_progress_is_unavailable(tmp_path):
    store = LocalRecordStore(tmp_path / 'caller-progress.bfr')
    attachment = ActionLog(store, owner='caller')
    try:
        attachment('example', {'run_id': 'run'}, {'bytes': b'\x00\xff'})
        before = store.path.read_bytes()
        assert attachment.append_progress() is not None
        store.close()
        assert attachment.append_progress() is None
        assert not attachment.closed
        assert store.path.read_bytes() == before
        assert reopen_records(store.path).issue is None
    finally:
        store.close()


def test_progress_metadata_read_serializes_with_store_close(tmp_path, monkeypatch):
    import os
    store = LocalRecordStore(tmp_path / 'progress-close.bfr')
    attachment = ActionLog(store, owner='caller')
    attachment('example', {}, {'marker': 'retained'})
    descriptor = store._stream.fileno()
    entered, release, closing, closed = (threading.Event() for _ in range(4))
    results, errors = [], []
    original = os.fstat
    def held_stat(value):
        if value == descriptor:
            entered.set()
            assert release.wait(5)
        return original(value)
    def progress():
        try:
            results.append(attachment.append_progress())
        except BaseException as error:
            errors.append(error)
    def close_store():
        closing.set()
        store.close()
        closed.set()
    monkeypatch.setattr(os, 'fstat', held_stat)
    reader = threading.Thread(target=progress)
    closer = threading.Thread(target=close_store)
    try:
        reader.start()
        assert entered.wait(2)
        closer.start()
        assert closing.wait(2)
        assert not closed.wait(.05)
        release.set()
        reader.join(2)
        closer.join(2)
        assert not reader.is_alive() and not closer.is_alive() and not errors
        assert results and results[0] is not None and closed.is_set()
        assert attachment.append_progress() is None
    finally:
        release.set()
        if reader.ident is not None: reader.join(5)
        if closer.ident is not None: closer.join(5)
        store.close()


def test_unsuccessful_validation_init_and_sink_failure(tmp_path, application_factory, capsys):
    app, _ = application_factory(stream_options={'open_error': OSError('refused')})
    request = app_request(tmp_path)
    assert app.submit(request).outcome == 'transport_failed'
    assert any(r.kind == 'action_result' for r in reopen_records(request.log_path).records)
    bad = app_request(tmp_path, 'bad')
    bad = replace(bad, conversation=replace(bad.conversation,
        plan=replace(bad.conversation.plan, required_capabilities=(Capability('unknown'),))))
    with pytest.raises(ContractError):
        app.submit(bad)
    assert reopen_records(bad.log_path).records[0].kind == 'application_failure'
    with LocalRecordStore(bad.log_path):
        pass
    failed_init = app_request(tmp_path, 'init')
    folder = tmp_path / 'directory'
    folder.mkdir()
    with pytest.raises(OSError):
        app.submit(replace(failed_init, record_path=str(folder)))
    with LocalRecordStore(failed_init.log_path):
        pass
    class Broken:
        def append(self, *args):
            raise OSError('required action log failed')
    app, traces = application_factory(action_logs=(ActionLog(Broken()),))
    request = app_request(tmp_path, 'broken')
    result = app.submit(request)
    assert result.outcome == 'recording_failed'
    assert not traces[0][0]
    assert 'required action log failed' in capsys.readouterr().err


def test_shared_command_log_destinations_and_callable_exact_paths(tmp_path, application_factory, monkeypatch):
    import json
    import os
    from pathlib import Path
    from bytefault.core.logging_utils import resolve_log_path
    from bytefault.fuzzers.cli import execute_arguments, resolve_configuration
    from bytefault.replay.replay_packet import resolve_arguments as replay_arguments, replay_packets
    from bytefault.management.maintenance import resolve_arguments as maintenance_arguments, run_maintenance
    monkeypatch.chdir(tmp_path)
    app, traces = application_factory()
    common = ['offline.invalid','--port','1234','--seed-hex','58','--no-recv','--no-ui',
        '--health-check-mode','disabled']
    paths = ('bare.bfr', 'other/forward.bfr', r'other\back.bfr', str(tmp_path / 'absolute.bfr'))
    starts = []
    for index, selected in enumerate(paths):
        argv = [*common,'--records',str(tmp_path / ('run' + str(index) + '.bfr')),'--log-file',selected]
        config = resolve_configuration(argv, app)
        expected = tmp_path / 'artifacts/logs/bare.bfr' if index == 0 else Path(selected).absolute()
        assert Path(config.request.log_path).absolute() == expected
        result = execute_arguments(argv, app)
        log = reopen_records(expected)
        assert log.issue is None and any(r.kind == 'action_result' for r in log.records)
        start = next((r, ref) for r, ref in zip(app.read_records(result.run_id).records,
            app.read_records(result.run_id).refs) if r.kind == 'case_start')
        starts.append((config.request, start))
    assert not (tmp_path / 'artifacts/logs/other').exists()
    if os.name == 'nt':
        assert resolve_log_path('C:relative.bfr', tmp_path / 'artifacts') == 'C:relative.bfr'
    assert replay_arguments(['offline.invalid','58','--port','1234','--no-recv',
        '--log-file','replay.bfr'], app).request.log_path == str(tmp_path / 'artifacts/logs/replay.bfr')
    assert execute_arguments(['replay','offline.invalid','58','--port','1234','--no-recv',
        '--records',str(tmp_path / 'replay-run.bfr'),'--log-file','replay.bfr'], app).outcome == 'completed'
    source, (start, ref) = starts[0]
    portable = app.export_case(source.record_path, start.record_id)
    copied = tmp_path / 'copied.case.json'; copied.write_text(json.dumps(portable), encoding='utf-8')
    saved_args = ['saved-case',json.dumps({'path':str(copied)}),'--records',str(tmp_path / 'saved-run.bfr'),
        '--log-file','saved.bfr','--no-ui']
    assert execute_arguments(saved_args, app).log_path == str(tmp_path / 'artifacts/logs/saved.bfr')
    assert execute_arguments([*saved_args,'--execute'], app).outcome == 'completed'
    prefix = tmp_path / 'prefix.bfr'; prefix.write_bytes(Path(source.record_path).read_bytes()[:ref.offset + ref.length])
    case = app.inspect_resume(str(prefix)).cases[0]
    resume_args = ['resume-run',json.dumps({'path':str(prefix),'choices':[
        {'conversation_id':case['conversation_id'],'disposition':'rerun'}]}),
        '--records',str(tmp_path / 'resume-run.bfr'),'--log-file','resume.bfr','--no-ui']
    assert execute_arguments(resume_args, app).log_path == str(tmp_path / 'artifacts/logs/resume.bfr')
    assert execute_arguments([*resume_args,'--execute'], app).outcome == 'completed'
    cache = tmp_path / 'cache'; cache.mkdir(); (cache / 'selected').write_bytes(b'X')
    maintenance = maintenance_arguments(['--local-only','--local-cache',str(cache),
        '--local-entry','selected','--log-file','maintenance.bfr'])
    assert run_maintenance(maintenance, app).outcome == 'completed'
    for name, kind in (('replay','case_start'),('saved','case_start'),('resume','case_start'),
            ('maintenance','standalone_maintenance_terminal')):
        history = reopen_records(tmp_path / 'artifacts/logs' / (name + '.bfr'))
        assert history.issue is None and any(r.kind == kind for r in history.records)
    # Callable path arguments are exact; only command ingress applies the bare convention.
    exact = replay_packets('offline.invalid',1234,('58',),application=app,prepare=True,
        log_path='callable.bfr',record_path=str(tmp_path / 'callable-run.bfr'),skip_recv=True)
    assert exact.log_path == 'callable.bfr'
    assert app.submit(exact).outcome == 'completed' and (tmp_path / 'callable.bfr').exists()
    from bytefault.application import SavedCaseIntent, ResumeIntent, ResumeChoice
    assert app.saved_case(SavedCaseIntent(str(copied)),log_path='exact-saved.bfr').log_path == 'exact-saved.bfr'
    assert app.resume(ResumeIntent(str(prefix),(ResumeChoice(case['conversation_id'],'rerun'),)),
        log_path='exact-resume.bfr').log_path == 'exact-resume.bfr'
    assert all(stream.closed for _, stream, _ in traces)
