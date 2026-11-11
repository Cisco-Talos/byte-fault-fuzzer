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

"""Explicit shared-client choices and overlapping real owner initialization."""
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest

from bytefault.core.contracts import ContractError
from bytefault.core.records import encode_value
from bytefault.core.storage import LocalRecordStore
from bytefault.fuzzers.cli import execute_arguments
from bytefault.management import Management
from bytefault.management.collection import Collection
from bytefault.management.configuration import ServiceConfiguration
from bytefault.monitoring.heartbeat import HeartbeatMonitor
from bytefault.reporting import Reporting, ResultRoot, WriterAttachedError
from test_followup_heartbeat import offers, request, wait_until


def arguments(tmp_path, name, *choices):
    return ['submit', 'controlled-A', '--port', '1234', '--seed-hex', '41', '--no-ui',
        '--records', str(tmp_path / (name + '.bfr')), '--monitoring-json', json.dumps(encode_value({
            'health_check_mode': 'disabled', 'rules': [{'rule_id': 'unrequested', 'kind': 'unrequested',
                                                     'actions': [{'report': True}]}]})), *choices]


def test_explicit_service_choices_reuse_or_refuse_and_omissions_retain_configuration(tmp_path, application_factory):
    configuration = ServiceConfiguration(result_root=str(tmp_path / 'results'), ssh_user='operator',
        remote_dir='/chosen', cache_dir=str(tmp_path / 'cache'), ssh_key='chosen-key',
        max_file_size_mb=7, min_timeout=11, core_write_wait=0)
    app, traces = application_factory(service_configuration=configuration)
    first = execute_arguments(arguments(tmp_path, 'first'), app)
    assert first.outcome == 'completed' and not app.management.wait(5)['pending']
    owner, reporter = app.management, app.reporting
    prepared = execute_arguments(['prepare', *arguments(tmp_path, 'preview', '-k', 'chosen-key')[1:]], app)
    try:
        assert len(list(prepared)) == 1
    finally:
        prepared.close()
    assert app.service_configuration is configuration and app.management is owner
    compatible = ['--results', str(tmp_path / 'results' / '..' / 'results'), '--ssh-user', 'operator',
        '--core-dir', '/chosen', '--core-cache', str(tmp_path / 'cache'), '-k', 'chosen-key',
        '--core-max-size', '7', '--core-timeout', '11', '--core-dump-wait', '0']
    assert execute_arguments(arguments(tmp_path, 'compatible', *compatible), app).outcome == 'completed'
    assert not owner.wait(5)['pending']
    before = len(offers(traces))
    for flag, value in (('--results', str(tmp_path / 'other')), ('--ssh-user', 'different'),
                        ('--core-dir', '/different'), ('--core-cache', str(tmp_path / 'other-cache')),
                        ('--ssh-key', 'different'), ('--core-max-size', '8'), ('--core-timeout', '12'),
                        ('--core-dump-wait', '1'), ('--heartbeat-interval', '3')):
        for command in ('submit', 'prepare', 'validate'):
            with pytest.raises(ContractError) as caught:
                execute_arguments([command, *arguments(tmp_path, flag[2:], flag, value)[1:]], app)
            assert caught.value.code == 'busy'
    with pytest.raises(ContractError, match='busy'):
        execute_arguments(arguments(tmp_path, 'heartbeat', '--heartbeat'), app)
    assert len(offers(traces)) == before and app.management is owner and app.reporting is reporter
    assert app.service_configuration == configuration
    assert execute_arguments(arguments(tmp_path, 'omitted'), app).outcome == 'completed'
    assert not owner.wait(5)['pending'] and app.service_configuration == configuration
    assert len(app.reporting.layout.snapshot()) == 3
    default, _ = application_factory()
    assert execute_arguments(arguments(tmp_path / 'default', 'first'), default).outcome == 'completed'
    assert not default.management.wait(5)['pending']
    original = default.service_configuration
    assert execute_arguments(arguments(tmp_path / 'default', 'same', '--results', str(default.reporting.root.path),
        '--core-cache', default.management.collection.core_cache_dir), default).outcome == 'completed'
    assert not default.management.wait(5)['pending'] and default.service_configuration is original


def test_supplied_owners_compare_actual_settings_and_remain_caller_owned(tmp_path, application_factory, monkeypatch):
    import bytefault.monitoring.heartbeat as module
    pings = []
    def ping(command, **options):
        pings.append(command)
        return SimpleNamespace(returncode=0, stdout='controlled alive', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', ping)
    root = ResultRoot(tmp_path / 'caller-results')
    reporter = Reporting(root)
    store = LocalRecordStore(tmp_path / 'caller-management.bfr')
    collection = Collection('controlled-A', ssh_key=Path('caller-key'), ssh_user='caller', remote_dir='/caller',
        cache_dir=tmp_path / 'caller-cache', max_file_size_mb=9, min_timeout=14, core_write_wait=0)
    management = Management(store, reporting=reporter, collection=collection)
    heartbeat = HeartbeatMonitor('controlled-A', interval=17)
    app, traces = application_factory(management=management, reporting=reporter, heartbeat=heartbeat)
    try:
        assert execute_arguments(arguments(tmp_path, 'omitted'), app).outcome == 'completed'
        assert not management.wait(5)['pending'] and app.service_configuration is None
        for command in ('submit', 'prepare', 'validate'):
            with pytest.raises(ContractError, match='conflicting_input'):
                execute_arguments([command, *arguments(tmp_path, 'wrong-user', '--ssh-user', 'root')[1:]], app)
        with pytest.raises(ContractError, match='conflicting_input'):
            execute_arguments(arguments(tmp_path, 'wrong-interval', '--heartbeat-interval', '2'), app)
        with pytest.raises(ContractError, match='conflicting_input'):
            execute_arguments(arguments(tmp_path, 'wrong-root', '--results', str(tmp_path / 'wrong')), app)
        assert offers(traces) == [b'A'] and app.service_configuration is None
        assert execute_arguments(arguments(tmp_path, 'same', '--ssh-user', 'caller', '--results', str(root.path),
            '--heartbeat', '--heartbeat-interval', '17'), app).outcome == 'completed'
        assert not management.wait(5)['pending']
        assert app.management is management and app.reporting is reporter and app._heartbeats[heartbeat.host] is heartbeat
        assert app.service_configuration.ssh_key == 'caller-key'
        assert app.service_configuration.cache_dir == collection.core_cache_dir
        assert app.close()['outcome'] == 'completed'
        assert not root.closed and not store.closed and not heartbeat.closed and not management.status()['finalized']
        for name, configuration in (('omitted', None), ('configured-disabled', ServiceConfiguration(
                result_root=str(tmp_path / 'configured-disabled-results')))):
            scoped, scoped_traces = application_factory(heartbeat=heartbeat, service_configuration=configuration)
            argv = arguments(tmp_path / name, name)
            argv[1] = 'controlled-B'
            assert execute_arguments(argv, scoped).outcome == 'completed'
            assert not scoped.management.wait(5)['pending']
            assert not scoped.service_configuration.heartbeat
            assert scoped._heartbeats == {'controlled-A': heartbeat} and not scoped._heartbeat_logs
            assert offers(scoped_traces) == [b'A']
            assert scoped.close()['outcome'] == 'completed' and not heartbeat.closed
        assert not pings
        opaque = Management(LocalRecordStore(tmp_path / 'opaque.bfr'), collection=object())
        try:
            opaque_app, _ = application_factory(management=opaque)
            with pytest.raises(ContractError, match='conflicting_input'):
                execute_arguments(arguments(tmp_path, 'opaque', '--ssh-user', 'root'), opaque_app)
        finally:
            opaque.close(); opaque.wait(5); opaque.store.close()
    finally:
        management.close(); management.wait(5); store.close(); root.close(); heartbeat.close()


@pytest.mark.parametrize('ending', ['success', 'start_failure', 'cleanup_failed', 'cleanup_raises', 'open_failure'])
def test_last_reserved_worker_start_settles_pending_owner_close(
        tmp_path, application_factory, monkeypatch, ending):
    from bytefault.logging import ActionLog
    application_log = ActionLog.open(tmp_path / 'application.bfr', owner='application')
    caller_store = LocalRecordStore(tmp_path / 'caller.bfr')
    caller_log = ActionLog(caller_store)
    root_path = tmp_path / 'results'
    app, traces = application_factory(action_logs=(application_log, caller_log),
        service_configuration=ServiceConfiguration(result_root=str(root_path)))
    assert app.submit(request(tmp_path, 'warm', 'controlled', two=False)).outcome == 'completed'
    root = app.reporting.root
    entered, release = threading.Event(), threading.Event()
    start_error = RuntimeError('controlled application worker-start failure')
    cleanup_error = OSError('controlled failed-start owner cleanup failure')
    start = threading.Thread.start
    def worker_start(thread):
        if thread.name == 'bytefault-final':
            entered.set(); assert release.wait(8)
            if ending != 'success':
                raise start_error
        return start(thread)
    monkeypatch.setattr(threading.Thread, 'start', worker_start)
    results, errors = [], []
    def submit():
        try:
            results.append(app.start(request(tmp_path, 'final', 'controlled', two=False)))
        except BaseException as error:
            errors.append(error)
    caller = threading.Thread(target=submit, name='controlled-start-caller')
    close, end = app.close, application_log.end
    try:
        caller.start(); assert entered.wait(5)
        if ending != 'open_failure':
            pending = app.close()
            assert pending['outcome'] == 'pending' and pending['pending_runs'] == ('final',)
            assert app.management.status()['finalized'] and not root.closed
        if ending == 'cleanup_failed':
            def fail_end(boundary):
                if boundary == 'application':
                    raise cleanup_error
                return end(boundary)
            monkeypatch.setattr(application_log, 'end', fail_end)
        elif ending == 'cleanup_raises':
            def fail_close():
                close()
                raise cleanup_error
            monkeypatch.setattr(app, 'close', fail_close)
        release.set(); caller.join(5)
        assert not caller.is_alive()
        if ending == 'success':
            assert not errors and results[0].wait(5).outcome == 'stopped'
        else:
            assert errors == [start_error] and errors[0] is start_error and not results
        final = app.status('final')
        assert not final['active'] and final['finalized']
        assert not caller_log.closed and not caller_store.closed
        assert offers(traces) == [b'A']
        if ending == 'open_failure':
            assert not root.closed and not application_log.closed
            assert final['application_finalization'] is None and not final['cleanup_errors']
            assert app.submit(request(tmp_path, 'reused', 'controlled', two=False)).outcome == 'completed'
        else:
            assert root.closed and app.management.store.closed
            reopened = ResultRoot(root_path); reopened.close()
            assert application_log.closed is (ending != 'cleanup_failed')
        if ending.startswith('cleanup_'):
            assert final['error'] == str(start_error) and final['state'] == 'failed'
            assert final['cleanup_errors'][-1]['operation'] == 'application_finalize'
            assert any('Application cleanup:' in note for note in start_error.__notes__)
            assert any(record.kind == 'application_cleanup_failure' for record in caller_store.snapshot().records)
            if ending == 'cleanup_failed':
                assert final['application_finalization']['outcome'] == 'failed'
                assert final['application_finalization']['cleanup_failures'][0]['error'] == str(cleanup_error)
            else:
                assert final['cleanup_errors'][-1]['error'] == str(cleanup_error)
        elif ending != 'open_failure':
            assert final['application_finalization']['outcome'] == 'completed'
            assert not final['cleanup_errors']
    finally:
        release.set(); caller.join(5)
        monkeypatch.setattr(app, 'close', close)
        monkeypatch.setattr(application_log, 'end', end)
        app.close(); app.management.wait(5); caller_store.close()


def waiting_on(handle, entry):
    frame = sys._current_frames().get(handle.application._run(handle.run_id).worker.ident)
    while frame is not None:
        if frame.f_code.co_name == '_begin_attachment' and frame.f_locals.get('entry') is entry:
            return True
        frame = frame.f_back
    return False


@pytest.mark.parametrize(('kind', 'ending'), [
    ('services', 'complete'), ('heartbeat', 'complete'),
    ('services', 'close'), ('heartbeat', 'close'),
    ('services', 'failure'), ('heartbeat', 'failure'),
    ('services', 'failure_changed'), ('services', 'start_failure'), ('heartbeat', 'start_failure')])
def test_overlapping_initialization_shares_result_and_close_remains_responsive(
        tmp_path, application_factory, monkeypatch, kind, ending):
    import bytefault.monitoring.heartbeat as module
    monkeypatch.setattr(module.subprocess, 'run', lambda command, **options:
        SimpleNamespace(returncode=0, stdout='controlled alive', stderr=''))
    created_monitors = []
    original_monitor = module.HeartbeatMonitor
    def monitor(*args, **kwargs):
        value = original_monitor(*args, **kwargs); created_monitors.append(value)
        return value
    monkeypatch.setattr(module, 'HeartbeatMonitor', monitor)
    root_path = tmp_path / 'results'
    app, traces = application_factory(service_configuration=ServiceConfiguration(
        result_root=str(root_path), heartbeat=kind == 'heartbeat', heartbeat_interval=60))
    root = None
    if kind == 'heartbeat':
        assert app.submit(request(tmp_path, 'warm', 'warm', two=False)).outcome == 'completed'
        root = app.reporting.root
        blocked = root_path / ('heartbeat-' + __import__('hashlib').sha256(b'cold').hexdigest()[:16] + '.bfr')
    else:
        blocked = root_path / 'results.bfr'
    entered, release = threading.Event(), threading.Event()
    registering, release_registration = threading.Event(), threading.Event()
    register = ResultRoot.register_run_log
    def register_run_log(result_root, run_id, log_path):
        if ending == 'close' and run_id == 'second':
            registering.set()
            assert release_registration.wait(8)
        return register(result_root, run_id, log_path)
    monkeypatch.setattr(ResultRoot, 'register_run_log', register_run_log)
    opened, handles = [], []
    actual_error = OSError('controlled initialization failure')
    failed = ending in ('failure', 'failure_changed', 'start_failure')
    failed_workers, logs = [], []
    if ending == 'start_failure':
        from bytefault.logging import ActionLog
        original_open, original_start = ActionLog.open, threading.Thread.start
        def open_log(cls, *args, **kwargs):
            value = original_open(*args, **kwargs); logs.append(value)
            return value
        def start(thread):
            target_owner = getattr(getattr(thread, '_target', None), '__self__', None)
            if thread.name == 'heartbeat-monitor' or isinstance(target_owner, Management):
                if isinstance(target_owner, Management):
                    failed_workers.append(target_owner)
                raise actual_error
            return original_start(thread)
        monkeypatch.setattr(ActionLog, 'open', classmethod(open_log))
        monkeypatch.setattr(threading.Thread, 'start', start)
    enabled = True
    def gate(event, values):
        if enabled and event == 'open' and values[0] == str(blocked):
            opened.append(values)
            if len(opened) == 1:
                entered.set(); assert release.wait(8)
                if failed and ending != 'start_failure':
                    raise actual_error
    sys.addaudithook(gate)
    key = 'services' if kind == 'services' else 'heartbeat:cold'
    try:
        first = app.start(request(tmp_path, 'first', 'cold', two=False)); handles.append(first)
        assert entered.wait(5)
        entry = app._attachments[key]
        second = app.start(request(tmp_path, 'second', 'cold', two=False)); handles.append(second)
        wait_until(lambda: waiting_on(second, entry))
        assert len(opened) == 1 and not entry.done.is_set()
        assert offers(traces) == ([b'A'] if kind == 'heartbeat' else [])
        with pytest.raises(ContractError, match='busy'):
            app.configure_services(ServiceConfiguration(result_root=str(tmp_path / 'changed')))
        if kind == 'services':
            with pytest.raises(WriterAttachedError):
                ResultRoot(root_path)  # A genuinely independent writer still refuses.
        if ending == 'close':
            closed, errors = [], []
            def close():
                try:
                    closed.append(app.close())
                except BaseException as error:
                    errors.append(error)
            closer = threading.Thread(target=close); closer.start(); closer.join(1)
            assert not closer.is_alive() and not errors
            assert closed[0]['outcome'] == 'pending' and key in closed[0]['pending_initializations']
            assert first.status()['stop_requested'] and second.status()['stop_requested']
            if root is not None:
                assert not root.closed  # Unpublished heartbeat journal is still part of its lifetime.
        elif failed:
            assert second.control('stop').outcome == 'completed'
            assert second.status()['stop_requested'] and not first.status()['stop_requested']
        release.set()
        if ending == 'close':
            assert registering.wait(5)
            assert first.wait(5).outcome == 'stopped'
            assert first.status()['finalized'] and not second.status()['finalized']
            assert app.management.status()['finalized']
            assert not app.reporting.root.closed and not app.reporting.root.store.closed
            held = app.close()
            assert held['outcome'] == 'pending' and held['pending_runs'] == ('second',)
            assert not held['pending_initializations']
            with pytest.raises(WriterAttachedError):
                ResultRoot(root_path)
            assert any(record.kind == 'run_action_log' and record.identity['run_id'] == 'first'
                       for record in ResultRoot.read(root_path).records)
            release_registration.set()
        for handle in handles:
            if failed:
                with pytest.raises(OSError) as caught:
                    handle.wait(5)
                assert caught.value is actual_error
            else:
                result = handle.wait(5)
                assert result.outcome == ('completed' if ending == 'complete' else 'stopped')
            assert handle.status()['finalized']
        if failed:
            assert entry.error is actual_error
            assert app.management is None if kind == 'services' else 'cold' not in app._heartbeats
            if kind == 'services':
                independent = ResultRoot(root_path); independent.close()  # Failed initialization released ownership.
        else:
            assert app.management is not None
            if kind == 'heartbeat' and ending != 'close':
                assert tuple(app._heartbeats).count('cold') == 1 and len(app._heartbeat_logs) == 2
        if kind == 'heartbeat' and not failed:
            assert len(created_monitors) == 2
            assert set(created_monitors) == set(app._heartbeats.values())
        assert offers(traces) == ([b'A'] * ((1 if kind == 'heartbeat' else 0) +
                                          (2 if ending == 'complete' else 0)))
        if failed:
            if ending == 'start_failure':
                if kind == 'heartbeat':
                    cold_monitors = [m for m in created_monitors if m.host == 'cold']
                    assert cold_monitors and all(m.closed and not m.status()['running'] for m in cold_monitors)
                else:
                    assert failed_workers and all(m.action_log.closed and m.store.closed for m in failed_workers)
                assert logs and all(log.closed for log in logs)
                monkeypatch.setattr(threading.Thread, 'start', original_start)
            configuration = (ServiceConfiguration(result_root=str(tmp_path / 'recovered'))
                             if ending == 'failure_changed' else app.service_configuration)
            app.configure_services(configuration)
            assert app.submit(request(tmp_path, 'recovered', 'cold', two=False)).outcome == 'completed'
            assert app.reporting.root.path == (tmp_path / 'recovered' if ending == 'failure_changed' else root_path).resolve()
        if ending == 'close':
            wait_until(lambda: app.reporting.root.closed)
            assert {record.identity['run_id'] for record in ResultRoot.read(root_path).records
                    if record.kind == 'run_action_log'} >= {'first', 'second'}
            reacquired = ResultRoot(root_path)
            reacquired.close()
        app.close()
        if app.management is not None:
            app.management.wait(5)
        assert app.close()['outcome'] == 'completed'
        assert not app._pending_attachments()
        assert all(m.closed and not m.status()['running'] for h, m in app._heartbeats.items() if h in app._heartbeat_logs)
        assert all(m.closed and not m.status()['running'] for m in created_monitors)
        assert all(log.closed for log in app._heartbeat_logs.values())
        if app._owned_services is not None:
            assert app._owned_services[1].closed and app.reporting.root.closed
        assert all(stream.closed for trace, stream, _ in traces if any(e[0] == 'open' for e in trace))
    finally:
        enabled = False; release.set(); release_registration.set()
        for handle in handles:
            handle.control('stop')
            try:
                handle.wait(5)
            except OSError:
                pass
        app.close()
