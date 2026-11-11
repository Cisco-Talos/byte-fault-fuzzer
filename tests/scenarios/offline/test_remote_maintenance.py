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

"""Retained Collection and explicit Maintenance behavior with controlled subprocesses."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import os
import threading
import pytest

from bytefault.application import Application
from bytefault.core.contracts import ContractError
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.management import Management
from bytefault.management.collection import Collection
from bytefault.management.configuration import ServiceConfiguration
from bytefault.management.maintenance import MaintenanceRequest, run_maintenance, resolve_arguments as maintenance_arguments


@pytest.mark.parametrize('route', ('direct', 'service'))
def test_maintenance_close_retains_inflight_inventory_and_stops_later_deletes(tmp_path, monkeypatch, route):
    entered, release = threading.Event(), threading.Event()
    caller_store = LocalRecordStore(tmp_path / 'caller-management.bfr') if route == 'service' else None
    app = Application(management=Management(caller_store)) if caller_store else Application()
    commands, output, errors = [], [], []

    def remote_process(argv, **options):
        commands.append(argv)
        entered.set()
        assert release.wait(5)
        return SimpleNamespace(returncode=0, stdout='/root/cores/first\0/root/cores/second\0', stderr='')

    if route == 'service':
        monkeypatch.setattr('bytefault.management.collection.subprocess.run', remote_process)
    request = MaintenanceRequest('controlled', 'key', local=False,
        remote_entries=('first', 'second'), log_path=str(tmp_path / 'actions.bfr'))

    def execute():
        try:
            output.append(app.service('maintenance', request) if route == 'service' else
                run_maintenance(replace(request, result_root=str(tmp_path / 'results')),
                    app, process=remote_process))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=execute)
    worker.start()
    try:
        assert entered.wait(3)
        closing = app.close()
        assert closing.outcome == 'pending' and closing.pending_independent
        assert worker.is_alive() and app.action_logs and not app.action_logs[0].closed
        assert not app.management.store.closed
        if app.reporting is not None:
            assert not app.reporting.root.closed
        release.set()
        worker.join(6)
        assert not worker.is_alive() and not errors
        assert output[0].outcome == 'stopped'
        assert [item.status for item in output[0]['items']] == ['not_started']
        assert len(commands) == 1 and commands[0][-1].startswith('find ')
        assert all(log.closed for log in app.action_logs)
        history = reopen_records(tmp_path / 'actions.bfr')
        assert history.issue is None
        assert any(record.kind == 'standalone_maintenance_terminal' for record in history.records)
        if caller_store is None:
            assert app.management.store.closed and app.reporting.root.closed
        else:
            assert not caller_store.closed and not app.management.status().closed
            assert not app.management.action_log.closed
            retained = caller_store.snapshot()
            assert retained.issue is None
            terminal = next(record for record in retained.records if record.kind == 'maintenance_terminal')
            assert terminal.data.outcome.inventories.remote == 'not_started'
            assert [item.status for item in terminal.data.outcome['items']] == ['not_started']
    finally:
        release.set()
        worker.join(6)
        app.close()
        if app.management is not None:
            app.management.wait(6)
            if caller_store is not None:
                app.management.close()
                app.management.wait(6)
                caller_store.close()


def test_collection_inventory_states_and_nested_literal_maintenance(tmp_path, monkeypatch):
    mode = ['empty']
    commands = []
    def process(argv, **options):
        commands.append(argv)
        if argv[0] == 'rsync':
            if mode[0] == 'absent':
                return SimpleNamespace(returncode=23, stdout='', stderr=(
                    'rsync: [sender] change_dir "/root/cores" failed: No such file or directory (2)'))
            if mode[0] == 'unavailable':
                return SimpleNamespace(returncode=255, stdout='', stderr='denied')
            if mode[0] == 'empty':
                return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')
            directory = Path(argv[-1])
            for i in range(22):
                (directory / f'core {i};$x').write_bytes(b'X')
            return SimpleNamespace(returncode=0, stdout='\n'.join((
                *(f'BF|>f+++++++++|1|2026/10/22-15:00:57|core {i};$x' for i in range(22)),
                'Number of files: 23 (reg: 22, dir: 1)')), stderr='')
        if argv[0] == 'ssh' and argv[-1].startswith('find '):
            if mode[0] == 'absent': return SimpleNamespace(returncode=44, stdout='', stderr='absent')
            if mode[0] == 'unavailable': return SimpleNamespace(returncode=45, stdout='', stderr='denied')
            if mode[0] == 'empty': return SimpleNamespace(returncode=0, stdout='', stderr='')
            directory = ('/selected path;$x' if 'selected path;' in argv[-1] else
                './-L' if argv[-1].startswith('find ./-L ') else '/root/cores')
            return SimpleNamespace(returncode=0, stdout=''.join(
                directory + '/core ' + str(i) + ';$x\0' for i in range(22)), stderr='')
        if argv[0] == 'ssh':
            if argv[-1].startswith('stat '):
                size = 101 * 1048576 if 'core 1;' in argv[-1] else 1
                return SimpleNamespace(returncode=0, stdout=f'{size} 1', stderr='')
            return SimpleNamespace(returncode=1 if 'core 7;' in argv[-1] else 0, stdout='', stderr='denied' if 'core 7;' in argv[-1] else '')
        if 'core 2;' in argv[-2]:
            return SimpleNamespace(returncode=23, stdout='', stderr='transfer failed')
        Path(argv[-1]).write_bytes(b'' if 'core 3;' in argv[-2] else b'X')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    collection = Collection('controlled', ssh_key='key', process=process, cache_dir=tmp_path / 'cache')
    for state in ('empty', 'absent', 'unavailable'):
        mode[0] = state
        outcome = collection.acquire()
        assert outcome.inventory_status == state and outcome.status == ('succeeded' if state == 'empty' else 'failed')
    mode[0] = 'files'
    acquired = collection.acquire()
    assert acquired.status == 'succeeded' and len(acquired.artifacts) == len(acquired.items) == 22
    assert len(set(acquired.artifacts)) == 22
    assert all(Path(path).read_bytes() == b'X' for path in acquired.artifacts)
    assert all(item['status'] == 'cached' for item in acquired.items)
    assert not any('rm -f' in str(c) for c in commands)
    cache = tmp_path / 'local'; nested = cache / 'uuid'; nested.mkdir(parents=True)
    (nested / 'a file;$x').write_bytes(b'A')
    outside = tmp_path / 'outside'; outside.write_bytes(b'keep')
    app = Application(service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results')))
    try:
        local = run_maintenance(MaintenanceRequest(local_cache=str(cache), remote=False,
            log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
        assert local.outcome == 'completed' and local['items'][0].status == 'removed'
        assert not list(nested.iterdir()) and outside.read_bytes() == b'keep'
        # Ambiguous parent/child sets are rejected as a set, in either order.
        for entries in (('uuid', 'uuid/retained'), ('uuid/retained', 'uuid'), ('uuid/retained', 'uuid/./retained')):
            retained = nested / 'retained'; retained.write_bytes(b'keep')
            ambiguous = run_maintenance(MaintenanceRequest(local_cache=str(cache), remote=False,
                local_entries=entries, log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
            assert ambiguous.outcome == 'failed' and len(ambiguous['items']) == 2
            assert retained.read_bytes() == b'keep'
        rejected = run_maintenance(MaintenanceRequest(local_cache=str(cache), remote=False,
            local_entries=('../outside',), log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
        assert rejected.outcome == 'failed' and outside.read_bytes() == b'keep'
        remote = run_maintenance(MaintenanceRequest('controlled', 'key', ssh_user='operator',
            remote_dir='/selected path;$x', local=False, log_path=str(tmp_path / 'maintenance-actions.bfr')), app, process=process)
        assert len(remote['items']) == 22 and remote.outcome == 'failed'
        deletes = [argv for argv in commands if argv[0] == 'ssh' and argv[-1].startswith('rm -f')]
        assert len(deletes) == 22 and all(argv[-2] == 'operator@controlled' for argv in deletes)
        assert all(argv[-1].startswith("rm -f -- '/selected path;$x/") for argv in deletes)
        assert any(argv[-1].startswith("find '/selected path;$x' ") and '[ -x / ]' in argv[-1]
            for argv in commands if argv[0] == 'ssh')
        history = app.management.store.snapshot()
        assert history.issue is None and sum(r.kind == 'maintenance_terminal' for r in history.records) == 6
        assert sum(r.kind == 'maintenance_external_operation' for r in history.records) == 45
        assert not app.management.store.closed
        disjoint = cache / 'unselected'; disjoint.write_bytes(b'keep')
        combined = run_maintenance(MaintenanceRequest('controlled', 'key', ssh_user='operator',
            remote_dir='-L', local_cache=str(cache), local_entries=('uuid/retained',),
            remote_entries=('core 0;$x', 'missing'), log_path=str(tmp_path / 'maintenance-actions.bfr')),
            app, process=process)
        assert combined.outcome == 'failed' and [i.status for i in combined['items']] == ['removed', 'removed', 'absent']
        assert disjoint.read_bytes() == b'keep' and not (nested / 'retained').exists()
        assert any(argv[-1].startswith('find ./-L ') and '[ -x . ]' in argv[-1]
            for argv in commands if argv[0] == 'ssh')
        assert commands[-1][-1] == "rm -f -- '-L/core 0;$x'"
        # Omitted local destination follows this actual app Collection's UUID cache.
        attached_cache = Path(app.management.collection.core_cache_dir)
        attached_file = attached_cache / 'uuid' / 'core'; attached_file.parent.mkdir(parents=True)
        attached_file.write_bytes(b'cached')
        defaulted = run_maintenance(MaintenanceRequest(remote=False, log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
        assert defaulted.outcome == 'completed' and not attached_file.exists()
        assert Path(defaulted['items'][0].path).is_relative_to(attached_cache)
        repeated = run_maintenance(MaintenanceRequest(remote=False, log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
        assert repeated.outcome == 'completed' and repeated.inventories.local == 'empty'
        missing = run_maintenance(MaintenanceRequest(local_cache=str(cache), remote=False,
            local_entries=('uuid/retained',), log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
        assert missing.outcome == 'failed' and missing['items'][0].status == 'absent'
        # Ordinary unlink failures retain disjoint successful outcomes.
        denied, ordinary = nested / 'denied', nested / 'ordinary'
        denied.write_bytes(b'D'); ordinary.write_bytes(b'O')
        unlink = Path.unlink
        with monkeypatch.context() as patch:
            def fail_one(path, *args, **kwargs):
                if path == denied: raise PermissionError('controlled local failure')
                return unlink(path, *args, **kwargs)
            patch.setattr(Path, 'unlink', fail_one)
            partial = run_maintenance(MaintenanceRequest(local_cache=str(cache), remote=False,
                local_entries=('uuid/denied', 'uuid/ordinary'), log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
        assert [item.status for item in partial['items']] == ['failed', 'removed']
        assert denied.read_bytes() == b'D' and not ordinary.exists()
        # A required save failure is not an ordinary per-file error: no deletion follows it.
        ordinary.write_bytes(b'O')
        save, failed_save = app.management._save, []
        with monkeypatch.context() as patch:
            def fail_once(kind, identity, data):
                if kind == 'maintenance_operation' and not failed_save:
                    failed_save.append(True); raise OSError('controlled required write failure')
                return save(kind, identity, data)
            patch.setattr(app.management, '_save', fail_once)
            from bytefault.core.records import RequiredServiceSaveFailure
            with pytest.raises(RequiredServiceSaveFailure):
                run_maintenance(MaintenanceRequest(local_cache=str(cache), remote=False,
                    local_entries=('uuid/denied', 'uuid/ordinary'), log_path=str(tmp_path / 'maintenance-actions.bfr')), app)
        assert denied.read_bytes() == b'D' and ordinary.read_bytes() == b'O'
        # A failed acknowledgement after one actual remote deletion stops the next.
        before_deletes = len([argv for argv in commands if argv[0] == 'ssh' and argv[-1].startswith('rm -f')])
        failed_remote_save = []
        with monkeypatch.context() as patch:
            def fail_remote_once(kind, identity, data):
                if (kind == 'maintenance_external_operation' and data['operation']['argv'][-1].startswith('rm -f')
                        and not failed_remote_save):
                    failed_remote_save.append(True); raise OSError('controlled remote operation history failure')
                return save(kind, identity, data)
            patch.setattr(app.management, '_save', fail_remote_once)
            with pytest.raises(RequiredServiceSaveFailure):
                run_maintenance(MaintenanceRequest('controlled', 'key', local=False,
                    remote_entries=('core 0;$x', 'core 1;$x'), log_path=str(tmp_path / 'maintenance-actions.bfr')),
                    app, process=process)
        after_deletes = len([argv for argv in commands if argv[0] == 'ssh' and argv[-1].startswith('rm -f')])
        assert failed_remote_save and after_deletes == before_deletes + 1
        failure = next(record for record in reversed(app.management.store.snapshot().records)
            if record.kind == 'maintenance_failure')
        operation = failure.data.diagnostic.unacknowledged_action.operation
        assert operation.argv[-1].startswith('rm -f -- ') and operation.returncode == 0
        assert operation.started_at and operation.completed_at
    finally:
        app.close()
    assert app.management.store.closed
    assert maintenance_arguments(['--local-only']).remote is False
    with pytest.raises(ContractError): maintenance_arguments(['--local-only', '--remote-only'])


@pytest.mark.parametrize('credentials', (
    {'ssh_key': 'key'}, {'ssh_user': 'operator', 'ssh_pass': 'cleartext'},
))
def test_selected_remote_maintenance_credential_parity_and_auth_failure(tmp_path, credentials):
    seen = []
    def process(command, **options):
        seen.append((command, options))
        if command[-1].startswith('find '):
            return SimpleNamespace(returncode=0, stdout='/root/cores/one\0', stderr='')
        if command[-1].startswith('stat '):
            return SimpleNamespace(returncode=0, stdout='3 123', stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    request = MaintenanceRequest('controlled', local=False, remote_entries=('one',),
        log_path=str(tmp_path / 'maintenance.bfr'), **credentials)
    app = Application(service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results')))
    try:
        result = run_maintenance(request, app, process=process)
        assert result.outcome == 'completed'
        assert [(item.side, item.name, item.status) for item in result['items']] == [
            ('remote', 'one', 'removed')]
        assert [command[-1].split(' ', 1)[0] for command, _ in seen] == ['find', 'stat', 'rm']
        assert all(command[0] == 'ssh' for command, _ in seen)
        assert all(command[-2] == f'{request.ssh_user}@controlled' for command, _ in seen)
        if 'ssh_pass' in credentials:
            assert all(options['env']['BYTEFAULT_SSH_ASKPASS_PASSWORD'] == 'cleartext'
                for _, options in seen)
            assert 'cleartext' not in str(result.operations)
        else:
            assert all('env' not in options for _, options in seen)
    finally:
        app.close()

    def reject_auth(command, **options):
        return SimpleNamespace(returncode=255, stdout='', stderr='Permission denied')
    failed_app = Application(service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'failed-results')))
    try:
        failed = run_maintenance(replace(request, log_path=str(tmp_path / 'failure.bfr')),
            failed_app, process=reject_auth)
        assert failed.outcome == 'failed' and failed.inventories.remote == 'unavailable'
        assert failed['items'][0].status == 'failed'
    finally:
        failed_app.close()


def test_maintenance_password_input_requires_explicit_user_and_excludes_key():
    selected = maintenance_arguments(['controlled', '--remote-only', '--ssh-user', 'operator',
        '--ssh-pass', 'cleartext'])
    assert selected.remote and not selected.local and selected.ssh_key is None
    assert selected.ssh_user == 'operator' and selected.ssh_pass == 'cleartext'
    assert maintenance_arguments(['controlled', '--ssh-key', 'key']).ssh_user == 'root'
    with pytest.raises(ContractError, match='explicit SSH user'):
        maintenance_arguments(['controlled', '--ssh-pass', 'cleartext'])
    with pytest.raises(ContractError, match='conflict'):
        maintenance_arguments(['controlled', '--ssh-key', 'key', '--ssh-user', 'operator',
            '--ssh-pass', 'cleartext'])
    with pytest.raises(ContractError, match='SSH credentials'):
        maintenance_arguments(['controlled', '--remote-only'])


def test_password_collection_auth_failure_records_one_rsync_and_removes_helper(tmp_path):
    seen = []
    def reject_auth(command, **options):
        assert command[0] == 'rsync'
        helper = Path(options['env']['PYTHONPATH'].split(os.pathsep)[0]) / 'sitecustomize.py'
        assert helper.is_file()
        seen.append((command, helper))
        return SimpleNamespace(returncode=255, stdout='', stderr='Permission denied')
    collection = Collection('controlled', ssh_user='operator', ssh_pass='cleartext',
        process=reject_auth, cache_dir=tmp_path / 'cache')
    result = collection.acquire()
    assert result.status == 'failed' and result.inventory_status == 'unavailable'
    assert len(result.operations) == len(seen) == 1
    assert not seen[0][1].exists()
    assert 'cleartext' not in str(result.operations)
    assert 'Permission denied' in result.error
    with pytest.raises(ContractError, match='nonempty SSH password'):
        Collection('controlled', ssh_user='operator', ssh_pass='')
