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

"""A3 file and mixed-source selections through the owned offline application fixture."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from bytefault import cli
from bytefault.core.contracts import ContractError
from bytefault.core.records import encode_value
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.management import Management
from bytefault.management.collection import Collection
from bytefault.management.maintenance import run_maintenance
from bytefault.reporting import Reporting, ReportRequest, ResultRoot


def config(tmp_path, body):
    path = tmp_path / 'selections with spaces.txt'
    path.write_text('format-version 1\n' + body, encoding='utf-8')
    return path


def offers(traces):
    return [step[1] for trace, _, _ in traces for step in trace if step[0] == 'offer']


def journal(path):
    retained = reopen_records(path)
    assert retained.issue is None
    starts = [record.data['request']['selected_actions'] for record in retained.records
              if record.kind == 'case_start']
    terminals = [record for record in retained.records if record.kind == 'case_terminal']
    assert starts and len(terminals) == len(starts)
    stable = []
    for record in terminals:
        result = record.data['result']
        stable.append((result['outcome'], result['planned_actions'], result['unreached'],
            result['reason'], tuple((action['action_id'], action['materialized']['final_bytes'],
                action['transport']['accepted_prefix'], action['transport']['acceptance'],
                action['transport']['receive_outcome']) for action in result['actions'])))
    return starts, stable


def maintenance_evidence(app):
    history = app.management.store.snapshot()
    assert history.issue is None
    terminal = next(record for record in history.records if record.kind == 'maintenance_terminal')
    result = terminal.data.outcome
    return (result.outcome, tuple((item.side, item.get('name') if item.side == 'remote' else None, item.status)
        for item in result['items']))


def test_fuzz_file_only_and_mixed_source_execute_same_bytes(tmp_path, application_factory):
    args = ('[fuzz]\nport 1234\nseed-hex 414243\n'
            'gen-field @1:list:5a,59,mode:overwrite\n'
            'health-check-mode disabled\nno-recv true\nretries 0\n')
    path = config(tmp_path, '[run]\ncommand fuzz\nprotocol raw\nhost offline.invalid\n' + args +
        '[output]\nrecords ' + str(tmp_path / 'file.bfr') + '\nresults ' + str(tmp_path / 'file-results') + '\n')
    app, traces = application_factory()
    outcome = cli.execute_arguments(['--config', str(path)], app)
    assert outcome.outcome == 'completed' and offers(traces) == [b'AZC', b'AYC']
    assert (tmp_path / 'file.bfr').exists()
    file_actions = journal(tmp_path / 'file.bfr')
    path = config(tmp_path, args)
    app, traces = application_factory()
    outcome = cli.execute_arguments(['fuzz', 'raw', 'offline.invalid', '--config', str(path),
        '--records', str(tmp_path / 'mixed.bfr'), '--results', str(tmp_path / 'mixed-results')], app)
    assert outcome.outcome == 'completed' and offers(traces) == [b'AZC', b'AYC']
    assert (tmp_path / 'mixed.bfr').exists()
    assert journal(tmp_path / 'mixed.bfr') == file_actions
    app, traces = application_factory()
    outcome = cli.execute_arguments(['fuzz', 'raw', 'offline.invalid', '--port', '1234',
        '--seed-hex', '414243', '--gen-field', '@1:list:5a,59,mode:overwrite',
        '--health-check-mode', 'disabled', '--no-recv', '--retries', '0',
        '--records', str(tmp_path / 'cli.bfr'), '--results', str(tmp_path / 'cli-results')], app)
    assert outcome.outcome == 'completed' and offers(traces) == [b'AZC', b'AYC']
    assert journal(tmp_path / 'cli.bfr') == file_actions


def test_replay_file_only_and_mixed_source_preserve_packet_order(tmp_path, application_factory):
    selections = ('[replay]\nport 1234\nno-recv true\nhealth-check-mode disabled\n')
    path = config(tmp_path, '[run]\ncommand replay\nprotocol raw\nhost offline.invalid\n'
        'packet 41\npacket 42\n' + selections + '[output]\nrecords ' +
        str(tmp_path / 'replay-file.bfr') + '\nresults ' + str(tmp_path / 'replay-file-results') + '\n')
    app, traces = application_factory()
    outcome = cli.execute_arguments(['--config', str(path)], app)
    assert outcome.outcome == 'completed' and offers(traces) == [b'A', b'B']
    assert (tmp_path / 'replay-file.bfr').exists()
    file_actions = journal(tmp_path / 'replay-file.bfr')
    path = config(tmp_path, selections)
    app, traces = application_factory()
    outcome = cli.execute_arguments(['replay', 'raw', 'offline.invalid', '41', '42',
        '--config', str(path), '--records', str(tmp_path / 'replay-mixed.bfr'),
        '--results', str(tmp_path / 'replay-mixed-results')], app)
    assert outcome.outcome == 'completed' and offers(traces) == [b'A', b'B']
    assert (tmp_path / 'replay-mixed.bfr').exists()
    assert journal(tmp_path / 'replay-mixed.bfr') == file_actions
    app, traces = application_factory()
    outcome = cli.execute_arguments(['replay', 'raw', 'offline.invalid', '41', '42',
        '--port', '1234', '--no-recv', '--health-check-mode', 'disabled',
        '--records', str(tmp_path / 'replay-cli.bfr'),
        '--results', str(tmp_path / 'replay-cli-results')], app)
    assert outcome.outcome == 'completed' and offers(traces) == [b'A', b'B']
    assert journal(tmp_path / 'replay-cli.bfr') == file_actions


def test_local_maintenance_file_only_and_mixed_source_record_selected_removal(tmp_path, application_factory):
    evidence = []
    for mode in ('file', 'mixed', 'cli'):
        cache = tmp_path / mode
        cache.mkdir()
        (cache / 'one').write_bytes(b'1')
        (cache / 'two').write_bytes(b'2')
        app, traces = application_factory()
        if mode == 'mixed':
            path = config(tmp_path, '[maintenance]\nlocal-only true\nlocal-entry one\nlocal-entry two\n')
            args = ['maintenance', '--local-cache', str(cache), '--config', str(path),
                    '--results', str(tmp_path / 'maintenance-mixed-results')]
        elif mode == 'file':
            path = config(tmp_path, '[run]\ncommand maintenance\n[maintenance]\nlocal-only true\n'
                'local-cache ' + str(cache) + '\nlocal-entry one\nlocal-entry two\n'
                '[output]\nresults ' + str(tmp_path / 'maintenance-file-results') + '\n')
            args = ['--config', str(path)]
        else:
            args = ['maintenance', '--local-only', '--local-cache', str(cache),
                    '--local-entry', 'one', '--local-entry', 'two',
                    '--results', str(tmp_path / 'maintenance-cli-results')]
        outcome = cli.execute_arguments(args, app)
        assert outcome.outcome == 'completed' and not list(cache.iterdir())
        assert {item.path for item in outcome['items']} == {str(cache / 'one'), str(cache / 'two')}
        evidence.append(maintenance_evidence(app))
        assert not traces
    assert evidence[0] == evidence[1] == evidence[2]


def test_selected_remote_maintenance_file_key_and_mixed_password_match_cli_requests(
        tmp_path, application_factory):
    for mode in ('key', 'password'):
        root = tmp_path / mode
        root.mkdir()
        base = '[maintenance]\nremote-only true\nremote-entry one\n'
        if mode == 'key':
            path = config(root, '[run]\ncommand maintenance\nhost controlled\n' + base +
                '[collection]\nssh-key key.pem\n[output]\nresults ' + str(root / 'results') + '\n')
            request = cli.resolve_arguments(['--config', str(path)])
            direct = cli.resolve_arguments(['maintenance', 'controlled', '--remote-only',
                '--remote-entry', 'one', '--ssh-key', 'key.pem', '--results', str(root / 'results')])
        else:
            path = config(root, base + '[collection]\nssh-user operator\nssh-pass cleartext\n')
            request = cli.resolve_arguments(['maintenance', 'controlled', '--config', str(path),
                '--results', str(root / 'results')])
            direct = cli.resolve_arguments(['maintenance', 'controlled', '--remote-only',
                '--remote-entry', 'one', '--ssh-user', 'operator', '--ssh-pass', 'cleartext',
                '--results', str(root / 'results')])
        assert (request.host, request.remote, request.local, request.remote_entries,
                request.ssh_key, request.ssh_user, request.ssh_pass) == (
                direct.host, direct.remote, direct.local, direct.remote_entries,
                direct.ssh_key, direct.ssh_user, direct.ssh_pass)
        seen = []
        def process(command, **options):
            seen.append((command, options))
            if command[-1].startswith('find '):
                return SimpleNamespace(returncode=0, stdout='/root/cores/one\0', stderr='')
            if command[-1].startswith('stat '):
                return SimpleNamespace(returncode=0, stdout='3 123', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        app, traces = application_factory()
        outcome = run_maintenance(request, app, process=process)
        assert outcome.outcome == 'completed'
        assert [(item.side, item.name, item.status) for item in outcome['items']] == [
            ('remote', 'one', 'removed')]
        assert [command[-1].split(' ', 1)[0] for command, _ in seen] == ['find', 'stat', 'rm']
        assert all(command[-2] == f'{request.ssh_user}@controlled' for command, _ in seen)
        if mode == 'password':
            assert all(options['env']['BYTEFAULT_SSH_ASKPASS_PASSWORD'] == 'cleartext'
                       for _, options in seen)
        assert not traces
        configured_evidence = maintenance_evidence(app)
        seen.clear()
        direct = replace(direct, result_root=str(root / 'cli-results'),
                         log_path=str(root / 'cli-maintenance.bfr'))
        app, traces = application_factory()
        cli_outcome = run_maintenance(direct, app, process=process)
        assert cli_outcome.outcome == outcome.outcome
        assert [command[-1].split(' ', 1)[0] for command, _ in seen] == ['find', 'stat', 'rm']
        assert maintenance_evidence(app) == configured_evidence
        assert not traces


def test_invalid_generation_selection_has_same_error_and_no_execution(tmp_path, application_factory):
    path = config(tmp_path, '[run]\ncommand configure\nhost offline.invalid\n'
        '[fuzz]\nport 1234\nseed-hex 00\ngen-field malformed\n')
    errors = []
    for args in (['--config', str(path)],
                 ['configure', 'offline.invalid', '--port', '1234', '--seed-hex', '00',
                  '--gen-field', 'malformed']):
        app, traces = application_factory()
        with pytest.raises(ContractError) as error:
            cli.execute_arguments(args, app)
        errors.append((error.value.path, error.value.code, str(error.value)))
        assert not traces
    assert errors[0] == errors[1]


def test_config_file_stays_a_consumed_input_for_prepared_routes(tmp_path, application_factory):
    app, traces = application_factory()
    path = config(tmp_path, '[run]\ncommand configure\nhost offline.invalid\n'
        '[fuzz]\nport 1234\nseed-hex 41\n')
    configured = cli.resolve_arguments(['--config', str(path)], app)
    assert str(path.resolve()) in configured.request.conversation.input_files
    template = configured.request

    path = config(tmp_path, '[run]\ncommand prepare\nhost offline.invalid\n'
        '[fuzz]\nport 1234\nseed-hex 41\n')
    prepared = cli.execute_arguments(['--config', str(path)], app)
    assert str(path.resolve()) in prepared.request.conversation.input_files
    prepared.close()

    path = config(tmp_path, '[run]\ncommand replay\nprotocol raw\nhost offline.invalid\n'
        'packet 41\n[replay]\nport 1234\nprepare true\n')
    replay = cli.resolve_arguments(['--config', str(path)], app)
    assert str(path.resolve()) in replay.request.conversation.input_files
    assert not traces

    supplied = SimpleNamespace(saved_case=lambda *args, **kwargs: template,
                               resume=lambda *args, **kwargs: template)
    for command in ('saved-intent', 'resume-run'):
        path = config(tmp_path, '[run]\ncommand ' + command + '\n'
            'intent-json {"path":"unused"}\n')
        selected = cli.execute_arguments(['--config', str(path)], supplied)
        assert str(path.resolve()) in selected.conversation.input_files

    path = config(tmp_path, '[run]\ncommand configure\nhost offline.invalid\n'
        '[fuzz]\nport 1234\nseed-hex 41\n')
    colliding = cli.resolve_arguments(['configure', '--config', str(path),
        '--records', str(path)], app)
    with pytest.raises(ContractError) as error:
        app.submit(colliding.request)
    assert error.value.code == 'source_collision'
    assert path.read_text(encoding='utf-8').startswith('format-version 1\n')
    assert not traces


@pytest.mark.parametrize('selection', ('whole-cache', 'exact-entry'))
def test_config_is_protected_before_selected_local_maintenance(tmp_path, application_factory, selection):
    cache = tmp_path / 'cache'
    cache.mkdir()
    sibling = cache / 'older-core'
    sibling.write_bytes(b'old')
    path = cache / 'run.conf'
    entry = 'local-entry run.conf\n' if selection == 'exact-entry' else ''
    path.write_text('format-version 1\n[run]\ncommand maintenance\n'
        '[maintenance]\nlocal-only true\nlocal-cache ' + str(cache) + '\n' + entry +
        '[output]\nresults ' + str(tmp_path / 'results') + '\n', encoding='utf-8')
    original = path.read_bytes()
    app, traces = application_factory()
    with pytest.raises(ContractError) as error:
        cli.execute_arguments(['--config', str(path)], app)
    assert error.value.code == 'source_collision'
    assert path.read_bytes() == original and sibling.read_bytes() == b'old'
    assert not traces


def test_config_hardlink_alias_is_rejected_before_sibling_cleanup(tmp_path, application_factory):
    cache = tmp_path / 'cache'
    cache.mkdir()
    sibling = cache / 'older-core'
    sibling.write_bytes(b'old')
    path = tmp_path / 'run.conf'
    path.write_text('format-version 1\n[run]\ncommand maintenance\n'
        '[maintenance]\nlocal-only true\nlocal-cache ' + str(cache) + '\n'
        'local-entry older-core\nlocal-entry alias.conf\n', encoding='utf-8')
    alias = cache / 'alias.conf'
    try:
        alias.hardlink_to(path)
    except OSError as error:
        pytest.skip(f'hardlinks unavailable: {error}')
    original = path.read_bytes()
    app, traces = application_factory()
    with pytest.raises(ContractError) as error:
        cli.execute_arguments(['--config', str(path)], app)
    assert error.value.code == 'source_collision'
    assert path.read_bytes() == alias.read_bytes() == original
    assert sibling.read_bytes() == b'old' and not traces


def test_config_input_reaches_generic_maintenance(tmp_path, application_factory):
    cache = tmp_path / 'cache'
    cache.mkdir()
    sibling = cache / 'older-core'
    sibling.write_bytes(b'old')
    path = cache / 'service.conf'
    payload = {'local_cache': str(cache), 'local': True, 'remote': False,
               'local_entries': ['older-core', 'service.conf']}
    path.write_text('format-version 1\n[run]\ncommand service\nowner maintenance\n'
        'request-json ' + json.dumps(encode_value(payload)) + '\n', encoding='utf-8')
    original = path.read_bytes()
    manager = Management(LocalRecordStore(tmp_path / 'management.bfr'))
    try:
        app, traces = application_factory(management=manager)
        with pytest.raises(ContractError) as error:
            cli.execute_arguments(['--config', str(path)], app)
        assert error.value.code == 'source_collision'
        assert path.read_bytes() == original and sibling.read_bytes() == b'old'
        assert not traces
    finally:
        manager.close(); manager.wait()


def test_config_input_protects_direct_typed_management_maintenance(tmp_path):
    cache = tmp_path / 'cache'
    cache.mkdir()
    sibling = cache / 'older-core'
    sibling.write_bytes(b'old')
    path = cache / 'run.conf'
    path.write_text('format-version 1\n[run]\ncommand maintenance\n'
        '[maintenance]\nlocal-only true\nlocal-cache ' + str(cache) + '\n', encoding='utf-8')
    request = cli.resolve_arguments(['--config', str(path)])
    assert request.input_files == (str(path.resolve()),)
    original = path.read_bytes()
    manager = Management(LocalRecordStore(tmp_path / 'management.bfr'))
    try:
        with pytest.raises(ContractError) as error:
            manager.maintain(request)
        assert error.value.code == 'source_collision'
        assert path.read_bytes() == original and sibling.read_bytes() == b'old'
        assert manager.store.snapshot().records == ()
    finally:
        manager.close(); manager.wait()


def test_config_input_protects_reused_report_destination(tmp_path, application_factory):
    from bytefault.core.contracts import Correlation, MonitoringAction
    action = MonitoringAction('action', 'event', 'observation',
        Correlation('run', 'case', 'conversation', 'send', 'attempt'), 'followup', {'report': True})
    root = ResultRoot(tmp_path / 'results')
    try:
        app, traces = application_factory(reporting=Reporting(root))
        first = app.service('reporting', ReportRequest('first', action, 'disabled'))
        assert first.status == 'succeeded'
        path = Path(first.location)
        payload = ReportRequest('second', action, 'disabled')
        path.write_text('format-version 1\n[run]\ncommand service\nowner reporting\n'
            'request-json ' + json.dumps(encode_value(payload)) + '\n', encoding='utf-8')
        original = path.read_bytes()
        second = cli.execute_arguments(['--config', str(path)], app)
        assert second.status == 'failed' and 'aliases an input' in second.error
        assert path.read_bytes() == original and not traces
    finally:
        root.close()


def test_selected_collection_cache_input_guard_has_endpoint_control(tmp_path, application_factory):
    from bytefault.core.contracts import Correlation, MonitoringAction
    action = MonitoringAction('action', 'event', 'observation',
        Correlation('run', 'case', 'conversation', 'send', 'attempt'), 'followup', {'collect': True})
    cache = tmp_path / 'cache'
    calls = []
    def process(command, **options):
        calls.append((command, options))
        return SimpleNamespace(returncode=255, stdout='', stderr='controlled offline failure')
    collector = Collection('controlled', ssh_key='key.pem', cache_dir=cache,
        core_write_wait=0, process=process)
    manager = Management(LocalRecordStore(tmp_path / 'management.bfr'), collection=collector)
    try:
        app, traces = application_factory(management=manager)
        selected = collector._endpoint_root() / 'current'
        selected.mkdir(parents=True)
        current = selected / 'run.conf'
        text = 'format-version 1\n[run]\ncommand service\nowner management\n'
        text += 'request-json ' + json.dumps(encode_value(action)) + '\n'
        current.write_text(text, encoding='utf-8')
        outcome = cli.execute_arguments(['--config', str(current)], app)
        assert outcome.collection.status == 'failed'
        assert 'current input' in outcome.collection.error
        assert not calls and current.read_text(encoding='utf-8') == text
        sibling = cache / 'unrelated' / 'run.conf'
        sibling.parent.mkdir()
        sibling.write_text(text, encoding='utf-8')
        outcome = cli.execute_arguments(['--config', str(sibling)], app)
        assert outcome.collection.status == 'failed'
        assert calls and 'controlled offline failure' in outcome.collection.error
        assert sibling.read_text(encoding='utf-8') == text and not traces
    finally:
        manager.close(); manager.wait()
