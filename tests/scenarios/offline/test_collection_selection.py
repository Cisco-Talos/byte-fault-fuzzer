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

"""Campaign collection intent and authentication admission through current clients."""
from types import SimpleNamespace
import json

import pytest

from bytefault.application import CampaignRequest
from bytefault.core.contracts import ContractError
from bytefault.core.records import encode_value
from bytefault.fuzzers.cli import execute_arguments as fuzz_arguments
from bytefault.management.configuration import ServiceConfiguration
from bytefault.monitoring import Monitoring, MonitoringConfig, ObservationRule
from bytefault.replay.replay_packet import execute_arguments as replay_arguments
from bytefault.replay.replay_packet import replay_packets
from test_followup_heartbeat import request


def failed_service(app, traces):
    original = app.transport_factory
    def transport(target):
        adapter = original(target)
        stream = traces[-1][1]
        connect = stream.connect
        count = [0]
        def controlled(address):
            count[0] += 1
            stream.open_error = OSError('controlled unavailable service') if count[0] == 2 else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = transport


def followup(app):
    status = app.management.wait(5)
    assert not status['pending'] and len(status['outcomes']) == 1
    return status['outcomes'][0]['outcome']


@pytest.mark.parametrize('route,credentials,selected,expected', (
    ('fuzz', ('--ssh-key', 'key'), False, 'disabled'),
    ('fuzz', ('--ssh-user', 'operator'), False, 'disabled'),
    ('fuzz', ('--ssh-user', 'operator', '--ssh-pass', 'cleartext'), False, 'disabled'),
    ('fuzz', ('--ssh-key', 'key'), True, 'succeeded'),
    ('fuzz', ('--ssh-key', 'key', '--ssh-user', 'operator'), True, 'succeeded'),
    ('fuzz', ('--ssh-user', 'operator', '--ssh-pass', 'cleartext'), True, 'succeeded'),
    ('replay', ('--ssh-key', 'key'), False, 'disabled'),
    ('replay', ('--ssh-key', 'key'), True, 'succeeded'),
    ('replay', ('--ssh-user', 'operator', '--ssh-pass', 'cleartext'), True, 'succeeded'),
))
def test_campaign_collection_selection_and_report(tmp_path, application_factory, monkeypatch,
                                                   route, credentials, selected, expected):
    import bytefault.management.collection as module
    commands = []
    def process(command, **options):
        commands.append((command, options))
        assert command[0] == 'rsync'
        return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', process)
    app, traces = application_factory()
    failed_service(app, traces)
    if route == 'fuzz':
        policy = json.dumps(encode_value({'retries': 0, 'recovery_delays': [], 'recovery_budget': 0,
            'reconnect_attempts': 0, 'crash_throttle': 0}))
        argv = ['submit', 'controlled-A', '--port', '1234', '--seed-hex', '41', '--no-recv',
            '--records', str(tmp_path / 'run.bfr'), '--results', str(tmp_path / 'results'),
            '--core-dump-wait', '0', '--monitoring-json', policy, *credentials]
        if selected:
            argv.append('--collect-cores')
        result = fuzz_arguments(argv, app)
    else:
        argv = ['controlled-A', '41', '--port', '1234', '--no-recv',
            '--records', str(tmp_path / 'replay.bfr'), '--results', str(tmp_path / 'results'),
            '--core-dump-wait', '0', '--recovery-attempts', '0', *credentials]
        if selected:
            argv.append('--collect-cores')
        result = replay_arguments(argv, app)
    outcome = followup(app)
    assert result.fuzz_tests == 1
    assert outcome.collection.status == expected
    assert outcome.report.status == 'succeeded'
    assert len(commands) == (1 if expected == 'succeeded' else 0)
    if commands:
        user = 'operator' if '--ssh-user' in credentials else 'root'
        command, options = commands[0]
        assert command[-2].startswith(f'{user}@controlled-A:')
        if '--ssh-pass' in credentials:
            assert options['env']['BYTEFAULT_SSH_ASKPASS_PASSWORD'] == 'cleartext'
            assert all('cleartext' not in str(part) for part in command)
            assert 'cleartext' not in str(outcome.collection.operations)
        else:
            assert 'env' not in options
    assert app.reporting.layout.snapshot()
    assert any(record.kind == 'collection_outcome' and
        record.data['collection']['status'] == expected for record in app.management.store.snapshot().records)


@pytest.mark.parametrize('choices', (
    ('--collect-cores',),
    ('--ssh-pass', 'cleartext', '--collect-cores'),
    ('--ssh-key', 'key', '--ssh-user', 'operator', '--ssh-pass', 'cleartext', '--collect-cores'),
    ('--ssh-key', 'key', '--ssh-user', 'operator', '--ssh-pass', 'cleartext'),
))
def test_cli_invalid_collection_credentials_refuse_before_transport(tmp_path, application_factory, choices):
    app, traces = application_factory()
    argv = ['submit', 'controlled-A', '--port', '1234', '--seed-hex', '41',
        '--records', str(tmp_path / 'invalid.bfr'), *choices]
    with pytest.raises(ContractError):
        fuzz_arguments(argv, app)
    assert not traces and app.management is None


@pytest.mark.parametrize('command', ('prepare', 'validate'))
@pytest.mark.parametrize('credentials,selected', (
    ((), False), (('--ssh-key', 'key'), False),
    (('--ssh-user', 'operator', '--ssh-pass', 'test-value'), False),
    (('--ssh-key', 'key'), True),
    (('--ssh-user', 'operator', '--ssh-pass', 'test-value'), True),
))
def test_cli_collection_preparation_preserves_selection_and_services(
        tmp_path, application_factory, command, credentials, selected):
    app, traces = application_factory()
    arguments = [command, 'raw', 'controlled-A', '--port', '49152', '--seed-hex', '41',
        '--records', str(tmp_path / 'prepare.bfr'), *credentials]
    if selected:
        arguments.append('--collect-cores')
    preparation = fuzz_arguments(arguments, app)
    try:
        rows = list(preparation)
        assert len(rows) == 1
        assert preparation.request.monitoring_configuration.collect_cores is selected
    finally:
        preparation.close()
    assert not traces and app.management is None and app.reporting is None
    assert app.service_configuration is None and not app._preparations
    assert not (tmp_path / 'prepare.bfr').exists()


def test_cli_collection_preparation_credentials_and_inherited_options(tmp_path, application_factory):
    original = ServiceConfiguration(ssh_key='caller-key', remote_dir='/caller')
    app, traces = application_factory(service_configuration=original)
    common = ['prepare', 'raw', 'controlled-A', '--port', '49152', '--seed-hex', '41',
        '--records', str(tmp_path / 'prepare.bfr'), '--collect-cores']
    for choices in ((), ('--ssh-key', 'selected-key')):
        preparation = fuzz_arguments([*common, *choices], app)
        try:
            assert len(list(preparation)) == 1
        finally:
            preparation.close()
        assert app.service_configuration is original
    for choices in (('--ssh-pass', 'test-value'),
                    ('--ssh-user', 'operator', '--ssh-pass', 'test-value')):
        with pytest.raises(ContractError):
            fuzz_arguments([*common, *choices], app)
    empty, empty_traces = application_factory()
    with pytest.raises(ContractError, match='campaign.collect_cores'):
        fuzz_arguments(common, empty)
    assert not traces and not empty_traces
    assert app.management is None and empty.management is None
    assert app.service_configuration is original and empty.service_configuration is None


def test_replay_callable_collection_choice_and_invalid_cli_admission(tmp_path, application_factory):
    app, traces = application_factory()
    prepared = replay_packets('controlled-A', 1234, (b'A',), application=app,
        prepare=True, collect_cores=True, ssh_key='key', skip_recv=True)
    assert prepared.monitoring_configuration.collect_cores
    assert prepared.monitoring_configuration.health_check_mode == 'new_connection'
    assert not traces and app.management is None
    for choices in (('--collect-cores',), ('--collect-cores', '--ssh-pass', 'cleartext'),
                    ('--ssh-key', 'key', '--ssh-user', 'operator', '--ssh-pass', 'cleartext')):
        with pytest.raises(ContractError):
            replay_arguments(['controlled-A', '41', '--port', '1234',
                '--records', str(tmp_path / 'replay-invalid.bfr'), *choices], app)
        assert not traces and app.management is None


@pytest.mark.parametrize('policy', (
    MonitoringConfig(collect_cores=True),
    MonitoringConfig(rules=(ObservationRule('selected', 'unrequested',
        actions=({'collect': True},)),)),
))
def test_structured_monitoring_selection_refuses_before_transport(tmp_path, application_factory, policy):
    app, traces = application_factory(monitoring=Monitoring(configuration=policy))
    base = request(tmp_path, two=False)
    with pytest.raises(ContractError, match='campaign.collect_cores'):
        app.submit(CampaignRequest(base.conversation, base.transport, base.record_path))
    assert not traces and app.management is None


@pytest.mark.parametrize('selected', (False, True))
def test_structured_key_selection_keeps_report_without_implicit_ssh(
        tmp_path, application_factory, monkeypatch, selected):
    import bytefault.management.collection as module
    commands = []
    def process(command, **options):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', process)
    app, traces = application_factory(service_configuration=ServiceConfiguration(
        result_root=str(tmp_path / 'results'), ssh_key='key', core_write_wait=0))
    failed_service(app, traces)
    base = request(tmp_path, two=False)
    result = app.submit(CampaignRequest(base.conversation, base.transport, base.record_path,
        monitoring_configuration=MonitoringConfig(collect_cores=selected, retries=0,
            recovery_delays=(), recovery_budget=0, reconnect_attempts=0, crash_throttle=0)))
    outcome = followup(app)
    assert result.fuzz_tests == 1
    assert outcome.collection.status == ('succeeded' if selected else 'disabled')
    assert outcome.report.status == 'succeeded'
    assert len(commands) == int(selected)


def test_caller_monitoring_selection_uses_default_failed_service_action(
        tmp_path, application_factory, monkeypatch):
    import bytefault.management.collection as module
    commands = []
    def process(command, **options):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', process)
    monitor = Monitoring(configuration=MonitoringConfig(collect_cores=True, retries=0,
        recovery_delays=(), recovery_budget=0, reconnect_attempts=0, crash_throttle=0))
    app, traces = application_factory(monitoring=monitor,
        service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results'),
            ssh_key='key', core_write_wait=0))
    failed_service(app, traces)
    assert app.campaign(request(tmp_path, two=False)).fuzz_tests == 1
    outcome = followup(app)
    assert outcome.collection.status == 'succeeded' and outcome.report.status == 'succeeded'
    assert len(commands) == 1


def test_replay_explicit_disabled_has_no_check_or_collection(tmp_path, application_factory, monkeypatch):
    import bytefault.management.collection as module
    monkeypatch.setattr(module.subprocess, 'run', lambda *_a, **_k:
        pytest.fail('disabled replay must not start collection'))
    app, traces = application_factory()
    result = replay_arguments(['controlled-A', '41', '--port', '1234', '--no-recv',
        '--records', str(tmp_path / 'disabled.bfr'), '--collect-cores', '--ssh-key', 'key',
        '--health-check-mode', 'disabled'], app)
    assert result.fuzz_tests == 1
    assert len([entry for entry in traces[0][0] if entry[0] == 'open']) == 1
    assert not [record for record in app.read_records(result.run_id).records
        if record.kind == 'observation' and record.data['observation']['kind'] == 'service_check']
    assert not app.management.status()['outcomes']


def test_explicit_monitoring_cleanup_remains_separate_from_collection_flag(
        tmp_path, application_factory, monkeypatch):
    import bytefault.management.collection as module
    from pathlib import Path
    commands = []
    def process(command, **options):
        commands.append(command)
        if command[0] == 'rsync':
            (Path(command[-1]) / 'core').write_bytes(b'C')
            return SimpleNamespace(returncode=0,
                stdout='BF|>f+++++++++|1|2026/10/22-15:00:57|core\nNumber of files: 2 (reg: 1, dir: 1)',
                stderr='')
        assert command[0] == 'ssh' and command[-1].startswith('rm -f -- ')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', process)
    app, _ = application_factory(service_configuration=ServiceConfiguration(
        result_root=str(tmp_path / 'results'), ssh_key='key', core_write_wait=0))
    base = request(tmp_path, two=False)
    rule = ObservationRule('selected_cleanup', 'unrequested',
        actions=({'collect': True, 'cleanup': True, 'report': True},))
    app.submit(CampaignRequest(base.conversation, base.transport, base.record_path,
        monitoring_configuration=MonitoringConfig(health_check_mode='disabled',
            rules=(rule,), retries=0)))
    outcome = followup(app)
    assert outcome.collection.status == 'succeeded' and outcome.report.status == 'succeeded'
    assert [command[0] for command in commands] == ['rsync', 'ssh']
    assert outcome.collection['items'][0]['cleanup']['status'] == 'succeeded'


def test_structured_password_selection_and_tui_use_same_request(
        tmp_path, application_factory, monkeypatch):
    from bytefault.ui.controller import run_terminal
    import bytefault.management.collection as module
    import io
    commands = []
    def process(command, **options):
        commands.append((command, options))
        return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', process)
    app, traces = application_factory(service_configuration=ServiceConfiguration(
        result_root=str(tmp_path / 'results'), ssh_user='operator', ssh_pass='cleartext',
        core_write_wait=0))
    failed_service(app, traces)
    base = request(tmp_path, two=False)
    selected = CampaignRequest(base.conversation, base.transport, base.record_path,
        monitoring_configuration=MonitoringConfig(collect_cores=True, retries=0,
            recovery_delays=(), recovery_budget=0, reconnect_attempts=0, crash_throttle=0))
    shown = io.StringIO()
    result = run_terminal(app, selected, {'no_ui': True}, stream=shown)
    outcome = followup(app)
    assert result.fuzz_tests == 1 and outcome.collection.status == 'succeeded'
    assert outcome.report.status == 'succeeded'
    assert len(commands) == 1 and commands[0][0][0] == 'rsync'
    assert commands[0][1]['env']['BYTEFAULT_SSH_ASKPASS_PASSWORD'] == 'cleartext'
    assert 'SUMMARY' in shown.getvalue()
    assert app.reporting.layout.snapshot()
