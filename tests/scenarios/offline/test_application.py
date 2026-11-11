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
import threading
import importlib.util
from pathlib import Path
import sys

import pytest

from bytefault.application import ApplicationRequest, SavedCaseIntent, SavedStepIntent
from bytefault.core.contracts import (TransportRequest, PreparedRow, PreparedContribution,
    SourceInvocation, Placement, ContractError, MonitoringDecision)
from bytefault.fuzzers.inputs import request_to_data
from bytefault.fuzzers.cli import argument_request, execute_arguments
from bytefault.monitoring import Monitoring


def composed_request():
    from test_conversation import request
    base = request()
    plan = replace(base.plan, actions=tuple(replace(a, seed=b'U=aa;P=bb')
        if a.action_id == 'selected' else a for a in base.plan.actions))
    contributions = tuple(PreparedContribution(f'C{i}', data, SourceInvocation(f'S{i}', 'literal'))
        for i, data in enumerate((b'XXX', b'Y', b'ZZ')))
    placements = (Placement('P0', 'C0', 'selected', 'replace', 2, 4),
        Placement('P1', 'C1', 'selected', 'replace', 8, 10),
        Placement('P2', 'C2', 'selected', 'append'))
    return replace(base, plan=plan, row=PreparedRow('row', 1, contributions, placements),
                   original_request={'password': 'marker-X'})


def test_cli_callable_parity(tmp_path, application_factory):
    app, traces = application_factory(stream_options={'reads': (b'\x01',)}, event_capacity=2)
    cli_conversation = composed_request()
    argv = ['offline.invalid', '--port', '1234', '--timeout', '10', '--records',
        str(tmp_path / 'cli.bfr'), '--log-file', str(tmp_path / 'cli.log'),
        '--request-json', json.dumps(request_to_data(cli_conversation)), '--health-check-mode', 'disabled']
    resolved = argument_request(argv)
    caller = replace(resolved, conversation=replace(resolved.conversation, run_id='callable'),
        record_path=str(tmp_path / 'callable.bfr'), log_path=str(tmp_path / 'callable.log'))
    with app.validate(resolved) as left, app.validate(caller) as right:
        assert next(left)['materialized'] == next(right)['materialized']
    cli_result = execute_arguments(argv, app)
    caller_result = app.submit(caller)
    assert cli_result.run_id != caller_result.run_id
    assert [r.transport.offered for r in cli_result.last_conversation.actions] == [b'\x10', b'U=XXX;P=YZZ']
    assert [r.transport for r in cli_result.last_conversation.actions] == [r.transport for r in caller_result.last_conversation.actions]
    assert app.status(cli_result.run_id)['state'] == 'completed'
    assert app.control(cli_result.run_id, 'stop').outcome == 'rejected'
    batch = app.observe(cli_result.run_id)
    assert batch['resnapshot_required'] and batch['dropped_before'] > 0
    assert len(batch['events']) == 2
    assert len({e['event_id'] for e in batch['events']}) == 2
    assert batch['events'][0]['sequence'] < batch['events'][1]['sequence']
    with pytest.raises(TypeError):
        batch['events'][0]['identity'].run_id = 'mutated'
    assert len(app.record_refs(cli_result.run_id)) == len(app.read_records(cli_result.run_id).records)
    assert app.read_records(cli_result.run_id).records[0].data['application_request']['conversation']['original_request']['argv'] == tuple(argv)
    assert 'resume' in app.inspect()['operations']
    with pytest.raises(ContractError, match='unavailable_input'):
        app.saved_case(SavedCaseIntent(str(tmp_path / 'absent.bfr'), 'record', steps=(
            SavedStepIntent('setup'), SavedStepIntent('selected', 'fresh_dynamic', True, 'source'),)))
    assert app.inspect()['passive_version'] == 1
    assert {'declaration_schema', 'inspect_declaration', 'export_declaration', 'admit'} <= set(app.inspect()['operations'])
    assert 'authoring' not in app.inspect()['unavailable']
    assert app.inspect()['unavailable']['schema_to_dissector'].due == 'later converter'
    assert app.admit(app.export_declaration(cli_conversation.plan)) == cli_conversation.plan
    supplied = {'version': 99, 'declaration_id': 'unknown', 'actions': [],
                'required_capabilities': [{'name': 'unknown_feature'}]}
    inspected = app.inspect_declaration(supplied)
    assert inspected['status'] == 'unavailable'
    assert inspected['supplied']['version'] == 99
    assert inspected['supplied']['required_capabilities'][0]['name'] == 'unknown_feature'
    assert app.import_request(app.export_request(cli_conversation)) == cli_conversation
    from bytefault.core.contracts import ResponseField, ResponseEdge
    control = replace(cli_conversation.plan.actions[0],
        response_fields=(ResponseField('control', 0, 1), ResponseField('unknown')),
        edges=(ResponseEdge(b'\x01', 'selected', 'positive', 'control'),))
    field_plan = replace(cli_conversation.plan, actions=(control, *cli_conversation.plan.actions[1:]))
    exported = app.export_declaration(field_plan)
    assert exported['actions'][0]['response_fields'][1]['offset'] is None
    assert exported['actions'][0]['edges'][0]['field_id'] == 'control'
    assert app.admit(exported) == field_plan
    from bytefault.core.contracts import freeze
    assert app.inspect_declaration(exported)['plan'] == freeze(field_plan)
    assert app.import_request(app.export_request(replace(cli_conversation, plan=field_plan))).plan == field_plan
    assert app.declaration_schema()['action']['response_field_fields'] == ('field_id', 'offset', 'size')
    bad = replace(resolved, conversation=replace(resolved.conversation, selected_actions=('absent',)))
    with pytest.raises(ContractError):
        list(app.validate(bad))
    badargv = list(argv)
    badargv[badargv.index('--request-json')+1] = json.dumps(request_to_data(bad.conversation))
    with pytest.raises(ContractError):
        argument_request(badargv)


def test_hold_controls_cancel_and_query_during_storage(tmp_path, application_factory):
    held = threading.Event()
    class Policy:
        def evaluate(self, observation):
            held.set()
            return MonitoringDecision('hold', observation.observation_id, observation.correlation,
                                      'hold', 'awaited', ('external',))
    app, _ = application_factory(monitoring=Monitoring(Policy()))
    from test_logging_lifetime import app_request
    request = app_request(tmp_path)
    from bytefault.fuzzers.inputs import positional_plan
    request = replace(request, conversation=replace(request.conversation,
        plan=positional_plan((b'A', b'B')), selected_actions=('1', '2')))
    result = []
    thread = threading.Thread(target=lambda: result.append(app.submit(request)))
    thread.start()
    try:
        assert held.wait(5)
        assert app.observe(request.conversation.run_id)['status']['active']
        assert app.control(request.conversation.run_id, 'stop').outcome == 'completed'
        thread.join(5)
        assert not thread.is_alive() and result[0].outcome == 'stopped'
        from bytefault.core.storage import LocalRecordStore
        with LocalRecordStore(request.log_path):
            pass
    finally:
        app.close(); thread.join(5)


def test_initialization_failure_and_transport_validation(tmp_path, application_factory):
    from test_logging_lifetime import app_request
    from bytefault.application import Application
    app, _ = application_factory()
    request = app_request(tmp_path)
    with pytest.raises(ContractError):
        app.validate(replace(request, conversation='not typed'))
    for name in ('run_id', 'case_id', 'conversation_id'):
        for value in ([], 123, None, ''):
            invalid = replace(request, conversation=replace(request.conversation, **{name: value}))
            with pytest.raises(ContractError, match='invalid_identity'):
                app.submit(invalid)
    assert not (tmp_path / 'A.log.bfr').exists()
    for value in (float('nan'), float('inf'), 'wrong', True):
        with pytest.raises(ContractError):
            app.validate(replace(request, transport=replace(request.transport, pre_delay=value)))
    def failed_factory(target):
        raise OSError('injected adapter initialization failure')
    failing = Application(transport_factory=failed_factory)
    with pytest.raises(OSError, match='adapter initialization'):
        failing.submit(request)
    from bytefault.core.storage import reopen_records, LocalRecordStore
    assert reopen_records(request.log_path).records[0].kind == 'application_failure'
    with LocalRecordStore(request.log_path):
        pass
    failing.close()


def test_queries_and_optional_projection_during_required_io(tmp_path, application_factory, monkeypatch):
    from bytefault.application import _Run
    from bytefault.core.storage import LocalRecordStore, reopen_records
    from test_logging_lifetime import app_request
    entered, release = threading.Event(), threading.Event()
    original = LocalRecordStore.append
    def append(store, kind, identity, data):
        if kind == 'materialization' and store.path.name == 'A.bfr':
            entered.set()
            assert release.wait(5)
        return original(store, kind, identity, data)
    monkeypatch.setattr(LocalRecordStore, 'append', append)
    def bad_projection(self, *args):
        raise RuntimeError('optional projection unavailable')
    monkeypatch.setattr(_Run, 'event', bad_projection)
    app, _ = application_factory()
    request = replace(app_request(tmp_path), log_path=None)
    result = []
    thread = threading.Thread(target=lambda: result.append(app.submit(request)))
    thread.start()
    try:
        assert entered.wait(5)
        assert app.status(request.conversation.run_id)['active']
        assert app.observe(request.conversation.run_id)['projection_failed'] > 0
        assert app.control(request.conversation.run_id, 'stop').outcome == 'completed'
        release.set()
        thread.join(5)
        assert not thread.is_alive() and result[0].outcome == 'stopped'
        assert reopen_records(request.record_path + '.actions.bfr').records
        assert not app.status(request.conversation.run_id)['storage_failure']
    finally:
        release.set(); app.close(); thread.join(5)


def test_executable_factory_and_removed_auth_refuse_before_protocol_import(tmp_path, monkeypatch):
    from bytefault.replay.replay_packet import replay_packets, main
    pending = replay_packets('offline.invalid', 1234, [b'A'], session_factory=lambda: None)
    assert pending.status == 'pending' and pending.pending[0]['path'] == 'replay.session_factory'
    with pytest.raises(SystemExit) as refused:
        main(['offline.invalid', 'aa', '--auth'])
    assert refused.value.code == 2
    assert 'bytefault.protocols.registry' not in sys.modules


def test_current_cli_options_pending_handling_and_help(tmp_path, application_factory, monkeypatch):
    from bytefault.fuzzers.cli import build_parser, resolve_configuration, operation_exit_code
    parser = build_parser()
    spellings = {spelling for option in parser._actions for spelling in option.option_strings}
    expected = '''--port --target --target2 --list-targets --field-same --base-payload
        --mutate-seed --mutate-seed-file --mutate-seed-dir --mutate-count --mutate-raw
        --random-len --random-iter --random-seed --mutate-max-len --mutate-rng-seed
        --base --gen-field --gen-strategy --skip --base-packet --prefix --pad-byte
        --offset --fuzz-length --mask --mask2 --exclude --exclude2 --start --start2
        --auto-length --no-auto-length --test-length-mismatch --no-test-banner --ui --tui
        --no-ui --heartbeat --no-recv --check-interval --crash-delay --crash-throttle
        --timeout --tcp-pre-delay --tcp-spacing --tcp-post-delay --health-check-mode
        --core-dump-wait --delayed-crash-check --recovery-delays --reconnect-attempts
        --reconnect-delay --persistent --non-persistent --fuzz-stage
        --list-stages --verbose -v --debug --hide-field --log-file -l
        --ssh-key -k --ssh-user --ssh-pass --collect-cores'''.split()
    assert set(expected) <= spellings
    assert not {'--require-auth', '--auth', '--username', '--user', '--password', '--pass'} & spellings
    help_text = parser.format_help()
    assert '--gen-field' in help_text and '--ui' in help_text and '--mutate-seed-file' in help_text
    defaults = parser.parse_args(['neutral', 'offline.invalid'])
    assert not defaults.ui and not defaults.no_ui
    assert parser.parse_args(['neutral', 'offline.invalid', '--tui']).ui
    from bytefault.replay.replay_packet import build_parser as replay_parser
    replay = replay_parser(root=True)
    replay_spellings = {spelling for option in replay._actions for spelling in option.option_strings}
    assert not {'--auth', '--username', '--user', '--password', '--pass'} & replay_spellings
    assert {'--ssh-key', '--ssh-user', '--ssh-pass', '--collect-cores'} <= replay_spellings
    assert not replay.parse_args(['raw', 'offline.invalid', '41']).ui
    assert replay.parse_args(['raw', 'offline.invalid', '41', '--tui']).ui
    from bytefault.cli import build_parser as root_parser
    with pytest.raises(SystemExit) as removed:
        root_parser().parse_args(['test', 'raw', 'name'])
    assert removed.value.code == 2
    assert defaults.mutate_count == 100 and defaults.random_iter == 100
    assert defaults.gen_strategy == 'single' and defaults.skip == 0
    app, traces = application_factory()
    config = execute_arguments(['configure','neutral','offline.invalid','--gen-field',
        '@0:list:00,ff,mode:overwrite','--gen-strategy','zip','--base','payload=00ff',
        '--ui','--hide-field','password','--no-test-banner','-vvv'], app)
    assert config.status == 'pending' and operation_exit_code(config) == 2
    assert config.options['gen_strategy'] == 'zip' and config.options['verbose'] == 3
    assert config.resolved['base_values']['payload'] == b'\x00\xff'
    spec = config.resolved['generator_specs'][0]
    assert spec['primary'] == '00,ff' and spec['modifiers']['mode'] == 'overwrite'
    assert not any(p.owner == 'Generators/Mutators' for p in config.pending)
    assert config.generation['sources'][0]['options']['payloads'] == (b'\x00', b'\xff')
    assert any(p.owner == 'Passive declarations' and 'protocol' in p.options for p in config.pending)
    assert not any(set(p.options) & {'ui','no_ui','hide_field','test_banner'} for p in config.pending)
    assert config.options['ui'] and config.options['hide_field'] == ('password',)
    assert config.options['test_banner'] is False
    assert config.resolved['ui']['requested']
    assert config.resolved['ui']['attachment'] == 'optional ApplicationView client'
    assert not traces
    raw = ['offline.invalid','--port','1234','--seed-hex','414243','--records',str(tmp_path / 'raw.bfr'),
           '--no-ui','--no-recv','--tcp-spacing','2','--tcp-pre-delay','3','--tcp-post-delay','4',
           '--no-auto-length']
    resolved = resolve_configuration(raw)
    assert not resolved.pending and not resolved.request.conversation.repair
    assert resolved.request.transport.pre_delay == 3 and resolved.request.transport.post_delay == 4
    assert execute_arguments(raw, app).outcome == 'completed'
    for extra in (['--gen-field','a:list:00','--target','offset'],
                  ['--random-len','2-1'], ['--base','bad'], ['--mask','not-a-mask']):
        with pytest.raises(ContractError):
            resolve_configuration(['neutral','offline.invalid',*extra])

    from bytefault.fuzzers import cli
    def forbidden_boundary(*args, **kwargs):
        pytest.fail('conflicting CLI input reached application construction or generation preparation')
    monkeypatch.setattr(cli, 'Application', forbidden_boundary)
    monkeypatch.setattr(cli, '_generation', forbidden_boundary)
    before = len(traces)
    for extra, diagnostic in (
        (['--gen-field','@1:list:5a,mode:overwrite','--mutate-seed','4142'],
         '--gen-field cannot combine with --target, mutation seeds or --random-len'),
        (['--gen-field','@1:list:5a,mode:overwrite','--random-len','1'],
         '--gen-field cannot combine with --target, mutation seeds or --random-len'),
    ):
        with pytest.raises(ContractError) as refused:
            resolve_configuration(['neutral','offline.invalid',*extra])
        assert refused.value.path == 'cli.configuration'
        assert refused.value.code == 'invalid'
        assert isinstance(refused.value.__cause__, ValueError)
        assert str(refused.value.__cause__) == diagnostic
    assert len(traces) == before


def test_cli_dispatch_uses_current_application(tmp_path, application_factory):
    from bytefault.fuzzers.cli import operation_exit_code
    from bytefault.core.records import encode_value
    from bytefault.core.contracts import Correlation, MonitoringAction
    from bytefault.core.storage import LocalRecordStore
    from bytefault.management import Management
    store = LocalRecordStore(tmp_path / 'service.bfr')
    management = Management(store)
    app, traces = application_factory(management=management)
    try:
        assert execute_arguments(['schema'], app)['version'] == 1
        declaration = {'declaration_id':'neutral','version':1,'actions':[{'action_id':'1','seed_hex':'00ff'}]}
        literal = json.dumps(declaration)
        assert execute_arguments(['admit',literal], app).declaration_id == 'neutral'
        assert execute_arguments(['export-declaration',literal], app)['actions'][0]['seed_hex'] == '00ff'
        assert operation_exit_code(execute_arguments(['inspect-declaration',json.dumps(
            {**declaration, 'version':99})], app)) == 2
        assert execute_arguments(['inspect','--directory',str(tmp_path/'absent')], app)['declarations']['issues']
        request = argument_request(['offline.invalid','--port','1234','--seed-hex','00ff',
                                   '--records',str(tmp_path/'run.bfr')])
        result = app.submit(request)
        run_id = result.run_id
        assert execute_arguments(['status',run_id],app)['state'] == 'completed'
        assert execute_arguments(['control',run_id,'stop'],app).outcome == 'rejected'
        assert execute_arguments(['observe',run_id,'--after','0'],app)['events']
        assert execute_arguments(['record-refs',run_id],app)
        assert execute_arguments(['records',run_id],app).records
        with pytest.raises(ContractError, match='unavailable_input'):
            execute_arguments(['saved-intent',json.dumps(
                {'path':str(tmp_path/'absent.bfr'),'record_id':'ref','steps':[{'action_id':'1','choice':'fresh_dynamic',
                 'reapply_mutations':True}]})],app)
        before = len(traces)
        action = MonitoringAction('followup','event','observation',Correlation('r','c','v','a','attempt'),
                                  'followup', {'report':True})
        value = execute_arguments(['service','management',json.dumps(encode_value(action))],app)
        assert value.report.status == 'unavailable' and operation_exit_code(value) == 2
        assert len(traces) == before
    finally:
        app.close(); management.close(); management._worker.join(5); store.close()


def test_root_and_replay_current_configuration(tmp_path):
    source = Path(__file__).resolve().parents[3] / 'bytefault.py'
    spec = importlib.util.spec_from_file_location('current_root_entry',source)
    root = importlib.util.module_from_spec(spec); spec.loader.exec_module(root)
    declarations = tmp_path / 'protocols' / 'neutral'; declarations.mkdir(parents=True)
    (declarations / 'protocol.json').write_text(json.dumps({'format_version': 1, 'protocol_id': 'neutral',
        'transport': 'tcp', 'declaration': 'declaration.json', 'defaults': {'port': 1234}}))
    (declarations / 'declaration.json').write_text(json.dumps({'declaration_id': 'neutral', 'version': 1,
        'actions': [{'action_id': 'outbound', 'seed_hex': ''}]}))
    with pytest.raises(SystemExit) as retired:
        root.resolve_arguments(['monitor','neutral','offline.invalid','--declaration-dir', str(declarations.parent)])
    assert retired.value.code == 2
    config = root.resolve_arguments(['replay','neutral','offline.invalid','00ff','--no-recv','--value','0xff'])
    assert config.resolved['packets'] == (b'\x00\xff',) and config.resolved['value'] == 255
    assert config.status == 'pending' and config.pending[0]['path'] == 'replay.protocol'
    from bytefault.replay.replay_packet import resolve_arguments
    cases = tmp_path / 'cases.txt'; cases.write_text('41\n', encoding='utf-8')
    config = resolve_arguments(['offline.invalid','00ff','@' + str(cases),'--wait','2','--recovery-attempts','3'])
    assert config.resolved['packets'] == (b'\x00\xff', b'A')
    assert config.resolved['source_inputs'][0]['path'] == str(cases.resolve())
    assert config.options['recovery_attempts'] == 3
    cache = tmp_path / 'cache'; cache.mkdir(); (cache / 'core').write_bytes(b'core')
    config = root.resolve_arguments(['maintenance','--local-cache',str(cache),'--local-only'])
    assert config.local and not config.remote and config.local_cache == str(cache)
    from bytefault.management.maintenance import main as maintenance_main
    assert maintenance_main(['--local-only', '--local-cache',str(cache), '--results', str(tmp_path / 'results')]) == 0
    assert not (cache / 'core').exists()
    assert 'bytefault.protocols.registry' not in sys.modules
    assert root.main(['replay', 'neutral', 'offline.invalid', 'aa']) == 2
    assert 'bytefault.protocols.registry' not in sys.modules
