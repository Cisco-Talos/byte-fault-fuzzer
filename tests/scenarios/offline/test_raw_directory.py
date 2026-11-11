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

"""Actual directory -> application -> executor -> retained history."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pytest

from bytefault.core.contracts import (ContractError, ConversationAction, ConversationRequest,
    PassivePlan, PreparedRow, PreparedContribution, SourceInvocation, Placement, ReceiveRequest, freeze)
from bytefault.core.storage import reopen_records
from bytefault.fuzzers.cli import execute_arguments, resolve_configuration, operation_exit_code
from bytefault.fuzzers.protocol_directory import discover_protocols, select_actions


RAW = Path(__file__).resolve().parents[3] / 'src' / 'bytefault' / 'protocols' / 'raw'


def test_bundled_protocol_source_is_raw_only():
    root = RAW.parent
    assert {path.name for path in root.iterdir() if path.is_dir() and path.name != '__pycache__'} == {'raw'}
    found = discover_protocols(root)
    assert tuple(entry.protocol_id for entry in found.entries) == ('raw',)
    assert not found.issues and not found.pending_directories


@pytest.fixture
def dropin(tmp_path):
    root = tmp_path / 'external'
    directory = root / 'moved-component'
    shutil.copytree(RAW, directory, ignore=shutil.ignore_patterns('__pycache__'))
    return root, directory


def write_json(path, data):
    path.write_text(json.dumps(data), encoding='utf-8')


def descriptor(directory, **changes):
    path = directory / 'protocol.json'
    value = json.loads(path.read_text(encoding='utf-8'))
    value.update(changes)
    write_json(path, value)


def offers(traces):
    return [step[1] for trace, _, _ in traces for step in trace if step[0] == 'offer']


def test_external_alias_callable_cli_and_exact_history(dropin, tmp_path, application_factory):
    root, directory = dropin
    # Merely adjacent Python is never imported, including a malicious initializer.
    (directory / '__init__.py').write_text('raise AssertionError("imported drop-in")', encoding='utf-8')
    app, traces = application_factory()
    before = set(sys.modules)
    canonical = app.resolve_protocol('raw', root)
    alias = app.resolve_protocol('tcp-raw', root)
    assert canonical.entry == alias.entry
    assert app.resolve_protocol(' RAW ',root).entry == canonical.entry
    assert app.resolve_protocol('Tcp-Raw',root).entry == canonical.entry
    assert alias.provenance['requested_selection'] == 'tcp-raw'
    assert canonical.entry.plan.actions[0].receive == ReceiveRequest()
    assert canonical.entry.defaults.port is None
    with pytest.raises(TypeError):
        canonical.entry.descriptor['protocol_id'] = 'changed'
    call = app.protocol_request(' TCP-RAW ', 'offline.invalid', directory=root, seed=b'\x00\xff\x80ABC',
        port=1234, no_receive=True, record_path=str(tmp_path / 'call.bfr'))
    argv = ['raw','offline.invalid','--declaration-dir',str(root),'--port','1234',
        '--seed-hex','00ff80414243','--no-ui','--no-recv','--health-check-mode','disabled','--records',str(tmp_path / 'cli.bfr')]
    config = resolve_configuration(argv, app)
    assert config.status == 'available'
    assert config.request.conversation.plan == call.conversation.plan
    with app.validate(config.request) as prepared:
        assert app.validate(call)['materialized'] == next(prepared)['materialized'][0]
    with execute_arguments(['validate',*argv],app) as prepared:
        assert next(prepared)['materialized'][0] == app.validate(call)['materialized']
    inspected = execute_arguments(['inspect','--directory',str(root)],app)
    assert inspected['protocols']['entries'][0]['protocol_id'] == 'raw'
    call_result = app.submit(call)
    cli_result = execute_arguments(argv, app)
    assert call_result.outcome == cli_result.outcome == 'completed'
    assert offers(traces) == [b'\x00\xff\x80ABC'] * 2
    assert call_result.run_id != cli_result.run_id
    for run_id, requested in ((call_result.run_id,' TCP-RAW '), (cli_result.run_id,'raw')):
        record = next(r for r in app.read_records(run_id).records if r.kind=='case_start')
        original = record.data['request']['original_request']
        source = original['protocol_input']['source']
        assert source['requested_selection'] == requested and source['protocol_id'] == 'raw'
        assert source['format_version'] == source['declaration_version'] == 1
        assert source['descriptor_path'] == str((directory / 'protocol.json').resolve())
        assert source['declaration_path'] == str((directory / 'declaration.json').resolve())
        assert original['protocol_input']['seed'] == b'\x00\xff\x80ABC'
        assert app.status(run_id)['state'] == 'completed'
        assert app.record_refs(run_id)
    assert next(r for r in app.read_records(cli_result.run_id).records if r.kind=='case_start').data['request']['original_request']['argv'] == tuple(argv)
    assert not any(name.startswith('bytefault.protocols') for name in set(sys.modules) - before)
    assert app.import_request(app.export_request(call.conversation)) == call.conversation


@pytest.mark.parametrize('mode', ('seed', 'prepared'))
@pytest.mark.parametrize('metadata', ('collision', 'empty', 'absent'))
def test_supplied_original_request_survives_provenance_and_history(
        dropin, tmp_path, application_factory, mode, metadata):
    root, directory = dropin
    app, traces = application_factory()
    caller = ({'protocol_input': {'source': b'\x00\xff\x80', 'seed': b'caller seed'},
        'supplied_original_request': {'protocol_input': b'nested collision'},
        'nested': [{'bytes': b'\x00\x80\xff'}], 'overlap': 'caller'}
        if metadata == 'collision' else {} if metadata == 'empty' else None)
    expected = freeze(caller)
    plan = app.resolve_protocol('raw', root).entry.plan
    row = PreparedRow('row', 1,
        (PreparedContribution('C', b'\x00\xff\x80ABC', SourceInvocation('S', 'literal')),),
        (Placement('P', 'C', 'outbound', 'append'),))
    prepared = ConversationRequest(plan, row, ('outbound',),
        'prepared-' + metadata, 'case', 'conversation', original_request={
            'protocol_input': {'prepared': b'original'}, 'overlap': 'prepared'})
    request = app.protocol_request(' TCP-RAW ', 'offline.invalid', directory=root,
        **({'seed': b'\x00\xff\x80ABC'} if mode == 'seed' else {'conversation': prepared}),
        port=1234, no_receive=True, record_path=str(tmp_path / (mode + '-' + metadata + '.bfr')),
        original_request=caller)
    original = request.conversation.original_request
    intent = original['protocol_input']
    assert intent['supplied_original_request'] == expected
    assert (intent['supplied_original_request'] is None) == (metadata == 'absent')
    assert intent['source']['protocol_id'] == 'raw'
    assert intent['source']['requested_selection'] == ' TCP-RAW '
    assert intent['source']['descriptor_path'] == str((directory / 'protocol.json').resolve())
    if metadata == 'collision':
        assert original['overlap'] == 'caller'  # Existing top-level merge precedence.
        assert original['supplied_original_request'] == expected['supplied_original_request']
        caller['protocol_input']['source'] = b'changed'
        caller['nested'][0]['bytes'] = b'changed'
        caller['nested'].append({'later': b'changed'})
    if caller is not None:
        caller['later'] = b'changed after binding'
        with pytest.raises(TypeError):
            intent['supplied_original_request']['later'] = b'cannot mutate snapshot'
    if mode == 'prepared':
        assert intent['supplied_conversation']['original_request'] == prepared.original_request
        assert intent['supplied_conversation']['original_request']['protocol_input']['prepared'] == b'original'
    roundtrip = app.import_request(app.export_request(request.conversation))
    assert roundtrip == request.conversation
    assert roundtrip.original_request['protocol_input']['supplied_original_request'] == expected
    result = app.submit(replace(request, conversation=roundtrip))
    assert result.outcome == 'completed'
    assert offers(traces) == [b'\x00\xff\x80ABC']
    case = next(record for record in app.read_records(result.run_id).records if record.kind == 'case_start')
    log = next(record for record in reopen_records(request.record_path + '.actions.bfr').records
               if record.kind == 'case_start')
    retained = case.data['request']['original_request']
    assert retained == original == log.data['action']['request']['original_request']
    assert retained['protocol_input']['supplied_original_request'] == expected


def test_renamed_removed_and_authoritative_root(dropin, tmp_path, application_factory):
    root, directory = dropin
    descriptor(directory, protocol_id='opaque', aliases=['wire-bytes'])
    app, traces = application_factory()
    request = app.protocol_request('wire-bytes', 'offline.invalid', directory=root,
        seed=b'ABC', port=1234, no_receive=True, record_path=str(tmp_path / 'renamed.bfr'))
    assert request.conversation.plan.declaration_id == 'raw'
    assert app.submit(request).actions[0].transport.offered == b'ABC'
    with pytest.raises(ContractError, match='absent'):
        app.resolve_protocol('raw', root)
    shutil.rmtree(directory)
    with pytest.raises(ContractError, match='absent'):
        app.protocol_request('wire-bytes', 'offline.invalid', directory=root, seed=b'ABC', port=1234)
    with pytest.raises(ContractError, match='absent'):
        app.resolve_protocol('raw', tmp_path / 'missing')
    inspection = execute_arguments(['inspect','--directory',str(tmp_path / 'missing')],app)
    assert inspection['status'] == 'unavailable' and operation_exit_code(inspection) == 2
    # Removal affects directory selection, not the ordinary schema-free input.
    result = execute_arguments(['offline.invalid','--port','1234','--seed-hex','00ff',
        '--records',str(tmp_path / 'operator.bfr')], app)
    assert result.last_conversation.actions[0].transport.offered == b'\x00\xff'
    assert offers(traces) == [b'ABC', b'\x00\xff']


def test_defaults_explicit_overrides_and_receive(dropin, tmp_path, application_factory):
    root, directory = dropin
    descriptor(directory, defaults={'port':2345,'timeout':7,'pre_delay':2,'post_delay':4})
    app, traces = application_factory(stream_options={'reads': (b'OK',)})
    default = app.protocol_request('raw','offline.invalid',directory=root,seed=b'D',
        record_path=str(tmp_path / 'default.bfr'))
    assert (default.transport.port,default.transport.timeout,default.transport.pre_delay,default.transport.post_delay) == (2345,7,2,4)
    assert app.submit(default).actions[0].transport.received == b'OK'
    argv = ['tcp-raw','offline.invalid','--declaration-dir',str(root),'--seed-hex','45',
        '--port','3456','--timeout','8','--tcp-spacing','1','--tcp-pre-delay','3','--tcp-post-delay','5',
        '--receive-cap','10','--receive-deadline','2','--records',str(tmp_path / 'override.bfr')]
    config = resolve_configuration(argv,app)
    assert (config.request.transport.port,config.request.transport.timeout,config.request.transport.pre_delay,
            config.request.transport.post_delay) == (3456,8,3,5)
    assert config.request.conversation.plan.actions[0].receive == ReceiveRequest(cap=10,deadline=2)
    assert execute_arguments(argv,app).outcome == 'completed'
    assert ('sleep',2) in traces[0][0] and ('sleep',4) in traces[0][0]
    assert ('sleep',3) in traces[1][0] and ('sleep',5) in traces[1][0]


def test_prepared_plan_and_stage_conflicts_are_pretraffic(dropin, tmp_path, application_factory):
    root, directory = dropin
    from bytefault.core.contracts import ResponseField, ResponseEdge
    app, traces = application_factory(stream_options={'reads': (b'\x01B',)})
    preparation = tuple(ConversationAction('p'+str(i), bytes([i]), 'P'+str(i)) for i in range(1, 6))
    plan = PassivePlan('neutral',1,(ConversationAction('setup',b'10','S0',
        receive=ReceiveRequest(cap=2, deadline=3), response_fields=(ResponseField('flag',0,1),),
        edges=(ResponseEdge(b'\x01','p1','positive','flag'),)), *preparation,
        ConversationAction('one',b'ABC','S1'), ConversationAction('two',b'DEF','S1')),
        ('S0','S1',*(a.stage_id for a in preparation)))
    write_json(directory / 'declaration.json', app.export_declaration(plan))
    assert select_actions(plan,stage='S0') == ('setup',)
    with pytest.raises(ContractError, match='ambiguous_action'):
        select_actions(plan,stage='S1')
    row = PreparedRow('prepared',1,(PreparedContribution('C',b'Z',SourceInvocation('S','literal')),),
        (Placement('P','C','two','overwrite',1),))
    conversation = ConversationRequest(plan,row,('two',),'prepared-run','case','conversation')
    request = app.protocol_request('tcp-raw','offline.invalid',directory=root,conversation=conversation,
        stage='S1',selected_actions=('two',),port=1234,record_path=str(tmp_path / 'prepared.bfr'))
    argv = ['raw','offline.invalid','--declaration-dir',str(root),'--port','1234','--request-json',
        json.dumps(app.export_request(replace(conversation,run_id='cli-prepared'))),'--fuzz-stage','S1',
        '--action','two','--records',str(tmp_path / 'cli-prepared.bfr')]
    assert execute_arguments(argv,app).outcome == 'completed'
    assert app.submit(request).outcome == 'completed'
    assert offers(traces) == [b'10',*(a.seed for a in preparation),b'ABC',b'DZF'] * 2
    cli_state = next(r.data.result.response_interpretation for r in app.read_records('cli-prepared').records
                     if r.kind == 'action_result')
    assert cli_state.fields[0].data == b'\x01' and cli_state.target == 'p1'
    count = len(traces)
    for kwargs, code in (({'seed':b'X'},'ambiguous_action'),
        ({'conversation':replace(conversation,plan=replace(plan,declaration_id='different'))},'conflicting_plan'),
        ({'conversation':conversation,'stage':'S0'},'conflicting_selection'),
        ({'conversation':conversation,'selected_actions':('one',)},'conflicting_selection'),
        ({'conversation':replace(conversation,selected_actions=()),'stage':'S1'},'conflicting_selection')):
        with pytest.raises(ContractError) as caught:
            app.protocol_request('raw','offline.invalid',directory=root,port=1234,**kwargs)
        assert caught.value.code == code
    assert len(traces) == count
    info = execute_arguments(['raw','offline.invalid','--declaration-dir',str(root),'--list-stages'],app)
    assert info.status == 'available' and info.request is None
    assert info.resolved['inspection']['stages'][1]['actions'] == ('one','two')
    with pytest.raises(ContractError,match='ambiguous_action'):
        execute_arguments(['configure','raw','offline.invalid','--declaration-dir',str(root),
            '--fuzz-stage','S1','--gen-field','@0:list:ff'],app)
    with pytest.raises(ContractError,match='conflicting_plan'):
        execute_arguments([*argv[:argv.index('--request-json')+1],
            json.dumps(app.export_request(replace(conversation,plan=replace(plan,declaration_id='other'))))],app)


@pytest.mark.parametrize('change,code', [
    ({'format_version':2},'unsupported_version'), ({'transport':'udp'},'unsupported_transport'),
    ({'aliases':['RAW']},'duplicate_identity'), ({'declaration':'missing.json'},'malformed'),
    ({'declaration':'../outside.json'},'invalid_reference'), ({'declaration':'C:/outside.json'},'invalid_reference'),
    ({'defaults':{'port':True}},'invalid'), ({'defaults':{'timeout':float('inf')}},'invalid'),
    ({'surprise':True},'unsupported_field')])
def test_descriptor_refusals_before_any_adapter(dropin, application_factory, change, code):
    root, directory = dropin
    descriptor(directory, **change)
    app, traces = application_factory()
    with pytest.raises(ContractError) as caught:
        execute_arguments(['raw','offline.invalid','--declaration-dir',str(root),'--port','1234','--seed-hex','ff'],app)
    assert caught.value.code == code
    assert str(directory) in caught.value.path and not traces


def test_duplicate_capability_collision_and_pending_dirs(dropin, application_factory):
    root, directory = dropin
    app, traces = application_factory()
    original = (directory / 'protocol.json').read_text(encoding='utf-8')
    for file, text, code in ((directory / 'protocol.json', original.replace('"tcp"','"tcp", "transport":"tcp"'),'duplicate_field'),
        (directory / 'declaration.json','{"declaration_id":"bad","version":1,"actions":[{"action_id":"1","seed_hex":""}],'
            '"required_capabilities":[{"name":"unknown"}]}','unsupported_capability')):
        saved = file.read_text(encoding='utf-8')
        file.write_text(text,encoding='utf-8')
        with pytest.raises(ContractError) as caught:
            app.resolve_protocol('raw',root)
        assert caught.value.code == code
        file.write_text(saved,encoding='utf-8')
    second = root / 'another'
    shutil.copytree(directory,second)
    descriptor(second,protocol_id='other',aliases=['TCP-RaW'])
    with pytest.raises(ContractError,match='duplicate_identity'):
        app.resolve_protocol('raw',root)
    shutil.rmtree(second)
    (root / 'unconverted').mkdir()
    (root / 'unconverted' / '__init__.py').write_text('raise AssertionError("imported")',encoding='utf-8')
    (root / '__pycache__').mkdir()
    found = app.discover_protocols(root)
    assert len(found.entries) == 1 and found.pending_directories == (str(root / 'unconverted'),)
    assert not traces
    with pytest.raises(ContractError) as caught:
        app.discover_protocols([])
    assert caught.value.path == 'protocol.root'


@pytest.mark.parametrize('data,code', [
    ('{','malformed'),
    ({'declaration_id':'raw','version':2,'actions':[{'action_id':'a','seed_hex':''}]},'unsupported_version'),
    ({'declaration_id':'raw','version':1,'actions':[{'action_id':'a','seed_hex':'xx'}]},'malformed'),
    ('{"declaration_id":"raw","version":1,"actions":[{"action_id":"a","seed_hex":"",'
        '"receive":{"requested":true,"cap":1,"cap":2}}]}','duplicate_field')])
def test_referenced_declaration_failures(dropin,application_factory,data,code):
    root,directory = dropin
    (directory / 'declaration.json').write_text(data if isinstance(data,str) else json.dumps(data),encoding='utf-8')
    app,traces = application_factory()
    with pytest.raises(ContractError) as caught:
        app.protocol_request('raw','offline.invalid',directory=root,seed=b'ABC',port=1234)
    assert caught.value.code == code and not traces


def test_current_shared_api_invalid_inputs_are_attributed(dropin,application_factory):
    root,directory = dropin
    app,traces = application_factory()
    for kwargs in ({'seed':'ABC'}, {'seed':b'ABC','port':False}, {'seed':b'ABC','timeout':float('nan')},
                   {'seed':b'ABC','original_request':[]}, {'seed':b'ABC','receive':{}},
                   {'seed':b'ABC','selected_actions':['outbound']}):
        with pytest.raises(ContractError):
            app.protocol_request('raw','offline.invalid',directory=root,**{'port':1234,**kwargs})
    with pytest.raises(ContractError,match='required'):
        app.protocol_request('raw','offline.invalid',directory=root,seed=b'')
    assert not traces


def test_empty_prepared_selection_never_becomes_an_iteration(dropin,tmp_path,application_factory):
    root,directory = dropin
    app,traces = application_factory()
    plan = app.resolve_protocol('raw',root).entry.plan
    conversation = ConversationRequest(plan,PreparedRow('setup-only',1),(),
        'setup-only','case','conversation')
    assert select_actions(plan,()) == ()
    with pytest.raises(ContractError,match='unknown_action'):
        app.protocol_request('raw','offline.invalid',directory=root,conversation=conversation,
            port=1234,record_path=str(tmp_path / 'setup-only.bfr'))
    with pytest.raises(ContractError,match='conflicting_selection'):
        app.protocol_request('raw','offline.invalid',directory=root,conversation=conversation,port=1234,stage='send')
    assert not traces


def test_root_forwarding_uses_actual_directory(dropin,tmp_path,application_factory,capsys,monkeypatch):
    root,directory = dropin
    path = RAW.parents[3] / 'bytefault.py'
    spec = importlib.util.spec_from_file_location('raw_root',path)
    entry = importlib.util.module_from_spec(spec); spec.loader.exec_module(entry)
    app,traces = application_factory()
    argv = ['fuzz','tcp-raw','offline.invalid','--','--declaration-dir',str(root),'--port','1234',
        '--seed-hex','00ff80414243','--no-ui','--no-recv','--health-check-mode','disabled','--records',str(tmp_path / 'root.bfr')]
    result = entry.resolve_arguments(argv,app)
    assert result.outcome == 'completed'
    assert app.read_records(result.run_id).records[0].data['request']['original_request']['argv'] == tuple(argv)
    import bytefault.fuzzers.cli as cli
    monkeypatch.setattr(cli,'Application',lambda:app)
    assert entry.main(argv) == 0
    assert offers(traces) == [b'\x00\xff\x80ABC'] * 2
    assert 'completed' in capsys.readouterr().out


def test_public_fuzz_command_keeps_schema_as_protocol_identity(dropin,tmp_path,application_factory):
    from bytefault import cli as public

    root,directory=dropin
    descriptor(directory,protocol_id='schema',aliases=[])
    app,traces=application_factory()
    argv=['fuzz','schema','inspect','--declaration-dir',str(root),'--seed-hex','52',
          '--port','1234','--no-recv','--no-ui','--health-check-mode','disabled',
          '--records',str(tmp_path/'reserved.bfr')]
    result=public.execute_arguments(argv,app)
    assert result.outcome=='completed' and offers(traces)==[b'\x52']
    start=next(record for record in app.read_records(result.run_id).records if record.kind=='case_start')
    assert start.data['request']['original_request']['protocol_input']['source']['protocol_id']=='schema'

    schema=public.execute_arguments(['schema'],app)
    assert schema['version']==1 and offers(traces)==[b'\x52']
