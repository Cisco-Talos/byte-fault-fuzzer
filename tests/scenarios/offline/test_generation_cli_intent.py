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

"""Exact CLI option intent through guarded ordinary packet execution."""
import json

import pytest

from bytefault.core.contracts import ContractError
from bytefault.core.records import encode_value
from bytefault.core.storage import reopen_records
from bytefault.fuzzers.cli import build_parser, execute_arguments, resolve_configuration


def arguments(tmp_path, *options):
    return ['offline.invalid', '--port', '1234', '--seed-hex', '414243', '--no-ui', '--no-recv',
            '--records', str(tmp_path / 'case.bfr'), '--health-check-mode','disabled', *options]


def paired():
    return ['--target', 'byte:0', '--mask', '0x41-0x42',
            '--target2', 'byte:1', '--mask2', '0x31-0x32']


def configuration():
    return {'sources': (
        {'source_id': 'X', 'kind': 'list', 'options': {'payloads': (b'A', b'B')}},
        {'source_id': 'Y', 'kind': 'list', 'options': {'payloads': (b'1', b'2')}}),
        'sets': ({'set_id': 'X', 'source_id': 'X'}, {'set_id': 'Y', 'source_id': 'Y'}),
        'positions': ({'position_id': 'X', 'set_id': 'X', 'operation': 'overwrite', 'offset': 0},
                      {'position_id': 'Y', 'set_id': 'Y', 'operation': 'overwrite', 'offset': 1}),
        'strategy': 'zip'}


def offers(traces):
    return [step[1] for trace, _, _ in traces for step in trace if step[0] == 'offer']


@pytest.mark.parametrize('target,placement', (
    ('body', {'operation': 'replace', 'field_id': 'body'}),
    ('raw', {'operation': 'replace', 'offset': 0, 'end': 'seed'}),
    ('@1-3', {'operation': 'replace', 'offset': 1, 'end': 3}),
    ('@append', {'operation': 'append'})))
def test_missing_protocol_retains_resolved_generation_positions(
        tmp_path, application_factory, target, placement):
    app, traces = application_factory()
    config = resolve_configuration(['unavailable-protocol', 'offline.invalid',
        '--records', str(tmp_path / 'case.bfr'), '--gen-field', target + ':list:5a',
        '--generation-limit', '1'], app)
    assert config.status == 'pending' and config.request is None
    assert any(item.owner == 'Passive declarations' and item.options == ('protocol',)
               for item in config.pending)
    position, = config.generation['positions']
    assert {key: position[key] for key in placement} == placement
    assert not traces and not tuple(tmp_path.iterdir())


@pytest.mark.parametrize('options', (
    ('--gen-field', '@3-1:list:5a'), ('--gen-field', '@bad:list:5a'),
    ('--generation-limit', '1'), ('--datasets-json', '{}')))
def test_invalid_placement_or_source_only_options_refuse_without_preparation(
        tmp_path, application_factory, options):
    app, traces = application_factory()
    with pytest.raises(ContractError) as caught:
        resolve_configuration(arguments(tmp_path, *options), app)
    assert caught.value.path == 'cli.configuration' and caught.value.code == 'invalid'
    assert not traces and not app._preparations and not tuple(tmp_path.iterdir())


def test_named_encoding_cli_api_and_copied_fresh_keep_action_context(tmp_path, application_factory):
    from dataclasses import replace
    from bytefault.application import SavedStepIntent
    from bytefault.core.contracts import (PassivePlan, ConversationAction, ConversationRequest, PreparedRow,
        PreparedContribution, SourceInvocation, Placement, FieldLocation, Calculation, ReceiveRequest,
        ResponseField, ResponseEdge)
    from bytefault.fuzzers.inputs import request_to_data
    app, traces = application_factory(stream_options={'reads': (b'\x01B',)})
    setup = ConversationAction('setup', b'S', receive=ReceiveRequest(cap=2, deadline=3),
        response_fields=(ResponseField('flag', 0, 1),),
        edges=(ResponseEdge(b'\x01', 'A', 'positive', 'flag'),))
    a = ConversationAction('A', b'\0\0ABCDxy!', fields=(FieldLocation('length', 0, 2),
        FieldLocation('body', 2, 4), FieldLocation('second', 6, 2, variable=True)))
    b = ConversationAction('B', b'\0\0UVWz?', fields=(FieldLocation('length', 0, 2),
        FieldLocation('body', 2, 3, variable=True), FieldLocation('second', 5, 1)))
    plan = PassivePlan('neutral-fields', 1, (setup, a, b))
    row = PreparedRow('base', 1, (PreparedContribution('last', b'\xff\xff', SourceInvocation('last', 'literal')),),
        final_overrides=(Placement('last', 'last', 'B', 'overwrite', 0),))
    conversation = ConversationRequest(plan, row, ('A', 'B'), 'named', 'case', 'conversation', repair=True,
        calculations=tuple(Calculation('length-' + key, key, 'payload_length', size=2,
            field_id='length', payload_offset=2) for key in ('A', 'B')))
    root = tmp_path / 'external'
    directory = root / 'moved-neutral'
    directory.mkdir(parents=True)
    (directory / 'protocol.json').write_text(json.dumps({'format_version': 1, 'protocol_id': 'raw',
        'transport': 'tcp', 'declaration': 'declaration.json'}), encoding='utf-8')
    (directory / 'declaration.json').write_text(json.dumps(app.export_declaration(plan)), encoding='utf-8')

    def arguments_for(name, extra=()):
        return ['raw', 'offline.invalid', '--declaration-dir', str(root), '--port', '1234', '--no-ui',
            '--health-check-mode', 'disabled', '--records', str(tmp_path / (name + '.bfr')),
            '--request-json', json.dumps(request_to_data(replace(conversation, run_id=name))),
            '--target', 'body', '--mask', '01-02', '--start', '02',
            '--target2', 'second', '--mask2', '03-04', '--exclude2', '03', '--start2', '04',
            '--base', 'body=4142', '--base', 'second=58595a', '--pad-byte', 'cc', *extra]

    argv = arguments_for('named')
    config = resolve_configuration(argv, app)
    assert config.status == 'available' and not traces
    assert len(config.generation['sources']) == len(config.generation['sets']) == 2
    assert config.generation['strategy'] == 'cartesian'
    result = execute_arguments(argv, app)
    expected = [b'S', bytes.fromhex('000802cc414204595a21'), bytes.fromhex('ffff024204595a3f')]
    assert result.outcome == 'completed' and offers(traces) == expected
    assert result.prepared_cases == 1 and result.fuzz_tests == 2
    start = next(r for r in app.read_records(result.run_id).records if r.kind == 'case_start')
    current = start.data.request
    selections = current.row.selection.bounds.per_action_selection
    assert selections['A'].unmodified_seed == bytes.fromhex('0000cccc414258595a21')
    assert selections['B'].unmodified_seed == bytes.fromhex('0000414258595a3f')
    encoded = [c for c in current.row.contributions if c.mutators]
    assert [c.mutators[-1].options.resolved_context.action_id for c in encoded] == ['A', 'A', 'B', 'B']
    assert [c.mutators[-1].options.resolved_context.width for c in encoded] == [4, 3, 2, 1]
    assert [c.source_result.data for c in encoded] == [b'\x02', b'\x04', b'\x02', b'\x04']
    assert current.original_request.resolved_options.base_values.body == b'AB'
    assert current.original_request.generation.configuration == config.generation
    parity = replace(config.request, conversation=replace(config.request.conversation, run_id='callable'),
                     record_path=str(tmp_path / 'callable.bfr'))
    assert app.submit(parity).outcome == 'completed'
    assert offers(traces)[3:] == expected

    portable = app.export_case(config.request.record_path, start.record_id)
    copied = tmp_path / 'copied.case.json'
    copied.write_text(json.dumps(portable), encoding='utf-8')
    for mode, reapply, wanted in (('literal', False, expected), ('fresh_dynamic', True, expected),
            ('fresh_dynamic', False, [b'S', bytes.fromhex('0003020421'), bytes.fromhex('ffff02043f')])):
        client, replay_traces = application_factory(stream_options={'reads': (b'\x01C',)})
        steps = tuple(SavedStepIntent(key, mode if mode != 'literal' else 'recorded', reapply)
                      for key in ('A', 'B'))
        replay = client.import_case(json.loads(copied.read_text(encoding='utf-8')), mode=mode, steps=steps,
            record_path=str(tmp_path / (mode + str(reapply) + '.bfr')))
        actual = client.submit(replay)
        assert actual.outcome == 'completed' and offers(replay_traces) == wanted
        assert actual.actions[0].transport.received == b'\x01C'
        assert actual.actions[0].response_meaning == 'positive'
        if reapply:
            values = [c for c in replay.conversation.row.contributions if c.mutators]
            assert [c.mutators[-1].options['resolved_context']['action_id'] for c in values] == ['A','A','B','B']
        assert all(stream.closed for _, stream, _ in replay_traces)

    # Explicit fill uses nominal fixed guidance, variable base extent, and both
    # selected independent iterators; it does not silently borrow A's context.
    filled = execute_arguments(arguments_for('fill', ('--field-same',)), app)
    assert [a.transport.offered for a in filled.last_conversation.actions] == [b'S',
        bytes.fromhex('00080202020204040421'), bytes.fromhex('ffff0202043f')]


def test_retained_prefix_baselines_random_order_and_copied_derivation(tmp_path, application_factory):
    from dataclasses import replace
    from pathlib import Path
    from bytefault.application import SavedStepIntent
    from bytefault.core.contracts import (PassivePlan, ConversationAction, ConversationRequest, PreparedRow,
        PreparedContribution, SourceInvocation, Placement, FieldLocation, Calculation)
    from bytefault.fuzzers.inputs import request_to_data
    app, traces = application_factory()
    root = tmp_path / 'declarations'; directory = root / 'neutral'; directory.mkdir(parents=True)
    def run(name, seed, variable, options, *, request=None):
        plan = PassivePlan('prefix', 1, (ConversationAction('send', seed,
            fields=(FieldLocation('payload', 0, len(seed), variable=variable),)),))
        (directory / 'protocol.json').write_text(json.dumps({'format_version':1, 'protocol_id':'raw',
            'transport':'tcp', 'declaration':'declaration.json'}), encoding='utf-8')
        (directory / 'declaration.json').write_text(json.dumps(app.export_declaration(plan)), encoding='utf-8')
        common = ['offline.invalid', '--port','1234','--no-ui','--no-recv','--health-check-mode','disabled',
            '--records',str(tmp_path / (name + '.bfr'))]
        argv = ([*common, '--request-json', json.dumps(request_to_data(request))] if request else
            ['raw', *common, '--declaration-dir',str(root)])
        argv += ['--prefix','50', *options]
        config = resolve_configuration(argv, app)
        before = len(offers(traces))
        result = execute_arguments(argv, app)
        assert result.outcome == 'completed'
        start = next(r for r in app.read_records(result.run_id).records if r.kind == 'case_start')
        return offers(traces)[before:], config, result, start
    offset = ['--target','offset','--offset','1','--fuzz-length','1','--mask','5a']
    packets, config, result, start = run('offset', b'ABC', True, offset)
    assert packets == [b'PZBC'] and 'prefix' not in config.resolved['inactive_options']
    assert start.data.request.row.selection.bounds.per_action_selection['send'].unmodified_seed == b'PABC'
    assert start.data.request.row.contributions[0].data == b'P'
    opaque = ConversationRequest(PassivePlan('opaque',1,(ConversationAction('send',b'ABC'),)),
        PreparedRow('base',1),('send',),'opaque','case','conversation')
    packets, _, opaque_result, _ = run('opaque', b'', True, offset, request=opaque)
    assert packets == [b'PZBC'] and opaque_result.last_conversation.actions[0].materialized.final_fields == ()
    randomized = ['--random-len','1','--random-iter','1','--random-byte-range','90-90',
        '--target','offset','--offset','1','--offset-range','1-1','--offset-seed','7']
    assert run('random-offset', b'ABC', True, randomized)[0] == [b'PZBC']
    for name, packet, expected in (('whole', '414243', b'AZC'), ('empty', '', b'\0Z')):
        packets, config, _, _ = run(name, b'ABC', True, [*offset, '--base-packet',packet])
        assert packets == [expected] and 'prefix' in config.resolved['inactive_options']

    random = ['--random-len','1','--random-iter','1','--random-byte-range','88-88','--random-seed','5']
    for name, variable, options, expected in (
            ('fixed', False, random, b'P\0\0\0X'),
            ('variable', True, random, b'PX'),
            ('oversized', False, [*random, '--random-len','6'], b'PXXXXXX')):
        packets, config, result, start = run(name, b'ABCD', variable, options)
        assert packets == [expected]
        encoded = next(c for c in start.data.request.row.contributions if c.mutators)
        assert [m.options.kind for m in encoded.mutators] == ['field_encode', 'prepend']
        assert encoded.source_result.data == (b'XXXXXX' if name == 'oversized' else b'X')
        if name != 'fixed': continue
        portable = app.export_case(config.request.record_path, start.record_id)
        copied = tmp_path / 'random.case.json'; copied.write_text(json.dumps(portable), encoding='utf-8')
        Path(config.request.record_path).rename(tmp_path / 'random-original.bfr')
        for mode, reapply, wanted in (('literal', False, expected),
                ('fresh_dynamic', False, b'X'), ('fresh_dynamic', True, expected)):
            client, replay = application_factory()
            prepared = client.import_case(json.loads(copied.read_text(encoding='utf-8')), mode=mode,
                steps=(SavedStepIntent('send', 'recorded' if mode == 'literal' else mode, reapply),),
                record_path=str(tmp_path / ('random-' + mode + str(reapply) + '.bfr')))
            assert client.submit(prepared).outcome == 'completed' and offers(replay) == [wanted]
    packets, _, _, start = run('mutation', b'ABCD', False,
        ['--mutate-seed','58','--mutate-count','1','--mutate-rng-seed','7'])
    encoded = next(c for c in start.data.request.row.contributions if c.mutators)
    assert [m.options.kind for m in encoded.mutators] == ['mutate','prepend','field_encode']
    assert encoded.source_result.data == b'X' and packets == [encoded.data]

    # Prefix belongs to payload identity, including field-count consumers and
    # later named edits, not an insertion outside that field. Finals remain last.
    action = ConversationAction('send', b'\0AB!', fields=(FieldLocation('length',0,1),
        FieldLocation('payload',1,2,variable=True), FieldLocation('tail',3,1)))
    baseline_file = tmp_path / 'baseline.bin'; baseline_file.write_bytes(b'AB')
    row = PreparedRow('base',1,(
        PreparedContribution('file-base', b'AB', SourceInvocation('file-base','file',
            options={'path':str(baseline_file),'source_mode':'whole'})),
        PreparedContribution('last',b'?',SourceInvocation('last','literal'))),
        placements=(Placement('file-base','file-base','send','replace',field_id='payload'),),
        final_overrides=(Placement('last','last','send','append'),))
    request = ConversationRequest(PassivePlan('counted',1,(action,)),row,('send',),'counted','case','conversation',
        calculations=(Calculation('count','send','length',field_id='length',size=1,
            counts='field',counts_field='payload',required=True),))
    packets, config, result, start = run('counted', b'', True,
        ['--target','offset','--offset','2','--fuzz-length','1','--mask','5a'], request=request)
    assert packets == [b'\x03PZB!?']
    materialized = result.last_conversation.actions[0].materialized
    span = next(f for f in materialized.final_fields if f.field_id == 'payload')
    assert (span.offset, span.size) == (1,3)
    baseline = start.data.request.row
    assert next(c for c in baseline.contributions if c.source.mode == 'file').source.options['path'] == str(baseline_file)
    prefix_edit = next(p for p in baseline.placements if p.placement_id.startswith('offset-payload-prefix'))
    assert prefix_edit.include_in_field
    assert next(c for c in baseline.contributions if c.contribution_id == prefix_edit.contribution_id).data == b'P'
    portable = app.export_case(config.request.record_path,start.record_id)
    Path(config.request.record_path).rename(tmp_path / 'counted-original.bfr')
    baseline_file.write_bytes(b'XYZ')
    for mode, reapply, wanted in (('literal',False,b'\x03PZB!?'),
            ('fresh_dynamic',False,b'\x04PZYZ!?'),('fresh_dynamic',True,b'\x04PZYZ!?')):
        client, replay = application_factory()
        prepared = client.import_case(portable, mode=mode,
            steps=(SavedStepIntent('send','recorded' if mode == 'literal' else mode,reapply),),
            record_path=str(tmp_path / ('counted-' + mode + str(reapply) + '.bfr')))
        assert client.submit(prepared).outcome == 'completed' and offers(replay) == [wanted]
        if mode == 'fresh_dynamic':
            refreshed = next(c for c in prepared.conversation.row.contributions
                if c.source.options.get('path') == str(baseline_file))
            assert refreshed.data == b'XYZ'
    follow = replace(config.request, record_path=str(tmp_path / 'later-named.bfr'),
        conversation=replace(config.request.conversation,run_id='later-named'))
    from bytefault.application import ApplicationRequest
    follow = ApplicationRequest(follow.conversation,follow.transport,follow.record_path,follow.log_path)
    generation = {'sources':({'source_id':'s','kind':'list','options':{'payloads':(b'Q',)}},),
        'sets':({'set_id':'s','source_id':'s'},),
        'positions':({'position_id':'p','set_id':'s','operation':'replace','field_id':'payload'},)}
    actual, = app.submit_generated(follow, generation)
    assert actual.actions[0].transport.offered == b'\x01Q!?'


def test_named_encoding_extents_aliases_and_context_refusals(tmp_path, application_factory):
    from dataclasses import replace
    from itertools import islice
    from bytefault.core.contracts import (PassivePlan, ConversationAction, ConversationRequest,
        PreparedRow, PreparedContribution, SourceInvocation, Placement, FieldLocation)
    from bytefault.fuzzers.inputs import request_to_data
    from bytefault.generators.transforms import MutationPipeline, TransformSpec
    from bytefault.generators.field_encoding import FieldByteGenerator
    from bytefault.fuzzers.byte_mask import ByteMask
    app, traces = application_factory()
    # Logical metadata with the same name cannot turn off outbound fixed padding.
    action = ConversationAction('send', b'PabT', fields=(
        FieldLocation('body', 0, 1, buffer_id='logical', variable=True), FieldLocation('body', 1, 2)))
    def run(name, options, *, selected=action, row=None, count=1):
        before = len(offers(traces))
        value = ConversationRequest(PassivePlan('extent', 1, (selected,)), row or PreparedRow('base', 1),
            ('send',), name, 'case', 'conversation')
        argv = ['offline.invalid', '--port', '1234', '--no-ui', '--health-check-mode', 'disabled',
            '--records', str(tmp_path / (name + '.bfr')), '--request-json', json.dumps(request_to_data(value)), *options]
        configuration = resolve_configuration(argv, app)
        result = execute_arguments(argv, app)
        assert result.outcome == 'completed'
        actual = offers(traces)[before:]
        if count is not None:
            assert len(actual) == count
        return actual, result, configuration

    assert run('oversize', ['--target','body','--mask','0102','--base','body=4142434445'])[0] == [b'P\x01\x02CDET']
    assert run('wide-number', ['--target','body','--mask','010203','--base','body=4142434445'])[0] == [b'P\x01\x02\x03DET']
    assert run('nominal-fill', ['--target','body','--mask','0102','--base','body=4142434445','--field-same'])[0] == [b'P\x02\x02T']
    assert run('baseline-only', ['--base','body=01','--pad-byte','cc'])[0] == [b'P\xcc\x01T']
    assert run('inline-byte', ['--gen-field','body:list:ff','--pad-byte','cc'])[0] == [b'P\xcc\xffT']
    assert run('inline-integer', ['--gen-field','body:iter:1'])[0] == [b'P\x00\x01T']
    assert run('inline-fill', ['--gen-field','body:iter:1,fill'])[0] == [b'P\x01\x01T']
    edge_values, edge_result, edge_configuration = run('inline-edge', ['--gen-field','body:edge'], count=None)
    assert b'P\x01\x00T' in edge_values and b'P\xff\xffT' in edge_values
    assert all(len(packet) == 4 for packet in edge_values) and edge_result.fuzz_tests == len(edge_values)
    assert edge_configuration.generation['sources'][0]['options']['width'] == 2
    # A literal campaign applies named baseline intent to every actual case.
    cases = tuple(ConversationRequest(PassivePlan('literal-fields',1,(action,)), PreparedRow('base',1),
        ('send',), 'literal-' + str(i), 'case-' + str(i), 'conversation-' + str(i)) for i in (1,2))
    before = len(offers(traces))
    listed = execute_arguments(['offline.invalid','--port','1234','--no-ui','--health-check-mode','disabled',
        '--records',str(tmp_path / 'literal-fields.bfr'),'--campaign-json',
        json.dumps(encode_value({'cases':tuple(request_to_data(case) for case in cases)})),
        '--base','body=01','--pad-byte','cc'], app)
    assert offers(traces)[before:] == [b'P\xcc\x01T'] * 2
    assert tuple(item['state'] for item in listed.literal_items) == ('completed','completed')
    # Ordinary prepared baseline edits govern the actual tail, not the old seed.
    row = PreparedRow('changed', 1, (PreparedContribution('base', b'WXYZ', SourceInvocation('base','literal')),),
        (Placement('base','base','send','replace',field_id='body'),))
    assert run('prepared-tail', ['--target','body','--mask','01'], row=row)[0] == [b'P\x01XYZT']
    mixed, _, mixed_config = run('mixed-secondary', ['--target','byte:0','--mask','50',
        '--target2','body','--mask2','41','--field-same'])
    assert mixed == [b'PAAT'] and 'field_same' not in mixed_config.resolved.inactive_options

    for alias in ('payload', 'raw', 'normal'):
        empty = ConversationAction('send', b'PT', fields=(FieldLocation(alias,1,0,variable=True),))
        assert run('named-' + alias, ['--target',alias,'--mask','41'], selected=empty)[0] == [b'PAT']
        known = replace(empty, seed=b'PABT', fields=(FieldLocation(alias,1,2,variable=True),))
        for operation, expected in (('overwrite', b'P\xffBT'), ('replace', b'P\xffT'), ('insert', b'P\xffABT')):
            assert run(alias + '-' + operation, ['--gen-field',alias + ':list:ff,mode:' + operation],
                       selected=known)[0] == [expected]
        # Without a same-named field, these aliases still address the whole seed.
        plain = replace(known, fields=())
        assert run('whole-' + alias, ['--gen-field',alias + ':list:ff'], selected=plain)[0] == [b'\xff']
    empty_fixed = replace(empty, fields=(FieldLocation('normal',1,0),))
    assert run('fixed-empty-fill', ['--target','normal','--mask','41','--field-same'], selected=empty_fixed)[0] == [b'PT']
    # A 64-bit mask stays lazy through the current ordinary source path.
    actual, limited, _ = run('large-mask', ['--target','body','--mask','0-ffffffffffffffff',
        '--base','body=4142434445','--generation-limit','2'], count=2)
    assert actual == [b'P\x00BCDET', b'P\x01BCDET'] and limited.prepared_cases == 2
    helper = FieldByteGenerator(ByteMask(((0, 2**64 - 1),), ()), 2, b'ABCDE')
    assert helper.count() == 2**64 and list(islice(helper.generate(),2)) == [b'\x00BCDE',b'\x01BCDE']

    contexts = {'send': {'width':2,'base':b'AB'}}
    for malformed in (None, (), {'send':1}, {'send':{'width':2,'unexpected':1}}):
        with pytest.raises(ContractError, match='transform_configuration'):
            MutationPipeline((TransformSpec('encoding','field_encode', {'contexts':malformed}),))
    spec = TransformSpec('encoding','field_encode', {'contexts':contexts})
    for context in (None, 'send', {'action_id':'other'}):
        with pytest.raises(ContractError, match='missing_context') as caught:
            MutationPipeline((spec,)).apply(b'\x01', context=context)
        assert caught.value.failed_mutator.mutator_id == 'encoding'
    with pytest.raises(ContractError, match='contextual_filter_prefix'):
        MutationPipeline((spec, TransformSpec('filter','filter_empty')))
    result = MutationPipeline((TransformSpec('filter','filter_empty'), spec)).apply(b'\x01', context={'action_id':'send'})
    assert result.data == b'\x01B' and result.mutators[-1].options.resolved_context.action_id == 'send'
    for unsupported in ({'fill':True, 'mode':'bogus'}, {'mode':'pad', 'endian':'bogus'},
                        {'fill':True, 'pad_byte':256}):
        with pytest.raises(ContractError, match='transform_failed') as caught:
            MutationPipeline((TransformSpec('unsupported', 'field_encode', {
                'width':2, **unsupported}),)).apply(b'\x01')
        assert all(caught.value.failed_mutator.options[key] == value for key, value in unsupported.items())


@pytest.mark.parametrize('secondary_mask', [(), ('--mask2', '0x00-0xff')])
def test_secondary_exclusions_apply_to_effective_mask_and_history(
        tmp_path, application_factory, secondary_mask):
    app, traces = application_factory()
    argv = arguments(tmp_path, '--target', 'byte:0', '--mask', '0x41', '--target2', 'byte:1',
                     '--exclude2', '0x00', '--generation-limit', '1', *secondary_mask)
    normalized = resolve_configuration(argv, app)
    assert normalized.generation['sources'][1]['options']['excludes'] == (0,)
    execution = execute_arguments(argv, app)
    result = execution
    assert result.outcome == 'completed' and offers(traces) == [bytes.fromhex('410143')]
    stored = next(r for r in app.read_records(result.run_id).records if r.kind=='case_start').data['request']
    assert stored['original_request']['argv'] == tuple(argv)
    assert stored['original_request']['resolved_options']['mask2']['excludes'] == (0,)
    source = stored['row']['contributions'][1]
    assert source['source']['options']['excludes'] == (0,)
    assert source['source_result']['data'] == b'\x01'
    assert stored['row']['selection']['strategy'] == 'finite_product'
    assert all(stream.closed for _, stream, _ in traces)


@pytest.mark.parametrize('secondary_mask', [(), ('--mask2', '0x00-0xff')])
def test_all_secondary_values_excluded_give_empty_product(
        tmp_path, application_factory, secondary_mask):
    app, traces = application_factory()
    argv = arguments(tmp_path, '--target', 'byte:0', '--mask', '0x41', '--target2', 'byte:1',
        '--exclude2', ','.join(hex(value) for value in range(256)), '--generation-limit', '1', *secondary_mask)
    execution = execute_arguments(argv, app)
    assert execution.prepared_cases==execution.fuzz_tests==0 and offers(traces)==[]
    assert execution.preparation_summary['status']=='exhausted' and execution.preparation_summary['prepared_rows']==0
    records = reopen_records(str(tmp_path/'case.bfr.preparation.bfr')).records
    assert records[-1].data['summary']['status'] == 'exhausted'
    assert records[0].data['configuration']['sources'][1]['options']['excludes'] == tuple(range(256))


@pytest.mark.parametrize('secondary_mask', [(), ('--mask2', '0x00-0xff')])
@pytest.mark.parametrize('excluded', ['not-a-byte', '0x00-0x02'])
def test_secondary_exclusion_validation_preserves_csv_value_grammar(
        tmp_path, application_factory, secondary_mask, excluded):
    app, traces = application_factory()
    with pytest.raises(ContractError) as error:
        execute_arguments(arguments(tmp_path, '--target', 'byte:0', '--mask', '0x41', '--target2', 'byte:1',
                                    '--exclude2', excluded, *secondary_mask), app)
    assert error.value.path == 'cli.configuration' and error.value.code == 'invalid'
    assert not traces and not (tmp_path / 'case.bfr.preparation.bfr').exists()


@pytest.mark.parametrize('secondary_mask', [(), ('--mask2', '0x00-0xff')])
def test_secondary_start_and_exclusions_agree_with_default_or_explicit_mask(
        tmp_path, application_factory, secondary_mask):
    app, traces = application_factory()
    argv = arguments(tmp_path, '--target', 'byte:0', '--mask', '0x41', '--target2', 'byte:1',
                     '--exclude2', '0x00,0x01,0x02', '--start2', '0x03', '--generation-limit', '2', *secondary_mask)
    result = execute_arguments(argv, app)
    assert offers(traces) == [bytes.fromhex('410343'), bytes.fromhex('410443')]
    source = next(r for r in app.read_records(result.run_id).records if r.kind=='case_start').data['request']['row']['contributions'][1]
    assert source['source']['options']['start_value'] == 3
    assert source['source']['options']['excludes'] == (0, 1, 2)


@pytest.mark.parametrize('strategy_option,expected,strategy', [
    (('--gen-strategy', 'zip'), [b'A1C', b'B2C'], 'zip'),
    (('--gen-strat', 'zip'), [b'A1C', b'B2C'], 'zip'),
    (('--gen-strat=zip',), [b'A1C', b'B2C'], 'zip'),
    (('--gen-strategy', 'single'), [b'A1C', b'B1C', b'A1C', b'A2C'], 'retained_single'),
    (('--gen-strat=single',), [b'A1C', b'B1C', b'A1C', b'A2C'], 'retained_single')])
def test_admitted_strategy_spellings_select_exact_rows_and_original_intent(
        tmp_path, application_factory, strategy_option, expected, strategy):
    app, traces = application_factory()
    argv = arguments(tmp_path, *paired(), '--generation-limit', '4', *strategy_option)
    result = execute_arguments(argv, app)
    assert offers(traces) == expected and result.fuzz_tests == len(expected)
    for record in (r for r in app.read_records(result.run_id).records if r.kind=='case_start'):
        stored = record.data['request']
        assert stored['original_request']['argv'] == stored['original_request']['forwarded_argv'] == tuple(argv)
        assert stored['row']['selection']['strategy'] == strategy
    assert all(stream.closed for _, stream, _ in traces)


@pytest.mark.parametrize('strategy_option', [('--gen-strategy', 'cartesian'),
    ('--gen-strat', 'cartesian'), ('--gen-strat=cartesian',)])
def test_strategy_conflicts_refuse_before_preparation_for_all_admitted_spellings(
        tmp_path, application_factory, strategy_option):
    app, traces = application_factory()
    with pytest.raises(ContractError, match='disagrees'):
        execute_arguments(arguments(tmp_path, '--generation-json', json.dumps(encode_value(configuration())),
                                    *strategy_option), app)
    assert not traces and not (tmp_path / 'case.bfr.preparation.bfr').exists()


@pytest.mark.parametrize('source_options,override', [
    (('--generation-json',), ('--offset-sc', 'per_test')),
    (('--generation-json',), ('--offset-sc=per_test',)),
    (('--gen-field', '@1:random:1,count:1'), ('--random-content-sc=per_test',)),
    (('--target', 'byte:1'), ('--offset-sc=per_test',))])
def test_source_and_placement_checks_use_consumed_default_valued_options(
        tmp_path, application_factory, source_options, override):
    app, traces = application_factory()
    if source_options == ('--generation-json',):
        source_options = (*source_options, json.dumps(encode_value(configuration())))
    with pytest.raises(ContractError):
        execute_arguments(arguments(tmp_path, *source_options, *override), app)
    assert not traces and not (tmp_path / 'case.bfr.preparation.bfr').exists()


def test_parser_tracks_consumed_actions_without_defaults_and_retains_aliases():
    parser = build_parser()
    parsed = parser.parse_args(['offline.invalid', '--gen-strat=single', '-vvv', '-llocal.log',
                               '-kowned.key', '--ui'])
    assert parsed.gen_strategy == 'single' and parsed.verbose == 3
    assert parsed.log_file == 'local.log' and parsed.ssh_key == 'owned.key'
    assert parser.explicit_destinations == {'gen_strategy', 'verbose', 'log_file', 'ssh_key', 'ui'}
    assert 'explicit_destinations' not in vars(parsed)
    parser.parse_args(['offline.invalid'])
    assert parser.explicit_destinations == set()
    help_text = ' '.join(parser.format_help().split())
    assert 'journal-based interrupted recovery' in help_text
    assert 'unchanged inputs and matching random seeds' in help_text
    assert 'optional calculated-field repair' in help_text
    assert 'new requests default False' in help_text and 'header value summaries' in help_text
    assert 'requires root access' not in help_text and 'resume an interrupted --gen-field' not in help_text
