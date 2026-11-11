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

"""Actual shared source/parser -> ordinary engine/store vectors (class O)."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from bytefault.application import ApplicationRequest
from bytefault.core.contracts import (TransportRequest, PreparedRow, Placement,
    PreparedContribution, SourceInvocation, Calculation, ContractError)
from bytefault.core.storage import reopen_records, LocalRecordStore
from bytefault.core.records import encode_value, RequiredServiceSaveFailure
from bytefault.fuzzers.inputs import raw_request, positional_plan, request_to_data
from bytefault.fuzzers.cli import execute_arguments, resolve_configuration


def base(tmp_path, seed=b'ABC', *, name='run', plan=None, selected=None):
    conversation = raw_request(seed, original_request={'marker': 'exact-secret'})
    if plan is not None:
        conversation = replace(conversation, plan=plan, selected_actions=selected)
    conversation = replace(conversation, run_id=name, conversation_id='conversation', case_id='case')
    return ApplicationRequest(conversation, TransportRequest('offline.invalid', 1234, 10), str(tmp_path / (name + '.bfr')))


def config(values=(b'Z',), *, operation='overwrite', offset=1, end=None, strategy='single'):
    position = {'position_id': 'P', 'set_id': 'S', 'operation': operation}
    if operation != 'append':
        position['offset'] = offset
    if end is not None:
        position['end'] = end
    return {'sources': ({'source_id': 'source', 'kind': 'list', 'options': {'payloads': values}},),
        'sets': ({'set_id': 'S', 'source_id': 'source'},), 'positions': (position,), 'strategy': strategy}


def offered(traces):
    return [step[1] for trace, _, _ in traces for step in trace if step[0] == 'offer']


def cli_args(tmp_path, *extra):
    return ['offline.invalid', '--port', '1234', '--seed-hex', '414243',
            '--records', str(tmp_path / 'cli.bfr'), '--no-ui', '--no-recv', '--health-check-mode', 'disabled', *extra]


@pytest.mark.parametrize('operation', ('validate_generated', 'submit_generated'))
def test_ordinary_generated_operations_refuse_campaign_base(tmp_path, application_factory, operation):
    from bytefault.application import CampaignRequest
    app, traces = application_factory()
    ordinary = base(tmp_path)
    campaign = CampaignRequest(ordinary.conversation, ordinary.transport, ordinary.record_path)
    with pytest.raises(ContractError) as caught:
        getattr(app, operation)(campaign, config(), limit=1)
    assert caught.value.path == 'generation.base'
    assert caught.value.code == 'unsupported_request'
    assert not traces and not app._preparations
    assert not tuple(tmp_path.iterdir())


def test_shared_generated_campaign_remains_supported(tmp_path, application_factory):
    from bytefault.application import CampaignRequest
    from bytefault.monitoring import MonitoringConfig
    app, traces = application_factory()
    ordinary = base(tmp_path)
    campaign = CampaignRequest(ordinary.conversation, ordinary.transport, ordinary.record_path,
        generation=config(), monitoring_configuration=MonitoringConfig(health_check_mode='disabled'))
    result = app.submit(campaign)
    assert result.outcome == 'completed' and result.fuzz_tests == 1
    assert offered(traces) == [b'AZC']


@pytest.mark.parametrize('target,modifier,operation,end,expected', [
    ('@1', 'insert', 'insert', None, b'AZBC'),
    ('@1', 'overwrite', 'overwrite', None, b'AZC'),
    ('@1-3', 'replace', 'replace', 3, b'AZ')])
def test_generated_field_real_cli_and_callable(tmp_path, application_factory, target, modifier, operation, end, expected):
    app, traces = application_factory()
    args = cli_args(tmp_path, '--gen-field', target + ':list:5a,mode:' + modifier)
    parsed = resolve_configuration(args, app)
    assert parsed.status == 'available' and not parsed.pending
    execution = execute_arguments(args, app)
    assert execution.selected_cases == execution.fuzz_tests == execution.prepared_variants == 1
    assert offered(traces) == [expected]
    record = next(r for r in app.read_records(execution.run_id).records if r.kind == 'case_start')
    original = record.data['request']['original_request']
    assert original['argv'] == tuple(args)
    assert original['generation']['configuration']['sources'][0]['options']['payloads'] == (b'Z',)
    assert record.data['request']['row']['contributions'][0]['source_result']['data'] == b'Z'
    request = next(app.generate(base(tmp_path, name='api'), config(operation=operation, end=end)))
    assert app.import_request(app.export_request(request.conversation)) == request.conversation
    assert app.validate(request)['materialized'][0].final_bytes == expected
    app.submit(request)
    assert offered(traces) == [expected, expected]
    # Caller closes an inspected prefix explicitly.
    app.close()


def test_selected_raw_directory_whole_seed_is_baseline(tmp_path, application_factory):
    from bytefault.core.contracts import (PassivePlan, ConversationAction, FieldLocation, SelectionIntent, freeze)
    app, traces = application_factory()
    args = ['raw', *cli_args(tmp_path), '--gen-field', '@1:list:5a,mode:overwrite']
    result = execute_arguments(args, app)
    assert offered(traces) == [b'AZC']
    request = next(r for r in app.read_records(result.run_id).records if r.kind == 'case_start').data['request']
    assert request['plan']['actions'][0]['seed'] == b'ABC'
    assert request['original_request']['protocol_input']['seed'] == b'ABC'

    # Normalize the recognized Raw row before named context or base edits, not
    # only later inside generated preparation for raw coordinates.
    root = tmp_path / 'declarations'
    directory = root / 'neutral'; directory.mkdir(parents=True)
    plan = PassivePlan('named-seed', 1, (ConversationAction('send', b'PABCDT',
        fields=(FieldLocation('body', 1, 4),)),))
    (directory / 'protocol.json').write_text(json.dumps({'format_version': 1, 'protocol_id': 'raw',
        'transport': 'tcp', 'declaration': 'declaration.json'}), encoding='utf-8')
    (directory / 'declaration.json').write_text(json.dumps(app.export_declaration(plan)), encoding='utf-8')
    common = ['offline.invalid', '--port', '1234', '--no-ui', '--no-recv', '--health-check-mode', 'disabled']
    seed_file = tmp_path / 'seed.bin'; seed_file.write_bytes(b'P1234T')
    for name, extra, expected, baseline in (
            ('leading', ['--target', 'body', '--mask', '01'], b'P\x01234T', b'1234'),
            ('named-base', ['--target', 'body', '--mask', '01', '--base', 'body=5758595a'], b'P\x01XYZT', b'WXYZ'),
            ('inline', ['--gen-field', 'body:list:ff'], b'P\0\0\0\xffT', b'1234'),
            ('file-leading', ['--target', 'body', '--mask', '01'], b'P\x01234T', b'1234'),
            ('file-base', ['--target', 'body', '--mask', '01', '--base', 'body=5758595a'], b'P\x01XYZT', b'WXYZ')):
        if name.startswith('file-'):
            # The callable Raw input reads exact file bytes; no seed-file CLI flag
            # is invented. Retain the consumed file through its generic seam.
            bound = app.protocol_request('raw', 'offline.invalid', directory=str(root), port=1234,
                seed=seed_file.read_bytes(), no_receive=True, record_path=str(tmp_path / 'file-input.bfr'))
            conversation = replace(bound.conversation, input_files=(str(seed_file),))
            entry = [*common, '--request-json', json.dumps(request_to_data(conversation))]
        else:
            entry = ['raw', *common, '--declaration-dir', str(root), '--seed-hex', b'P1234T'.hex()]
        argv = [*entry, '--records', str(tmp_path / (name + '.bfr')), *extra]
        parsed = resolve_configuration(argv, app)
        transform = parsed.generation['sets'][0]['transforms'][-1]
        assert transform['options']['contexts']['send'] == {'width': 4, 'base': baseline}
        assert parsed.request.conversation.plan.actions[0].seed == b'P1234T'
        assert not parsed.request.conversation.row.final_overrides
        original = parsed.request.conversation.original_request.cli_input.seed_baseline_input
        assert original.plan == freeze(plan) and original.row.final_overrides[0].placement_id == 'whole-input'
        assert original.row.contributions[0].data == b'P1234T'
        before = len(offered(traces))
        result = execute_arguments(argv, app)
        assert result.outcome == 'completed' and offered(traces)[before:] == [expected]
        history = app.read_records(result.run_id)
        start = next(r for r in history.records if r.kind == 'case_start')
        current = start.data.request
        encoded = next(c for c in current.row.contributions if c.mutators)
        assert encoded.source_result.data == (b'\xff' if name == 'inline' else b'\x01')
        assert encoded.mutators[-1].options.resolved_context.base == baseline
        assert current.original_request.protocol_input.seed == b'P1234T'
        if name.startswith('file-'):
            assert current.input_files == (str(seed_file),)
        if name != 'file-base':
            continue
        portable = app.export_case(parsed.request.record_path, start.record_id)
        copied = tmp_path / 'copied-seeded.case.json'
        copied.write_text(json.dumps(portable), encoding='utf-8')
        Path(parsed.request.record_path).rename(tmp_path / 'retained-seeded.bfr')
        seed_file.unlink()
        for mode, reapply, wanted in (('literal', False, expected),
                ('fresh_dynamic', False, b'P\x01T'), ('fresh_dynamic', True, expected)):
            from bytefault.application import SavedCaseIntent, SavedStepIntent
            client, replay = application_factory()
            prepared = client.saved_case(SavedCaseIntent(str(copied), mode=mode,
                steps=(SavedStepIntent('send', 'recorded' if mode == 'literal' else mode, reapply),)),
                record_path=str(tmp_path / (mode + str(reapply) + '.bfr')))
            assert client.submit(prepared).outcome == 'completed'
            assert offered(replay) == [wanted]

    # Near matches retain caller-authored final authority after named base edits.
    for name, amend, wanted in (
            ('selection', lambda row: replace(row, selection=SelectionIntent(bounds={'custom': True})), b'P1234T'),
            ('append', lambda row: replace(row, final_overrides=(replace(row.final_overrides[0],
                operation='append', offset=None, end=None),)), b'P\x01XYZTP1234T')):
        bound = app.protocol_request('raw', 'offline.invalid', directory=str(root), port=1234,
            seed=b'P1234T', no_receive=True, record_path=str(tmp_path / (name + '.bfr')))
        conversation = replace(bound.conversation, row=amend(bound.conversation.row))
        argv = [*common, '--request-json', json.dumps(request_to_data(conversation)),
            '--records', bound.record_path, '--target', 'body', '--mask', '01', '--base', 'body=5758595a']
        parsed = resolve_configuration(argv, app)
        assert parsed.request.conversation.row.final_overrides == conversation.row.final_overrides
        before = len(offered(traces))
        assert execute_arguments(argv, app).outcome == 'completed'
        assert offered(traces)[before:] == [wanted]

    # Normalization belongs to generation, not ordinary literal/base-only input.
    argv = ['raw', *common, '--declaration-dir', str(root), '--seed-hex', b'P1234T'.hex(),
        '--records', str(tmp_path / 'no-generation.bfr'), '--base', 'body=5758595a']
    parsed = resolve_configuration(argv, app)
    assert parsed.generation is None and parsed.request.conversation.row.final_overrides
    before = len(offered(traces))
    assert execute_arguments(argv, app).outcome == 'completed'
    assert offered(traces)[before:] == [b'P1234T']


def test_near_match_final_override_is_preserved(tmp_path, application_factory):
    app, traces = application_factory()
    request = app.protocol_request('raw', 'offline.invalid', seed=b'ABC', port=1234,
                                   record_path=str(tmp_path / 'near.bfr'))
    row = request.conversation.row
    row = replace(row, final_overrides=(replace(row.final_overrides[0], operation='append', offset=None, end=None),))
    request = replace(request, conversation=replace(request.conversation, row=row))
    generated, = app.generate(request, config((b'Z',), operation='append'))
    app.submit(generated)
    assert offered(traces) == [request.conversation.plan.actions[0].seed + b'ZABC']


def test_plural_sources_transforms_one_actual_packet(tmp_path, application_factory):
    app, traces = application_factory()
    value = {'sources': (
        {'source_id': 'X', 'kind': 'random', 'options': {'min_len': 3, 'max_len': 3, 'count': 1,
            'seed': 13, 'byte_range': (88, 88), 'length_scope': 'sample_once', 'content_scope': 'per_test'}},
        {'source_id': 'Y', 'kind': 'list', 'options': {'payloads': (b'59',)}},
        {'source_id': 'Z', 'kind': 'file', 'options': {'path': str(tmp_path / 'Z')}}),
        'sets': (
            {'set_id': 'X', 'source_id': 'X', 'transforms': ({'mutator_id': 'encode-X', 'kind': 'hex_encode'},
                                                         {'mutator_id': 'hex-X', 'kind': 'hex_decode'})},
            {'set_id': 'Y', 'source_id': 'Y', 'transforms': ({'mutator_id': 'hex', 'kind': 'hex_decode'},)},
            {'set_id': 'Z', 'source_id': 'Z'}),
        'positions': (
            {'position_id': 'X', 'set_id': 'X', 'operation': 'replace', 'offset': 2, 'end': 4},
            {'position_id': 'Y', 'set_id': 'Y', 'operation': 'replace', 'offset': 8, 'end': 10},
            {'position_id': 'Z', 'set_id': 'Z', 'operation': 'append'}), 'strategy': 'zip'}
    # Independent explicit transforms produce the required XXX,Y,ZZ vector.
    (tmp_path / 'Z').write_bytes(b'ZZ')
    execution = app.submit_generated(base(tmp_path, b'U=aa;P=bb'), value)
    result, = execution
    assert offered(traces) == [b'U=XXX;P=YZZ']
    assert execution.summary['fuzz_sends'] == 1
    start = app.read_records(result.run_id).records[0].data['request']
    contributions = start['row']['contributions']
    assert tuple(c['data'] for c in contributions) == (b'XXX', b'Y', b'ZZ')
    assert contributions[0]['source_result']['data'] == b'XXX'
    assert contributions[0]['mutator_results'][0]['input_data'] == b'XXX'
    assert contributions[0]['mutator_results'][0]['output_data'] == b'585858'
    assert contributions[0]['mutator_results'][1]['output_data'] == b'XXX'
    assert {c['scope'] for c in contributions[0]['random_choices']} == {'sample_once', 'per_test'}
    assert (tmp_path / 'Z').read_bytes() == b'ZZ'


@pytest.mark.parametrize('strategy,expected', [
    ('zip', (b'a1', b'b2')),
    ('cartesian', (b'a1', b'a2', b'a3', b'b1', b'b2', b'b3')),
    ('single', (b'a1', b'b1', b'a1', b'a2', b'a3'))])
def test_strategy_real_multiple_rows(tmp_path, application_factory, strategy, expected):
    app, traces = application_factory()
    value = {'sources': ({'source_id': 'X', 'kind': 'list', 'options': {'payloads': (b'a', b'b')}},
                         {'source_id': 'Y', 'kind': 'list', 'options': {'payloads': (b'1', b'2', b'3')}}),
        'sets': ({'set_id': 'X', 'source_id': 'X'}, {'set_id': 'Y', 'source_id': 'Y'}),
        'positions': ({'position_id': 'X', 'set_id': 'X', 'operation': 'overwrite', 'offset': 0},
                      {'position_id': 'Y', 'set_id': 'Y', 'operation': 'overwrite', 'offset': 1}), 'strategy': strategy}
    args = cli_args(tmp_path, '--generation-json', json.dumps(encode_value(value)))
    execution = execute_arguments(args, app)
    assert offered(traces) == [value + b'C' for value in expected]
    assert execution.prepared_cases == execution.fuzz_tests == execution.executed_variants == len(expected)
    starts = [r for r in app.read_records(execution.run_id).records if r.kind == 'case_start']
    assert len({r.identity['case_id'] for r in starts}) == len(expected)
    for ordinal, start in enumerate(starts, 1):
        record = start.data['request']
        assert record['row']['ordinal'] == ordinal
        assert record['row']['selection']['dimension_order'] == ('X', 'Y')
        assert record['original_request']['generation']['configuration']['strategy'] == strategy


@pytest.mark.parametrize('strategy,expected', [
    ('one-position', (b'aB', b'bB', b'Aa', b'Ab')),
    ('broadcast', (b'aa', b'bb'))])
def test_explicit_shared_set_cli(tmp_path, application_factory, strategy, expected):
    app, traces = application_factory()
    value = config((b'a', b'b'), offset=0, strategy=strategy)
    value['positions'] = ({'position_id': 'X', 'set_id': 'S', 'operation': 'replace', 'offset': 0, 'end': 1},
                          {'position_id': 'Y', 'set_id': 'S', 'operation': 'replace', 'offset': 1, 'end': 2})
    args = cli_args(tmp_path, '--generation-json', json.dumps(encode_value(value)))
    result = execute_arguments(args, app)
    materials = [r.data['materialized'][0] for r in app.read_records(result.run_id).records if r.kind=='case_start']
    assert result.fuzz_tests == len(expected)
    assert offered(traces) == [v + b'C' for v in expected]
    if strategy == 'one-position':
        assert all(len(material['placements']) == 1 for material in materials)
    else:
        assert all(len({p['placement']['contribution_id'] for p in material['placements']}) == 1 for material in materials)


def test_one_position_inactive_insert_append_never_edits(tmp_path, application_factory):
    app, traces = application_factory()
    value = config((b'XXX',), operation='insert', offset=1, strategy='one-position')
    value['positions'] = (*value['positions'], {'position_id': 'tail', 'set_id': 'S', 'operation': 'append'})
    results = list(app.submit_generated(base(tmp_path), value))
    assert offered(traces) == [b'AXXXBC', b'ABCXXX']
    assert all(len(r.actions[0].materialized.placements) == 1 for r in results)


def test_generated_existing_calculation_and_final_precedence(tmp_path, application_factory):
    app, traces = application_factory()
    request = base(tmp_path, b'\x00\x01A')
    request = replace(request, conversation=replace(request.conversation, repair=True,
        calculations=(Calculation('length', '1', 'payload_length', 0, 2, 'big', 2),)))
    results = list(app.submit_generated(request, config((b'XYZ', b'W'), operation='append')))
    assert offered(traces) == [b'\x00\x04AXYZ', b'\x00\x02AW']
    assert all(r.actions[0].materialized.calculations == (('length', 'repaired'),) for r in results)
    app2, traces2 = application_factory()
    row = PreparedRow('base', 1, (PreparedContribution('final', b'\xff\xff', SourceInvocation('final', 'literal')),),
        final_overrides=(Placement('final', 'final', '1', 'overwrite', 0),))
    request = replace(request, record_path=str(tmp_path / 'final.bfr'), conversation=replace(request.conversation,
        run_id='final', row=row))
    list(app2.submit_generated(request, config(operation='append')))
    assert offered(traces2) == [b'\xff\xffAZ']


def test_random_scopes_multi_selected_sends_and_setup(tmp_path, application_factory):
    app, traces = application_factory()
    plan = positional_plan((b'setup', b'AAAAAA', b'BBBBBB'))
    value = {'sources': (
        {'source_id': 'held', 'kind': 'random', 'options': {'min_len': 1, 'max_len': 3, 'count': 3,
            'seed': 13, 'length_scope': 'sample_once', 'content_scope': 'per_test'}},
        {'source_id': 'fresh', 'kind': 'random', 'options': {'min_len': 1, 'max_len': 3, 'count': 3,
            'seed': 22, 'length_scope': 'per_test', 'content_scope': 'sample_once'}}),
        'sets': ({'set_id': 'held', 'source_id': 'held', 'transforms': ({'mutator_id': 'mutate', 'kind': 'mutate',
            'options': {'seed': 14, 'operation': 'flip_byte', 'scopes': {'index': 'sample_once'}}},)},
                 {'set_id': 'fresh', 'source_id': 'fresh'}),
        'positions': ({'position_id': 'held', 'set_id': 'held', 'operation': 'overwrite', 'offset': 0,
            'offset_range': (0, 2), 'offset_seed': 55, 'offset_scope': 'sample_once'},
            {'position_id': 'fresh', 'set_id': 'fresh', 'operation': 'append'}), 'strategy': 'zip'}
    results = list(app.submit_generated(base(tmp_path, plan=plan, selected=('2', '3')), value))
    assert len(results) == 3 and len(offered(traces)) == 9
    held_lengths, held_offsets, content_draws, reservoir = [], [], [], []
    for result in results:
        assert result.actions[0].iteration_id is None
        assert result.actions[0].transport.offered == b'setup'
        request = next(r for r in app.read_records(result.run_id).records if r.kind == 'case_start').data['request']
        for contribution in request['row']['contributions']:
            choices = contribution['random_choices']
            expected = request['conversation_id'] + ':' + next(p['action_id'] for p in request['row']['placements']
                         if p['contribution_id'] == contribution['contribution_id'])
            assert all(c['iteration_id'] == expected for c in choices if c['scope'] == 'per_test')
            if contribution['set_id'] == 'held':
                held_lengths.extend(c['resolved'] for c in choices if c['option'] == 'length')
                content_draws.append(contribution['source_result']['data'])
            else:
                reservoir.append(contribution['source_result']['data'])
        held_offsets.extend(p['offset'] for p in request['row']['placements'] if p['random_choices'])
    assert len(set(held_lengths)) == len(set(held_offsets)) == 1
    assert len(set(content_draws)) > 1
    assert all(a.startswith(b) or b.startswith(a) for a in reservoir for b in reservoir)


def test_disjoint_actions_dimension_and_baseline_history(tmp_path, application_factory):
    app, traces = application_factory()
    plan = positional_plan((b'AA', b'BB'))
    value = {'sources': ({'source_id': 'Y', 'kind': 'list', 'options': {'payloads': (b'1', b'2')}},
                         {'source_id': 'X', 'kind': 'list', 'options': {'payloads': (b'a', b'b')}}),
        'sets': ({'set_id': 'Y', 'source_id': 'Y'}, {'set_id': 'X', 'source_id': 'X'}),
        'positions': ({'position_id': 'Y', 'set_id': 'Y', 'operation': 'replace', 'offset': 0, 'end': 1, 'action_ids': ('2',)},
                      {'position_id': 'X', 'set_id': 'X', 'operation': 'replace', 'offset': 0, 'end': 1, 'action_ids': ('1',)}),
        'strategy': 'cartesian'}
    results = list(app.submit_generated(base(tmp_path, plan=plan, selected=('1', '2')), value))
    assert offered(traces) == [b'aA', b'1B', b'bA', b'1B', b'aA', b'2B', b'bA', b'2B']
    for result in results:
        row = app.read_records(result.run_id).records[0].data['request']['row']
        assert row['selection']['dimension_order'] == ('Y', 'X')
    shared = config((b'Z',), operation='replace', offset=0, end=1, strategy='one-position')
    shared['positions'] = (*shared['positions'], {'position_id': 'Q', 'set_id': 'S', 'operation': 'append'})
    request = base(tmp_path, name='baselines', plan=plan, selected=('1', '2'))
    generated = app.generate(request, shared)
    first = next(generated)
    selections = first.conversation.row.selection.bounds['per_action_selection']
    assert selections['1']['selection']['bindings'][0]['baseline'] == b'A'
    assert selections['2']['selection']['bindings'][0]['baseline'] == b'B'
    generated.close()


def test_filter_all_trailing_error_and_save_boundaries(tmp_path, application_factory, monkeypatch):
    app, traces = application_factory()
    value = config((b'#one', b'Z', b'#tail'))
    value['sets'][0]['transforms'] = ({'mutator_id': 'filter', 'kind': 'filter_comments'},)
    stream = app.submit_generated(base(tmp_path), value)
    assert len(list(stream)) == 1 and offered(traces) == [b'AZC']
    evidence = reopen_records(stream.prepared.path).records
    assert sum(r.kind == 'source_disposition' for r in evidence) == 2
    assert evidence[-1].kind == 'preparation_terminal'
    assert stream.summary['status'] == 'exhausted'
    all_filtered = config((b'#one', b'#two'))
    all_filtered['sets'][0]['transforms'] = value['sets'][0]['transforms']
    empty = app.submit_generated(base(tmp_path, name='empty'), all_filtered)
    assert list(empty) == [] and empty.summary['dispositions'] == 2
    assert empty.summary['prepared_rows'] == 0 and empty.summary['status'] == 'exhausted'
    broken = config((b'not hex',))
    broken['sets'][0]['transforms'] = ({'mutator_id': 'hex', 'kind': 'hex_decode'},)
    failed = app.submit_generated(base(tmp_path, name='bad'), broken)
    with pytest.raises(ContractError, match='mutators.hex'):
        next(failed)
    records = reopen_records(failed.prepared.path).records
    disposition = next(r.data['disposition'] for r in records if r.kind == 'source_disposition')
    assert disposition['source_result']['data'] == b'not hex'
    assert disposition['mutators'][-1]['mutator_id'] == 'hex'
    original = LocalRecordStore.append
    def save(store, kind, identity, data):
        if kind == 'prepared_row':
            raise OSError('controlled preparation save failure')
        return original(store, kind, identity, data)
    monkeypatch.setattr(LocalRecordStore, 'append', save)
    guarded = app.submit_generated(base(tmp_path, name='save-fail'), config())
    before = len(offered(traces))
    with pytest.raises(RequiredServiceSaveFailure):
        next(guarded)
    assert len(offered(traces)) == before and guarded.summary['status'] == 'recording_failed'


def test_filtered_random_refresh_rejections_reach_exact_selected_sends_and_records(tmp_path, application_factory, monkeypatch):
    from bytefault.generators.random_bytes import RandomBytesGenerator
    draws = iter((b'A', b'#', b'B'))
    def sample(generator, *, length=None):
        data = next(draws)
        return data, (('length', (1, 1), 'per_test', 1), ('content', (0, 255), 'per_test', data))
    monkeypatch.setattr(RandomBytesGenerator, 'sample', sample)
    app, traces = application_factory()
    plan = positional_plan((b'SETUP', b'X=', b'Y='))
    value = config(operation='append', strategy='broadcast')
    value['sources'][0].update(kind='random', options={'min_len': 1, 'max_len': 1, 'count': 1})
    value['sets'][0]['transforms'] = ({'mutator_id': 'comment', 'kind': 'filter_comments'},)
    operation = app.submit_generated(base(tmp_path, plan=plan, selected=('2', '3')), value)
    result, = list(operation)
    assert offered(traces) == [b'SETUP', b'X=A', b'Y=B']
    assert operation.summary['prepared_rows'] == 1
    assert operation.summary['fuzz_sends'] == 2 and operation.summary['setup_sends'] == 1
    records = reopen_records(operation.prepared.path).records
    rejected = next(r.data['disposition'] for r in records if r.kind == 'source_disposition')
    assert rejected['source_result']['data'] == b'#'
    assert rejected['source_result']['index'] == 1
    assert rejected['source_result']['sample_id'] == '1:S:6:source:sample:2'
    request = next(r for r in app.read_records(result.run_id).records if r.kind == 'case_start').data['request']
    results = [c['source_result'] for c in request['row']['contributions']]
    assert [r['data'] for r in results] == [b'A', b'B']
    assert [r['sample_id'] for r in results] == ['1:S:6:source:sample:1', '1:S:6:source:sample:3']


def test_cancel_during_filtered_refresh_delivers_zero_partial_rows_or_offers(tmp_path, application_factory, monkeypatch):
    from bytefault.generators.random_bytes import RandomBytesGenerator
    draws = iter((b'A', b'#', b'#'))
    def sample(generator, *, length=None):
        data = next(draws)
        return data, (('content', (0, 255), 'per_test', data),)
    monkeypatch.setattr(RandomBytesGenerator, 'sample', sample)
    app, traces = application_factory()
    plan = positional_plan((b'X=', b'Y='))
    value = config(operation='append', strategy='broadcast')
    value['sources'][0].update(kind='random', options={'min_len': 1, 'max_len': 1, 'count': 1})
    value['sets'][0]['transforms'] = ({'mutator_id': 'comment', 'kind': 'filter_comments'},)
    operation = app.submit_generated(base(tmp_path, plan=plan, selected=('1', '2')), value)
    append, rejected = LocalRecordStore.append, []
    def save(store, kind, identity, data):
        reference = append(store, kind, identity, data)
        if kind == 'source_disposition':
            rejected.append(data['disposition'])
            if len(rejected) == 2:
                operation.prepared.close()
        return reference
    monkeypatch.setattr(LocalRecordStore, 'append', save)
    assert list(operation) == []
    assert operation.summary['status'] == 'cancelled'
    assert operation.summary['prepared_rows'] == operation.summary['fuzz_sends'] == 0
    assert offered(traces) == []
    records = reopen_records(operation.prepared.path).records
    assert [r.kind for r in records] == ['preparation_start', 'source_disposition', 'source_disposition', 'preparation_terminal']
    assert [r.source_result.sample_id for r in rejected] == ['1:S:6:source:sample:2', '1:S:6:source:sample:3']


@pytest.mark.parametrize('cancel', ('stream', 'application'))
def test_generated_preparation_serializes_consumers_and_active_close(
        tmp_path, application_factory, monkeypatch, cancel):
    import threading
    from bytefault.generators.transforms import MutationPipeline
    app, traces = application_factory()
    value = config(values=(b'',))
    value['sets'][0]['transforms'] = ({'mutator_id': 'empty', 'kind': 'filter_empty'},)
    stream = app.generate(base(tmp_path), value)
    entered, release = threading.Event(), threading.Event()
    apply = MutationPipeline.apply
    def blocked(pipeline, *args, **kwargs):
        entered.set()
        assert release.wait(5)
        return apply(pipeline, *args, **kwargs)
    monkeypatch.setattr(MutationPipeline, 'apply', blocked)
    results, errors = [], []
    def consume():
        try:
            results.extend(stream)
        except BaseException as error:
            errors.append(error)
    worker = threading.Thread(target=consume)
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(ContractError) as caught:
            next(stream)
        assert caught.value.path == 'generation' and caught.value.code == 'busy'
        if cancel == 'stream':
            stream.close()
        else:
            assert app.close().outcome == 'pending'
        assert not stream._done and stream.preparation_id in app._preparations
    finally:
        stream.close()
        release.set()
        worker.join(5)
    assert not worker.is_alive() and not errors and not results
    assert stream._done and not app._preparations and not traces
    assert stream.summary['status'] == 'cancelled' and stream.summary['prepared_rows'] == 0
    assert stream.summary['cleanup_errors'] == ()
    records = reopen_records(stream.path).records
    assert records[-1].kind == 'preparation_terminal'
    assert sum(record.kind == 'preparation_terminal' for record in records) == 1
    stream.close()
    assert list(stream) == [] and reopen_records(stream.path).records == records


def test_lazy_bounded_sources_close_and_failure_stop(tmp_path, application_factory):
    app, traces = application_factory()
    value = config()
    value['sources'][0].update(kind='random', options={'min_len': 2, 'max_len': 2, 'count': None, 'seed': 42})
    bounded = app.submit_generated(base(tmp_path), value, limit=3)
    assert len(list(bounded)) == 3 and bounded.summary['status'] == 'bounded'
    prefix = app.generate(base(tmp_path, name='prefix'), value)
    next(prefix)
    app.close()
    assert list(prefix) == [] and prefix.summary['status'] == 'cancelled'
    assert reopen_records(prefix.path).records[-1].kind == 'preparation_terminal'
    app2, traces2 = application_factory(stream_options={'close_error': OSError('uncertain close')})
    execution = app2.submit_generated(base(tmp_path, name='failure'), config((b'1', b'2', b'3')))
    results = list(execution)
    assert len(results) == 1 and results[0].outcome == 'cleanup_failed'
    assert execution.summary['status'] == 'cleanup_failed' and len(offered(traces2)) == 1


def test_retained_modes_cli_and_lazy_large_numeric_prefix(tmp_path, application_factory):
    app, traces = application_factory()
    for index, extra in enumerate((
        ('--random-len', '2', '--random-iter', '2', '--random-seed', '3', '--prefix', 'ff'),
        ('--mutate-seed', '4142', '--mutate-seed', '4344', '--mutate-count', '2', '--mutate-rng-seed', '4'),
        ('--target', 'offset', '--offset', '1', '--fuzz-length', '8', '--generation-limit', '2'),
        ('--target', 'byte:0', '--mask', '0x5a-0x5b', '--target2', 'byte:2', '--mask2', '0x31-0x32'))):
        args = cli_args(tmp_path / str(index), *extra)
        result = execute_arguments(args, app)
        assert result.outcome == 'completed'
        records = app.read_records(result.run_id).records
        starts = [r.data['request'] for r in records if r.kind=='case_start']
        actions = [r.data['result'] for r in records if r.kind=='action_result']
        if index == 1:
            seeds = [request['row']['contributions'][0]['source_result']['data'] for request in starts]
            assert seeds == [b'AB', b'AB', b'CD', b'CD']
        if index == 2:
            assert [r['transport']['offered'] for r in actions] == [b'A' + bytes(8), b'A' + bytes(7) + b'\x01']
        if index == 3:
            assert [r['transport']['offered'] for r in actions] == [b'ZB1', b'ZB2', b'[B1', b'[B2']


@pytest.mark.parametrize('spec', ['@1:list:5a,mode:nonsense', '@1:list:zz,mode:overwrite'])
def test_parser_refuses_without_delivery(tmp_path, application_factory, spec):
    app, traces = application_factory()
    with pytest.raises(ContractError):
        execute_arguments(cli_args(tmp_path, '--gen-field', spec), app)
    assert not traces


@pytest.mark.parametrize('failure', ['terminal_save', 'source_close'])
def test_application_close_stops_held_engine_despite_preparation_cleanup_failure(
        tmp_path, application_factory, monkeypatch, failure):
    import threading
    import time
    from bytefault.monitoring import Monitoring
    from bytefault.core.contracts import MonitoringDecision
    from bytefault.generators.sources import SourceStream
    class Policy:
        def evaluate(self, observation):
            return MonitoringDecision('hold', observation.observation_id, observation.correlation,
                                      'hold', 'awaited', ('readiness',))
    app, traces = application_factory(monitoring=Monitoring(Policy()))
    stream = app.submit_generated(base(tmp_path, plan=positional_plan((b'ABC', b'later')), selected=('1',)),
                                  config((b'Z', b'Y')))
    results, errors = [], []
    def execute():
        try:
            results.append(next(stream))
        except BaseException as error:
            errors.append(error)
    worker = threading.Thread(target=execute)
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if app.status('run:row:1')['engine']['monitoring_hold']:
                    break
            except (ContractError, TypeError):
                pass
            time.sleep(.005)
        else:
            pytest.fail('generated ordinary send did not reach hold')
        if failure == 'terminal_save':
            original = LocalRecordStore.append
            def save(store, kind, identity, data):
                if kind == 'preparation_terminal':
                    raise OSError('controlled preparation terminal save failure')
                return original(store, kind, identity, data)
            monkeypatch.setattr(LocalRecordStore, 'append', save)
        else:
            def close(source):
                raise OSError('controlled source close failure')
            monkeypatch.setattr(SourceStream, 'close', close)
        outcome = app.close()
        assert outcome['preparation_failures']
        worker.join(5)
        assert not worker.is_alive() and not errors
        assert results[0].outcome == 'stopped' and len(offered(traces)) == 1
        assert app.close()['outcome'] == 'failed'
    finally:
        app.close()
        worker.join(5)


@pytest.mark.parametrize('change', [
    lambda value: value['sets'][0].update(transforms='reverse'),
    lambda value: value['sets'][0].update(transforms=({'mutator_id': 'm', 'kind': 'reverse', 'bad': True},)),
    lambda value: value['sets'][0].update(source_id={}),
    lambda value: value['positions'][0].update(set_id={}),
    lambda value: value.update(strategy={}),
    lambda value: value['positions'][0].update(baseline=1),
    lambda value: value['positions'][0].update(offset_range=(0, 1), offset_seed={})])
def test_malformed_generation_is_attributed(tmp_path, application_factory, change):
    app, traces = application_factory()
    value = config()
    change(value)
    with pytest.raises(ContractError) as error:
        list(app.generate(base(tmp_path), value))
    assert error.value.path.startswith('generation.') and not offered(traces)


def test_raw_payload_end_seed_resolves_each_action(tmp_path, application_factory):
    app, traces = application_factory()
    request = base(tmp_path, plan=positional_plan((b'AAAA', b'BB')), selected=('1', '2'))
    value = config((b'Z',), operation='replace', offset=0, end='seed')
    results = list(app.submit_generated(request, value))
    assert offered(traces) == [b'Z', b'Z']
    assert tuple(p.span for a in results[0].actions for p in a.materialized.placements) == ((0, 4), (0, 2))


@pytest.mark.parametrize('extra', [
    ('--gen-field', '@1:list:5a', '--offset-range', '5-5'),
    ('--gen-field', '@1:random:2,count:1', '--random-content-scope', 'sample_once')])
def test_inline_rejects_ignored_new_global_controls(tmp_path, application_factory, extra):
    app, traces = application_factory()
    with pytest.raises(ContractError, match='inline'):
        execute_arguments(cli_args(tmp_path, *extra), app)
    assert not traces


@pytest.mark.parametrize('kind', ['iter', 'edge', 'sweep', 'whole', 'lines', 'dataset', 'mutate'])
def test_every_offered_source_actual_cli_delivery(tmp_path, application_factory, kind):
    app, traces = application_factory()
    source = tmp_path / 'binary-input'
    source.write_bytes(b'Z\n\nY\n')
    datasets = {'neutral': {'selected': (b'Q', b'R'), 'all': (b'never',)}}
    specifications = {
        'iter': ('@1:iter:0-2,exclude:1,mode:overwrite', (b'A\x00C', b'A\x02C')),
        'edge': ('@1:edge:width:1,mode:overwrite', tuple(b'A' + bytes([n]) + b'C' for n in
            (0, 1, 2, 15, 16, 31, 32, 63, 64, 65, 126, 127, 128, 129, 191, 192, 254, 255))),
        'sweep': ('@append:sweep:1-3,byte_range:90,seed:2', (b'ABCZ', b'ABCZZ', b'ABCZZZ')),
        'whole': (f'@1:file:{source},mode:overwrite', (b'AZ\n\nY\n',)),
        'lines': (f'@1:file:{source},source_mode:lines,mode:overwrite', (b'AZC', b'ABC', b'AYC')),
        'dataset': ('@1:dataset:neutral.selected,mode:overwrite', (b'AQC', b'ARC')),
        'mutate': ('@1:mutate:41,count:1,seed:2,mode:overwrite', (b'ACC',))}
    spec, expected = specifications[kind]
    extra = ['--gen-field', spec]
    if kind == 'dataset':
        extra.extend(('--datasets-json', json.dumps(encode_value(datasets))))
    result = execute_arguments(cli_args(tmp_path, *extra), app)
    assert offered(traces) == list(expected) and result.fuzz_tests == len(expected)
    for record in (r for r in app.read_records(result.run_id).records if r.kind=='case_start'):
        contribution = record.data['request']['row']['contributions'][0]
        assert contribution['source_result']['source_id'] == contribution['source']['source_id']
        assert contribution['source_result']['sample_id']
        if kind == 'mutate':
            assert contribution['source_result']['data'] == b'A'
            assert contribution['mutator_results'][0]['output_data'] == b'C'
    assert source.read_bytes() == b'Z\n\nY\n'


def test_generated_overlap_and_beyond_eof(tmp_path, application_factory):
    app, traces = application_factory()
    value = {'sources': ({'source_id': 'X', 'kind': 'literal', 'options': {'data': b'X'}},
                         {'source_id': 'Y', 'kind': 'literal', 'options': {'data': b'Y'}}),
        'sets': ({'set_id': 'X', 'source_id': 'X'}, {'set_id': 'Y', 'source_id': 'Y'}),
        'positions': ({'position_id': 'X', 'set_id': 'X', 'operation': 'overwrite', 'offset': 1},
                      {'position_id': 'Y', 'set_id': 'Y', 'operation': 'overwrite', 'offset': 1}), 'strategy': 'zip'}
    result, = app.submit_generated(base(tmp_path), value)
    assert offered(traces) == [b'AYC']
    assert tuple(p.after for p in result.actions[0].materialized.placements) == (b'AXC', b'AYC')
    list(app.submit_generated(base(tmp_path, name='eof'), config(operation='insert', offset=5)))
    assert offered(traces)[-1] == bytes.fromhex('41424300005a')


def test_primary_submit_error_survives_preparation_cleanup_error(tmp_path, application_factory, monkeypatch):
    app, _ = application_factory()
    original = LocalRecordStore.append
    def save(store, kind, identity, data):
        if kind == 'preparation_terminal':
            raise OSError('secondary preparation failure')
        return original(store, kind, identity, data)
    def submit(request):
        raise RuntimeError('primary execution error')
    monkeypatch.setattr(LocalRecordStore, 'append', save)
    monkeypatch.setattr(app, 'submit', submit)
    stream = app.submit_generated(base(tmp_path), config())
    with pytest.raises(RuntimeError, match='primary execution error') as caught:
        next(stream)
    assert 'secondary preparation failure' in caught.value.__notes__[0]
    assert stream.summary['reason'] == 'primary execution error'
    assert stream.summary['operation_cleanup_errors'][0]['diagnostic']['required_record_kind'] == 'preparation_terminal'


def test_exact_selection_near_match_final_input_preserved(tmp_path, application_factory):
    from bytefault.core.contracts import SelectionIntent
    app, traces = application_factory()
    request = app.protocol_request('raw', 'offline.invalid', seed=b'ABC', port=1234,
                                   record_path=str(tmp_path / 'custom-selection.bfr'))
    row = replace(request.conversation.row, selection=SelectionIntent(bounds={'exact': 'custom'}))
    request = replace(request, conversation=replace(request.conversation, row=row))
    list(app.submit_generated(request, config()))
    assert offered(traces) == [b'ABC\x00Z']  # retained empty-seed range inserts ABC after generated edits
    result_request = app.read_records(request.conversation.run_id + ':row:1').records[0].data['request']
    assert result_request['original_request']['generation']['base_request']['row']['selection']['bounds']['exact'] == 'custom'


@pytest.mark.parametrize('alias', ['exact', 'hardlink', 'seed_directory', 'first_row'])
def test_source_output_collision_refuses_without_modification(tmp_path, application_factory, alias):
    app, traces = application_factory()
    request = base(tmp_path)
    source = tmp_path / 'source'
    source.write_bytes(b'unchanged-input')
    if alias == 'exact':
        source = Path(request.record_path + '.preparation.bfr')
        source.write_bytes(b'unchanged-input')
    elif alias == 'hardlink':
        Path(request.record_path + '.preparation.bfr').hardlink_to(source)
    elif alias == 'first_row':
        source = tmp_path / 'run.row-000001.bfr'
        source.write_bytes(b'unchanged-input')
    value = config()
    if alias == 'seed_directory':
        value['sources'][0].update(kind='seed', options={'seed_directory': str(tmp_path)})
    else:
        value['sources'][0].update(kind='file', options={'path': str(source)})
    before = source.read_bytes()
    with pytest.raises(ContractError, match='source_collision'):
        app.generate(request, value)
    assert source.read_bytes() == before and not traces


def test_cli_zero_length_and_json_override_attribution(tmp_path, application_factory):
    app, traces = application_factory()
    result = execute_arguments(cli_args(tmp_path, '--random-len', '0', '--random-iter', '2'), app)
    assert not offered(traces) and result.fuzz_tests == 2
    actions = [r.data['result']['transport'] for r in app.read_records(result.run_id).records if r.kind=='action_result']
    assert len(actions)==2 and all(t['offered']==b'' and t['accepted_count']==0 and t['acceptance']=='accepted' for t in actions)
    for extra in (('--prefix', 'ff'), ('--offset-range', '2-3'), ('--random-content-scope', 'sample_once')):
        with pytest.raises(ContractError, match='JSON owns'):
            resolve_configuration(cli_args(tmp_path, '--generation-json', json.dumps(encode_value(config())), *extra), app)
