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

"""CC-02 copied portable inputs and finite lists through actual engine/stores."""
from dataclasses import replace
import copy
import json
from pathlib import Path

import pytest

from bytefault.application import ApplicationRequest, SavedCaseIntent, SavedStepIntent
from bytefault.core.contracts import (Calculation, CampaignOptions, ContractError,
    ConversationAction, ConversationRequest, FieldLocation, PassivePlan, Placement,
    PreparedContribution, PreparedRow, ReceiveRequest, ResponseEdge, SourceInvocation,
    TransportRequest)
from bytefault.fuzzers.cli import execute_arguments
from bytefault.fuzzers.inputs import request_to_data, value_from_data, request_from_record, contract_from_record


def base(tmp_path, identity='original', *, two=False):
    setup = ConversationAction('setup', b'S', stage_id='setup',
        receive=ReceiveRequest(cap=2, deadline=3),
        edges=(ResponseEdge(b'OK', 'A', 'positive'),), unknown_target=None)
    actions = tuple(ConversationAction(key, b'\0\0AB', stage_id='selected', fields=(
        FieldLocation('length', 0, 2), FieldLocation('body', 2, 2, variable=True)))
        for key in (('A', 'B') if two else ('A',)))
    request = ConversationRequest(PassivePlan('saved-neutral', 1, (setup, *actions), ('setup', 'selected')),
        PreparedRow('row', 1), tuple(a.action_id for a in actions),
        identity, 'case', 'conversation', repair=True,
        calculations=tuple(Calculation('len-' + a.action_id, a.action_id, 'payload_length',
            size=2, payload_offset=2, field_id='length') for a in actions))
    return ApplicationRequest(request, TransportRequest('offline.invalid', 1234, 3),
                              str(tmp_path / (identity + '.bfr')))


def case_data(app, request):
    records = app.read_records(request.conversation.run_id).records
    start = next(r for r in records if r.kind == 'case_start')
    return app.export_case(request.record_path, start.record_id), start


def offers(result):
    return [a.transport.offered for a in result.actions]


def test_copied_literal_preserves_intended_prefix_and_complete_intent(tmp_path, application_factory):
    original, _ = application_factory(stream_options={'reads': (b'OK',),
        'sends': (1, 2, OSError('partial selected offer'))})
    request = base(tmp_path)
    from bytefault.core.contracts import ResponseField
    request = replace(request, conversation=replace(request.conversation,
        plan=replace(request.conversation.plan, actions=(replace(request.conversation.plan.actions[0],
            response_fields=(ResponseField('flag', 0, 1),),
            edges=(ResponseEdge(b'O', 'A', 'positive', 'flag'),)),
            *request.conversation.plan.actions[1:]))))
    contributions = tuple(PreparedContribution(key, data, SourceInvocation(key, 'literal'))
        for key, data in (('body', b'WXYZ'), ('tail', b'!'), ('override', b'\xff\xff')))
    row = PreparedRow('multi', 1, contributions,
        (Placement('body', 'body', 'A', 'replace', field_id='body'),
         Placement('tail', 'tail', 'A', 'append')),
        final_overrides=(Placement('override', 'override', 'A', 'overwrite', 0),))
    request = replace(request, conversation=replace(request.conversation, row=row))
    failed = original.submit(request)
    assert failed.outcome == 'transport_failed'
    assert failed.actions[-1].transport.accepted_prefix == b'\xff\xff'
    expected = b'\xff\xffWXYZ!'
    assert failed.actions[-1].materialized.final_bytes == expected
    data, start = case_data(original, request)
    assert request_from_record(start.data['request']) == request.conversation
    copied = tmp_path / 'copied.case.json'
    copied.write_text(json.dumps(data), encoding='utf-8')
    # The portable recipe no longer depends on the source journal.
    (tmp_path / 'original.bfr').unlink()
    rerun, traces = application_factory(stream_options={'reads': (b'OZ',)})
    prepared = execute_arguments(['saved-case', json.dumps({'path': str(copied)}),
        '--records', str(tmp_path / 'rerun.bfr')], rerun)
    assert traces == []  # preparation never constructs a target adapter
    assert prepared.conversation.run_id != request.conversation.run_id
    assert prepared.conversation.calculations == ()
    retained = prepared.conversation.original_request['saved_case']
    assert retained.original_request.row == start.data.request.row
    assert retained.origin.record_id == start.record_id
    assert retained.original_request.plan.actions[0].edges[0].literal == b'O'
    assert retained.original_request.plan.actions[0].response_fields[0].field_id == 'flag'
    outcome = rerun.submit(prepared)
    assert outcome.outcome == 'completed' and offers(outcome) == [b'S', expected]
    assert outcome.actions[-1].transport.accepted_prefix == expected
    assert outcome.actions[0].transport.received == b'OZ'
    assert outcome.actions[0].response_interpretation.fields[0].data == b'O'
    fresh = rerun.import_case(data, mode='fresh_dynamic', record_path=str(tmp_path / 'fresh-control.bfr'))
    fresh_result = rerun.submit(fresh)
    assert fresh_result.actions[0].response_meaning == 'positive'
    assert fresh_result.actions[0].response_interpretation == outcome.actions[0].response_interpretation
    assert fresh.conversation.run_id != prepared.conversation.run_id
    # Resume a retained valid preparation prefix with a different actual control
    # byte. Neither prior successful setup nor its extracted value can be reused.
    from bytefault.core.storage import reopen_records
    from bytefault.application import ResumeIntent, ResumeChoice
    recovery = reopen_records(fresh.record_path)
    reference = next(ref for record, ref in zip(recovery.records, recovery.refs)
        if record.kind == 'materialization' and record.identity.get('action_id') == 'A')
    prefix = tmp_path / 'control-prefix.bfr'
    prefix.write_bytes(Path(fresh.record_path).read_bytes()[:reference.offset + reference.length])
    resumed_app, _ = application_factory(stream_options={'reads': (b'NZ',)})
    continuation = resumed_app.resume(ResumeIntent(str(prefix), (
        ResumeChoice(fresh.conversation.conversation_id, 'rerun'),)),
        record_path=str(tmp_path / 'control-resume.bfr'))
    resumed_result = resumed_app.submit(continuation).last_conversation
    assert offers(resumed_result) == [b'S'] and resumed_result.unreached
    assert resumed_result.actions[0].response_meaning == 'unknown'
    assert resumed_result.actions[0].response_interpretation.fields[0].data == b'N'
    assert all(stream.closed for _, stream, _ in traces)
    # A rerun is itself an ordinary reconstructable current record.
    again, _ = case_data(rerun, prepared)
    assert value_from_data(again['origin'])['identity']['run_id'] == outcome.run_id


def test_per_action_fresh_file_and_selected_mutation(tmp_path, application_factory, monkeypatch):
    source = tmp_path / 'source.bin'
    source.write_bytes(b'AB')
    app, _ = application_factory(stream_options={'reads': (b'OK', b'R')})
    request = base(tmp_path, two=True)
    request = replace(request, conversation=replace(request.conversation,
        plan=replace(request.conversation.plan, actions=tuple(replace(a,
            receive=ReceiveRequest(cap=1, deadline=3)) if a.action_id == 'A' else a
            for a in request.conversation.plan.actions))))
    configuration = {'sources': ({'source_id': 'src', 'kind': 'file',
        'options': {'path': str(source), 'source_mode': 'whole'}},),
        'sets': ({'set_id': 'set', 'source_id': 'src', 'transforms': (
            {'mutator_id': 'reverse', 'kind': 'reverse'},)},),
        'positions': ({'position_id': 'body', 'set_id': 'set', 'operation': 'replace',
                       'field_id': 'body', 'action_ids': ('A', 'B')},)}
    from contextlib import closing
    with closing(app.generate(request, configuration, limit=1)) as prepared:
        current = next(prepared)
        original = app.submit(current)
    assert offers(original) == [b'S', bytes.fromhex('00024241'), bytes.fromhex('00024241')]
    data, _ = case_data(app, current)
    recorded = app.import_case(data, no_receive=True, record_path=str(tmp_path / 'recorded-parent.bfr'))
    assert app.submit(recorded).outcome == 'completed'
    recorded_data, _ = case_data(app, recorded)
    # Retained materialization prefixes qualify the same source ancestry through
    # repeated ordinary resume, while existing tests cover actual writer kills.
    from pathlib import Path
    from bytefault.application import ResumeIntent, ResumeChoice
    from bytefault.core.storage import reopen_records
    def prefix(path, destination):
        history = reopen_records(path)
        reference = next(ref for r, ref in zip(history.records, history.refs)
            if r.kind == 'materialization' and r.identity.get('action_id') == 'B')
        destination.write_bytes(Path(path).read_bytes()[:reference.offset + reference.length])
        return str(destination)
    original_prefix = prefix(current.record_path, tmp_path / 'original-prefix.bfr')
    logical = current.conversation.conversation_id
    resumed = app.resume(ResumeIntent(original_prefix, (ResumeChoice(logical, 'rerun'),)),
                         record_path=str(tmp_path / 'recorded-resume.bfr'))
    assert app.submit(resumed).outcome == 'completed'
    resume_prefix = prefix(resumed.record_path, tmp_path / 'resume-prefix.bfr')
    source.write_bytes(b'XYZ')
    import bytefault.generators.sources as sources
    import bytefault.generators.transforms as transforms
    opened, mutated = [], []
    open_source, apply = sources.open_source, transforms.MutationPipeline.apply
    def observed_source(spec, **options):
        opened.append(spec)
        return open_source(spec, **options)
    def observed_mutator(self, value, *args, **options):
        mutated.append(value)
        return apply(self, value, *args, **options)
    monkeypatch.setattr(sources, 'open_source', observed_source)
    monkeypatch.setattr(transforms.MutationPipeline, 'apply', observed_mutator)
    for reapply, expected in ((False, '000358595a'), (True, '00035a5958')):
        rerun, traces = application_factory(stream_options={'reads': (b'OK', b'SENTINEL')})
        prepared = rerun.import_case(data, steps=(SavedStepIntent('A'),
            SavedStepIntent('B', 'fresh_dynamic', reapply, 'src')),
            record_path=str(tmp_path / ('fresh-' + str(reapply) + '.bfr')), no_receive=True)
        result = rerun.submit(prepared)
        assert result.outcome == 'completed'
        assert offers(result) == [b'S', bytes.fromhex('00024241'), bytes.fromhex(expected)]
        assert sum(t[0] == 'read' for t in traces[0][0]) == 1
        assert traces[0][1].reads == [b'SENTINEL']
        fresh = prepared.conversation.row.contributions[-1]
        assert fresh.source_result.data == b'XYZ'
        assert fresh.source.options['kind'] == 'file'
        assert bool(fresh.mutator_results) is reapply
    assert len(opened) == 2 and all(s.kind == 'file' for s in opened)
    assert mutated == [b'XYZ']
    # A recorded intermediate keeps latest exact bytes/receive choices, while a
    # later fresh action resolves the retained original field/source recipe.
    for reference in (None, 'src'):
        rerun, traces = application_factory(stream_options={'reads': (b'OK', b'R', b'SENTINEL')})
        fresh = rerun.import_case(recorded_data, steps=(SavedStepIntent('A', 'fresh_dynamic', True, reference),
            SavedStepIntent('B')), record_path=str(tmp_path / ('ancestry-' + str(reference) + '.bfr')))
        result = rerun.submit(fresh)
        assert offers(result) == [b'S', bytes.fromhex('00035a5958'), bytes.fromhex('00024241')]
        assert sum(t[0] == 'read' for t in traces[0][0]) == 2
        assert traces[0][1].reads == [b'SENTINEL']
        assert fresh.conversation.plan.actions[1].receive.requested
        assert not fresh.conversation.plan.actions[2].receive.requested
        assert fresh.conversation.original_request['saved_case']['original_request']['run_id'] == recorded.conversation.run_id
        latest_data, _ = case_data(rerun, fresh)
        continuation = rerun.resume(ResumeIntent(resume_prefix, (ResumeChoice(logical, 'rerun', (
            SavedStepIntent('A', 'fresh_dynamic', True, reference), SavedStepIntent('B'))),)),
            record_path=str(tmp_path / ('resume-ancestry-' + str(reference) + '.bfr')))
        continued = rerun.submit(continuation)
        assert continued.outcome == 'completed'
        assert offers(continued.last_conversation) == [b'S', bytes.fromhex('00035a5958'), bytes.fromhex('00024241')]
        case = next(r for r in rerun.read_records(continued.run_id).records if r.kind == 'case_start')
        assert case.data['request']['original_request']['resume']['logical_conversation_id'] == logical
        assert case.data['request']['original_request']['resume']['previous_identity']['run_id'] == resumed.conversation.run_id
    # Fresh execution without mutation must not erase the original transform
    # recipe needed by a later explicitly selected reapplication.
    unmutated = app.import_case(recorded_data, steps=(SavedStepIntent('B', 'fresh_dynamic'),),
                               record_path=str(tmp_path / 'unmutated-parent.bfr'))
    assert offers(app.submit(unmutated)) == [b'S', bytes.fromhex('00024241'), bytes.fromhex('000358595a')]
    unmutated_data, _ = case_data(app, unmutated)
    for reference in (None, 'src'):
        restored = app.import_case(unmutated_data, steps=(SavedStepIntent('B', 'fresh_dynamic', True, reference),),
                                  record_path=str(tmp_path / ('reapplied-' + str(reference) + '.bfr')))
        assert offers(app.submit(restored)) == [b'S', bytes.fromhex('00024241'), bytes.fromhex('00035a5958')]
    with pytest.raises(ContractError, match='source_collision'):
        app.import_case(recorded_data, steps=(SavedStepIntent('B', 'fresh_dynamic', True, 'src'),),
                        record_path=str(source))
    # Older inline ancestry has no direct recipe field. Resolve its existing
    # original_request link rather than requiring a rewritten parent journal.
    from collections.abc import Mapping
    def inline(value):
        if isinstance(value, Mapping): return {k: inline(v) for k, v in value.items()}
        if isinstance(value, tuple): return tuple(inline(v) for v in value)
        return value
    old = app.import_request(recorded_data['request'])
    old_intent = inline(old.original_request)
    old_intent['saved_case'].pop('derivation_request')
    old_data = {**recorded_data, 'request': app.export_request(replace(old, original_request=old_intent))}
    old_fresh = app.import_case(old_data, steps=(SavedStepIntent('B', 'fresh_dynamic', True, 'src'),),
                                record_path=str(tmp_path / 'old-inline-fresh.bfr'))
    assert offers(app.submit(old_fresh)) == [b'S', bytes.fromhex('00024241'), bytes.fromhex('00035a5958')]
    assert source.read_bytes() == b'XYZ'
    source.unlink()
    # Literal remains portable; fresh preserves the unavailable prerequisite.
    literal = app.import_case(data, record_path=str(tmp_path / 'missing-literal.bfr'))
    assert app.submit(literal).outcome == 'completed'
    latest = app.import_case(latest_data, record_path=str(tmp_path / 'latest-recorded.bfr'))
    assert offers(app.submit(latest)) == [b'S', bytes.fromhex('00035a5958'), bytes.fromhex('00024241')]
    with pytest.raises(ContractError, match='source_configuration'):
        app.import_case(data, steps=(SavedStepIntent('B', 'fresh_dynamic'),),
                        record_path=str(tmp_path / 'missing-fresh.bfr'))


@pytest.mark.parametrize('owner,scope', [('source', 'sample_once'), ('source', 'per_test'),
                                       ('mutator', 'sample_once'), ('mutator', 'per_test')])
def test_fresh_saved_run_shares_held_runtime_and_refreshes_per_test(
        tmp_path, application_factory, monkeypatch, owner, scope):
    import random
    import bytefault.generators.sources as sources
    import bytefault.generators.transforms as transforms
    app, _ = application_factory(stream_options={'reads': (b'OK',)})
    request = base(tmp_path, two=True)
    configuration = {'sources': tuple({'source_id': key, 'kind': 'random' if owner == 'source' else 'literal',
        'options': {'min_len': 8, 'max_len': 8, 'count': 1, 'seed': seed, 'content_scope': scope}
        if owner == 'source' else {'data': data}}
        for key, seed, data in (('R', 29, b'ABCDEFGH'), ('Q', 31, b'abcdefgh'))),
        'sets': tuple({'set_id': key, 'source_id': key, 'transforms': () if owner == 'source' else (
            {'mutator_id': 'mutate-' + key, 'kind': 'mutate',
             'options': {'operation': 'arith_byte', 'scope': scope,
                         **({'seed': seed} if scope == 'per_test' else {})}},)}
             for key, seed in (('R', 29), ('Q', 31))),
        'positions': ({'position_id': 'R', 'set_id': 'R', 'operation': 'replace', 'field_id': 'body'},
                      {'position_id': 'Q', 'set_id': 'Q', 'operation': 'append'}), 'strategy': 'zip'}
    original = app.campaign(request, generation=configuration)
    data, _ = case_data(app, request)
    recorded = app.import_case(data, record_path=str(tmp_path / 'scope-recorded-parent.bfr'))
    assert app.submit(recorded).outcome == 'completed'
    data, _ = case_data(app, recorded)
    opened, refreshed, pipelines = [], [], {}
    open_source, refresh, apply = sources.open_source, sources.SourceStream.refresh, transforms.MutationPipeline.apply
    def observed_source(spec, **options):
        opened.append(spec.source_id)
        return open_source(spec, **options)
    def observed_refresh(self, candidate, iteration_id=None):
        refreshed.append((self.spec.source_id, iteration_id))
        return refresh(self, candidate, iteration_id)
    def observed_mutator(self, value, *args, **options):
        for spec in self.specs:
            pipelines.setdefault(spec.mutator_id, []).append(self)
        return apply(self, value, *args, **options)
    monkeypatch.setattr(sources, 'open_source', observed_source)
    monkeypatch.setattr(sources.SourceStream, 'refresh', observed_refresh)
    monkeypatch.setattr(transforms.MutationPipeline, 'apply', observed_mutator)
    steps = tuple(SavedStepIntent(a, 'fresh_dynamic', owner == 'mutator') for a in ('A', 'B'))
    prepared = app.import_case(data, steps=steps, record_path=str(tmp_path / 'shared-fresh.bfr'))
    result = app.submit(prepared)
    assert result.outcome == 'completed'
    # Seeded new runs follow ordinary generation's two iterations. An unseeded
    # held mutator need only hold its choices within this new run.
    if owner == 'source' or scope == 'per_test':
        assert offers(result) == offers(original.last_conversation)
    assert opened == ['R', 'Q']
    assert [key for key, _ in refreshed] == ['R', 'Q']
    row = prepared.conversation.row
    for key in ('R', 'Q'):
        parts = [c for c in row.contributions if c.source.source_id == key]
        assert len(parts) == 2
        choices = [[c for c in part.random_choices if c.owner == owner and
                    (owner == 'mutator' or c.option == 'content')] for part in parts]
        assert all(c.scope == scope for group in choices for c in group)
        assert all(c.iteration_id == prepared.conversation.conversation_id + ':' + action
                   for group, action in zip(choices, ('A', 'B')) for c in group if scope == 'per_test')
        assert len({part.source_result.sample_id for part in parts}) == 2
        if scope == 'sample_once':
            assert [c.resolved for c in choices[0]] == [c.resolved for c in choices[1]]
            assert parts[0].data == parts[1].data
        if owner == 'source':
            rng = random.Random(29 if key == 'R' else 31)
            first = rng.randbytes(8)
            assert [part.data for part in parts] == [first, first if scope == 'sample_once' else rng.randbytes(8)]
        else:
            actual_pipelines = pipelines['mutate-' + key]
            assert len(actual_pipelines) == 2 and actual_pipelines[0] is actual_pipelines[1]
    if owner == 'mutator':
        assert pipelines['mutate-R'][0] is not pipelines['mutate-Q'][0]
    # Recorded action A is literal; only fresh B consumes the new source run.
    # Mutation is explicitly omitted and must not inherit an old transformation.
    mixed = app.import_case(data, steps=(SavedStepIntent('A'), SavedStepIntent('B', 'fresh_dynamic')),
                            record_path=str(tmp_path / 'mixed-fresh.bfr'))
    mixed_result = app.submit(mixed)
    assert offers(mixed_result)[1] == original.last_conversation.actions[1].transport.offered
    assert all(not c.mutators for c in mixed.conversation.row.contributions)
    if owner == 'mutator':
        assert offers(mixed_result)[2] == b'\0\x10ABCDEFGHabcdefgh'
    elif scope == 'per_test':
        # Explicit pool reuse retains its resolved candidate/sample identity,
        # although the underlying generator's ordinary scope is per-test.
        reused_request = replace(request, record_path=str(tmp_path / 'reuse-original.bfr'),
            conversation=replace(request.conversation, run_id='reuse-original'))
        reused_config = {**configuration, 'sets': tuple({**s, 'pool_mode': 'reuse'}
                                                       for s in configuration['sets'])}
        app.campaign(reused_request, generation=reused_config)
        reused_data, _ = case_data(app, reused_request)
        reused = app.import_case(reused_data, mode='fresh_dynamic',
                                 record_path=str(tmp_path / 'reuse-fresh.bfr'))
        assert app.submit(reused).outcome == 'completed'
        for key in ('R', 'Q'):
            parts = [c for c in reused.conversation.row.contributions if c.source.source_id == key]
            assert len(parts) == 2 and parts[0].data == parts[1].data
            assert parts[0].source_result.sample_id == parts[1].source_result.sample_id
            assert all(c.scope == 'sample_once' and c.iteration_id is None
                       for part in parts for c in part.random_choices)


@pytest.mark.parametrize('failure', ['version', 'missing_bytes', 'hex', 'request', 'row', 'origin', 'unknown_rule'])
def test_typed_portable_failures_before_target(tmp_path, application_factory, failure):
    app, traces = application_factory(stream_options={'reads': (b'OK',)})
    request = base(tmp_path)
    app.submit(request)
    data, _ = case_data(app, request)
    data = copy.deepcopy(data)
    steps = ()
    if failure == 'version': data['version'] = 999
    elif failure == 'missing_bytes': del data['intended']['A']
    elif failure == 'hex': data['intended']['A'] = 'not hex'
    elif failure == 'request': data['request'] = {'$type': 'ConversationRequest', 'fields': []}
    elif failure == 'row': data['request']['fields']['row'] = {'$mapping': []}
    elif failure == 'origin': data['origin'] = {'$type': 'ArbitraryExecutable', 'fields': {}}
    else:
        original = app.import_request(data['request'])
        original = replace(original, calculations=(Calculation('unknown', 'A', 'unknown_future', required=True),))
        data['request'] = app.export_request(original)
        steps = (SavedStepIntent('A', 'fresh_dynamic'),)
    before = len(traces)
    with pytest.raises(ContractError):
        prepared = app.import_case(data, steps=steps, record_path=str(tmp_path / 'invalid.bfr'))
        # Required semantic calculation qualification is the ordinary validator.
        app.validate(prepared)
    assert all(not any(t[0] == 'open' for t in trace) for trace, _, _ in traces[before:])


@pytest.mark.parametrize('stop,client', [(False, 'campaign'), (True, 'shared'),
    (False, 'replay_callable'), (True, 'replay_module'), (False, 'replay_root')])
def test_literal_list_preserves_item_outcomes_and_unsent(tmp_path, application_factory, monkeypatch, capsys, stop, client):
    from bytefault.monitoring import Monitoring
    class OrdinaryPolicy:
        def observe(self, fact):
            return Monitoring().observe(fact)
    replay = client.startswith('replay')
    from bytefault.fuzzers.transport import SendFailure
    app, traces = application_factory(monitoring=OrdinaryPolicy(), stream_options={
        'sends': (1, 1, SendFailure('item 2', accepted_count=0)) if replay else (1, OSError('item 2'))})
    from bytefault.fuzzers.inputs import raw_request
    conversation = raw_request(b'A')
    request = ApplicationRequest(conversation, TransportRequest('offline.invalid', 1234, 3),
                                 str(tmp_path / 'list.bfr'))
    cases = tuple(replace(conversation, row=PreparedRow('item' + str(n), n,
        (PreparedContribution('x', value, SourceInvocation('x', 'literal')),),
        final_overrides=(Placement('x', 'x', '1', 'replace', 0, 1),)))
        for n, value in enumerate((b'A', b'B', b'C'), 1))
    if stop:
        import bytefault.fuzzers.fuzzer as module
        real = module.ProtocolFuzzer._exchange_packet
        def halt(self, *args, **options):
            if self._record_request.campaign.case_number == 2:
                self.control('stop')
            return real(self, *args, **options)
        # Restore with pytest's own lifetime rather than leaking a global patch.
        from unittest.mock import patch
        context = patch.object(module.ProtocolFuzzer, '_exchange_packet', halt)
    else:
        from contextlib import nullcontext
        context = nullcontext()
    with context:
        if client == 'shared':
            from bytefault.core.records import encode_value
            result = execute_arguments(['offline.invalid', '--port', '1234', '--records', request.record_path,
                '--health-check-mode', 'disabled', '--campaign-json', json.dumps(encode_value(
                    {'cases': tuple(request_to_data(c) for c in cases)}))], app)
        elif client == 'campaign':
            result = app.campaign(request, cases=cases)
        elif client == 'replay_callable':
            from bytefault.replay.replay_packet import replay_packets
            result = replay_packets('offline.invalid', 1234, (b'A', b'BB', b'C'),
                application=app, record_path=request.record_path, skip_recv=True, tcp_pre_delay_s=0)
        else:
            import bytefault.fuzzers.cli as cli_module
            monkeypatch.setattr(cli_module, 'Application', lambda: app)
            arguments = ['offline.invalid', '41', '4242', '43', '--records', request.record_path, '--no-recv']
            if client == 'replay_module':
                from bytefault.replay.replay_packet import main
                code = main(arguments)
            else:
                import importlib.util
                source = Path(__file__).resolve().parents[3] / 'bytefault.py'
                spec = importlib.util.spec_from_file_location('replay_root_entry', source)
                root = importlib.util.module_from_spec(spec); spec.loader.exec_module(root)
                code = root.main(['replay', 'raw', *arguments, '--port', '1234'])
            assert code == 1
            from bytefault.core.records import decode_value
            from bytefault.core.contracts import freeze
            result = freeze(decode_value(json.loads(capsys.readouterr().out.splitlines()[0])))
    assert result.outcome == ('stopped' if stop else 'transport_failed')
    assert tuple(item['state'] for item in result.literal_items) == (
        'completed', 'stopped' if stop else 'transport_failed', 'not_started')
    assert [item['case_number'] for item in result.literal_items] == [1, 2, 3]
    assert result.literal_items[-1]['result'] is None
    assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == ([b'A'] if stop else
        [b'A', b'BB', b'B'] if replay else [b'A', b'B'])
    if replay and not stop:
        failed = result.literal_items[1]['result']
        assert failed.actions[-1].transport.accepted_count == 1
        assert failed.actions[-1].transport.accepted_prefix == b'B'
        assert failed.actions[-1].transport.acceptance == 'partial'
        assert failed.actions[-1].transport.offered == b'BB'
        assert 'item 2' in str(failed.actions[-1].transport.error)
    assert traces[0][1].closed
    terminal = app.read_records(result.run_id).records[-1]
    assert terminal.data['result']['outcome'] == result.outcome


def test_replay_inline_file_order_preparation_and_option_context(tmp_path, application_factory, caplog):
    from bytefault.replay.replay_packet import resolve_arguments, execute_arguments as replay, replay_packets
    from bytefault.management.configuration import ServiceConfiguration
    source = tmp_path / 'packets.txt'
    source.write_text('# heading\n42\n\nnot-hex\n43\n', encoding='utf-8')
    empty = tmp_path / 'empty.txt'; empty.write_text('# nothing\n\n', encoding='utf-8')
    invalid = tmp_path / 'invalid.txt'; invalid.write_text('invalid\n', encoding='utf-8')
    config = ServiceConfiguration(result_root=str(tmp_path / 'reporting'), core_write_wait=9)
    app, traces = application_factory(service_configuration=config)
    arguments = ['offline.invalid', '41', '@' + str(source), '44', '@' + str(empty), '@' + str(invalid),
        '@' + str(empty), '--no-recv', '--wait', '2',
        '--offset', '0', '--fuzz-length', '99', '--value', '0xff', '--fuzz-target', 'opaque',
        '--records', str(tmp_path / 'replay.bfr'), '--no-ui']
    prepared = replay([*arguments, '--prepare'], app)
    assert not traces and not Path(prepared.record_path).exists() and app.management is None
    resolved = resolve_arguments(arguments, app)
    assert resolved.resolved['packets'] == (b'A', b'B', b'C', b'D')
    assert [(item.get('line'), item['argument_index']) for item in resolved.resolved['items']] == [
        (None, 0), (2, 1), (5, 1), (None, 2)]
    assert str(source) + ':4:' in caplog.text
    assert resolved.resolved['diagnostics'][0]['text'] == 'not-hex'
    assert prepared.transport.pre_delay == 2 and prepared.transport.post_delay == 0
    assert prepared.monitoring_configuration.health_check_mode == 'new_connection'
    assert not prepared.conversation.plan.actions[0].receive.requested
    assert prepared.conversation.plan.actions[0].receive.length_offset is None
    assert prepared.conversation.original_request['replay']['options']['offset'] == 0
    assert prepared.conversation.original_request['replay']['options']['fuzz_length'] == 99
    assert prepared.cases[1].row.contributions[0].source.input_reference == str(source)
    assert prepared.conversation.input_files == tuple(str(p) for p in (source, empty, invalid, empty))
    assert all(case.input_files == prepared.conversation.input_files for case in prepared.cases)
    # Files consumed without a valid row are current inputs too; all writer
    # routes refuse them before initialization or traffic.
    original = {p: p.read_bytes() for p in (source, empty, invalid)}
    for flag, path in (('--records', source), ('--log-file', empty), ('--results', invalid)):
        refused, denied_traces = application_factory()
        with pytest.raises(ContractError, match='source_collision'):
            replay([*arguments, flag, str(path)], refused)
        assert not denied_traces and refused.management is None
        assert all(p.read_bytes() == data for p, data in original.items())
    result = replay(arguments, app)
    assert result.outcome == 'completed'
    assert [item['state'] for item in result.literal_items] == ['completed'] * 4
    assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == [b'A', b'B', b'C', b'D']
    assert not any(t[0] == 'read' for t in traces[0][0])
    assert len([t for t in traces[0][0] if t == ('sleep', 2)]) == 8
    assert sum(r.kind == 'observation' and r.data['observation']['kind'] == 'service_check'
        for r in app.read_records(result.run_id).records) == 4
    assert app.service_configuration.core_write_wait == 9
    assert app.management is not None and app.reporting is not None
    assert app.close()['outcome'] == 'completed'
    before = len(traces)
    with pytest.raises(ContractError, match='no valid packet literals'):
        replay(['offline.invalid', '@' + str(empty), '@' + str(invalid), '--prepare'], app)
    assert len(traces) == before
    # Callable zero overrides are meaningful; metadata stays passive.
    other, _ = application_factory()
    passive = replay_packets('offline.invalid', 1234, [b'A'], application=other, prepare=True,
        tcp_pre_delay_s=0, wait_between=9, tcp_spacing_s=8, skip_recv=True,
        crash_hint={'offset': 7}, replay_metadata={'label': 'opaque'},
        health_check_mode='disabled', enable_crash_handling=True, core_dump_wait_s=11,
        recovery_wait_s=2, recovery_attempts=3)
    assert passive.transport.pre_delay == 0
    assert passive.monitoring_configuration.health_check_mode == 'disabled'
    assert passive.monitoring_configuration.recovery_delays == (2, 2, 2)
    assert passive.conversation.original_request['replay']['metadata']['crash_hint']['offset'] == 7
    assert passive.conversation.original_request['replay']['options']['core_dump_wait'] == 11
    from bytefault.monitoring import Monitoring
    from bytefault.monitoring.configuration import MonitoringConfig
    owner = Monitoring(configuration=MonitoringConfig(recovery_delays=(2, 2, 2), recovery_budget=6))
    supplied, _ = application_factory(monitoring=owner)
    for flags in (('--recovery-wait', '2'), ('--recovery-attempts', '3')):
        compatible = resolve_arguments(['offline.invalid', '41', *flags], supplied)
        assert compatible.request.monitoring_configuration is None and supplied.monitoring is owner
    with pytest.raises(ContractError, match='replay.monitoring.*conflict'):
        resolve_arguments(['offline.invalid', '41', '--recovery-wait', '3'], supplied)


def test_replay_declared_port_and_receive_policy(tmp_path, application_factory, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location('replay_policy_root', Path(__file__).resolve().parents[3] / 'bytefault.py')
    root = importlib.util.module_from_spec(spec); spec.loader.exec_module(root)
    with pytest.raises(SystemExit) as error:
        root.main(['replay'])
    assert error.value.code == 2 and 'required' in capsys.readouterr().err
    for arguments in (['replay', '--help'], ['replay', 'raw', '--help']):
        with pytest.raises(SystemExit) as help_exit:
            root.main(arguments)
        text = capsys.readouterr().out
        assert help_exit.value.code == 0 and '--no-recv' in text and 'protocol host packets' in text
    app, traces = application_factory(stream_options={'reads': (b'\0\2AB',)})
    directory = tmp_path / 'protocols'; entry = directory / 'neutral'; entry.mkdir(parents=True)
    plan = PassivePlan('neutral', 1, (ConversationAction('1', b'',
        receive=ReceiveRequest(cap=8, deadline=9, length_offset=0)),))
    (entry / 'declaration.json').write_text(json.dumps(app.export_declaration(plan)), encoding='utf-8')
    (entry / 'protocol.json').write_text(json.dumps({'format_version': 1, 'protocol_id': 'neutral', 'aliases': [],
        'transport': 'tcp', 'declaration': 'declaration.json', 'defaults': {'port': 2468}}), encoding='utf-8')
    config = root.resolve_arguments(['replay', 'neutral', 'offline.invalid', '41', '--declaration-dir', str(directory),
        '-vv', '--debug'], app)
    assert config.request.transport.port == 2468
    assert config.options['verbose'] == 2 and config.options['debug'] and not config.options['ui']
    receive = config.request.conversation.plan.actions[0].receive
    assert (receive.cap, receive.deadline, receive.length_offset) == (8, 9, 0)
    from bytefault.replay.replay_packet import resolve_arguments, execute_arguments as replay
    module = resolve_arguments(['offline.invalid', '41', '--protocol', 'neutral', '--declaration-dir', str(directory)], app)
    assert module.request.transport.port == 1234 and module.request.conversation.plan.actions[0].receive == receive
    raw = resolve_arguments(['offline.invalid', '41'], app)
    assert raw.request.conversation.plan.actions[0].receive.length_offset is None
    result = replay(['offline.invalid', '41', '--records', str(tmp_path / 'unframed.bfr')], app)
    assert result.last_conversation.actions[-1].transport.received == b'\0\2AB'


def test_replay_owned_late_failure_retains_primary_and_cleanup(tmp_path, application_factory, monkeypatch, capsys):
    import bytefault.application as application_module
    import bytefault.replay.replay_packet as replay
    from bytefault.management.configuration import ServiceConfiguration
    from bytefault.monitoring import Monitoring
    from bytefault.monitoring.configuration import MonitoringConfig, ObservationRule
    monitor = Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',
        rules=(ObservationRule('unrequested', 'unrequested', actions=({'report': True},)),)))
    app, traces = application_factory(monitoring=monitor,
        service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results')))
    attach = app._attach_services
    def failing_report(request):
        attach(request)
        app.reporting.port = lambda request: (_ for _ in ()).throw(OSError('controlled late report failure'))
    monkeypatch.setattr(app, '_attach_services', failing_report)
    monkeypatch.setattr(application_module, 'Application', lambda **kwargs: app)
    class BrokenDiagnostic:
        def write(self, text):
            raise OSError('controlled diagnostic delivery failure')
    with monkeypatch.context() as scoped:
        scoped.setattr(replay.sys, 'stderr', BrokenDiagnostic())
        result = replay.replay_packets('offline.invalid', 1234, [b'A', b'BB', b'C'], skip_recv=True,
            record_path=str(tmp_path / 'owned.bfr'), tcp_pre_delay_s=0)
    assert result.outcome == 'cleanup_failed' and result.execution_outcome == 'completed'
    assert [item['state'] for item in result.literal_items] == ['completed'] * 3
    assert [item['result'].actions[-1].transport.offered for item in result.literal_items] == [b'A', b'BB', b'C']
    assert any(fact['owner'] == 'management' for fact in result.application_cleanup_errors)
    assert any(fact['owner'] == 'replay_diagnostic' and 'delivery failure' in fact['error']
               for fact in result.application_cleanup_errors)
    assert app.management.store.closed and app.reporting.root.closed and traces[0][1].closed
    assert any(record.kind == 'report_outcome' and record.data['outcome']['status'] == 'failed'
               for record in app.read_service_records(result.run_id))
    assert 'REQUIRED RECORDING STOP' not in capsys.readouterr().err
    # A cleanup exception cannot replace an original preparation exception.
    failed, _ = application_factory()
    monkeypatch.setattr(application_module, 'Application', lambda **kwargs: failed)
    with monkeypatch.context() as scoped:
        scoped.setattr(failed, 'close', lambda: (_ for _ in ()).throw(OSError('controlled close failure')))
        with pytest.raises(ValueError, match='Invalid hex string'):
            replay.replay_packets('offline.invalid', 1234, ['not-hex'])
    diagnostic = capsys.readouterr().err
    assert 'REPLAY CLEANUP/FOLLOWUP FAILURE' in diagnostic and 'REQUIRED RECORDING STOP' not in diagnostic


def test_saved_case_collection_keeps_one_execution_after_failed_check(tmp_path, application_factory,
        monkeypatch):
    import bytefault.management.collection as collection_module
    from types import SimpleNamespace
    commands = []
    def process(command, **options):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')
    monkeypatch.setattr(collection_module.subprocess, 'run', process)
    original, _ = application_factory(stream_options={'reads': (b'OK',)})
    source = base(tmp_path)
    assert original.submit(source).outcome == 'completed'
    data, _ = case_data(original, source)
    copied = tmp_path / 'single.case.json'
    copied.write_text(json.dumps(data), encoding='utf-8')

    app, traces = application_factory(stream_options={'reads': (b'OK',)})
    transport_factory = app.transport_factory
    def unavailable_check(target):
        adapter = transport_factory(target)
        stream = traces[-1][1]
        connect, attempts = stream.connect, [0]
        def controlled(address):
            attempts[0] += 1
            stream.open_error = OSError('controlled service check failure') if attempts[0] == 2 else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = unavailable_check
    argv = ['saved-case', json.dumps({'path': str(copied)}), '--records',
        str(tmp_path / 'selected.bfr'), '--collect-cores', '--core-dump-wait', '0', '--ssh-user', 'operator',
        '--ssh-pass', 'cleartext']
    prepared = execute_arguments(argv, app)
    assert not traces and prepared.monitoring_configuration.collect_cores
    assert prepared.monitoring_configuration.retries == 0
    assert prepared.monitoring_configuration.reconnect_attempts == 0
    result = execute_arguments([*argv, '--execute'], app)
    offered = [entry[1] for trace, _, _ in traces for entry in trace if entry[0] == 'offer']
    assert result.fuzz_tests == 1 and offered == [b'S', bytes.fromhex('00024142')]
    status = app.management.wait(5)
    assert len(status['outcomes']) == 1, {name: status[name] for name in (
        'pending', 'failures', 'completed_total', 'failed_total', 'outcome')}
    assert status['outcomes'][0]['outcome']['collection']['status'] == 'succeeded'
    assert len(commands) == 1 and commands[0][0] == 'rsync'


def test_owned_callable_replay_completes_password_followup(
        tmp_path, application_factory, monkeypatch, capsys):
    import bytefault.application as application_module
    import bytefault.management.collection as collection_module
    import bytefault.replay.replay_packet as replay
    from bytefault.fuzzers.cli import operation_exit_code
    from types import SimpleNamespace

    commands = []
    def process(command, **options):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')
    monkeypatch.setattr(collection_module.subprocess, 'run', process)
    app, traces = application_factory()
    transport_factory = app.transport_factory
    def unavailable_check(target):
        adapter = transport_factory(target)
        stream = traces[-1][1]
        connect, attempts = stream.connect, [0]
        def controlled(address):
            attempts[0] += 1
            stream.open_error = OSError('controlled service check failure') if attempts[0] == 2 else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = unavailable_check
    monkeypatch.setattr(application_module, 'Application', lambda **_kwargs: app)
    result = replay.replay_packets('offline.invalid', 1234, (b'A',), skip_recv=True,
        wait_between=0, record_path=str(tmp_path / 'owned-password.bfr'),
        collect_cores=True, ssh_user='operator', ssh_pass='cleartext')
    primary = app.status(result.run_id)['result']
    assert primary.outcome == 'completed'
    assert result.outcome == 'completed' and result.execution_outcome == primary.outcome
    assert operation_exit_code(result) == 0
    assert not result.application_cleanup_errors
    selected = app.management.status()['outcomes'][0]['outcome']
    assert selected['collection']['status'] == 'succeeded'
    assert selected['action_id'] and selected['event_id'] and selected['observation_id']
    assert len(commands) == 1 and commands[0][0] == 'rsync'
    assert [entry[1] for trace, _, _ in traces for entry in trace if entry[0] == 'offer'] == [b'A']
    assert 'REPLAY FOLLOWUP PENDING' not in capsys.readouterr().err


def test_saved_cli_execution_and_record_errors(tmp_path, application_factory, capsys):
    app, _ = application_factory(stream_options={'reads': (b'OK',)})
    request = base(tmp_path)
    app.submit(request)
    _, start = case_data(app, request)
    data = execute_arguments(['export-case', request.record_path, start.record_id], app)
    from bytefault.fuzzers.cli import main
    assert main(['export-case', request.record_path, start.record_id]) == 0
    assert json.loads(capsys.readouterr().out) == data
    copied = tmp_path / 'case.json'
    copied.write_text(json.dumps(data), encoding='utf-8')
    result = execute_arguments(['saved-intent', json.dumps({'path': str(copied)}),
        '--records', str(tmp_path / 'cli-rerun.bfr'), '--results', str(tmp_path / 'caller-results'),
        '--core-dump-wait', '1.25', '--ssh-user', 'operator', '--execute'], app)
    assert result.outcome == 'completed' and offers(result) == [b'S', b'\0\2AB']
    owner, configuration = app.management, app.service_configuration
    again = execute_arguments(['saved-case', json.dumps({'path': str(copied)}),
        '--records', str(tmp_path / 'cli-again.bfr'), '--execute'], app)
    assert again.outcome == 'completed' and app.management is owner and app.service_configuration == configuration
    assert configuration.core_write_wait == 1.25 and configuration.ssh_user == 'operator'
    assert 'saved_case' in app.inspect()['operations'] and 'saved' not in app.inspect()['unavailable']
    with pytest.raises(ContractError, match='not_found'):
        app.export_case(request.record_path, 'absent')
    with pytest.raises(ContractError, match='conflicting_input'):
        app.import_case(data, steps=(SavedStepIntent('A', 'recorded', True),))
    with pytest.raises(ContractError, match='duplicate'):
        app.import_case(data, steps=(SavedStepIntent('A'), SavedStepIntent('A')))


@pytest.mark.parametrize('kind', ['dataset', 'seed_file', 'seed_directory'])
def test_fresh_retained_source_contract_and_output_collision(tmp_path, application_factory, kind):
    from contextlib import closing
    app, _ = application_factory(stream_options={'reads': (b'OK',)})
    request = base(tmp_path)
    source_dir = tmp_path / 'seeds'
    source_dir.mkdir()
    source_file = source_dir / 'one.bin'
    source_file.write_bytes(b'AB')
    if kind == 'dataset':
        spec = {'source_id': 'source', 'kind': 'dataset', 'options': {'name': 'neutral', 'subset': 'selected'}}
    else:
        spec = {'source_id': 'source', 'kind': 'seed', 'options': (
            {'seed_files': (str(source_file),)} if kind == 'seed_file' else
            {'seed_directory': str(source_dir)})}
    config = {'sources': (spec,), 'sets': ({'set_id': 'set', 'source_id': 'source'},),
        'positions': ({'position_id': 'body', 'set_id': 'set', 'operation': 'replace', 'field_id': 'body'},)}
    if kind == 'dataset':
        config['datasets'] = {'neutral': {'selected': (b'CD',)}}
    with closing(app.generate(request, config, limit=1)) as generation:
        generated = next(generation)
        app.submit(generated)
    data, _ = case_data(app, generated)
    prepared = app.import_case(data, mode='fresh_dynamic', record_path=str(tmp_path / 'fresh.bfr'))
    result = app.submit(prepared)
    assert result.outcome == 'completed'
    assert result.actions[-1].transport.offered == (b'\0\2CD' if kind == 'dataset' else b'\0\2AB')
    if kind != 'dataset':
        for output in (source_file, source_dir / 'new-output.bfr') if kind == 'seed_directory' else (source_file,):
            with pytest.raises(ContractError, match='source_collision'):
                app.import_case(data, steps=(SavedStepIntent('A', 'fresh_dynamic'),), record_path=str(output))
        assert source_file.read_bytes() == b'AB'


def test_partial_tail_origin_and_closed_monitoring_hydration(tmp_path, application_factory):
    from bytefault.core.contracts import (Correlation, MonitoringDecision, MonitoringObligation, freeze)
    app, _ = application_factory(stream_options={'reads': (b'OK',)})
    request = base(tmp_path)
    app.submit(request)
    _, start = case_data(app, request)
    with open(request.record_path, 'ab') as stream:
        stream.write(b'BFR')
    portable = app.export_case(request.record_path, start.record_id)
    assert value_from_data(portable['origin'])['recovery_issue']['kind'] == 'incomplete'
    assert app.submit(app.import_case(portable, record_path=str(tmp_path / 'tail-rerun.bfr'))).outcome == 'completed'
    decision = MonitoringDecision('decision', 'obs', Correlation('r', 'c', 'v', 'a', 'attempt'),
        'hold', 'awaited', ('external',), obligations=(MonitoringObligation('external', 'followup'),))
    assert contract_from_record(MonitoringDecision, freeze(decision)) == decision
    with pytest.raises(ContractError, match='unsupported_contract'):
        contract_from_record(object, {})


@pytest.mark.parametrize('execution_error', [False, True, 'retry_save', 'retry_stop', 'retry_cleanup', 'retry_setup'])
def test_reached_list_failure_and_preflight_failure_are_not_unsent(tmp_path, application_factory, monkeypatch, execution_error):
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.fuzzers.fuzzer import ProtocolFuzzer
    retry_boundary = isinstance(execution_error, str)
    if retry_boundary:
        from bytefault.monitoring import Monitoring
        from bytefault.core.contracts import CampaignDirective
        class FinalRetry:
            def observe(self, fact):
                return Monitoring().observe(fact)
            def decide_attempt(self, context, observations):
                return CampaignDirective('final:' + context.correlation.attempt_id,
                    context.campaign_id, context.test_id, context.correlation,
                    'retry' if context.final and context.attempt_number == 1 else 'advance')
        app, traces = application_factory(monitoring=FinalRetry())
    else:
        app, traces = application_factory()
    first = raw_request(b'A')
    if execution_error == 'retry_setup':
        from bytefault.fuzzers.inputs import positional_plan
        first = replace(first, plan=positional_plan((b'S', b'A')), selected_actions=('2',))
    second = replace(first, row=replace(first.row, row_id='second'))
    if execution_error is True:
        ordinary = ProtocolFuzzer._action_result
        def fail(self, request, result):
            ordinary(self, request, result)
            if request.campaign.case_number == 2:
                raise ValueError('controlled execution collaborator failure')
        monkeypatch.setattr(ProtocolFuzzer, '_action_result', fail)
    elif not retry_boundary:
        second = replace(second, calculations=(Calculation('required', '1', 'unknown', required=True),))
    cases = (first, second, first)
    request = ApplicationRequest(first, TransportRequest('offline.invalid', 1234, 3), str(tmp_path / 'list.bfr'))
    if retry_boundary:
        from bytefault.core.storage import LocalRecordStore
        ordinary_append = LocalRecordStore.append
        def append(store, kind, identity, data):
            if store.path.name == 'list.bfr' and kind == 'retry_wait':
                if execution_error == 'retry_save':
                    raise OSError('reopened required retry wait failed')
                reference = ordinary_append(store, kind, identity, data)
                if execution_error == 'retry_stop':
                    app.control(first.run_id, 'stop')
                elif execution_error == 'retry_cleanup':
                    traces[0][1].close_error = OSError('reopened retry close failed')
                else:
                    traces[0][1].sends = [OSError('reopened setup send failed')]
                return reference
            return ordinary_append(store, kind, identity, data)
        monkeypatch.setattr(LocalRecordStore, 'append', append)
        if execution_error == 'retry_cleanup':
            with pytest.raises(ContractError, match='cleanup_failed'):
                app.campaign(request, cases=cases)
        else:
            app.campaign(request, cases=cases)
    else:
        with pytest.raises((ValueError, ContractError)):
            app.campaign(request, cases=cases)
    result = app.status(first.run_id)['result']
    if retry_boundary:
        expected = {'retry_save': 'recording_failed', 'retry_stop': 'stopped',
                    'retry_cleanup': 'cleanup_failed', 'retry_setup': 'transport_failed'}[execution_error]
        assert tuple(item['state'] for item in result.literal_items) == ('completed', 'completed', expected)
        item = result.literal_items[-1]
        assert item['previous_result'].outcome == 'completed'
        assert item['previous_result'].actions[-1].transport.accepted_prefix == b'A'
        if execution_error in ('retry_stop', 'retry_setup'):
            assert item['result'].outcome == expected
            assert not app.read_records(first.run_id).incomplete_cases
            if execution_error == 'retry_setup':
                assert item['result'].actions[-1].transport.error == 'reopened setup send failed'
        else:
            assert item['result'] is None
            assert item['retry_progress']['terminal_available'] is False
            assert item['retry_progress']['reopen_reference'] is not None
            assert item['retry_progress']['actions'][0].transport.accepted_prefix == b'A'
            assert app.read_records(first.run_id).incomplete_cases
        expected_offers = [b'S', b'A'] * 3 + [b'S'] if execution_error == 'retry_setup' else [b'A'] * 3
        assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == expected_offers
        return
    assert tuple(item['state'] for item in result.literal_items) == ('completed', 'failed', 'not_started')
    if execution_error:
        assert result.literal_items[1]['result'].actions[0].transport.acceptance == 'accepted'
    else:
        assert result.literal_items[1]['error']['code'] == 'unsupported_capability'
    assert sum(t[0] == 'offer' for t in traces[0][0]) == (2 if execution_error else 1)
    assert traces[0][1].closed


def test_literal_required_failure_cli_callable_parity(tmp_path, application_factory):
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.core.records import encode_value
    for client in ('callable', 'cli'):
        app, traces = application_factory()
        first = raw_request(b'A')
        second = replace(first, calculations=(Calculation('overflow', '1', 'length', offset=0,
            size=1, counts='range', range_start=0, range_end=300, required=True),))
        request = ApplicationRequest(first, TransportRequest('offline.invalid', 1234, 3),
                                     str(tmp_path / (client + '.bfr')))
        cases = (first, second, first)
        with pytest.raises(ContractError, match='calculation_overflow'):
            if client == 'callable':
                app.campaign(request, cases=cases)
            else:
                execute_arguments(['offline.invalid', '--port', '1234', '--records', request.record_path,
                    '--health-check-mode', 'disabled', '--campaign-json', json.dumps(encode_value(
                        {'cases': tuple(request_to_data(c) for c in cases)}))], app)
        # CLI admission gives its own run ID; both projections retain identical
        # execution facts and known remaining ordinals.
        result = app.status(next(iter(app._runs)))['result']
        assert result.outcome == 'failed'
        assert tuple(i['state'] for i in result.literal_items) == ('completed', 'failed', 'not_started')
        assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == [b'A']
