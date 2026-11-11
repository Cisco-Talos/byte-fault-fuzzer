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

"""CC-03 actual killed writers, ordinary resumed campaigns and retained holds."""
from dataclasses import replace
from pathlib import Path
import json
import time

import pytest

from bytefault.application import (ApplicationRequest, ResumeIntent, ResumeChoice)
from bytefault.core.contracts import (ContractError, MonitoringCompletion, TransportRequest,
    CampaignOptions)
from bytefault.core.storage import reopen_records
from bytefault.fuzzers.cli import execute_arguments
from bytefault.fuzzers.inputs import raw_request, request_from_record
from bytefault.monitoring import Monitoring, MonitoringConfig


def killed(child, point):
    process, root = child('resume_' + point)
    deadline = time.monotonic() + 7
    while not (root / 'ready').exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(.01)
    if not (root / 'ready').exists():
        process.kill()
        pytest.fail(repr(process.communicate(timeout=5)))
    process.kill()
    process.wait(timeout=5)
    return root / 'campaign.bfr'


def offered(traces):
    return [value[1] for trace, _, _ in traces for value in trace if value[0] == 'offer']


def reference(tmp_path, application_factory):
    app, traces = application_factory(monitoring=Monitoring(configuration=MonitoringConfig(
        health_check_mode='disabled', retries=1, recovery_delays=(0,))))
    base = ApplicationRequest(raw_request(b'X'), TransportRequest('offline.invalid', 1234, 1),
                              str(tmp_path / 'reference.bfr'))
    generation = {'sources': ({'source_id': 'S', 'kind': 'random',
        'options': {'min_len': 2, 'max_len': 2, 'count': 3, 'seed': 913}},),
        'sets': ({'set_id': 'S', 'source_id': 'S'},),
        'positions': ({'position_id': 'P', 'set_id': 'S', 'operation': 'append'},)}
    result = app.campaign(base, generation=generation)
    assert result.outcome == 'completed'
    return offered(traces)


@pytest.mark.parametrize('point', ['materialized', 'postoffer', 'result', 'partialtail'])
@pytest.mark.parametrize('disposition', ['rerun', 'skip'])
def test_actual_termination_unresolved_then_explicit_resume(tmp_path, campaign_storage_child,
                                                         application_factory, point, disposition):
    journal = killed(campaign_storage_child, point)
    before = journal.read_bytes()
    expected = reference(tmp_path, application_factory)
    app, traces = application_factory()
    inspection = app.inspect_resume(str(journal))
    assert [item['state'] for item in inspection.cases] == ['completed', 'uncertain']
    uncertain = inspection.cases[1]['conversation_id']
    pending = app.resume(ResumeIntent(str(journal)), record_path=str(tmp_path / 'unresolved.bfr'))
    assert traces == []
    unresolved = app.submit(pending)
    assert unresolved.outcome == unresolved.execution_outcome == 'unresolved'
    assert unresolved.resume['barrier']['case_number'] == 2 and offered(traces) == []
    # The linked journal alone carries source history, including uncertain facts.
    source = tmp_path / 'source-preserved.bfr'
    journal.rename(source)
    arguments = ['resume-run', json.dumps({'path': pending.record_path,
        'choices': [{'conversation_id': uncertain, 'disposition': disposition}]}),
        '--records', str(tmp_path / 'resumed.bfr'), '--results', str(tmp_path / 'results'),
        '--core-dump-wait', '.75', '--no-ui', '--hide-field', 'opaque', '--no-test-banner', '-vv']
    before_prepare = len(offered(traces))
    resumed = execute_arguments(arguments, app, terminal=True)
    assert len(offered(traces)) == before_prepare and app.management is None
    if point == 'partialtail' and disposition == 'rerun':
        result = execute_arguments([*arguments, '--execute'], app, terminal=True)
        assert app.management is not None and app.service_configuration.core_write_wait == .75
    else:
        result = app.submit(resumed)
    assert result.outcome == 'completed'
    assert offered(traces) == (expected[1:] if disposition == 'rerun' else expected[2:])
    records = app.read_records(result.run_id).records
    start = next(r for r in records if r.kind == 'resume_start')
    assert start.data['choices'][0]['disposition'] == disposition
    assert records.index(start) < next(i for i, r in enumerate(records) if r.kind == 'materialization')
    requests = [r.data['request'] for r in records if r.kind == 'case_start']
    assert [r['campaign']['case_number'] for r in requests] == ([2, 3] if disposition == 'rerun' else [3])
    assert all(r['conversation_id'] != uncertain for r in requests)
    assert source.read_bytes() == before
    assert not app.inspect_resume(resumed.record_path).continuation['hold']
    finished = app.resume(ResumeIntent(resumed.record_path), record_path=str(tmp_path / 'again.bfr'))
    count = len(offered(traces))
    assert app.submit(finished).outcome == 'completed'
    assert len(offered(traces)) == count
    assert bool(inspection.recovery_issue) == (point == 'partialtail')


def test_retained_individual_hold_completion_and_stale_attempt(tmp_path, campaign_storage_child,
                                                            application_factory):
    journal = killed(campaign_storage_child, 'hold')
    from bytefault.core.contracts import MonitoringDecision
    class CurrentPolicy:
        held=False
        def evaluate(self,observation):
            disposition='hold' if not self.held else 'continue'
            self.held=True
            return MonitoringDecision('current:'+observation.observation_id,observation.observation_id,
                observation.correlation,disposition,'awaited' if disposition=='hold' else 'nonblocking',
                ('report',) if disposition=='hold' else ())
    app, traces = application_factory(monitoring=Monitoring(CurrentPolicy()))
    inspection = app.inspect_resume(str(journal))
    hold = inspection.continuation['hold']
    key = inspection.cases[1]['conversation_id']
    request = app.resume(ResumeIntent(str(journal), (ResumeChoice(key, 'rerun'),)),
                         record_path=str(tmp_path / 'held.bfr'))
    handle = app.start(request)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        engine = app._run(handle.run_id).engine
        if engine is not None and engine.continuation.hold is not None: break
        time.sleep(.005)
    try:
        assert engine.continuation.hold.decision_id == hold['decision_id']
        assert offered(traces) == []
        from bytefault.fuzzers.inputs import contract_from_record
        typed = contract_from_record(MonitoringDecision, hold)
        assert engine.continuation.satisfied == {('collection', 'one')}
        def completion(action, status='succeeded', correlation=typed.correlation, condition='collection'):
            return MonitoringCompletion('completion:' + str(action) + status + condition, typed.decision_id,
                typed.observation_id, correlation, condition, status, followup_action_id=action)
        assert not app.complete_monitoring(handle.run_id, completion('one', correlation=replace(
            typed.correlation, attempt_id='another-attempt')))
        assert app.complete_monitoring(handle.run_id, completion('one'))
        for status in ('pending', 'failed', 'disabled'):
            assert app.complete_monitoring(handle.run_id, completion('two', status))
            assert engine.continuation.hold is not None and offered(traces) == []
        assert app.complete_monitoring(handle.run_id, completion('two'))
        assert engine.continuation.hold is not None
        for action in ('one','two'):
            assert app.complete_monitoring(handle.run_id, completion(action, condition='report'))
        assert engine.continuation.hold is not None and offered(traces) == []
        assert app.complete_monitoring(handle.run_id, completion(None, condition='readiness'))
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and (engine.continuation.hold is None or
                engine.continuation.hold.decision_id==typed.decision_id):
            time.sleep(.005)
        current=engine.continuation.hold
        assert current is not None and current.correlation.attempt_id != typed.correlation.attempt_id
        assert not app.complete_monitoring(handle.run_id,completion('two'))
        assert engine.continuation.hold is current
        assert app.complete_monitoring(handle.run_id,MonitoringCompletion('current-complete',
            current.decision_id,current.observation_id,current.correlation,'report','succeeded'))
        assert handle.wait(5).outcome == 'completed'
        assert len(offered(traces)) == 2
        assert not app.complete_monitoring(handle.run_id, completion('one'))
    finally:
        handle.control('stop')
        handle.wait(5)


def test_resume_input_failures_are_typed(tmp_path, application_factory):
    app, traces = application_factory()
    with pytest.raises(ContractError, match='not_found'):
        app.resume(ResumeIntent(str(tmp_path / 'absent.bfr')))
    from bytefault.core.storage import LocalRecordStore
    malformed=tmp_path/'malformed.bfr'
    with LocalRecordStore(malformed) as store:
        store.append('campaign_start',{'run_id':'malformed'},
            {'application_request':{'resume':{'history':()}}})
    for operation in (lambda:app.inspect_resume(str(malformed)),
                      lambda:app.resume(ResumeIntent(str(malformed)))):
        with pytest.raises(ContractError,match='malformed'):
            operation()
    unsupported=tmp_path/'unsupported.bfr'
    unsupported.write_bytes(b'BFR2'+b'\0'*8)
    with pytest.raises(ContractError,match='unsupported_version'):
        app.resume(ResumeIntent(str(unsupported)))
    assert traces == []


def test_second_actual_interruption_retains_logical_origin(tmp_path, campaign_storage_child, application_factory):
    original = killed(campaign_storage_child, 'postoffer')
    process, root = campaign_storage_child('resume_again', source=original)
    deadline = time.monotonic() + 7
    while not (root/'ready').exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(.01)
    if not (root/'ready').exists():
        process.kill();pytest.fail(repr(process.communicate(timeout=5)))
    process.kill();process.wait(timeout=5)
    app,traces=application_factory()
    journal=root/'campaign.bfr'
    inspection=app.inspect_resume(str(journal))
    assert [(i['case_number'],i['state']) for i in inspection.cases]==[(1,'completed'),(2,'uncertain')]
    key=inspection.cases[1]['conversation_id']
    (root/'source.bfr').unlink()
    expected=reference(tmp_path,application_factory)
    request=app.resume(ResumeIntent(str(journal),(ResumeChoice(key,'rerun'),)),
        record_path=str(tmp_path/'third.bfr'))
    assert app.submit(request).outcome=='completed'
    assert offered(traces)==expected[1:]
    histories=app.read_records(request.conversation.run_id).records
    calls=[r.data['request'] for r in histories if r.kind=='case_start']
    assert [r['campaign']['case_number'] for r in calls]==[2,3]
    assert calls[0]['original_request']['resume']['logical_conversation_id']==key
    prior=next(r for r in reopen_records(journal).records if r.kind=='case_start')
    assert prior.identity['conversation_id'] != calls[0]['conversation_id']


def test_retained_deadline_expiry_enforces_configured_stop(tmp_path,campaign_storage_child,application_factory):
    journal=killed(campaign_storage_child,'expiry')
    app,traces=application_factory()
    inspection=app.inspect_resume(str(journal))
    deadline=inspection.continuation['deadline']
    assert deadline is not None
    factory=app.transport_factory
    def transport(target):
        adapter=factory(target)
        traces[-1][2].now=deadline+1
        return adapter
    app.transport_factory=transport
    request=app.resume(ResumeIntent(str(journal),(ResumeChoice(inspection.cases[1]['conversation_id'],'rerun'),)),
        record_path=str(tmp_path/'expiry.bfr'))
    result=app.submit(request)
    assert result.outcome=='monitoring_stopped' and offered(traces)==[]
    expiry=next(r for r in app.read_records(result.run_id).records if r.kind=='monitoring_expiry_result')
    assert expiry.data['applied'] and expiry.data['treatment']=='stop'


def retained_prefix(journal, output, predicate):
    snapshot=reopen_records(journal)
    index=next(i for i,r in enumerate(snapshot.records) if predicate(r))
    ref=snapshot.refs[index]
    output.write_bytes(journal.read_bytes()[:ref.offset+ref.length])
    return str(output)


def test_literal_variants_selection_setup_failure_and_current_items(tmp_path,application_factory):
    from bytefault.core.contracts import (Calculation,ConversationAction,ConversationRequest,
        PassivePlan,PreparedRow,ReceiveRequest,ResponseEdge)
    from bytefault.application import SavedStepIntent
    app,_=application_factory(stream_options={'reads':(b'OK',)},monitoring=Monitoring(configuration=
        MonitoringConfig(health_check_mode='disabled',retries=0)))
    setup=ConversationAction('setup',b'S',receive=ReceiveRequest(cap=2,deadline=3),
        edges=(ResponseEdge(b'OK','selected','positive'),),unknown_target=None)
    selected=ConversationAction('selected',b'\0Z',receive=ReceiveRequest(requested=False))
    conversation=ConversationRequest(PassivePlan('neutral',1,(setup,selected)),PreparedRow('row',1),
        ('selected',),'literal','case','conversation',repair=True,
        calculations=(Calculation('length','selected','payload_length',0,1,payload_offset=1),))
    path=tmp_path/'literal.bfr'
    base=ApplicationRequest(conversation,TransportRequest('offline.invalid',1234,1),str(path))
    app.campaign(base,cases=(conversation,conversation,conversation),
        options=CampaignOptions(selected_cases=(2,3),variants=('normal','length4')))
    prefix=retained_prefix(path,tmp_path/'prefix.bfr',lambda r:r.kind=='materialization' and
        r.identity.get('case_number')==2 and r.identity.get('variant_id')=='normal' and r.identity.get('action_id')=='selected')
    resumed,traces=application_factory(stream_options={'reads':(b'NO',)})
    inspection=resumed.inspect_resume(prefix)
    key=next(i['conversation_id'] for i in inspection.cases if i['state']=='uncertain')
    request=resumed.resume(ResumeIntent(prefix,(ResumeChoice(key,'rerun',(
        SavedStepIntent('setup','fresh_dynamic'),)),)),record_path=str(tmp_path/'failed-setup.bfr'))
    result=resumed.submit(request)
    assert result.outcome=='transport_failed' or result.outcome=='monitoring_failed'
    assert offered(traces) and set(offered(traces))=={b'S'}
    assert [(i['case_number'],i['variant_id']) for i in result.literal_items]==[
        (1,'normal'),(1,'length4'),(2,'normal'),(2,'length4'),(3,'normal'),(3,'length4')]
    assert [i['state'] for i in result.literal_items[:2]]==['omitted','omitted']
    attempted=[i for i in result.literal_items if i['result'] is not None]
    assert attempted and all(i['result']['unreached'] for i in attempted)
    assert attempted[0]['result']['actions'][0]['transport']['received']==b'NO'
    assert all(i['result']['outcome']!='completed' for i in attempted)
    # A successful resume retains both variants' exact recorded/fresh bytes and
    # original numbers, including original case3 sequence preparation.
    successful,good=application_factory(stream_options={'reads':(b'OK',)*4})
    request=successful.resume(ResumeIntent(prefix,(ResumeChoice(key,'rerun'),)),
        record_path=str(tmp_path/'successful.bfr'))
    result=successful.submit(request)
    assert result.outcome=='completed'
    assert offered(good)==[b'S',b'\x01Z',b'S',b'\x04Z',b'S',b'\x01Z',b'S',b'\x04Z']
    assert [i['state'] for i in result.literal_items]==['omitted','omitted']+['completed']*4
    assert all(i['result']['conversation_id']==i['conversation_id'] for i in result.literal_items[2:])


def test_source_inventory_and_resume_start_required_save(tmp_path,campaign_storage_child,application_factory,monkeypatch):
    journal=killed(campaign_storage_child,'materialized')
    app,traces=application_factory()
    key=app.inspect_resume(str(journal)).cases[1]['conversation_id']
    request=app.resume(ResumeIntent(str(journal),(ResumeChoice(key,'rerun'),)),
        record_path=str(tmp_path/'save-fails.bfr'))
    from bytefault.core.storage import LocalRecordStore
    from bytefault.core.records import RecordError,RequiredSaveFailure
    original=LocalRecordStore.append
    def append(store,kind,identity,data):
        if kind=='resume_start':raise RecordError('controlled required restart save failure')
        return original(store,kind,identity,data)
    with monkeypatch.context() as selected:
        selected.setattr(LocalRecordStore,'append',append)
        with pytest.raises(RequiredSaveFailure,match='controlled required restart'):
            app.submit(request)
    assert app.status(request.conversation.run_id)['state']=='recording_failed'
    assert offered(traces)==[]
    seeds=tmp_path/'seeds';seeds.mkdir()
    for key in ('A','B','C'):(seeds/key).write_bytes(key.encode())
    source,_=application_factory(monitoring=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled')))
    original_path=tmp_path/'seeds.bfr'
    base=ApplicationRequest(raw_request(b'X'),TransportRequest('offline.invalid',1234,1),str(original_path))
    generation={'sources':({'source_id':'S','kind':'seed','options':{'seed_directory':str(seeds)}},),
        'sets':({'set_id':'S','source_id':'S'},),'positions':({'position_id':'P','set_id':'S','operation':'append'},)}
    assert source.campaign(base,generation=generation).outcome=='completed'
    prefix=retained_prefix(original_path,tmp_path/'seed-prefix.bfr',lambda r:
        r.kind=='materialization' and r.identity.get('case_number')==2)
    # All recorded materializations are self-contained; unresolved admission
    # does not reopen the old seed directory or make it a current input.
    recorded=app.resume(ResumeIntent(prefix),record_path=str(seeds/'new-output.bfr'))
    assert app._current_input_inventory(recorded)==(
        {Path(prefix).resolve(),Path(str(original_path)+'.preparation.bfr').resolve()},set())
    from bytefault.application import SavedStepIntent
    selected=next(i['conversation_id'] for i in app.inspect_resume(prefix).cases if i['state']=='uncertain')
    with pytest.raises(ContractError,match='source_collision'):
        app.resume(ResumeIntent(prefix,(ResumeChoice(selected,'rerun',(
            SavedStepIntent('1','fresh_dynamic'),)),)),record_path=str(seeds/'new-output.bfr'))
    assert not (seeds/'new-output.bfr').exists()
    for seed in seeds.iterdir():seed.unlink()
    seeds.rmdir()
    # The next retained uncertain case is a barrier; neither preparation nor
    # execution may reopen the now-missing historical generation directory.
    assert app.submit(recorded).outcome=='unresolved'
    assert offered(traces)==[]


def test_single_recorded_case_keeps_nonfirst_ordinal_and_no_repetition(tmp_path,application_factory):
    from bytefault.core.contracts import PreparedRow
    original,_=application_factory()
    conversation=replace(raw_request(b'one'),row=PreparedRow('selected-original',17))
    journal=tmp_path/'single.bfr'
    request=ApplicationRequest(conversation,TransportRequest('offline.invalid',1234,1),str(journal))
    assert original.submit(request).outcome=='completed'
    prefix=retained_prefix(journal,tmp_path/'single-prefix.bfr',lambda r:r.kind=='materialization')
    app,traces=application_factory()
    state=app.inspect_resume(prefix)
    resumed=app.resume(ResumeIntent(prefix,(ResumeChoice(state.cases[0]['conversation_id'],'rerun'),)),
        record_path=str(tmp_path/'single-rerun.bfr'))
    result=app.submit(resumed)
    assert result.outcome=='completed' and offered(traces)==[b'one']
    assert len(result.literal_items)==1
    assert result.literal_items[0]['case_number']==17 and result.literal_items[0]['state']=='completed'
    assert result.last_conversation.row_id=='saved-input'
    final=app.resume(ResumeIntent(resumed.record_path),record_path=str(tmp_path/'single-final.bfr'))
    assert app.submit(final).outcome=='completed' and offered(traces)==[b'one']


def test_acknowledged_unseeded_preparation_before_case_start_survives(tmp_path,campaign_storage_child,application_factory):
    journal=killed(campaign_storage_child,'prepared')
    root_records=reopen_records(journal).records
    assert not [r for r in root_records if r.kind=='campaign_case' and r.identity.get('case_number')==2]
    preparation=reopen_records(str(journal)+'.preparation.bfr')
    row=next(r for r in preparation.records if r.kind=='prepared_row' and r.data['ordinal']==2)
    expected=b'X'+row.data['row']['contributions'][0]['data']
    app,traces=application_factory()
    state=app.inspect_resume(str(journal))
    assert [(i['case_number'],i['state']) for i in state.cases]==[(1,'completed'),(2,'not_started')]
    request=app.resume(ResumeIntent(str(journal)),record_path=str(tmp_path/'prepared-resume.bfr'))
    assert request.conversation.input_files==(str(journal.resolve()),
        str(Path(str(journal)+'.preparation.bfr').resolve()))
    assert app._current_input_inventory(request)==(
        {Path(p) for p in request.conversation.input_files},set())
    # Parent preparation is copied as acknowledged input into the continuation.
    result=app.submit(request)
    assert result.outcome=='completed' and offered(traces)==[expected]
    case=next(r for r in app.read_records(result.run_id).records if r.kind=='case_start')
    assert case.identity['case_number']==2
    assert case.data['request']['original_request']['resume']['logical_conversation_id']==row.data['conversation_id']


@pytest.mark.parametrize('seeded',[True,False])
def test_partial_prepared_variant_family_completed_or_explicit_gap_before_offer(tmp_path,
    campaign_storage_child,application_factory,seeded):
    journal=killed(campaign_storage_child,'partial_family_seeded' if seeded else 'partial_family_unseeded')
    app,traces=application_factory()
    state=app.inspect_resume(str(journal))
    assert [(i['case_number'],i['variant_id'],i['state']) for i in state.cases]==[
        (1,'normal','completed'),(1,'length4','completed'),(2,'normal','not_started')]
    request=app.resume(ResumeIntent(str(journal)),record_path=str(tmp_path/'variant-resume.bfr'))
    if not seeded:
        with pytest.raises(ContractError,match='resume.variants.*missing_evidence'):
            app.submit(request)
        assert offered(traces)==[]
        again=app.inspect_resume(request.record_path)
        assert [(i['case_number'],i['variant_id'],i['state']) for i in again.cases]==[
            (1,'normal','completed'),(1,'length4','completed'),(2,'normal','not_started')]
        # The newly sampled failed reconstruction is provenance. It cannot
        # overwrite the original first sibling or fill the missing sibling.
        second=app.resume(ResumeIntent(request.record_path),record_path=str(tmp_path/'variant-again.bfr'))
        from bytefault.fuzzers.resuming import ResumeFamilies
        families=ResumeFamilies(app,second)
        try:
            original_item=next(i for i in families.items.values() if i['case_number']==2)
            preparation=reopen_records(str(journal)+'.preparation.bfr')
            retained=next(r for r in preparation.records if r.kind=='prepared_row' and r.data['ordinal']==2)
            assert original_item['request']['row']==retained.data['row']
        finally:families.close()
        with pytest.raises(ContractError,match='resume.variants.*missing_evidence'):
            app.submit(second)
        assert offered(traces)==[]
        return
    from bytefault.core.contracts import Calculation
    reference_app,full=application_factory(monitoring=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled')))
    baseline=raw_request(b'\0X')
    baseline=replace(baseline,repair=True,calculations=(Calculation('length','1','payload_length',0,1,payload_offset=1),))
    base=ApplicationRequest(baseline,TransportRequest('offline.invalid',1234,1),str(tmp_path/'variant-reference.bfr'))
    generation={'sources':({'source_id':'S','kind':'random','options':{'min_len':2,'max_len':2,'count':3,'seed':913}},),
        'sets':({'set_id':'S','source_id':'S'},),'positions':({'position_id':'P','set_id':'S','operation':'append'},)}
    assert reference_app.campaign(base,generation=generation,options=CampaignOptions(
        variants=('normal','length4'),case_limit=2)).outcome=='completed'
    result=app.submit(request)
    assert result.outcome=='completed' and offered(traces)==offered(full)[2:]
    assert [r.identity['variant_id'] for r in app.read_records(result.run_id).records if r.kind=='case_start']==['normal','length4']
    family=next(r for r in app.read_records(result.run_id).records if r.kind=='campaign_case')
    assert len(family.data['requests'])==len(family.data['materialized'])==2


def test_repeated_unresolved_preserves_all_history_without_recursive_copies(tmp_path,
    campaign_storage_child,application_factory):
    journal=killed(campaign_storage_child,'partialtail')
    original=reopen_records(journal)
    expected_ids=[r.record_id for r in original.records]
    # Retain a real unresolved run written in the former inline representation,
    # then normalize it on the first ordinary resume. Existing evidence remains
    # readable; this deliberately bypasses only the new preparation compaction.
    from collections.abc import Mapping
    def inline(value):
        if isinstance(value,Mapping):return {k:inline(v) for k,v in value.items()}
        if isinstance(value,tuple):return tuple(inline(v) for v in value)
        return value
    legacy,traces=application_factory()
    prepared=legacy.resume(ResumeIntent(str(journal)),record_path=str(tmp_path/'legacy-inline.bfr'))
    prepared=replace(prepared,resume=inline(prepared.resume))
    assert legacy.submit(prepared).outcome=='unresolved' and offered(traces)==[]
    expected_ids.extend(r.record_id for r in legacy.read_records(prepared.conversation.run_id).records)
    parent=Path(prepared.record_path)
    journal.unlink()
    sizes=[]
    for generation in range(7):
        app,traces=application_factory()
        request=app.resume(ResumeIntent(str(parent)),record_path=str(tmp_path/f'unresolved-{generation}.bfr'))
        retained=request.resume['history']
        assert [r['record_id'] for r in retained]==expected_ids
        from bytefault.core.records import Record
        assert tuple(Record(**dict(r)) for r in retained[:len(original.records)])==original.records
        result=app.submit(request)
        assert result.outcome=='unresolved' and offered(traces)==[]
        current=app.read_records(result.run_id)
        assert current.records[0].kind=='resume_start'
        assert current.records[0].data['recovery_issue'] is None
        assert any(r['kind']=='resume_start' and r['data']['recovery_issue'] is not None and
            r['data']['recovery_issue']['kind']=='incomplete' for r in retained)
        expected_ids.extend(r.record_id for r in current.records)
        destination=Path(request.record_path)
        sizes.append((destination.stat().st_size,Path(str(destination)+'.actions.bfr').stat().st_size))
        parent.unlink()
        for sibling in (Path(str(parent)+'.actions.bfr'),Path(str(parent)+'.preparation.bfr')):
            if sibling.exists():sibling.unlink()
        parent=destination
    # Bound this exact seven-generation regression: actual records grow while
    # unchanged ancestor containers remain shared, rather than doubling files.
    for column in (0,1):
        assert sizes[-1][column] < 3*sizes[0][column]
        increments=[b[column]-a[column] for a,b in zip(sizes,sizes[1:])]
        assert max(increments)<sizes[0][column]//2


def test_actual_reruns_and_portable_saved_ancestry_remain_self_contained(tmp_path,
    campaign_storage_child,application_factory):
    from pathlib import Path
    from bytefault.application import SavedCaseIntent
    from bytefault.core.records import Record
    from bytefault.fuzzers.inputs import value_from_data
    journal=killed(campaign_storage_child,'partialtail')
    original=reopen_records(journal)
    key=next(r.identity['conversation_id'] for r in original.records
        if r.kind=='case_start' and r.identity.get('case_number')==2)
    expected=next(r.data['materialized']['final_bytes'] for r in original.records
        if r.kind=='materialization' and r.identity.get('case_number')==2)
    parent=journal
    executions=[]
    for generation in range(3):
        app,traces=application_factory()
        request=app.resume(ResumeIntent(str(parent),(ResumeChoice(key,'rerun'),)),
            record_path=str(tmp_path/f'rerun-{generation}.bfr'))
        retained=request.resume['history']
        assert tuple(Record(**dict(r)) for r in retained[:len(original.records)])==original.records
        assert request.resume['choices'][0]['disposition']=='rerun'
        assert request.resume['choices'][0]['conversation_id']==key
        assert any(r['kind']=='materialization' and r['data']['materialized']['final_bytes']==expected for r in retained)
        result=app.submit(request)
        assert result.outcome=='completed' and offered(traces)[0]==expected
        records=app.read_records(result.run_id)
        case=next(r for r in records.records if r.kind=='case_start' and r.identity.get('case_number')==2)
        executions.append(case.identity['conversation_id'])
        assert case.data['request']['original_request']['resume']['logical_conversation_id']==key
        data=app.export_case(request.record_path,case.record_id)
        if generation<2:
            next_parent=tmp_path/f'interrupted-again-{generation}.bfr'
            retained_prefix(Path(request.record_path),next_parent,lambda r:r.kind=='materialization' and
                r.identity.get('case_number')==2)
        else:next_parent=None
        for old in (parent,Path(request.record_path)):
            if old.exists():old.unlink()
            for sibling in (Path(str(old)+'.actions.bfr'),Path(str(old)+'.preparation.bfr')):
                if sibling.exists():sibling.unlink()
        parent=next_parent
    assert len(set(executions))==3
    ancestry_sizes=[]
    parent_ids=[]
    for generation in range(4):
        # Only the copied portable input is needed. Every parent journal and
        # source preparation sidecar above has been removed.
        portable=tmp_path/f'copy-{generation}.case.json'
        portable.write_text(json.dumps(data),encoding='utf-8')
        ancestry_sizes.append(portable.stat().st_size)
        app,traces=application_factory()
        request=app.saved_case(SavedCaseIntent(str(portable)),record_path=str(tmp_path/f'saved-{generation}.bfr'))
        parent_input=request.conversation.original_request['saved_case']['original_request']
        parent_ids.append(parent_input['conversation_id'])
        assert app.submit(request).outcome=='completed' and offered(traces)==[expected]
        records=app.read_records(request.conversation.run_id)
        case=next(r for r in records.records if r.kind=='case_start')
        data=app.export_case(request.record_path,case.record_id)
        origin=value_from_data(data['origin'])
        assert [r['record_id'] for r in origin['records']]==[r.record_id for r in records.records
            if r.identity.get('conversation_id')==case.identity['conversation_id']]
        assert origin['records'][0]['data']['request']['original_request']['saved_case']['original_request']==parent_input
        Path(request.record_path).unlink()
        Path(request.record_path+'.actions.bfr').unlink()
        portable.unlink()
    assert len(set(parent_ids))==4
    assert ancestry_sizes[-1]<3*ancestry_sizes[0]
