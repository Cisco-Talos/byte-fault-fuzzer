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

"""Actual campaign engine under the offline pre-import denial."""
from dataclasses import replace
import pytest
from bytefault.application import ApplicationRequest
from bytefault.core.contracts import CampaignOptions, CampaignConnection, Calculation, ContractError
from bytefault.fuzzers.inputs import raw_request


def base(tmp_path, name='campaign'):
    conv=raw_request(b'ABC')
    conv=replace(conv,run_id=name,conversation_id='conv',case_id='case')
    return ApplicationRequest(conv, __import__('bytefault.core.contracts',fromlist=['TransportRequest']).TransportRequest('offline.invalid',1234,10),str(tmp_path/(name+'.bfr')))


def generation(kind='list', options=None):
    return {'sources':({'source_id':'source','kind':kind,'options':options or {'payloads':(b'X',b'Y',b'Z')}},),
        'sets':({'set_id':'S','source_id':'source'},),
        'positions':({'position_id':'P','set_id':'S','operation':'overwrite','offset':1},)}


def offers(traces):
    return [step[1] for trace,_,_ in traces for step in trace if step[0]=='offer']


@pytest.mark.parametrize('mode,opens',[('fresh',3),('persistent',1)])
def test_generated_numbered_campaign_one_engine(tmp_path,application_factory,mode,opens):
    from bytefault.monitoring import Monitoring, ConfiguredPolicy
    app,traces=application_factory(monitoring=Monitoring(ConfiguredPolicy()))
    result=app.campaign(base(tmp_path),generation=generation(), options=CampaignOptions(connection=CampaignConnection(mode)))
    assert result.outcome=='completed'
    assert (result.prepared_cases,result.selected_cases,result.fuzz_tests,result.attempts)==(3,3,3,3)
    assert len(traces)==1
    trace=traces[0][0]
    assert sum(s[0]=='open' for s in trace)==opens
    assert offers(traces)==[b'AXC',b'AYC',b'AZC']
    records=app.read_records('campaign').records
    assert sum(r.kind=='campaign_case' for r in records)==3
    assert sum(r.kind=='connection_reuse' for r in records)==3-opens
    assert records[-1].kind=='campaign_terminal'


def test_selected_and_skipped_keep_original_cases(tmp_path,application_factory):
    app,traces=application_factory()
    result=app.campaign(base(tmp_path),generation=generation(), options=CampaignOptions(selected_cases=(1,2,3),skip=2))
    assert offers(traces)==[b'AZC']
    assert (result.prepared_cases,result.omitted_cases,result.selected_cases)==(3,2,1)
    result=app.campaign(base(tmp_path,'missing'),generation=generation(),options=CampaignOptions(selected_cases=(9,)))
    assert result.outcome=='unreached' and result.missing_cases==(9,)


def test_seeded_subset_matches_full_family(tmp_path,application_factory):
    app,traces=application_factory()
    config=generation('random',{'min_len':1,'max_len':3,'count':4,'seed':19})
    app.campaign(base(tmp_path,'full'),generation=config)
    full=offers(traces)
    app.campaign(base(tmp_path,'subset'),generation=config,options=CampaignOptions(selected_cases=(2,4)))
    assert offers(traces)[4:]==[full[1],full[3]]


def test_variant_family_resolved_and_preflight_before_offer(tmp_path,application_factory):
    app,traces=application_factory()
    request=base(tmp_path)
    with pytest.raises(ContractError,match='variant_unavailable'):
        app.campaign(request,generation=generation(), options=CampaignOptions(variants=('normal','length4')))
    assert offers(traces)==[]


def test_length_variant_sequence_and_shared_case(tmp_path,application_factory):
    app,traces=application_factory()
    request=base(tmp_path)
    request=replace(request,conversation=replace(request.conversation,
        plan=replace(request.conversation.plan,actions=(replace(request.conversation.plan.actions[0],seed=b'\x00\x01A'),)),
        calculations=(Calculation('len','1','payload_length',0,1,payload_offset=1), Calculation('seq','1','sequence',1,1,sequence_start=1))))
    config=generation(); config['positions']=({'position_id':'P','set_id':'S','operation':'append'},)
    result=app.campaign(request,generation=config, options=CampaignOptions(variants=('normal','length4'),case_limit=2))
    assert result.outcome=='completed' and result.fuzz_tests==4
    assert offers(traces)==[b'\x00\x01AX',b'\x04\x02AX',b'\x00\x03AY',b'\x04\x04AY']
    starts=[r.data['request'] for r in app.read_records('campaign').records if r.kind=='case_start']
    assert starts[0]['case_id']==starts[1]['case_id']
    assert starts[0]['conversation_id']!=starts[1]['conversation_id']


class RetryPolicy:
    """Controlled policy port: executor must consume decisions, not infer retries."""
    def __init__(self):
        from bytefault.monitoring import Monitoring
        self.ordinary=Monitoring()
    def observe(self, observation):
        return self.ordinary.observe(observation)
    def decide_attempt(self, context, observations):
        from bytefault.core.contracts import CampaignDirective
        failed=observations[-1].transport.error is not None
        retry=failed and context.attempt_number<=3
        return CampaignDirective('d:'+context.correlation.attempt_id,context.campaign_id,
            context.test_id,context.correlation,'retry' if retry else 'advance',
            wait_seconds=(3,5,10)[context.attempt_number-1] if retry else 0)


def test_retries_keep_exact_candidate_and_later_source(tmp_path,application_factory):
    app,traces=application_factory(monitoring=RetryPolicy(),stream_options={'sends':(OSError('fail1'),OSError('fail2'))})
    config=generation('random',{'min_len':1,'max_len':3,'count':3,'seed':71})
    result=app.campaign(base(tmp_path),generation=config)
    assert result.outcome=='completed' and (result.fuzz_tests,result.attempts)==(3,5)
    actual=offers(traces)
    assert actual[0]==actual[1]==actual[2]
    assert sum(s[1] for s in traces[0][0] if s[0]=='sleep')==pytest.approx(8)
    records=app.read_records('campaign').records
    attempts=[r.data['result'] for r in records if r.kind=='action_result']
    assert len({a['attempt_id'] for a in attempts})==5
    assert len({a['iteration_id'] for a in attempts[:3]})==1
    assert attempts[0]['materialized']==attempts[1]['materialized']==attempts[2]['materialized']
    control,control_traces=application_factory()
    control.campaign(base(tmp_path,'control'),generation=config)
    assert offers(control_traces)==[actual[0],*actual[3:]]


def test_failed_open_counts_distinct_tests_and_real_attempts(tmp_path,application_factory):
    app,traces=application_factory(monitoring=RetryPolicy(),stream_options={'open_error':OSError('refused')})
    result=app.campaign(base(tmp_path),generation=generation())
    assert result.outcome=='transport_failed'
    assert (result.selected_cases,result.fuzz_tests,result.attempts)==(3,3,12)
    assert offers(traces)==[]
    assert sum(s[0]=='open' for s in traces[0][0])==12
    assert sum(s[1] for s in traces[0][0] if s[0]=='sleep')==pytest.approx(54)


def test_literal_selection_and_unmet_ordinal(tmp_path,application_factory):
    from bytefault.core.contracts import PreparedRow,PreparedContribution,SourceInvocation,Placement
    app,traces=application_factory()
    request=base(tmp_path)
    cases=tuple(replace(request.conversation,row=PreparedRow('r'+str(i),i,
        (PreparedContribution('x',value,SourceInvocation('x','literal')),),
        (Placement('p','x','1','overwrite',1),))) for i,value in enumerate((b'X',b'Y',b'Z'),1))
    result=app.campaign(request,cases=cases,options=CampaignOptions(selected_cases=(2,3),skip=2))
    assert result.outcome=='completed' and offers(traces)==[b'AZC']


def test_variant_random_subset_resolves_omitted_families(tmp_path,application_factory):
    app,traces=application_factory()
    request=base(tmp_path,'full')
    request=replace(request,conversation=replace(request.conversation,calculations=(Calculation('length','1','payload_length',0,1,payload_offset=1),)))
    config=generation('random',{'min_len':1,'max_len':3,'count':3,'seed':32})
    config['positions']=({'position_id':'P','set_id':'S','operation':'append'},)
    options=CampaignOptions(variants=('normal','length4'))
    app.campaign(request,generation=config,options=options)
    full=offers(traces)
    assert full[0][3:]!=full[1][3:]
    request=replace(request,conversation=replace(request.conversation,run_id='subset'),record_path=str(tmp_path/'subset.bfr'))
    app.campaign(request,generation=config,options=replace(options,selected_cases=(3,)))
    assert offers(traces)[6:]==full[4:6]


@pytest.mark.parametrize('step,start,wrap,expected',[( -1,3,None,[3,2,1]),(1,257,256,[257,2,3])])
def test_sequence_retained_signed_step_initial_wrap(tmp_path,application_factory,step,start,wrap,expected):
    app,traces=application_factory()
    request=base(tmp_path)
    request=replace(request,conversation=replace(request.conversation,calculations=(Calculation('seq','1','sequence',0,2,sequence_start=start,sequence_step=step,sequence_wrap=wrap),)))
    config=generation();config['positions']=({'position_id':'P','set_id':'S','operation':'append'},)
    result=app.campaign(request,generation=config)
    assert result.outcome=='completed'
    assert [int.from_bytes(v[:2],'big') for v in offers(traces)]==expected


@pytest.mark.parametrize('operation',[ 'overwrite','replace'])
def test_length_explicit_edit_and_final_override_win(tmp_path,application_factory,operation):
    from bytefault.core.contracts import PreparedRow,PreparedContribution,SourceInvocation,Placement
    app,traces=application_factory()
    request=base(tmp_path)
    row=PreparedRow('base',1,(PreparedContribution('length',b'Z',SourceInvocation('length','literal')),
        PreparedContribution('final',b'F',SourceInvocation('final','literal'))),
        (Placement('length','length','1',operation,0,1 if operation=='replace' else None),),
        final_overrides=(Placement('final','final','1','overwrite',0),))
    request=replace(request,conversation=replace(request.conversation,row=row,
        calculations=(Calculation('length','1','payload_length',0,1,payload_offset=1),)))
    config=generation();config['positions']=({'position_id':'P','set_id':'S','operation':'append'},)
    result=app.campaign(request,generation=config,options=CampaignOptions(variants=('normal','length4'),case_limit=1))
    assert result.outcome=='completed' and offers(traces)==[b'FBCX',b'FBCX']


def test_multiaction_declared_persistent_setup_path(tmp_path,application_factory):
    from bytefault.fuzzers.inputs import positional_plan
    from bytefault.monitoring import Monitoring, ConfiguredPolicy
    app,traces=application_factory(monitoring=Monitoring(ConfiguredPolicy()))
    request=base(tmp_path)
    request=replace(request,conversation=replace(request.conversation,
        plan=positional_plan((b'SETUP',b'ABC')),selected_actions=('2',)))
    connection=CampaignConnection('persistent','2',('2',),('uninterpreted',))
    result=app.campaign(request,generation=generation(),options=CampaignOptions(connection=connection))
    assert result.outcome=='completed' and result.setup_sends==1 and result.fuzz_tests==3
    assert offers(traces)==[b'SETUP',b'AXC',b'AYC',b'AZC']
    assert sum(s[0]=='open' for s in traces[0][0])==1


@pytest.mark.parametrize('choice', ['recorded', 'declared_seed'])
def test_multiselected_retry_replays_explicit_prefix_as_setup(tmp_path,application_factory,choice):
    from bytefault.core.contracts import CampaignSetupStep, ReceiveRequest, ResponseField, ResponseEdge
    from bytefault.fuzzers.inputs import positional_plan
    app,traces=application_factory(monitoring=RetryPolicy(),stream_options={
        'sends':(3,OSError('second failed')), 'reads': (b'\x01B', b'\x01C')})
    request=base(tmp_path)
    plan = positional_plan((b'ABC', b'DEF'))
    plan = replace(plan, actions=(replace(plan.actions[0], receive=ReceiveRequest(cap=2, deadline=3),
        response_fields=(ResponseField('flag', 0, 1),),
        edges=(ResponseEdge(b'\x01', '2', 'positive', 'flag'),)), plan.actions[1]))
    request=replace(request,conversation=replace(request.conversation,
        plan=plan,selected_actions=('1','2')))
    connection=CampaignConnection(retry_setup=(CampaignSetupStep('1',choice),))
    result=app.campaign(request,generation=generation(),options=CampaignOptions(case_limit=1,connection=connection))
    assert result.outcome=='completed' and (result.fuzz_tests,result.attempts,result.setup_sends)==(2,3,1)
    prefix=b'AXC' if choice=='recorded' else b'ABC'
    assert offers(traces)==[b'AXC',b'DXF',prefix,b'DXF']
    results=[r.data['result'] for r in app.read_records('campaign').records if r.kind=='action_result']
    assert [r['iteration_id'] for r in results][2] is None
    assert results[1]['iteration_id']==results[3]['iteration_id']
    assert results[0].transport.received == b'\x01B' and results[2].transport.received == b'\x01C'
    assert results[0].response_interpretation == results[2].response_interpretation
    assert results[2].response_interpretation.fields[0].data == b'\x01'
    assert results[2].response_interpretation.target == '2'
    records=app.read_records('campaign').records
    start=next(r for r in records if r.kind=='case_start')
    replay=next(r for r in records if r.kind=='action_result' and
                r.data['result']['iteration_id'] is None)
    original_case=app.export_case(request.record_path,start.record_id)
    replayed_case=app.export_case(request.record_path,replay.record_id)
    assert original_case['intended']['1']=='415843'
    assert replayed_case['intended']['1']==prefix.hex()


@pytest.mark.parametrize('steps,code,path', [
    ((('1','recorded'),('1','declared_seed')), 'duplicate_identity', '1.action_id'),
    ((('missing','recorded'),), 'unknown_action', '0.action_id'),
    ((('1','unsupported'),), 'invalid_choice', '0.choice'),
])
def test_invalid_retry_setup_refused_before_execution(
        tmp_path, application_factory, monkeypatch, steps, code, path):
    from bytefault.core.contracts import CampaignSetupStep
    from bytefault.core.storage import LocalRecordStore
    from bytefault.logging import ActionLog

    app, traces = application_factory()
    calls = []
    original_engine, original_store, original_log = app._engine, LocalRecordStore.__init__, ActionLog.open

    def engine(request):
        calls.append('engine')
        return original_engine(request)

    def store(instance, *args, **kwargs):
        calls.append('store')
        original_store(instance, *args, **kwargs)

    def log(*args, **kwargs):
        calls.append('log')
        return original_log(*args, **kwargs)

    monkeypatch.setattr(app, '_engine', engine)
    monkeypatch.setattr(LocalRecordStore, '__init__', store)
    monkeypatch.setattr(ActionLog, 'open', staticmethod(log))
    connection = CampaignConnection(retry_setup=tuple(CampaignSetupStep(*step) for step in steps))
    with pytest.raises(ContractError) as caught:
        app.campaign(base(tmp_path), generation=generation(), options=CampaignOptions(connection=connection))
    assert caught.value.code == code
    assert caught.value.path == 'campaign.connection.retry_setup.' + path
    assert calls == [] and traces == [] and not app._runs and not app._preparations
    assert not list(tmp_path.iterdir())


def test_fresh_connection_keeps_valid_unused_reuse_and_dynamic_setup_intent(tmp_path, application_factory):
    from bytefault.core.contracts import CampaignSetupStep
    from bytefault.monitoring import Monitoring, ConfiguredPolicy

    app, traces = application_factory(monitoring=Monitoring(ConfiguredPolicy()))
    connection = CampaignConnection('fresh', '1', ('1',), ('positive',),
        retry_setup=(CampaignSetupStep('1', 'recorded', True, 'declared-regenerator'),))
    result = app.campaign(base(tmp_path), generation=generation(),
        options=CampaignOptions(case_limit=1, connection=connection))
    assert result.outcome == 'completed' and offers(traces) == [b'AXC']
    start = next(record for record in app.read_records('campaign').records if record.kind == 'campaign_start')
    assert start.data['options']['connection']['retry_setup'][0]['dynamic_source_reference'] == 'declared-regenerator'


def test_campaign_source_root_collision_unregisters_preparation(tmp_path,application_factory):
    app,traces=application_factory()
    request=base(tmp_path)
    source=__import__('pathlib').Path(request.record_path);source.write_bytes(b'X')
    config=generation('file',{'path':str(source)})
    with pytest.raises(ContractError,match='source_collision'):
        app.campaign(request,generation=config)
    assert not app._preparations and source.read_bytes()==b'X' and offers(traces)==[]



def test_stop_cancels_all_filtered_preparation_with_missing_selection(tmp_path,application_factory,monkeypatch):
    from bytefault.core.storage import LocalRecordStore
    app,traces=application_factory()
    original=LocalRecordStore.append
    rejected=[]
    def append(store,kind,identity,data):
        ref=original(store,kind,identity,data)
        if kind=='source_disposition':
            rejected.append(ref)
            app.control('campaign','stop')
        return ref
    monkeypatch.setattr(LocalRecordStore,'append',append)
    config=generation('random',{'min_len':1,'max_len':1,'count':None,'seed':7,'byte_range':(35,35)})
    config['sets'][0]['transforms']=({'mutator_id':'comments','kind':'filter_comments'},)
    result=app.campaign(base(tmp_path),generation=config,options=CampaignOptions(selected_cases=(3,)))
    assert result.outcome=='stopped' and result.missing_cases==(3,)
    assert len(rejected)==1 and result.preparation_summary['status']=='cancelled'
    assert offers(traces)==[] and not app._preparations and not app.status('campaign')['active']


@pytest.mark.parametrize('payloads,disposition',[
    ((b'A',b'#'),'stop'),((b'A',b'#',b'B'),'stop'),((b'A',b'#'),'continue'),
])
@pytest.mark.parametrize('selected_cases',[(),(1,2)])
def test_active_late_decision_at_filtered_source_boundary(tmp_path,application_factory,monkeypatch,payloads,disposition,selected_cases):
    from bytefault.core.contracts import freeze
    from bytefault.core.storage import LocalRecordStore,reopen_records
    from bytefault.monitoring import Monitoring,MonitoringConfig,ObservationRule
    monitor=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',retries=0,
        rules=(ObservationRule('late-rule','late_correlated',disposition=disposition),)))
    app,traces=application_factory(monitoring=monitor)
    request=base(tmp_path)
    request=replace(request,conversation=replace(raw_request(b'X'),run_id='campaign',
        case_id='case',conversation_id='conv'))
    config=generation(options={'payloads':payloads})
    config['sets'][0]['transforms']=({'mutator_id':'comments','kind':'filter_comments'},)
    config['positions']=({'position_id':'P','set_id':'S','operation':'append'},)
    append=LocalRecordStore.append;injected=[]
    def acknowledged(store,kind,identity,data):
        reference=append(store,kind,identity,data)
        if kind=='source_disposition' and not injected:
            original=next(o for o in monitor.observations if o.kind=='action')
            late=replace(original,observation_id='late-filtered',kind='late_response',
                prior_observation_id=original.observation_id,
                transport=replace(original.transport,received=b'LATE'))
            assert app.status('campaign').active
            injected.append(app.assess(late))
        return reference
    monkeypatch.setattr(LocalRecordStore,'append',acknowledged)
    result=app.campaign(request,generation=config,options=CampaignOptions(selected_cases=selected_cases))
    status=app.status('campaign');engine=app._run('campaign').engine
    records=app.read_records('campaign').records
    preparation=reopen_records(request.record_path+'.preparation.bfr').records
    stop=disposition=='stop'
    expected='monitoring_stopped' if stop else 'unreached' if selected_cases else 'completed'
    assert result.outcome==result.execution_outcome==status.state==expected
    assert result.missing_cases==((2,) if selected_cases else ())
    assert result.fuzz_tests==result.attempts==result.prepared_cases==1
    assert offers(traces)==[b'XA'] and all(stream.closed for _,stream,_ in traces)
    assert result.preparation_summary['status']==('cancelled' if stop else 'exhausted')
    assert result.preparation_summary['prepared_rows']==result.preparation_summary['source_cases']==1
    assert len([r for r in preparation if r.kind=='source_disposition'])==1
    assert len([r for r in preparation if r.kind=='prepared_row'])==1
    assert preparation[-1].kind=='preparation_terminal'
    assert {k:v for k,v in preparation[-1].data['summary'].items() if k!='last_reference'}=={
        k:v for k,v in result.preparation_summary.items() if k!='last_reference'}
    assert result.preparation_summary['last_reference']['record_id']==preparation[-1].record_id
    assert records[-1].kind=='campaign_terminal' and records[-1].data['result']==freeze(result)
    decision=injected[0]
    retained=next(r.data['decision'] for r in records if r.kind=='monitoring_decision'
        and r.data['decision']['observation_id']==decision.observation_id)
    assert retained==freeze(decision)
    assert engine.continuation.stopped==stop and not app._preparations and not status.active
    if stop:
        assert engine.continuation.stop_decision is decision
        assert decision.decision_id in result.reason and 'late-rule' in result.reason
        assert result.execution_reason==result.reason==status.result.reason
        cause=result.monitoring['continuation_stop']
        assert cause=={'decision_id':decision.decision_id,'observation_id':decision.observation_id,
            'correlation':freeze(decision.correlation),'cause':'observation_decision','reason':decision.reason}
    else:
        assert 'continuation_stop' not in result.monitoring
        assert result.reason==('requested case ordinals were not available' if selected_cases else '')


def test_campaign_preparation_error_retains_terminal_and_stops(tmp_path,application_factory):
    app,traces=application_factory()
    with pytest.raises(ContractError,match='variant_unavailable'):
        app.campaign(base(tmp_path),generation=generation(),options=CampaignOptions(variants=('normal','length4')))
    status=app.status('campaign')
    assert status['state']=='failed' and status['result'].outcome=='failed'
    assert status['result'].fuzz_tests==0 and not app._preparations
    records=app.read_records('campaign').records
    assert any(r.kind=='campaign_error' for r in records)
    assert records[-1].kind=='campaign_terminal'


@pytest.mark.parametrize('selected', [(1,), (3,)])
def test_stop_after_normal_yield_discards_partial_variant_family(
        tmp_path, application_factory, monkeypatch, selected):
    from bytefault.core.storage import reopen_records
    from bytefault.fuzzers.generated_inputs import PreparedStream
    from bytefault.monitoring import Monitoring, ConfiguredPolicy

    app, traces = application_factory(monitoring=Monitoring(ConfiguredPolicy()))
    request = base(tmp_path)
    request = replace(request, conversation=replace(request.conversation,
        calculations=(Calculation('length', '1', 'payload_length', 0, 1, payload_offset=1),)))
    original_next = PreparedStream.__next__
    returned = []

    def next_then_stop(stream):
        prepared = original_next(stream)
        returned.append(prepared.conversation.campaign.variant_id)
        assert app.control('campaign', 'stop').outcome == 'completed'
        return prepared

    monkeypatch.setattr(PreparedStream, '__next__', next_then_stop)
    result = app.campaign(request, generation=generation(), options=CampaignOptions(
        selected_cases=selected, variants=('normal', 'length4')))

    assert returned == ['normal']
    assert result.outcome == 'stopped' and result.missing_cases == selected
    assert (result.prepared_cases, result.fuzz_tests, result.attempts) == (0, 0, 0)
    assert result.preparation_summary['status'] == 'cancelled'
    assert result.preparation_summary['source_cases'] == 1
    assert result.preparation_summary['prepared_rows'] == 1
    preparation = reopen_records(request.record_path + '.preparation.bfr')
    prepared = [record for record in preparation.records if record.kind == 'prepared_row']
    assert len(prepared) == 1
    assert prepared[0].data['conversation_id'].endswith(':variant:normal')
    assert preparation.records[-1].kind == 'preparation_terminal'
    assert preparation.records[-1].data['summary']['status'] == 'cancelled'
    records = app.read_records('campaign').records
    assert not any(record.kind in ('campaign_case', 'campaign_error') for record in records)
    assert records[-1].kind == 'campaign_terminal'
    assert records[-1].data['result']['outcome'] == 'stopped'
    assert offers(traces) == []
    assert not any(step[0] == 'open' for trace, _, _ in traces for step in trace)
    assert not app._preparations and not app.status('campaign')['active']
    assert not app._run('campaign').engine._executing_conversation
