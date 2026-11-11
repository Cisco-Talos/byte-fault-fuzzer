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

"""Shared campaign consumers over the ordinary guarded application executor."""
from dataclasses import replace
import json
import threading
import pytest

from bytefault.application import CampaignRequest
from bytefault.core.contracts import CampaignOptions, ContractError, Calculation, freeze
from bytefault.core.records import encode_value
from bytefault.fuzzers.cli import execute_arguments, resolve_configuration
from bytefault.monitoring import Monitoring, ConfiguredPolicy
from bytefault.ui.application_client import ApplicationView
from test_campaign import base, generation, offers


def configured(application_factory):
    return application_factory(monitoring=Monitoring(ConfiguredPolicy()))


@pytest.mark.parametrize('operation', ('prepare', 'validate'))
def test_prepare_validate_same_complete_family_without_transport(
        tmp_path, application_factory, monkeypatch, operation):
    app, traces = configured(application_factory)
    def reject_engine(request):
        raise AssertionError('campaign inspection must not create an engine')
    monkeypatch.setattr(app, '_engine', reject_engine)
    original = base(tmp_path)
    original = replace(original, conversation=replace(original.conversation,
        calculations=(Calculation('length', '1', 'payload_length', 0, 1, payload_offset=1),)))
    request = CampaignRequest(original.conversation, original.transport, original.record_path,
        options=CampaignOptions(selected_cases=(2,4), variants=('normal','length4')),
        generation=generation())
    inspection = getattr(app, operation)(request)
    rows = list(inspection)
    assert [r['case_number'] for r in rows] == [2]
    assert [r.campaign.variant_id for r in rows[0]['requests']] == ['normal','length4']
    assert inspection.summary == {'prepared_cases':3, 'selected_cases':1, 'omitted_cases':2,
        'prepared_variants':6, 'selected_variants':2, 'offered':0,
        'outcome':'unreached', 'error':None, 'missing_cases':(4,), 'cleanup_errors':()}
    assert not traces and not app._runs and not app._preparations
    assert not __import__('pathlib').Path(original.record_path).exists()


def test_start_reserves_before_initialization_and_detach_does_not_stop(tmp_path, application_factory):
    app, traces = configured(application_factory)
    entered, release = threading.Event(), threading.Event()
    factory = app.transport_factory
    def blocked(target):
        entered.set()
        assert release.wait(3)
        return factory(target)
    app.transport_factory = blocked
    original = base(tmp_path)
    request = CampaignRequest(original.conversation, original.transport, original.record_path,
                              generation=generation())
    handle = app.start(request)
    assert entered.wait(3)
    view = ApplicationView(app, handle.run_id)
    assert view.refresh()['status']['active']
    view.detach()
    assert not handle.status()['stop_requested']
    assert handle.control('stop').outcome == 'completed'
    assert app.close()['outcome'] == 'pending'
    release.set()
    result = handle.wait(3)
    assert result.outcome == 'stopped' and offers(traces) == []
    assert not handle.status()['active'] and not app._preparations
    with pytest.raises(RuntimeError, match='detached'):
        view.refresh()


def test_original_whole_request_retained_before_traffic_and_isolated(tmp_path, application_factory):
    app, traces = configured(application_factory)
    original = base(tmp_path)
    supplied = replace(original.conversation, run_id='supplied-run', case_id='supplied-case',
                       conversation_id='supplied-conversation')
    request = CampaignRequest(original.conversation, original.transport, original.record_path,
                              cases=(supplied,), options=CampaignOptions())
    result = app.submit(request)
    assert (result.prepared_cases,result.prepared_variants,result.selected_variants,
            result.executed_variants,result.fuzz_tests)==(1,1,1,1,1)
    records = app.read_records('campaign').records
    assert records[0].kind == 'campaign_start'
    original_data = records[0].data['application_request']
    assert original_data['cases'][0]['run_id'] == 'supplied-run'
    assert original_data['cases'][0]['case_id'] == 'supplied-case'
    assert original_data['transport']['host'] == 'offline.invalid'
    assert original_data['record_path'] == original.record_path
    assert next(r for r in records if r.kind=='campaign_case').data['requests'][0]['case_id'] != 'supplied-case'


def test_generation_snapshot_and_duplicate_run_do_not_leave_preparation(tmp_path, application_factory):
    app, traces = configured(application_factory)
    original = base(tmp_path)
    value = generation()
    request = CampaignRequest(original.conversation, original.transport, original.record_path, generation=value)
    value['sources'] = ()
    app.submit(request)
    assert offers(traces) == [b'AXC',b'AYC',b'AZC']
    with pytest.raises(ContractError, match='run identity already used'):
        app.submit(request)
    assert not app._preparations
    inspection = app.prepare(replace(request, record_path=str(tmp_path/'not-started.bfr')))
    inspection.close()
    assert not app._preparations


def test_cleanup_failure_separate_from_execution_and_durable(tmp_path, application_factory, monkeypatch):
    from bytefault.logging import ActionLog
    app, traces = configured(application_factory)
    original_end = ActionLog.end
    failed_logs = []
    def end(log,boundary):
        if boundary=='run' and log.owner=='run':
            failed_logs.append(log)
            raise OSError('injected close failure')
        return original_end(log,boundary)
    monkeypatch.setattr(ActionLog,'end',end)
    result = app.campaign(base(tmp_path), generation=generation())
    assert result.outcome=='cleanup_failed' and result.execution_outcome=='completed'
    assert result.application_cleanup_errors[0]['operation'].startswith('action_log:')
    assert app.status('campaign')['cleanup_errors']
    from bytefault.core.storage import reopen_records
    logs = reopen_records(base(tmp_path).record_path+'.actions.bfr').records
    assert logs[-1].kind=='application_cleanup_failure'
    assert logs[-1].data['action']['result']['execution_outcome']=='completed'
    for log in failed_logs:
        original_end(log,'run')


def test_preparation_primary_error_survives_cleanup_failure(tmp_path, application_factory, monkeypatch):
    app,_=configured(application_factory)
    request=base(tmp_path)
    request=CampaignRequest(request.conversation,request.transport,request.record_path,generation=generation())
    request=replace(request,conversation=replace(request.conversation,selected_actions=('absent',)))
    factory=app._campaign_families
    def families(request):
        owner=factory(request);close=owner.close
        def failed_close():
            close();raise OSError('secondary source close')
        owner.close=failed_close
        return owner
    monkeypatch.setattr(app,'_campaign_families',families)
    operation=app.prepare(request)
    with pytest.raises(ContractError) as caught:
        next(operation)
    assert operation.summary['outcome']=='failed'
    assert operation.summary['error']==str(caught.value)
    assert operation.summary['cleanup_errors'][0]['error']=='secondary source close'
    assert any('secondary source close' in note for note in caught.value.__notes__)
    assert not app._preparations


@pytest.mark.parametrize('finish', ('complete', 'close'))
def test_preparation_family_cleanup_failure_is_reported_once(
        tmp_path, application_factory, monkeypatch, finish):
    app, traces = configured(application_factory)
    original = base(tmp_path)
    request = CampaignRequest(original.conversation, original.transport, original.record_path,
        generation=generation())
    factory, closed = app._campaign_families, []
    def families(request):
        owner = factory(request)
        close = owner.close
        def failed_close():
            closed.append(owner)
            close()
            raise OSError('family close failure')
        owner.close = failed_close
        return owner
    monkeypatch.setattr(app, '_campaign_families', families)
    inspection = app.prepare(request)
    next(inspection)
    with pytest.raises(OSError, match='family close failure'):
        if finish == 'complete':
            list(inspection)
        else:
            inspection.close()
    summary = inspection.summary
    assert summary['outcome'] == 'cleanup_failed' and summary['error'] is None
    assert summary['cleanup_errors'] == ({'owner': 'families', 'error': 'family close failure',
        'error_type': 'OSError'},)
    assert inspection._done and not app._preparations and not traces
    inspection.close()
    assert len(closed) == 1 and inspection.summary == summary


def test_same_process_run_resources_and_late_original_policy_history(tmp_path, application_factory):
    from pathlib import Path
    import logging
    from bytefault.logging import ActionLog
    from bytefault.monitoring import MonitoringConfig, ObservationRule
    caller_log=ActionLog.open(str(tmp_path/'services.bfr'),owner='application')
    handlers=tuple(logging.getLogger().handlers)
    level=logging.getLogger().level
    app,traces=application_factory(action_logs=(caller_log,),monitoring=Monitoring(ConfiguredPolicy()))
    original=base(tmp_path,'A')
    policy=MonitoringConfig(health_check_mode='disabled',rules=(ObservationRule('original-only','late_correlated',
        classification='original-policy-late',disposition='stop'),))
    request=CampaignRequest(original.conversation,original.transport,original.record_path,
        generation=generation(options={'payloads':(b'X',)}),monitoring_configuration=policy)
    app.submit(request)
    retained={path:Path(path).read_bytes() for path in (original.record_path,original.record_path+'.actions.bfr')}
    observation=next(o for o in app._run('A').engine.monitoring.observations if o.kind=='action')
    app.campaign(base(tmp_path,'B'),generation=generation(options={'payloads':(b'Y',)}))
    late=replace(observation,observation_id='late-A',kind='late_response',prior_observation_id=observation.observation_id,
                 transport=replace(observation.transport,received=b'late'))
    decision=app.assess(late)
    assert any(a.classification=='original-policy-late' for a in decision.assessments)
    assert decision.disposition=='stop'
    assert app.status('A').state==app.status('B').state=='completed'
    assert not app._run('A').engine.continuation.stopped and not app._run('B').engine.continuation.stopped
    assert decision.correlation==observation.correlation
    refs=app.service_record_refs('A')
    assert len(refs)==2 and {r.kind for r in app.read_service_records('A')}=={'monitoring_observation','monitoring_decision'}
    assert app.service_record_refs('B')==()
    assert all(Path(path).read_bytes()==data for path,data in retained.items())
    assert offers(traces)==[b'AXC',b'AYC']
    assert tuple(logging.getLogger().handlers)==handlers and logging.getLogger().level==level
    assert app.close()['outcome']=='completed' and caller_log.closed


def cli(tmp_path,*extra):
    return ['offline.invalid','--port','1234','--seed-hex','414243','--records',str(tmp_path/'cli.bfr'),
            '--no-ui','--health-check-mode','disabled',*extra]


@pytest.fixture
def literal_cli_cases():
    from bytefault.core.contracts import (ReceiveRequest, PreparedRow, PreparedContribution,
                                         SourceInvocation, Placement)
    from bytefault.fuzzers.inputs import raw_request
    first = replace(raw_request(b'\x00ABC', receive=ReceiveRequest(cap=2, deadline=1)),
        run_id='submitted-A', case_id='case-A', conversation_id='conversation-A', repair=True,
        calculations=(Calculation('length', '1', 'payload_length', 0, 1, payload_offset=1),),
        original_request={'operator': {'case': b'A'}, 'cli_input': {'caller': b'preserved'}})
    second = replace(first, run_id='submitted-B', case_id='case-B', conversation_id='conversation-B',
        repair=False, original_request={'operator': {'case': b'B'}},
        row=PreparedRow('second-row', 2,
            (PreparedContribution('different', b'XYZ', SourceInvocation('different', 'literal')),),
            (Placement('different', 'different', '1', 'overwrite', 1),)))
    return first, second


@pytest.mark.parametrize('campaign,count,suppress', [
    (False, 1, True), (True, 1, True), (True, 2, True), (True, 2, False)])
def test_cli_literal_controls_and_submitted_case_history(
        tmp_path, application_factory, literal_cli_cases, campaign, count, suppress):
    from bytefault.fuzzers.inputs import request_to_data
    app, traces = application_factory(stream_options={'reads': (b'OK', b'OK')})
    supplied = literal_cli_cases[:count]
    source = (['--campaign-json', json.dumps(encode_value({'cases': tuple(map(request_to_data, supplied))}))]
              if campaign else ['--request-json', json.dumps(request_to_data(supplied[0]))])
    args = cli(tmp_path)
    del args[args.index('--seed-hex'):args.index('--seed-hex') + 2]
    args += [*source, *(['--no-recv', '--no-auto-length'] if suppress else [])]
    config = resolve_configuration(args, app)
    assert not traces
    effective = config.request.cases or (config.request.conversation,)
    for original, case in zip(supplied, effective):
        assert case.original_request['cli_input']['supplied_conversation'] == freeze(original)
        assert case.original_request['operator'] == original.original_request['operator']
        assert case.original_request['argv'] == tuple(args)
        assert case.repair == (False if suppress else original.repair)
        assert case.plan.actions[0].receive.requested is (not suppress)
    result = execute_arguments(args, app)
    assert result.outcome == 'completed' and result.fuzz_tests == count
    expected = [b'\x00ABC' if suppress else b'\x03ABC', b'\x00XYZ'][:count]
    assert offers(traces) == expected
    assert sum(step[0] == 'read' for trace, _, _ in traces for step in trace) == (0 if suppress else count)
    records = app.read_records(result.run_id).records
    start = next(r for r in records if r.kind == 'campaign_start').data['application_request']
    retained = start['cases'] or (start['conversation'],)
    starts = [r.data['request'] for r in records if r.kind == 'case_start']
    actions = [r.data['result'] for r in records if r.kind == 'action_result']
    for original, effective_case, case, action, data in zip(supplied, retained, starts, actions, expected):
        assert effective_case['original_request']['cli_input']['supplied_conversation'] == freeze(original)
        assert case['original_request'] == effective_case['original_request']
        assert case['repair'] == effective_case['repair']
        assert action['materialized']['final_bytes'] == action['transport']['offered'] == data
        assert action['transport']['receive_requested'] is (not suppress)
        assert action['materialized']['calculations'] == (
            ('length', 'repaired' if effective_case['repair'] else 'disabled'),)
    assert all(stream.closed for _, stream, _ in traces)


def test_cli_literal_conflicts_are_admitted_for_every_case_before_transport(
        tmp_path, application_factory, literal_cli_cases):
    from bytefault.fuzzers.inputs import request_to_data
    app, traces = configured(application_factory)
    cases = literal_cli_cases
    args = cli(tmp_path)
    del args[args.index('--seed-hex'):args.index('--seed-hex') + 2]
    def source(cases):
        return ['--campaign-json', json.dumps(encode_value({'cases': tuple(map(request_to_data, cases))}))]
    with pytest.raises(ContractError, match='cli.receive'):
        execute_arguments([*args, *source(cases), '--receive-cap', '2', '--receive-deadline', '1'], app)
    incompatible = replace(cases[1], plan=replace(cases[1].plan, declaration_id='different'))
    with pytest.raises(ContractError, match='plan_mismatch'):
        execute_arguments([*args, *source((cases[0], incompatible)), '--no-recv'], app)
    assert not traces and not app._runs


def test_cli_normal_campaign_and_nonexecuting_prepare(tmp_path, application_factory):
    app,traces=configured(application_factory)
    args=cli(tmp_path,'--gen-field','@1:list:58,59,5a,mode:overwrite','--cases','1,3','--skip','1')
    config=resolve_configuration(args,app)
    assert isinstance(config.request,CampaignRequest) and not config.pending
    inspection=execute_arguments(['prepare',*args],app)
    rows=list(inspection)
    assert [r['case_number'] for r in rows]==[3] and offers(traces)==[]
    # Preparation evidence is append-only; execution uses a fresh declared destination.
    result=execute_arguments([*args,'--records',str(tmp_path/'execute.bfr')],app)
    assert offers(traces)==[b'AZC']
    assert (result.prepared_cases,result.omitted_cases,result.selected_cases,result.fuzz_tests)==(3,2,1,1)


def test_json_policy_typed_snapshot_and_actual_intent_conflict(tmp_path, application_factory):
    from bytefault.monitoring.configuration import ObservationRule
    app,_=configured(application_factory)
    policy={'health_check_mode':'disabled','rules':[{'rule_id':'latency','kind':'latency',
        'parameters':{'threshold':0.1}}]}
    args=cli(tmp_path)
    args=args[:-2]+['--monitoring-json',json.dumps(encode_value(policy))]
    config=resolve_configuration(args,app)
    assert isinstance(config.request.monitoring_configuration.rules[0],ObservationRule)
    for flag in ('--health-check-mode=disabled','--health-check-m=disabled'):
        with pytest.raises(ContractError,match='conflicting_input'):
            resolve_configuration([*args,flag],app)
    assert resolve_configuration(cli(tmp_path,'--recovery-delays',''),app).request.monitoring_configuration.recovery_delays==(3,5,10,15,17)


def test_main_preparation_missing_coverage_has_nonclean_exit(tmp_path, application_factory, monkeypatch, capsys):
    from bytefault.fuzzers import cli as module
    app,traces=configured(application_factory)
    monkeypatch.setattr(module,'Application',lambda:app)
    code=module.main(['prepare',*cli(tmp_path,'--gen-field','@1:list:58,mode:overwrite','--cases','9')])
    assert code==1 and offers(traces)==[]
    output=capsys.readouterr().out
    assert 'unreached' in output and 'missing_cases' in output


@pytest.mark.parametrize('failure',['constructor','start'])
def test_start_failure_finalizes_reserved_run(tmp_path,application_factory,monkeypatch,failure):
    import bytefault.application as module
    app,_=configured(application_factory)
    def fail(*args,**kwargs):raise RuntimeError('thread unavailable')
    if failure=='constructor':monkeypatch.setattr(module.threading,'Thread',fail)
    else:monkeypatch.setattr(module.threading.Thread,'start',fail)
    with pytest.raises(RuntimeError,match='thread unavailable'):app.start(base(tmp_path))
    status=app.status('campaign')
    assert not status.active and status.finalized and status.state=='failed'
    assert app.close().outcome=='completed'


def test_wait_and_close_pending_until_cleanup_finishes(tmp_path,application_factory,monkeypatch):
    from bytefault.logging import ActionLog
    app_log=ActionLog.open(str(tmp_path/'app.bfr'),owner='application')
    app,_=application_factory(action_logs=(app_log,),monitoring=Monitoring(ConfiguredPolicy()))
    entered,release=threading.Event(),threading.Event()
    original=ActionLog.end
    def blocked(log,boundary):
        if boundary=='run' and log.owner=='run':
            entered.set()
            assert release.wait(3)
            original(log,boundary)
            raise OSError('cleanup uncertainty')
        return original(log,boundary)
    monkeypatch.setattr(ActionLog,'end',blocked)
    handle=app.start(base(tmp_path))
    assert entered.wait(3)
    try:
        assert handle.wait(.01) is None
        assert handle.status().active and handle.status().closing and not handle.status().finalized
        assert app.close().outcome=='pending' and not app_log.closed
    finally:release.set()
    result=handle.wait(3)
    assert result.outcome=='cleanup_failed' and result.execution_outcome=='completed'
    assert not handle.status().active and handle.status().finalized
    assert app.close().outcome=='failed' and app_log.closed


def test_main_consumes_application_cleanup_outcome(tmp_path,application_factory,monkeypatch,capsys):
    from bytefault.fuzzers import cli as module
    app,_=configured(application_factory)
    close=app.close
    monkeypatch.setattr(module,'Application',lambda:app)
    def failed_close():
        close()
        return {'outcome':'failed','cleanup_failures':('injected',)}
    monkeypatch.setattr(app,'close',failed_close)
    assert module.main(cli(tmp_path))!=0
    assert 'application_cleanup' in capsys.readouterr().out


def test_public_preparation_cancel_running_filtered_source(tmp_path,application_factory,monkeypatch):
    from bytefault.generators.transforms import MutationPipeline
    app,traces=configured(application_factory)
    original=base(tmp_path)
    value=generation('random',{'min_len':0,'max_len':0,'seed':4})
    value['sets']=({'set_id':'S','source_id':'source','transforms':({'mutator_id':'empty','kind':'filter_empty'},)},)
    operation=app.prepare(CampaignRequest(original.conversation,original.transport,original.record_path,generation=value))
    entered,release=threading.Event(),threading.Event()
    apply=MutationPipeline.apply
    def blocked(self,*args,**kwargs):
        entered.set();assert release.wait(3)
        return apply(self,*args,**kwargs)
    monkeypatch.setattr(MutationPipeline,'apply',blocked)
    errors=[]
    def consume():
        try:list(operation)
        except BaseException as error:errors.append(error)
    worker=threading.Thread(target=consume);worker.start()
    assert entered.wait(3)
    operation.close()
    assert not operation._done and operation.preparation_id in app._preparations
    assert app.close().outcome=='pending'
    release.set();worker.join(3)
    assert not worker.is_alive() and not errors and not app._preparations
    assert operation.summary['outcome']=='cancelled' and offers(traces)==[]


@pytest.mark.parametrize('finish',['complete','stop'])
def test_active_shared_assessment_hold_blocks_next_send(tmp_path,application_factory,finish):
    from bytefault.monitoring import MonitoringConfig,ObservationRule
    from bytefault.core.contracts import MonitoringCompletion
    from bytefault.fuzzers.inputs import positional_plan
    monitor=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',rules=(
        ObservationRule('late','late_correlated',disposition='hold',conditions=('report',),actions=({'report':True},)),)))
    app,traces=application_factory(monitoring=monitor)
    request=base(tmp_path)
    request=replace(request,conversation=replace(request.conversation,plan=positional_plan((b'A',b'B')),selected_actions=('1','2')))
    ready=threading.Event();injected=[]
    class Sink:
        def __call__(self,kind,identity,data,reference=None):
            if kind=='monitoring_decision' and not injected:
                observation=monitor.observations[0]
                late=replace(observation,observation_id='late',kind='late_response',prior_observation_id=observation.observation_id,
                    transport=replace(observation.transport,received=b'LATE'))
                injected.append(late);app.assess(late);ready.set()
        def end(self,boundary):pass
    app.action_logs=(Sink(),)
    handle=app.start(CampaignRequest(request.conversation,request.transport,request.record_path))
    assert ready.wait(3)
    engine=app._run(handle.run_id).engine;hold=engine.continuation.hold
    try:
        assert hold.correlation==injected[0].correlation and offers(traces)==[b'A']
        completion=MonitoringCompletion('done',hold.decision_id,hold.observation_id,hold.correlation,'report','succeeded',
            followup_action_id=hold.actions[0].action_id)
        assert not app.complete_monitoring(handle.run_id,replace(completion,decision_id='stale'))
        if finish=='stop':handle.control('stop')
        else:assert app.complete_monitoring(handle.run_id,completion)
        result=handle.wait(3)
        assert result.outcome==('stopped' if finish=='stop' else 'completed')
        assert offers(traces)==([b'A'] if finish=='stop' else [b'A',b'B'])
        record=next(r for r in app.read_records(handle.run_id).records if r.kind=='observation' and r.data['observation']['observation_id']=='late')
        assert record.identity['action_id']=='1' and record.identity['attempt_id']==hold.correlation.attempt_id
    finally:
        handle.control('stop');handle.wait(3)


@pytest.mark.parametrize('save_failure',[False,True])
def test_external_A_during_B_retry_wait_exact_context_and_storage_stop(tmp_path,application_factory,monkeypatch,save_failure):
    from bytefault.monitoring import MonitoringConfig
    from bytefault.fuzzers.fuzzer import ProtocolFuzzer
    from bytefault.core.storage import LocalRecordStore
    from bytefault.core.records import RequiredSaveFailure
    monitor=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',retries=1,recovery_delays=(.1,)))
    app,traces=application_factory(monitoring=monitor,stream_options={'sends':(3,OSError('B send failed'))})
    entered,release=threading.Event(),threading.Event()
    wait=ProtocolFuzzer._policy_wait
    def blocked(engine,seconds):
        if engine._record_context.get('case_number')==2:
            entered.set();assert release.wait(3)
        return wait(engine,seconds)
    monkeypatch.setattr(ProtocolFuzzer,'_policy_wait',blocked)
    original=base(tmp_path)
    handle=app.start(CampaignRequest(original.conversation,original.transport,original.record_path,generation=generation()))
    assert entered.wait(3)
    engine=app._run(handle.run_id).engine
    A=next(o for o in monitor.observations if o.correlation.case_id.endswith(':row:1'))
    B=dict(engine._record_context)
    late=replace(A,observation_id='external-A',kind='late_response',prior_observation_id=A.observation_id,
        transport=replace(A.transport,received=b'late'))
    append=LocalRecordStore.append
    failed=[]
    def save(store,kind,identity,data):
        if save_failure and kind=='observation' and data.get('observation',{}).observation_id=='external-A':
            failed.append((identity,data));raise OSError('late history failed')
        return append(store,kind,identity,data)
    monkeypatch.setattr(LocalRecordStore,'append',save)
    if save_failure:
        close=ProtocolFuzzer.close_observers
        def failed_close(engine):
            close(engine);raise OSError('observer cleanup failed after storage stop')
        monkeypatch.setattr(ProtocolFuzzer,'close_observers',failed_close)
    try:
        if save_failure:
            with pytest.raises(RequiredSaveFailure):app.assess(late)
            diagnostic=engine.storage_failure
            assert diagnostic['failed_record_identity']['case_id']==A.correlation.case_id
            assert diagnostic['failed_record_data']['observation']['observation_id']=='external-A'
            assert diagnostic['execution_identity']['case_id']==B['case_id']
            assert len(failed)==1
        else:
            app.assess(late)
            assert dict(engine._record_context)==B
    finally:release.set()
    result=handle.wait(3)
    records=app.read_records(handle.run_id).records
    if save_failure:
        assert result.outcome=='recording_failed' and len(offers(traces))==2 and len(failed)==1
        assert result.application_cleanup_errors[0]['operation']=='observers'
    else:
        assert result.outcome=='completed' and result.attempts==4
        late_record=next(r for r in records if r.kind=='observation' and r.data['observation']['observation_id']=='external-A')
        assert late_record.identity['case_id']==A.correlation.case_id
        waits=[r for r in records if r.kind=='retry_wait']
        assert waits and all(r.identity['case_id']==B['case_id'] for r in waits)
        retries=[r for r in records if r.kind=='action_result' and r.identity.get('case_number')==2]
        assert len(retries)==2 and all(r.identity['action_id']=='1' for r in retries)


def test_shared_policy_second_start_does_not_clobber_A(tmp_path,application_factory,monkeypatch):
    from bytefault.monitoring import MonitoringConfig,ObservationRule
    from bytefault.fuzzers.recording import RecordingMixin
    monitor=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',rules=(
        ObservationRule('wait','unrequested',disposition='hold',conditions=('report',)),)))
    app,traces=application_factory(monitoring=monitor)
    ready=threading.Event();save=RecordingMixin._required_save
    def saved(engine,kind,data,**kwargs):
        ref=save(engine,kind,data,**kwargs)
        if kind=='monitoring_decision':ready.set()
        return ref
    monkeypatch.setattr(RecordingMixin,'_required_save',saved)
    A=base(tmp_path,'A');B=base(tmp_path,'B')
    from bytefault.fuzzers.inputs import positional_plan
    A=replace(A,conversation=replace(A.conversation,plan=positional_plan((b'ABC',b'later')),selected_actions=('1','2')))
    handle=app.start(CampaignRequest(A.conversation,A.transport,A.record_path))
    assert ready.wait(3)
    try:
        second=app.start(CampaignRequest(B.conversation,B.transport,B.record_path))
        with pytest.raises(ContractError,match='one active campaign per policy'):second.wait(3)
        assert monitor.policy._campaign['id']=='A'
        assert app.status('A').active and offers(traces)==[b'ABC']
    finally:handle.control('stop');handle.wait(3)


@pytest.mark.parametrize('scenario,overall,primary,count',[('complete','cleanup_failed','completed',1),
    ('transport','transport_failed','transport_failed',1),('stop','stopped','stopped',1),
    ('fresh','cleanup_failed','unreached',1)])
def test_campaign_cleanup_keeps_primary_and_unreached_coverage(tmp_path,application_factory,scenario,overall,primary,count):
    options={'close_error':OSError('uncertain local close')}
    if scenario=='transport':options['sends']=(OSError('send failed'),)
    app,traces=application_factory(monitoring=Monitoring(ConfiguredPolicy()),stream_options=options)
    request=base(tmp_path)
    if scenario=='stop':
        factory=app.transport_factory
        def transport(target):
            adapter=factory(target);create=adapter.socket_factory
            def stream(*args):
                value=create(*args);send=value.send
                def stopped(data):
                    amount=send(data);app.control(request.conversation.run_id,'stop');return amount
                value.send=stopped;return value
            adapter.socket_factory=stream;return adapter
        app.transport_factory=transport
    result=app.campaign(request,generation=generation(options={'payloads':(b'X',b'Y') if scenario=='fresh' else (b'X',)}))
    assert result.outcome==overall and result.execution_outcome==primary
    assert result.fuzz_tests==count and len(offers(traces))==1
    if scenario=='fresh':
        assert result.prepared_cases==result.selected_cases==2 and result.executed_variants==1
        assert result.case_entry_attempts==1
        assert result.cleanup_errors[0]['unreached_request']['campaign']['case_number']==2
        assert result.last_conversation.execution_outcome=='completed'
    records=app.read_records(request.conversation.run_id).records
    assert records[-1].data['result']['execution_outcome']==primary


@pytest.mark.parametrize('generated',[False,True])
@pytest.mark.parametrize('cancel',['operation','application'])
def test_cancel_during_pure_validation_never_yields_or_validates_later_family(
        tmp_path,application_factory,monkeypatch,generated,cancel):
    import bytefault.fuzzers.conversation as module
    app,traces=configured(application_factory)
    original=base(tmp_path)
    original=replace(original,conversation=replace(original.conversation,
        calculations=(Calculation('length','1','payload_length',0,1,payload_offset=1),)))
    request=CampaignRequest(original.conversation,original.transport,original.record_path,
        options=CampaignOptions(variants=('normal','length4')),
        generation=generation() if generated else None,
        cases=() if generated else (original.conversation,original.conversation,original.conversation))
    entered,release=threading.Event(),threading.Event()
    validate=module.validate_conversation;calls=[]
    def blocked(conversation):
        calls.append(conversation.campaign)
        entered.set();assert release.wait(3)
        return validate(conversation)
    monkeypatch.setattr(module,'validate_conversation',blocked)
    operation=app.prepare(request);rows=[];errors=[]
    def consume():
        try:rows.extend(operation)
        except BaseException as error:errors.append(error)
    worker=threading.Thread(target=consume);worker.start()
    try:
        assert entered.wait(3)
        if cancel=='operation':operation.close()
        else:assert app.close().outcome=='pending'
        assert not operation._done and operation.preparation_id in app._preparations
    finally:release.set();worker.join(3)
    assert not worker.is_alive() and not errors and rows==[] and len(calls)==1
    assert operation.summary['outcome']=='cancelled' and operation.summary['selected_cases']==0
    assert operation._done and not app._preparations and traces==[]


@pytest.mark.parametrize('generated',[False,True])
@pytest.mark.parametrize('invalid,path,code',[
    ('empty_record','record_path','required'),('empty_log','log_path','invalid'),
    ('same_paths','log_path','invalid')])
def test_prepare_and_submit_share_destination_admission_without_adapter(
        tmp_path,application_factory,generated,invalid,path,code):
    app,traces=configured(application_factory)
    original=base(tmp_path)
    request=CampaignRequest(original.conversation,original.transport,original.record_path,
        generation=generation() if generated else None)
    if invalid=='empty_record':request=replace(request,record_path='')
    elif invalid=='empty_log':request=replace(request,log_path='')
    else:request=replace(request,log_path=request.record_path)
    prepared=app.prepare(request)
    with pytest.raises(ContractError) as preparation_error:list(prepared)
    assert (preparation_error.value.path,preparation_error.value.code)==(path,code)
    assert prepared.summary['outcome']=='failed' and not app._preparations
    with pytest.raises(ContractError) as submission_error:app.submit(request)
    assert (submission_error.value.path,submission_error.value.code)==(path,code)
    assert traces==[] and not app._preparations
    assert not (tmp_path/'campaign.bfr').exists()
    assert not (tmp_path/'campaign.bfr.preparation.bfr').exists()


def test_actual_shared_late_conflict_keeps_B_hold_and_original_ids(tmp_path,application_factory,monkeypatch):
    from bytefault.monitoring import MonitoringConfig,ObservationRule
    from bytefault.fuzzers.inputs import positional_plan
    from bytefault.core.contracts import ReceiveRequest
    from bytefault.fuzzers.recording import RecordingMixin
    monitor=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',rules=(
        ObservationRule('B','prefix',{'value':b'B','expect':'match'},disposition='hold',conditions=('report',)),
        ObservationRule('late','late_correlated',disposition='hold',conditions=('collection',)))))
    app,traces=application_factory(monitoring=monitor,stream_options={'reads':(b'A',b'B')})
    request=base(tmp_path)
    plan=positional_plan((b'A',b'B',b'C'))
    plan=replace(plan,actions=tuple(replace(a,receive=ReceiveRequest(cap=1,deadline=1)) for a in plan.actions))
    request=replace(request,conversation=replace(request.conversation,plan=plan,selected_actions=('1','2','3')))
    ready=threading.Event();save=RecordingMixin._required_save
    def saved(engine,kind,data,**kwargs):
        ref=save(engine,kind,data,**kwargs)
        if kind=='monitoring_decision' and data['decision'].disposition=='hold':ready.set()
        return ref
    monkeypatch.setattr(RecordingMixin,'_required_save',saved)
    handle=app.start(CampaignRequest(request.conversation,request.transport,request.record_path))
    assert ready.wait(3)
    engine=app._run(handle.run_id).engine
    # Acquire the same short action lock after the decision has been installed.
    with engine._action_lock:hold=engine.continuation.hold
    A=next(o for o in monitor.observations if o.correlation.action_id=='1')
    late=replace(A,observation_id='late-A-conflict',kind='late_response',prior_observation_id=A.observation_id)
    with pytest.raises(ContractError,match='hold_conflict'):app.assess(late)
    result=handle.wait(3)
    assert result.outcome=='monitoring_stopped' and offers(traces)==[b'A',b'B']
    assert engine.continuation.hold==hold and hold.correlation.action_id=='2'
    failure=next(r for r in app.read_records(handle.run_id).records if r.kind=='monitoring_failure')
    assert failure.identity['action_id']=='1' and failure.data['active_hold']['correlation']['action_id']=='2'


def test_active_external_probe_original_connection_and_exact_records(tmp_path,application_factory):
    from bytefault.core.contracts import MonitoringDecision,ProbeRequest,ReceiveRequest,MonitoringCompletion
    from bytefault.fuzzers.inputs import positional_plan
    class Policy:
        def evaluate(self,observation):
            if observation.kind=='late_response':
                probe=ProbeRequest('late-probe',observation.observation_id,observation.correlation,
                    prepared=b'P',receive=ReceiveRequest(requested=False),decision_id='late-decision')
                return MonitoringDecision('late-decision',observation.observation_id,observation.correlation,
                    'hold','awaited',('assessment',),probes=(probe,))
            return MonitoringDecision('continue-'+observation.observation_id,observation.observation_id,observation.correlation,'continue')
    monitor=Monitoring(Policy());app,traces=application_factory(monitoring=monitor)
    request=base(tmp_path)
    request=replace(request,conversation=replace(request.conversation,plan=positional_plan((b'A',b'B')),selected_actions=('1','2')))
    ready=threading.Event();injected=[]
    class Sink:
        def __call__(self,kind,identity,data,reference=None):
            if kind=='monitoring_decision' and not injected:
                A=monitor.observations[0];late=replace(A,observation_id='late-probe-observation',kind='late_response',prior_observation_id=A.observation_id)
                injected.append(late);app.assess(late);ready.set()
        def end(self,boundary):pass
    app.action_logs=(Sink(),)
    handle=app.start(CampaignRequest(request.conversation,request.transport,request.record_path))
    assert ready.wait(3)
    try:
        assert offers(traces)==[b'A',b'P']
        hold=app._run(handle.run_id).engine.continuation.hold
        assert app.complete_monitoring(handle.run_id,MonitoringCompletion('done',hold.decision_id,hold.observation_id,
            hold.correlation,'assessment','succeeded'))
        assert handle.wait(3).outcome=='completed'
        records=app.read_records(handle.run_id).records
        probe=next(r for r in records if r.kind=='probe_result')
        assert probe.identity['case_id']==injected[0].correlation.case_id and probe.identity['action_id']=='late-probe'
        assert probe.data['result']['transport']['accepted_prefix']==b'P'
        assert probe.data['association']['original_observation_id']==injected[0].prior_observation_id
        assert probe.data['association']['original_connection_epoch']==probe.data['association']['actual_connection']['epoch']
        assert offers(traces)==[b'A',b'P',b'B']
    finally:handle.control('stop');handle.wait(3)


@pytest.mark.parametrize('mode',['automatic','manual','unknown'])
def test_external_probe_on_retired_A_connection_unavailable_before_offer(tmp_path,application_factory,monkeypatch,mode):
    from bytefault.monitoring import MonitoringConfig,RulePolicy
    from bytefault.core.contracts import ProbeRequest
    from bytefault.fuzzers.fuzzer import ProtocolFuzzer
    class Policy(RulePolicy):
        def evaluate(self,observation):
            decision=super().evaluate(observation)
            if observation.kind=='late_response':
                probe=ProbeRequest('old-connection',observation.observation_id,observation.correlation,b'P',decision_id=decision.decision_id)
                decision=replace(decision,disposition='hold',mode='awaited',required_conditions=('assessment',),
                    probes=(probe,) if mode=='automatic' else ())
            return decision
    monitor=Monitoring(Policy(MonitoringConfig(health_check_mode='disabled',retries=1,recovery_delays=(.1,))))
    app,traces=application_factory(monitoring=monitor,stream_options={'sends':(3,OSError('B failed'))})
    entered,release=threading.Event(),threading.Event();wait=ProtocolFuzzer._policy_wait
    def blocked(engine,seconds):
        entered.set();assert release.wait(3);return wait(engine,seconds)
    monkeypatch.setattr(ProtocolFuzzer,'_policy_wait',blocked)
    request=base(tmp_path)
    handle=app.start(CampaignRequest(request.conversation,request.transport,request.record_path,generation=generation()))
    assert entered.wait(3)
    A=monitor.observations[0]
    late=replace(A,observation_id='old-A',kind='late_response',prior_observation_id='unknown' if mode=='unknown' else A.observation_id)
    try:
        if mode!='automatic':
            decision=app.assess(late)
            probe=ProbeRequest('manual',late.observation_id,late.correlation,b'P',decision_id=decision.decision_id)
        with pytest.raises(ContractError,match='probe.connection.*unavailable') as caught:
            if mode=='automatic':app.assess(late)
            else:app._run(handle.run_id).engine.execute_probe(probe)
        assert (caught.value.path,caught.value.code)==('probe.connection','unavailable')
        assert offers(traces)==[b'AXC',b'AYC']
        if mode!='automatic':
            assert app._run(handle.run_id).engine.continuation.hold==decision
            handle.control('stop')
    finally:release.set()
    assert handle.wait(3).outcome==('monitoring_stopped' if mode=='automatic' else 'stopped')
    unavailable=next(r for r in app.read_records(handle.run_id).records if r.kind=='probe_unavailable')
    assert unavailable.identity['case_id']==A.correlation.case_id
    if mode=='unknown':assert unavailable.data['original_association'] is None
    else:assert unavailable.data['original_association'][1]!=unavailable.data['actual_connection']['epoch']


@pytest.mark.parametrize('boundary',['persistent','fresh','eof','retry'])
def test_retained_probe_serializes_next_case_entry(tmp_path,application_factory,monkeypatch,boundary):
    from bytefault.core.contracts import MonitoringDecision,ProbeRequest,MonitoringCompletion,CampaignConnection
    from bytefault.generators.transforms import MutationPipeline
    from bytefault.fuzzers.recording import RecordingMixin
    from bytefault.fuzzers.generated_inputs import PreparedStream
    from bytefault.fuzzers.fuzzer import ProtocolFuzzer
    from bytefault.monitoring import MonitoringConfig
    class Policy:
        def __init__(self):self.ordinary=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',retries=1,recovery_delays=(.1,),reconnect_attempts=1))
        def begin_campaign(self,identity):self.ordinary.begin_campaign(identity)
        def end_campaign(self):return self.ordinary.end_campaign()
        def decide_attempt(self,*args,**kwargs):return self.ordinary.decide_attempt(*args,**kwargs)
        def evaluate(self,observation):
            if observation.kind=='late_response':
                probe=ProbeRequest('P',observation.observation_id,observation.correlation,b'P',decision_id='late')
                return MonitoringDecision('late',observation.observation_id,observation.correlation,
                    'hold','awaited',('assessment',),probes=(probe,))
            return self.ordinary.observe(observation)
    monitor=Monitoring(Policy());app,traces=application_factory(monitoring=monitor,
        stream_options={'sends':(OSError('retry original'),)} if boundary=='retry' else {})
    preparing,release_preparation=threading.Event(),threading.Event()
    probing,release_probe,entering=threading.Event(),threading.Event(),threading.Event()
    apply=MutationPipeline.apply
    def prepare(pipeline,data,*args,**kwargs):
        if data==b'Y':preparing.set();assert release_preparation.wait(3)
        return apply(pipeline,data,*args,**kwargs)
    monkeypatch.setattr(MutationPipeline,'apply',prepare)
    if boundary=='eof':
        next_row=PreparedStream.__next__
        def eof(stream):
            if stream.prepared_rows==1:preparing.set();assert release_preparation.wait(3)
            return next_row(stream)
        monkeypatch.setattr(PreparedStream,'__next__',eof)
    if boundary=='retry':
        wait=ProtocolFuzzer._policy_wait
        def retry_wait(engine,seconds):
            preparing.set();assert release_preparation.wait(3);return wait(engine,seconds)
        monkeypatch.setattr(ProtocolFuzzer,'_policy_wait',retry_wait)
    factory=app.transport_factory
    def transport(target):
        adapter=factory(target);create=adapter.socket_factory
        def create_stream(*args):
            stream=create(*args);send=stream.send
            def blocked(data):
                if data==b'P':probing.set();assert release_probe.wait(3)
                return send(data)
            stream.send=blocked;return stream
        adapter.socket_factory=create_stream;return adapter
    app.transport_factory=transport
    original=base(tmp_path)
    handle=app.start(CampaignRequest(original.conversation,original.transport,original.record_path,
        options=CampaignOptions(connection=CampaignConnection('fresh' if boundary=='fresh' else 'persistent')),
        generation=generation(options={'payloads':(b'X',) if boundary in ('eof','retry') else (b'X',b'Y')})))
    assert preparing.wait(3)
    engine=app._run(handle.run_id).engine
    class ObservedLock:
        def __init__(self,lock):self.lock=lock
        def __enter__(self):
            if not self.lock.acquire(blocking=False):entering.set();self.lock.acquire()
            return self
        def __exit__(self,*args):self.lock.release()
    engine._action_lock=ObservedLock(engine._action_lock)
    A=monitor.observations[0]
    late=replace(A,observation_id='late',kind='late_response',prior_observation_id=A.observation_id)
    assessed=[];errors=[]
    def assess():
        try:assessed.append(app.assess(late))
        except BaseException as error:errors.append(error)
    thread=threading.Thread(target=assess);thread.start()
    try:
        assert probing.wait(3)
        release_preparation.set()
        assert entering.wait(3)
        engine=app._run(handle.run_id).engine
        assert engine._record_request.case_id==A.correlation.case_id
        release_probe.set();thread.join(3)
        assert not thread.is_alive() and not errors
        assert offers(traces)==[b'AXC',b'P']
        hold=assessed[0]
        if boundary!='eof':
            assert app.complete_monitoring(handle.run_id,MonitoringCompletion('done',hold.decision_id,hold.observation_id,
                hold.correlation,'assessment','succeeded'))
        assert handle.wait(3).outcome=='completed'
        assert offers(traces)==([b'AXC',b'P'] if boundary=='eof' else [b'AXC',b'P',b'AXC' if boundary=='retry' else b'AYC'])
        records=app.read_records(handle.run_id).records
        probe_index=next(i for i,r in enumerate(records) if r.kind=='probe_result')
        if boundary=='eof':assert probe_index<len(records)-1 and records[-1].kind=='campaign_terminal'
        elif boundary=='retry':assert probe_index<next(i for i,r in enumerate(records) if r.kind=='transport_cleanup' and r.data.get('purpose')=='retry')
        else:assert probe_index<next(i for i,r in enumerate(records) if r.kind=='case_start' and r.identity.get('case_number')==2)
    finally:
        release_preparation.set();release_probe.set();handle.control('stop');thread.join(3);handle.wait(3)


def test_simultaneous_first_start_claims_shared_policy_atomically(tmp_path,application_factory,monkeypatch):
    from bytefault.monitoring import MonitoringConfig,ObservationRule
    from bytefault.fuzzers.inputs import positional_plan
    monitor=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',rules=(
        ObservationRule('wait','unrequested',disposition='hold',conditions=('assessment',)),)))
    app,traces=application_factory(monitoring=monitor)
    entered,release,contended=threading.Event(),threading.Event(),threading.Event()
    policy=monitor.policy;begin=policy._begin_campaign_locked
    def blocked(identity):
        if identity=='A':entered.set();assert release.wait(3)
        return begin(identity)
    monkeypatch.setattr(policy,'_begin_campaign_locked',blocked)
    class ObservedLock:
        def __init__(self,lock):self.lock=lock
        def __enter__(self):
            if not self.lock.acquire(blocking=False):contended.set();self.lock.acquire()
            return self
        def __exit__(self,*args):self.lock.release()
    policy._campaign_lock=ObservedLock(policy._campaign_lock)
    A=base(tmp_path,'A');B=base(tmp_path,'B')
    A=replace(A,conversation=replace(A.conversation,plan=positional_plan((b'A',b'later')),selected_actions=('1','2')))
    first=app.start(CampaignRequest(A.conversation,A.transport,A.record_path))
    assert entered.wait(3)
    second=app.start(CampaignRequest(B.conversation,B.transport,B.record_path))
    try:
        assert contended.wait(3)
        release.set()
        with pytest.raises(ContractError,match='one active campaign per policy'):second.wait(3)
        assert policy._campaign['id']=='A'
        assert all(step[1]!=b'ABC' for trace,_,_ in traces for step in trace if step[0]=='offer')
    finally:release.set();first.control('stop');first.wait(3)


def test_shared_policy_keeps_bounded_ended_A_history_across_B(tmp_path,application_factory):
    from pathlib import Path
    from bytefault.logging import ActionLog
    from bytefault.monitoring import MonitoringConfig
    from bytefault.core.contracts import ReceiveRequest
    log=ActionLog.open(str(tmp_path/'independent.bfr'),owner='application')
    monitor=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',retries=0))
    app,_=application_factory(monitoring=monitor,action_logs=(log,),stream_options={'reads':()})
    A=base(tmp_path,'A')
    A=replace(A,conversation=replace(A.conversation,plan=replace(A.conversation.plan,actions=(
        replace(A.conversation.plan.actions[0],receive=ReceiveRequest(cap=1,deadline=1)),))))
    resultA=app.campaign(A)
    observation=next(o for o in monitor.observations if o.kind=='action')
    assert observation.transport.receive_outcome=='deadline'
    retained={p:Path(p).read_bytes() for p in (A.record_path,A.record_path+'.actions.bfr')}
    resultB=app.campaign(base(tmp_path,'B'))
    assert resultB.monitoring['id']=='B' and resultB.monitoring['failed_tests']==0
    late=replace(observation,observation_id='late-ended-A',kind='late_response',prior_observation_id=observation.observation_id,
        transport=replace(observation.transport,received=b'late'))
    decision=app.assess(late)
    assert any(a.classification=='missing_response_resolved' for a in decision.assessments)
    assert decision.correlation==observation.correlation
    assert len(app.service_record_refs('A'))==2 and app.service_record_refs('B')==()
    assert all(Path(p).read_bytes()==data for p,data in retained.items())


def test_retry_cleanup_failure_does_not_count_unentered_connection(tmp_path,application_factory):
    from bytefault.monitoring import MonitoringConfig
    app,traces=application_factory(monitoring=Monitoring(configuration=MonitoringConfig(
        health_check_mode='disabled',retries=1,recovery_delays=(0,))),
        stream_options={'sends':(OSError('failed initial offer'),),'close_error':OSError('retry close failed')})
    request=base(tmp_path)
    result=app.campaign(request,generation=generation(options={'payloads':(b'X',)}))
    assert result.outcome!='completed' and result.case_entry_attempts==1
    assert result.attempts==result.fuzz_tests==1 and len(offers(traces))==1
    records=app.read_records(request.conversation.run_id).records
    assert sum(r.kind=='connection_attempt' for r in records)==1
    assert not any(r.kind=='reconnect_attempt' for r in records)
    assert any(r.kind=='transport_cleanup' and r.data.get('purpose')=='retry' and
               r.data['cleanup']['outcome']=='uncertain' for r in records)
