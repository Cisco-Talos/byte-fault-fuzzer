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

"""Actual setup/acquisition scope: prepared candidates, no fabricated fuzz tests."""
from dataclasses import replace
import pytest

from bytefault.core.contracts import (CampaignConnection, CampaignSetupStep, ReceiveRequest, ResponseEdge)
from bytefault.fuzzers.inputs import positional_plan
from bytefault.monitoring import MonitoringConfig
from test_monitoring_policy import run_campaign, setup_plan


def records_of(records,kind):return [record for record in records if record.kind==kind]


def test_initial_connection_failures_advance_two_candidates_without_selected_attempts(tmp_path):
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        plan=setup_plan(),payloads=(b'A',b'B'),open_errors=(True,)*12)
    assert result.outcome=='transport_failed' and result.selected_cases==2
    assert (result.fuzz_tests,result.attempts,result.executed_variants)==(0,0,0)
    assert (result.case_entry_attempts,result.setup_attempts,result.setup_retries)==(4,2,2)
    assert not [item for item in trace if item[0]=='send']
    assert len(records_of(records,'reconnect_attempt'))==10
    actions=[r.data['result'] for r in records_of(records,'action_result')]
    assert all(a['iteration_id'] is None and a['transport']['acceptance']=='not_offered' for a in actions)
    directives=[r.data['directive'] for r in records_of(records,'campaign_setup_directive')]
    assert all(d['scope']=='setup' and d['test_id'] is None and d['candidate_id'] for d in directives)
    exhausted=[d for d in directives if d['facts'].get('reconnect_exhausted')]
    assert len(exhausted)==2 and all(d['facts']['unused_retries']==2 for d in exhausted)
    assert result.monitoring['setup_failed_candidates']==2
    assert (result.monitoring['failed_tests'],result.monitoring['consecutive'],result.monitoring['service_checks'])==(0,0,0)
    assert len(records_of(records,'case_start'))==len(records_of(records,'case_terminal'))==2


@pytest.mark.parametrize('declared_dependency',[True,False])
def test_requested_setup_silence_retries_then_advances_without_selected_traffic(tmp_path,declared_dependency):
    plan=setup_plan()
    if not declared_dependency:
        plan=replace(plan,actions=(replace(plan.actions[0],edges=(),next_action='2'),plan.actions[1]))
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        plan=plan,payloads=(b'A',b'B'))
    assert result.outcome=='monitoring_failed' and result.selected_cases==2
    assert result.fuzz_tests==result.attempts==0
    assert (result.setup_attempts,result.setup_retries,result.case_entry_attempts)==(8,6,8)
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP']*8
    assert [r.data['directive']['wait_seconds'] for r in records_of(records,'setup_retry_wait')]==[3,5,10]*2
    assert len({r.data['result']['attempt_id'] for r in records_of(records,'action_result')})==8
    assert all(r.data['result']['iteration_id'] is None for r in records_of(records,'action_result'))
    assert result.last_conversation.unreached and result.last_conversation.unreached[0][0]=='2'
    assert result.monitoring['setup_failed_candidates']==2 and result.monitoring['consecutive']==0
    contexts=[r.data['context'] for r in records_of(records,'campaign_setup_directive')]
    assert all(c['governed_actions']==('2',) for c in contexts)
    if not declared_dependency:
        assert all(c['continuation_available'] and c['declared_target']=='2' for c in contexts)


def test_explicit_no_retry_preserves_unconditional_declared_continuation(tmp_path):
    plan=setup_plan();plan=replace(plan,actions=(replace(plan.actions[0],edges=(),next_action='2'),plan.actions[1]))
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled',retry_rules=()),
        plan=plan,payloads=(b'A',b'B'))
    assert result.outcome=='completed' and result.fuzz_tests==result.attempts==2
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP',b'XA',b'SETUP',b'XB']
    assert not records_of(records,'setup_retry_wait')
    assert any(a['classification']=='potential_crash' for r in records_of(records,'monitoring_decision')
        for a in r.data['decision']['assessments'])


@pytest.mark.parametrize('first_failure',['connect','silence'])
def test_initial_setup_eventual_recovery_keeps_first_selected_attempt_identity(tmp_path,first_failure):
    errors=(True,False,False) if first_failure=='connect' else ()
    reads={1:(b'READY',),2:(b'READY',)}
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        plan=setup_plan(),payloads=(b'A',b'B'),open_errors=errors,stream_reads=reads)
    assert result.outcome=='completed' and result.fuzz_tests==result.attempts==2
    assert result.setup_retries==1
    selected=[r.data['result'] for r in records_of(records,'action_result') if r.data['result']['iteration_id']]
    assert [a['materialized']['final_bytes'] for a in selected]==[b'XA',b'XB']
    assert all(a['attempt_id'].endswith(':2:attempt-1') for a in selected)
    assert all(not r.data['directive']['facts']['advance_candidate'] for r in records_of(records,'campaign_setup_directive'))


def mid_plan(declared_dependency=False,c_receive=False):
    plan=positional_plan((b'A',b'B',b'C'))
    b=replace(plan.actions[1],receive=ReceiveRequest(cap=8,deadline=1))
    if declared_dependency:b=replace(b,edges=(ResponseEdge(b'READY','3','positive'),),unknown_target=None)
    c=replace(plan.actions[2],receive=ReceiveRequest(cap=4,deadline=1)) if c_receive else plan.actions[2]
    return replace(plan,actions=(plan.actions[0],b,c))


def test_new_connection_checks_after_two_selected_actions_close_original_first(tmp_path):
    plan = positional_plan((b'A', b'B'))
    result, trace, records, _ = run_campaign(tmp_path,
        MonitoringConfig(health_check_mode='new_connection', delayed_check=0,
            retries=0, recovery_delays=()),
        plan=plan, selected_actions=('1', '2'), payloads=(b'X',))
    assert result.outcome == 'completed'
    sequence = [step[0] for step in trace if step[0] in ('send', 'open', 'close')]
    assert sequence == ['open', 'send', 'send', 'close', 'open', 'close', 'open', 'close']
    assert [r.data['attempt_id'] for r in records if r.kind == 'campaign_assessment_deferred']
    checks = [r.data['observation'] for r in records if r.kind == 'observation'
        and r.data['observation']['kind'] == 'service_check']
    assert [check['correlation']['action_id'] for check in checks] == ['1', '2']


@pytest.mark.parametrize('condition,actions', [
    ('collection', ({'collect': True},)),
    ('report', ({'collect': True, 'report': True},)),
    ('report', ({'collect': True}, {'report': True})),
])
def test_required_collection_hold_rejects_open_multi_action_pacing_conflict(tmp_path, condition, actions):
    from bytefault.monitoring import ObservationRule
    from bytefault.management.configuration import ServiceConfiguration
    config = MonitoringConfig(health_check_mode='disabled', rules=(
        ObservationRule('collect_unrequested', 'unrequested', disposition='hold',
            conditions=(condition,), actions=actions),))
    result, trace, records, _ = run_campaign(tmp_path, config,
        plan=positional_plan((b'A', b'B')), selected_actions=('1', '2'),
        payloads=(b'X',), connection_delay=.02,
        service_configuration=ServiceConfiguration(ssh_key='controlled-key', core_write_wait=0))
    assert result.outcome == 'failed'
    assert not [step for step in trace if step[0] in ('open', 'send')]
    assert not records_of(records, 'action_result')
    incompatibilities = records_of(records, 'monitoring_incompatibility')
    assert len(incompatibilities) == 1
    assert incompatibilities[0].data['next_action'] == '2'
    assert records_of(records, 'case_terminal')


@pytest.mark.parametrize('condition,actions', [
    ('collection', ({'collect': True},)),
    ('report', ({'collect': True, 'report': True},)),
    ('report', ({'collect': True}, {'report': True})),
])
def test_dynamic_required_collection_hold_stops_before_next_action(tmp_path, condition, actions):
    from bytefault.monitoring import ObservationRule
    from bytefault.management.configuration import ServiceConfiguration
    plan = positional_plan((b'A', b'B'))
    plan = replace(plan, actions=(replace(plan.actions[0], receive=ReceiveRequest(cap=8, deadline=1)),
        plan.actions[1]))
    config = MonitoringConfig(health_check_mode='disabled', rules=(
        ObservationRule('collect_missing', 'missing_response',
            disposition='hold', conditions=(condition,), actions=actions),))
    result, trace, records, _ = run_campaign(tmp_path, config, plan=plan,
        selected_actions=('1', '2'), payloads=(b'X',),
        connection_delay=.02,
        service_configuration=ServiceConfiguration(ssh_key='controlled-key', core_write_wait=0))
    assert result.outcome in ('failed', 'monitoring_stopped')
    assert [step[2] for step in trace if step[0] == 'send'] == [b'AX']
    assert len([step for step in trace if step[0] == 'open']) == 1
    assert len(records_of(records, 'action_result')) == 1
    assert records_of(records, 'monitoring_incompatibility')
    assert records_of(records, 'monitoring_failure')


def test_ordinary_conversation_rejects_known_collection_spacing_conflict_before_connect(engine_factory):
    from bytefault.monitoring import Monitoring, ObservationRule
    from bytefault.fuzzers.inputs import raw_request
    rule = ObservationRule('collect_unrequested', 'unrequested', disposition='hold',
        conditions=('report',), actions=({'collect': True, 'report': True},))
    engine, trace, _, _ = engine_factory(monitoring=Monitoring(configuration=MonitoringConfig(
        health_check_mode='disabled', rules=(rule,))))
    engine.transport.request = replace(engine.transport.request, connection_delay=.02)
    assert engine._preflight_required_collection_spacing(positional_plan((b'A',))) is None
    terminal_entry = replace(positional_plan((b'A', b'B')), entry_action='2')
    assert engine._preflight_required_collection_spacing(terminal_entry) is None
    assert engine._preflight_required_collection_spacing(
        positional_plan((b'A', b'B')), entry_action='2') is None
    from bytefault.core.validation import collection_blocks_required_followup
    assert not collection_blocks_required_followup(({'report': True}, {'collect': True}), ('report',))
    request = replace(raw_request(b'X'), plan=positional_plan((b'A', b'B')),
        selected_actions=('1', '2'))
    result = engine.execute_conversation(request)
    assert result.outcome == 'failed'
    assert not [item for item in trace if item[0] in ('connect', 'send', 'offer')]
    from bytefault.core.storage import reopen_records
    records = reopen_records(engine.record_store.path).records
    assert records_of(records, 'monitoring_incompatibility')


def test_earlier_pending_collection_blocks_later_required_report(engine_factory):
    from bytefault.monitoring import Monitoring, ObservationRule
    from bytefault.fuzzers.inputs import raw_request
    rule = ObservationRule('report_unrequested', 'unrequested', disposition='hold',
        conditions=('report',), actions=({'report': True},))
    engine, trace, _, _ = engine_factory(monitoring=Monitoring(configuration=MonitoringConfig(
        health_check_mode='disabled', rules=(rule,))))
    engine.transport.request = replace(engine.transport.request, connection_delay=.02)
    engine.pending_collection = lambda _run_id: True
    request = replace(raw_request(b'X'), plan=positional_plan((b'A', b'B')),
        selected_actions=('1', '2'))
    result = engine.execute_conversation(request)
    assert result.outcome == 'failed'
    assert len([step for step in trace if step[0] == 'offer']) == 1
    from bytefault.core.storage import reopen_records
    records = reopen_records(engine.record_store.path).records
    blocked = records_of(records, 'monitoring_incompatibility')
    assert len(blocked) == 1 and blocked[0].data['earlier_collection_pending']


def test_deferred_checks_do_not_connect_after_uncertain_original_close(tmp_path):
    result, trace, records, _ = run_campaign(tmp_path,
        MonitoringConfig(health_check_mode='new_connection', delayed_check=0),
        plan=positional_plan((b'A', b'B')), selected_actions=('1', '2'),
        payloads=(b'X',), close_errors=(True,))
    assert result.outcome == 'cleanup_failed'
    assert [step[0] for step in trace if step[0] in ('open', 'send', 'close')] == [
        'open', 'send', 'send', 'close']
    pending = [r for r in records if r.kind == 'campaign_assessment_not_started']
    assert len(pending) == 2 and all('cleanup is uncertain' in r.data['reason'] for r in pending)
    assert not [r for r in records if r.kind == 'probe_result']


def test_default_sleep_stop_during_service_pre_delay_does_not_claim_outage(tmp_path):
    import threading
    timer = []

    def on_step(step, app):
        if step[:2] == ('close', 0):
            pending = threading.Timer(.03, lambda: app.control('run', 'stop'))
            timer.append(pending)
            pending.start()

    result, trace, records, _ = run_campaign(tmp_path,
        MonitoringConfig(health_check_mode='new_connection', delayed_check=0),
        payloads=(b'X',), on_step=on_step, default_sleep=True, pre_delay=.2)
    for pending in timer:
        pending.join(2)
    assert timer and result.outcome in ('stopped', 'monitoring_stopped')
    assert len([step for step in trace if step[0] == 'open']) == 1
    facts = [r.data for r in records if r.kind == 'probe_result']
    assert facts and facts[0]['service_readiness'] == 'unknown'
    assert facts[0]['transport']['connection']['connect_attempted'] is False
    checks = [r.data['observation'] for r in records if r.kind == 'observation'
        and r.data['observation']['kind'] == 'service_check']
    assert checks and checks[0]['service_readiness'] == 'unknown'
    assert not [a for r in records if r.kind == 'monitoring_decision'
        for a in r.data['decision']['assessments'] if a['classification'] == 'service_unavailable']


def test_deferred_first_action_retry_keeps_later_actual_action(tmp_path):
    plan = positional_plan((b'A', b'B'))
    result, trace, records, _ = run_campaign(tmp_path,
        MonitoringConfig(health_check_mode='new_connection', delayed_check=0,
            retries=1, recovery_delays=(0,)), plan=plan,
        selected_actions=('1', '2'), payloads=(b'X',),
        open_errors=(False, True, False, False, False, False))
    selected = [r.data['result'] for r in records if r.kind == 'action_result'
        and r.data['result']['iteration_id']]
    assert [item['action_id'] for item in selected] == ['1', '2', '1']
    assert selected[0]['materialized']['final_bytes'] == selected[2]['materialized']['final_bytes']
    checks = [r.data['observation'] for r in records if r.kind == 'observation'
        and r.data['observation']['kind'] == 'service_check']
    assert [item['correlation']['action_id'] for item in checks][-1] == '2'
    contexts = [r.data['context'] for r in records if r.kind == 'campaign_directive'
        and r.data['context']['correlation']['action_id'] in ('1', '2')]
    assert {context['executed_test_number'] for context in contexts
        if context['correlation']['action_id'] == '1'} == {1}
    assert {context['executed_test_number'] for context in contexts
        if context['correlation']['action_id'] == '2'} == {2}
    assert result.fuzz_tests == 2 and result.attempts == 3


def test_deferred_earlier_action_retry_uses_its_remaining_wait_budget(tmp_path):
    plan = positional_plan((b'A', b'B'))
    plan = replace(plan, actions=(replace(plan.actions[0],
        receive=ReceiveRequest(cap=8, deadline=1)), plan.actions[1]))
    result, trace, records, _ = run_campaign(tmp_path,
        MonitoringConfig(health_check_mode='new_connection', retries=3,
            recovery_budget=4, delayed_check=0), plan=plan,
        selected_actions=('1', '2'), payloads=(b'X',))
    waits = [record.data['directive'] for record in records
        if record.kind == 'retry_wait']
    assert [(item['correlation']['action_id'], item['wait_seconds']) for item in waits] == [
        ('1', 3), ('1', 1)]
    retry_contexts = [(record.data['context'], record.data['directive']) for record in records
        if record.kind == 'campaign_directive'
        and record.data['context']['correlation']['action_id'] == '1'
        and record.data['directive']['operation'] == 'retry']
    assert [(context['attempt_number'], context['recovery_elapsed'], directive['wait_seconds'])
        for context, directive in retry_contexts] == [(1, 0, 3), (2, 3, 1)]
    assert [event[2] for event in trace if event[0] == 'send'] == [b'AX', b'BX', b'AX', b'AX']
    assert result.fuzz_tests == 2 and result.attempts == 4


def test_stop_after_deferred_action_keeps_pending_check_unsent(tmp_path):
    plan = positional_plan((b'A', b'B'))
    stopped = []

    def step(event, app):
        if event[0] == 'send' and event[2].startswith(b'B') and not stopped:
            stopped.append(app.control('run', 'stop'))

    result, trace, records, _ = run_campaign(tmp_path,
        MonitoringConfig(health_check_mode='new_connection', delayed_check=0),
        plan=plan, selected_actions=('1', '2'), payloads=(b'X',), on_step=step)
    assert stopped and result.outcome == 'stopped'
    assert len([event for event in trace if event[0] == 'open']) == 1
    assert [r for r in records if r.kind == 'campaign_assessment_deferred']
    assert not [r for r in records if r.kind == 'probe_result']


def test_deferred_record_failure_stops_before_later_action_or_probe(tmp_path, monkeypatch):
    from bytefault.core.storage import LocalRecordStore
    original = LocalRecordStore.append

    def append(store, kind, identity, data):
        if kind == 'campaign_assessment_deferred':
            raise OSError('controlled deferral save failure')
        return original(store, kind, identity, data)

    monkeypatch.setattr(LocalRecordStore, 'append', append)
    result, trace, _, _ = run_campaign(tmp_path,
        MonitoringConfig(health_check_mode='new_connection', delayed_check=0),
        plan=positional_plan((b'A', b'B')), selected_actions=('1', '2'),
        payloads=(b'X',))
    assert result.outcome == 'recording_failed'
    assert [event[2] for event in trace if event[0] == 'send'] == [b'AX']
    assert len([event for event in trace if event[0] == 'open']) == 1


@pytest.mark.parametrize('declared_dependency',[True,False])
def test_mid_setup_exhaustion_replays_prior_selected_as_setup_and_advances(tmp_path,declared_dependency):
    connection=CampaignConnection(retry_setup=(CampaignSetupStep('1','recorded'),))
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        plan=mid_plan(declared_dependency),selected_actions=('1','3'),payloads=(b'X',b'Y'),connection=connection)
    assert result.outcome=='monitoring_failed' and result.selected_cases==2
    assert result.fuzz_tests==result.attempts==2
    assert (result.setup_retries,result.setup_attempts,result.case_entry_attempts)==(6,14,8)
    selected=[r.data['result'] for r in records_of(records,'action_result') if r.data['result']['iteration_id']]
    assert [a['action_id'] for a in selected]==['1','1']
    assert [a['materialized']['final_bytes'] for a in selected]==[b'AX',b'AY']
    replays=[r.data['result'] for r in records_of(records,'action_result') if r.data['result']['action_id']=='1' and r.data['result']['iteration_id'] is None]
    assert len(replays)==6 and len({r['attempt_id'] for r in replays})==6
    assert not [s for s in trace if s[0]=='send' and s[2] in (b'CX',b'CY')]
    assert result.last_conversation.unreached[0][0]=='3'
    assert result.monitoring['consecutive']==0


def test_mid_setup_prior_selected_replay_choice_required_before_replay_traffic(tmp_path):
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        plan=mid_plan(),selected_actions=('1','3'),payloads=(b'X',))
    assert result.outcome=='failed' and 'earlier selected send requires' in result.reason
    assert [s[2] for s in trace if s[0]=='send']==[b'AX',b'B']
    assert result.fuzz_tests==result.attempts==1 and result.setup_retries==0


def test_selected_retry_prefix_failure_uses_one_bounded_setup_budget_and_unique_cycles(tmp_path):
    connection=CampaignConnection(retry_setup=(CampaignSetupStep('1','recorded'),))
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        plan=mid_plan(True,True),selected_actions=('1','3'),payloads=(b'X',b'Y'),connection=connection,
        stream_reads={0:(b'READY',),5:(b'READY',b'OK')})
    assert result.outcome=='monitoring_failed' and result.selected_cases==2
    assert result.fuzz_tests==result.attempts==4
    assert result.setup_retries==3
    selected=[r.data['result'] for r in records_of(records,'action_result') if r.data['result']['iteration_id']]
    assert [a['materialized']['final_bytes'] for a in selected]==[b'AX',b'CX',b'AY',b'CY']
    assert all(a['attempt_id'].endswith('attempt-1') for a in selected)
    replays=[r.data['result'] for r in records_of(records,'action_result') if ':replay-' in r.data['result']['attempt_id']]
    assert len(replays)==8 and len({a['attempt_id'] for a in replays})==8
    assert [r.data['directive']['wait_seconds'] for r in records_of(records,'setup_retry_wait')]==[3,5,10]
    assert len(records_of(records,'retry_wait'))==1
    assert result.monitoring['setup_failed_candidates']==1


def test_retry_setup_does_not_change_later_seeded_candidates(tmp_path):
    generation={'sources':({'source_id':'s','kind':'random','options':{'min_len':1,'max_len':3,'count':2,'seed':719}},),
        'sets':({'set_id':'S','source_id':'s'},),'positions':({'position_id':'P','set_id':'S','operation':'append'},)}
    config=MonitoringConfig(health_check_mode='disabled')
    failed,_,actual,_=run_campaign(tmp_path/'failed',config,plan=setup_plan(),generation_config=generation,
        stream_reads={1:(b'READY',),2:(b'READY',)})
    control,_,expected,_=run_campaign(tmp_path/'control',config,plan=setup_plan(),generation_config=generation,
        reads=(b'READY',))
    def selected(records):return [r.data['result']['materialized'] for r in records_of(records,'action_result') if r.data['result']['iteration_id']]
    assert failed.setup_retries==1 and control.setup_retries==0
    assert selected(actual)==selected(expected)


@pytest.mark.parametrize('point',['wait','result_save'])
def test_setup_stop_or_required_failure_prevents_selected_and_later_candidate_traffic(tmp_path,point,monkeypatch,capsys):
    stopped=[]
    def step(event,app):
        if point=='wait' and not stopped and event[0]=='sleep' and event[1]>0:
            stopped.append(app.control('run','stop'))
    if point=='result_save':
        from bytefault.core.storage import LocalRecordStore
        original=LocalRecordStore.append
        def append(store,kind,identity,data):
            if kind=='campaign_setup_directive':raise OSError('setup directive save failed')
            return original(store,kind,identity,data)
        monkeypatch.setattr(LocalRecordStore,'append',append)
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        plan=setup_plan(),payloads=(b'A',b'B'),on_step=step)
    assert result.outcome==('stopped' if point=='wait' else 'recording_failed')
    assert result.fuzz_tests==result.attempts==0
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP']
    assert not records_of(records,'reconnect_attempt')
    if point=='result_save':assert 'BYTEFAULT REQUIRED RECORDING STOP' in capsys.readouterr().err


def test_final_eof_retry_prefix_exhaustion_retains_setup_history_and_acknowledged_terminal(tmp_path):
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='new_connection',check_interval=2,delayed_check=0),
        plan=setup_plan(),payloads=(b'A',),stream_reads={0:(b'READY',)},
        open_errors=(False,True,False,False,False,False,False))
    assert result.outcome=='unknown' and result.fuzz_tests==result.attempts==1
    assert result.setup_sends==result.setup_attempts==5 and result.setup_retries==3
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP',b'XA']+[b'SETUP']*4
    assert len(records_of(records,'retry_case_resume'))==1
    assert len(records_of(records,'case_start'))==1 and len(records_of(records,'case_terminal'))==2
    assert result.last_conversation.actions[-1].iteration_id is None
    assert result.last_conversation.actions[-1].response_meaning=='unknown'
    assert len({a.attempt_id for a in result.last_conversation.actions})==6
    assert result.monitoring['setup_failed_candidates']==1
    from bytefault.core.storage import reopen_records
    assert not reopen_records(tmp_path/'run.bfr').incomplete_cases


def test_one_candidate_setup_budget_spans_different_failed_actions_and_replay_cycles(tmp_path):
    plan=positional_plan((b'S',b'A',b'B',b'C'))
    s=replace(plan.actions[0],receive=ReceiveRequest(cap=8,deadline=1),
        edges=(ResponseEdge(b'READY','2','positive'),),unknown_target=None)
    b=replace(plan.actions[2],receive=ReceiveRequest(cap=8,deadline=1))
    plan=replace(plan,actions=(s,plan.actions[1],b,plan.actions[3]))
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),plan=plan,
        selected_actions=('2','4'),payloads=(b'X',),stream_reads={1:(b'READY',)},
        connection=CampaignConnection(retry_setup=(CampaignSetupStep('2','recorded'),)))
    assert result.outcome=='monitoring_failed' and result.fuzz_tests==result.attempts==1
    assert result.setup_retries==3 and result.case_entry_attempts==4
    assert [r.data['directive']['wait_seconds'] for r in records_of(records,'setup_retry_wait')]==[3,5,10]
    assert [s[2] for s in trace if s[0]=='send']==[b'S',b'S',b'AX',b'B',b'S',b'S']
    exhausted=next(r.data['directive'] for r in records_of(records,'campaign_setup_directive') if r.data['directive']['facts'].get('retry_exhausted'))
    assert exhausted['facts']['used_retries']==3 and exhausted['facts']['unused_retries']==0


def test_selected_port_rejects_setup_scoped_directive_before_counter_crossing(tmp_path):
    from bytefault.monitoring import Monitoring, ConfiguredPolicy
    from bytefault.core.contracts import CampaignDirective
    class WrongScope(Monitoring):
        def decide_attempt(self,context,observations):
            return CampaignDirective('wrong',context.campaign_id,context.test_id,context.correlation,'retry',
                scope='setup',candidate_id=context.correlation.conversation_id)
    monitor=WrongScope(ConfiguredPolicy())
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(),payloads=(b'A',),monitor=monitor)
    assert result.outcome=='failed' and 'campaign.directive' in result.reason
    assert result.setup_retries==0 and [s[2] for s in trace if s[0]=='send']==[b'XA']


def test_late_hold_installed_after_free_gate_check_awaits_same_unsent_action(engine_factory):
    import threading
    from bytefault.core.contracts import Observation, Correlation, TransportResult, MonitoringCompletion
    from bytefault.monitoring import Monitoring, ObservationRule
    from bytefault.fuzzers.inputs import raw_request
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('late','late_correlated',
        disposition='hold',conditions=('report',)),)))
    engine,trace,_,_=engine_factory(monitoring=monitor)
    request=replace(raw_request(b'X'),plan=positional_plan((b'X',b'Y')),selected_actions=('1','2'))
    original=Observation('original',Correlation(request.run_id,request.case_id,request.conversation_id,'old','old-attempt'),TransportResult(b'old'))
    engine._publish_observation(original)
    passed=threading.Event();release=threading.Event();waiting_held=threading.Event();once=[];results=[]
    wait=engine._await_monitoring
    def race_wait():
        if once and engine.continuation.hold is not None:
            waiting_held.set()
        permitted=wait()
        if not once:
            once.append(True);passed.set();assert release.wait(3)
        return permitted
    engine._await_monitoring=race_wait
    worker=threading.Thread(target=lambda:results.append(engine.execute_conversation(request)))
    worker.start()
    try:
        assert passed.wait(3)
        late=replace(original,observation_id='late',kind='late_response',prior_observation_id='original')
        with engine._action_lock:engine._publish_observation(late)
        hold=engine.continuation.hold;release.set()
        assert hold is not None and not [s for s in trace if s[0]=='offer']
        assert waiting_held.wait(3)
        assert engine.complete_monitoring(MonitoringCompletion('done',hold.decision_id,hold.observation_id,hold.correlation,'report','succeeded'))
        worker.join(3)
        assert not worker.is_alive() and results[0].outcome=='completed'
        assert [s[1] for s in trace if s[0]=='offer']==[b'X',b'Y']
        assert results[0].actions[0].attempt_id.endswith(':1:attempt-1')
    finally:
        release.set();engine.control('stop');worker.join(3)


@pytest.mark.parametrize('final',[False,True])
def test_monitoring_stop_during_replayed_setup_retains_policy_reason(tmp_path,final,monkeypatch):
    from bytefault.monitoring import ObservationRule, Monitoring
    from bytefault.core.contracts import Observation, Correlation, TransportResult
    from bytefault.fuzzers.continuation import ContinuationGate
    plan=setup_plan()
    if not final:plan=replace(plan,actions=(plan.actions[0],replace(plan.actions[1],receive=ReceiveRequest(cap=4,deadline=1))))
    config=MonitoringConfig(health_check_mode='new_connection' if final else 'disabled',
        check_interval=2,delayed_check=0,rules=(ObservationRule('bad_setup','prefix',
            {'value':b'BAD','expect':'match'},disposition='stop'),))
    errors=(False,True,False,False) if final else ()
    reads={0:(b'READY',),3 if final else 1:(b'BAD',)}
    monitor=Monitoring(configuration=config)
    applications=[];stops=[]
    select=ContinuationGate.select
    def interleaved(gate,decision,**values):
        select(gate,decision,**values)
        if decision.disposition=='stop' and not stops:
            stops.append(decision)
            later=Observation('after-stop',Correlation('run','other-case','other-conversation','other','other-attempt'),
                TransportResult(b''),kind='heartbeat')
            assert applications[0].assess(later).disposition=='continue'
    monkeypatch.setattr(ContinuationGate,'select',interleaved)
    result,trace,records,_=run_campaign(tmp_path,config,plan=plan,payloads=(b'A',),open_errors=errors,stream_reads=reads,
        monitor=monitor,on_step=lambda event,app:applications.append(app) if not applications else None)
    assert result.outcome=='monitoring_stopped' and 'bad_setup' in result.reason
    assert stops and stops[0].decision_id in result.reason
    assert monitor.decisions[-1].observation_id=='after-stop'
    assert monitor.decisions[-1].decision_id not in result.reason
    assert 'operator' not in result.reason
    assert result.fuzz_tests==result.attempts==1
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP',b'XA',b'SETUP']
    assert result.setup_sends==result.setup_attempts==2
