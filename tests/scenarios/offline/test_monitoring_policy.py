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

"""Real passive policy and engine enforcement with pre-import total denial."""
from dataclasses import replace
import socket
import pytest

from bytefault.application import Application, ApplicationRequest
from bytefault.core.contracts import (Correlation, Observation, TransportResult, TransportRequest,
    CampaignPolicyContext, CampaignOptions, CampaignConnection, ReceiveRequest, MonitoringCompletion,
    ContractError)
from bytefault.fuzzers.inputs import raw_request, positional_plan
from bytefault.fuzzers.transport import EngineTransport
from bytefault.monitoring import Monitoring, MonitoringConfig, ObservationRule


def observed(identity='obs', *, transport=None, kind='action', test='test', **values):
    return Observation(identity, Correlation('run','case','conv','send','attempt',test,'stage'),
        transport or TransportResult(b'X', receive_requested=True, receive_outcome='deadline'),
        kind=kind, **values)


def context(observation, *, number=1, attempt=1, elapsed=0, final=False):
    return CampaignPolicyContext('run','target',observation.correlation.iteration_id,
        observation.correlation,attempt,'uninterpreted',
        recovery_elapsed=elapsed,executed_test_number=number,final=final)


@pytest.mark.parametrize('kind,outcome,data,boundary,classes',[
    ('action','deadline',b'','unknown',{'potential_crash'}),
    ('action','unrequested',b'','unknown',{'unrequested'}),
    ('action','reset',b'\x00\x05X','declared',{'transport_reset','partial_response'}),
    ('action','complete',b'\x00\x03X','declared',set()),
    ('heartbeat','unrequested',b'','unknown',{'device_reachability'}),
])
def test_independent_facts(kind,outcome,data,boundary,classes):
    fact=TransportResult(b'X',acceptance='accepted',receive_requested=outcome!='unrequested',
        receive_outcome=outcome,received=data,response_boundary=boundary)
    decision=Monitoring().observe(observed(transport=fact,kind=kind))
    assert {a.classification for a in decision.assessments}==classes
    assert decision.disposition=='continue'


@pytest.mark.parametrize('boundary,outcome,data,expected',[
    ('unknown','bounded_chunk',b'BAD',{'prefix'}),
    ('declared','deadline',b'BAD',{'prefix'}),
    ('declared','complete',b'BAD',{'exact','prefix','length'}),
])
def test_framing_aware_explicit_predicates(boundary,outcome,data,expected):
    monitor=Monitoring(configuration=MonitoringConfig(rules=(
        ObservationRule('exact','exact',{'value':b'GOOD'}),
        ObservationRule('prefix','prefix',{'value':b'GO'}),
        ObservationRule('length','length',{'min':4,'max':4}))))
    fact=TransportResult(b'X',received=data,receive_outcome=outcome,response_boundary=boundary)
    decision=monitor.observe(observed(transport=fact))
    assert {a.rule for a in decision.assessments if a.rule in ('exact','prefix','length')}==expected
    assert all(a.parameters['response_boundary']==boundary for a in decision.assessments)


def test_explicit_latency_uses_offer_complete_and_first_byte():
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('slow','latency',{'threshold':.5}),)))
    fact=TransportResult(b'X',receive_requested=True,received=b'Y',offer_completed_at=10,first_response_at=10.6,receive_completed_at=99)
    assert [a.rule for a in monitor.observe(observed(transport=fact)).assessments]==['slow']
    assert not monitor.observe(observed('fast',transport=replace(fact,first_response_at=10.4))).assessments
    assert not Monitoring().observe(observed(transport=fact)).assessments


def test_late_reassessment_original_attempt_only():
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('stop','missing_response',disposition='stop'),)))
    original=observed()
    assert monitor.observe(original).disposition=='stop'
    late=replace(original,observation_id='late',kind='late_response',prior_observation_id='obs',
        transport=replace(original.transport,received=b'late',receive_outcome='bounded_chunk'))
    decision=monitor.observe(late)
    assert decision.disposition=='continue'
    assert decision.assessments[0].classification=='missing_response_resolved'
    assert monitor.decisions[0].disposition=='stop'
    ordinary=replace(original,observation_id='ordinary',transport=replace(late.transport,
        receive_outcome='complete',response_boundary='declared'))
    monitor.observe(ordinary)
    assert monitor.observe(replace(late,observation_id='extra',prior_observation_id='ordinary')).assessments[0].classification=='correlated_additional_response'
    assert monitor.observe(replace(late,observation_id='unknown',prior_observation_id='absent')).assessments[0].classification=='late_response_unknown'


@pytest.mark.parametrize('config,attempts,elapsed,waits,unused',[
    (MonitoringConfig(health_check_mode='disabled'),4,18,[3,5,10],0),
    (MonitoringConfig(health_check_mode='disabled',retries=6),6,50,[3,5,10,15,17],1),
    (MonitoringConfig(health_check_mode='disabled',retries=6,recovery_budget=4),3,4,[3,1],4),
    (MonitoringConfig(health_check_mode='disabled',retries=2,recovery_delays=(0,0)),3,0,[0,0],0),
    (MonitoringConfig(health_check_mode='disabled',retries=0),1,0,[],0),
])
def test_passive_retry_count_shared_schedule_budget(config,attempts,elapsed,waits,unused):
    monitor=Monitoring(configuration=config);monitor.begin_campaign('run')
    selected=[]; spent=0
    for attempt in range(1,attempts+1):
        obs=observed(str(attempt));monitor.observe(obs)
        decision=monitor.decide_attempt(context(obs,attempt=attempt,elapsed=spent), (obs,))
        if decision.operation=='retry':
            selected.append(decision.wait_seconds);spent+=decision.wait_seconds
    assert selected==waits and spent==elapsed
    assert decision.operation=='advance' and decision.facts['failed_test']
    assert decision.facts['unused_retries']==unused
    monitor.end_campaign()


def test_disabled_observations_cannot_trigger_retry():
    monitor=Monitoring(configuration=MonitoringConfig(observations=('service_check',),health_check_mode='disabled'))
    monitor.begin_campaign('run');obs=observed()
    assert not monitor.observe(obs).assessments
    assert monitor.decide_attempt(context(obs),(obs,)).operation=='advance'


class PortClock:
    def __init__(self): self.now=0;self.trace=[]
    def __call__(self): return self.now
    def sleep(self,value): self.trace.append(('sleep',value));self.now+=value


class PortStream:
    def __init__(self,clock,identity,*,reads=(),open_error=False,close_error=False):
        self.clock,self.identity=clock,identity;self.reads=list(reads);self.open_error=open_error;self.close_error=close_error
    def settimeout(self,value): pass
    def connect(self,target):
        self.clock.trace.append(('open',self.identity,target))
        if self.open_error: raise OSError('refused')
    def send(self,data): self.clock.trace.append(('send',self.identity,bytes(data)));return len(data)
    def recv(self,cap):
        self.clock.trace.append(('read',self.identity,cap))
        self.clock.now+=getattr(self.clock,'read_delay',1)
        value=self.reads.pop(0) if self.reads else socket.timeout('no byte')
        if isinstance(value,Exception):raise value
        if len(value)>cap:self.reads.insert(0,value[cap:])
        return value[:cap]
    def close(self):
        self.clock.trace.append(('close',self.identity))
        if self.close_error:raise OSError('controlled close failure')


def run_campaign(tmp_path,config,*,payloads=(b'A',b'B',b'C'),reads=(),open_errors=(),close_errors=(),receive=None,plan=None,connection=None,on_step=None,capture=None,monitor=None,read_delay=1,stream_reads=None,selected_actions=None,generation_config=None,default_sleep=False,pre_delay=0,connection_delay=0,service_configuration=None):
    if default_sleep:
        import time
        class RealtimePortClock(PortClock):
            def __call__(self): return time.monotonic()
        clock=RealtimePortClock()
    else:
        clock=PortClock()
    streams=[];errors=iter(open_errors);closes=iter(close_errors)
    clock.read_delay=read_delay
    def transport(request):
        def factory(*args):
            stream=PortStream(clock,len(streams),reads=(stream_reads.get(len(streams),reads) if stream_reads else reads),open_error=next(errors,False),close_error=next(closes,False))
            streams.append(stream);return stream
        return EngineTransport(request,socket_factory=factory,clock=clock,
            sleep=None if default_sleep else clock.sleep)
    monitor=monitor or Monitoring(configuration=config)
    app=Application(transport_factory=transport,monitoring=monitor,
        service_configuration=service_configuration)
    if on_step:
        class Trace(list):
            def append(self,step):
                super().append(step);on_step(step,app)
        clock.trace=Trace()
    conv=raw_request(b'X')
    conv=replace(conv,run_id='run',plan=plan or replace(conv.plan,actions=(replace(conv.plan.actions[0],receive=receive or ReceiveRequest(requested=False)),)))
    if plan:conv=replace(conv,selected_actions=selected_actions or ('2',))
    request=ApplicationRequest(conv,TransportRequest('offline.invalid',1234,10,pre_delay,0,connection_delay),str(tmp_path/'run.bfr'))
    generation={'sources':({'source_id':'s','kind':'list','options':{'payloads':payloads}},),
        'sets':({'set_id':'S','source_id':'s'},),'positions':({'position_id':'P','set_id':'S','operation':'append'},)}
    if generation_config is not None:generation=generation_config
    result=app.campaign(request,generation=generation,options=CampaignOptions(connection=connection or CampaignConnection()))
    records=app.read_records('run').records
    if capture is not None:capture.update(app.status('run'))
    app.close()
    return result,clock.trace,records,monitor


def test_deferred_check_does_not_replay_completed_intermediate_hold(tmp_path):
    import threading
    import time
    from bytefault.core.contracts import CampaignDirective, MonitoringDecision, ProbeRequest

    released = threading.Event()
    apps, trace, outcomes, errors = [], [], [], []

    class Policy:
        def evaluate(self, observation):
            held = observation.kind == 'action' and observation.correlation.action_id == '2'
            return MonitoringDecision('observation:' + observation.observation_id,
                observation.observation_id, observation.correlation,
                'hold' if held else 'continue', 'awaited' if held else 'nonblocking',
                ('readiness',) if held else ())

        def decide_attempt(self, context, observations):
            probes = ()
            if context.correlation.action_id == '1' and not any(
                    item.kind == 'service_check' for item in observations):
                probes = (ProbeRequest('probe:' + context.correlation.attempt_id,
                    observations[-1].observation_id, context.correlation, b'',
                    kind='service_connect', delay=0),)
            operation = ('hold' if context.correlation.action_id == '2'
                and not released.is_set() else 'advance')
            return CampaignDirective('attempt:' + context.correlation.attempt_id,
                context.campaign_id, context.test_id, context.correlation, operation, probes=probes)

    def step(value, app):
        trace.append(value)
        if not apps:
            apps.append(app)

    def execute():
        try:
            outcomes.append(run_campaign(tmp_path, MonitoringConfig(),
                monitor=Monitoring(Policy()), plan=positional_plan((b'A', b'B', b'C')),
                selected_actions=('1', '2', '3'), payloads=(b'X',), on_step=step))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=execute)
    worker.start()
    try:
        deadline = time.monotonic() + 3
        hold = None
        while time.monotonic() < deadline:
            if apps:
                engine = apps[0]._run('run').engine
                hold = engine.continuation.hold
                if hold is not None and engine._execution_state == 'monitoring_held':
                    break
            time.sleep(.001)
        assert hold is not None and hold.correlation.action_id == '2'
        assert worker.is_alive()
        assert [event[2] for event in trace if event[0] == 'send'] == [b'AX', b'BX']
        assert len([event for event in trace if event[0] == 'open']) == 1
        released.set()
        assert apps[0].complete_monitoring('run', MonitoringCompletion('done',
            hold.decision_id, hold.observation_id, hold.correlation,
            'readiness', 'succeeded'))
        worker.join(3)
        assert not worker.is_alive() and not errors
        result, trace, records, _ = outcomes[0]
        assert result.outcome == 'completed'
        assert [event[2] for event in trace if event[0] == 'send'] == [b'AX', b'BX', b'CX']
        deferred = [record.data['attempt_id'] for record in records
            if record.kind == 'campaign_assessment_deferred']
        assert deferred and all(':2:' not in attempt for attempt in deferred)
    finally:
        released.set()
        if worker.is_alive() and apps:
            apps[0].control('run', 'stop')
        worker.join(3)


@pytest.mark.parametrize('interval,first_purpose',[(1,'periodic'),(2,'final')])
@pytest.mark.parametrize('selection',[
    'default','custom','custom_no_retry','disabled_rule','disabled_observation','unmatched_replacement',
])
def test_service_policy_uses_effective_matching_rules(tmp_path,interval,first_purpose,selection):
    options = {}
    if selection.startswith('custom'):
        options.update(disabled_rules=('service_failure','service_success'),
            rules=(ObservationRule('failed_check','service_failure'),
                   ObservationRule('healthy_check','service_success')),
            retry_rules=('failed_check',) if selection=='custom' else (),
            throttle_rules=('failed_check',),healthy_rules=('healthy_check',))
    elif selection=='disabled_rule':
        options['disabled_rules']=('service_failure',)
    elif selection=='disabled_observation':
        options['observations']=('action',)
    elif selection=='unmatched_replacement':
        # Reusing a built-in ID does not grant its former kind or a match.
        options['rules']=(ObservationRule('service_failure','prefix',{'value':b'BAD'}),)
    config=MonitoringConfig(check_interval=interval,delayed_check=0,recovery_delays=(0,),
        retries=1,crash_throttle=0,**options)
    result,trace,records,monitor=run_campaign(tmp_path,config,payloads=(b'A',),
        open_errors=(False,True,False,False,True,False))
    retry=selection in ('default','custom')
    detected=retry or selection=='custom_no_retry'
    checks=[r.data['observation'] for r in records if r.kind=='observation'
        and r.data['observation']['kind']=='service_check']
    expected=([first_purpose,'recovery','retry_check','recovery'] if retry else
              [first_purpose,'recovery'] if detected else [first_purpose])
    assert [o['parameters']['purpose'] for o in checks]==expected
    assert checks[0]['service_readiness']=='unavailable'
    assert checks[0]['transport']['error']=='refused'
    assert [s[2] for s in trace if s[0]=='send']==[b'XA']*(2 if retry else 1)
    assert len([s for s in trace if s[0]=='open'])==(6 if retry else 3 if detected else 2)
    assert result.attempts==(2 if retry else 1) and result.fuzz_tests==1
    assert result.monitoring['service_checks']==len(checks)
    assert result.monitoring['failures']==int(detected)
    assert not result.monitoring['throttled'] and not result.monitoring['unrecovered']
    assert result.outcome==('monitoring_failed' if retry else 'completed')
    first_decision=next(r.data['decision'] for r in records if r.kind=='monitoring_decision'
        and r.data['decision']['observation_id']==checks[0]['observation_id'])
    assert {a['rule'] for a in first_decision['assessments']}==(
        {'failed_check' if selection.startswith('custom') else 'service_failure'} if detected else set())
    if not detected:
        assert not any(r.kind=='retry_wait' for r in records)
        assert not any(r.kind=='campaign_directive' and r.data['directive']['operation']=='stop' for r in records)
    assert all(any(o.observation_id==check['observation_id'] for o in monitor.observations) for check in checks)


def test_disabled_service_success_does_not_complete_recovery():
    monitor=Monitoring(configuration=MonitoringConfig(disabled_rules=('service_success',),
        recovery_delays=(0,),retries=0,crash_throttle=0))
    monitor.begin_campaign('run')
    action=observed(transport=TransportResult(b'X',acceptance='accepted'))
    failed=replace(action,observation_id='failed',kind='service_check',service_readiness='unavailable',
        parameters={'purpose':'periodic'})
    recovered=replace(failed,observation_id='recovered',service_readiness='available',
        parameters={'purpose':'recovery','delay':0})
    for obs in (action,failed,recovered):monitor.observe(obs)
    assert monitor.decide_attempt(context(action),(action,failed)).probes
    assert not monitor.decisions[-1].assessments
    decision=monitor.decide_attempt(context(action),(action,failed,recovered))
    assert decision.unrecovered and decision.facts['recovery_schedule_exhausted']
    assert not decision.probes


def test_repeated_recovery_failure_retains_first_episode_and_distinct_stop():
    monitor = Monitoring(configuration=MonitoringConfig(recovery_delays=(0, 0), retries=0,
        rules=(ObservationRule('service_failure', 'service_failure', disposition='hold',
            conditions=('readiness', 'collection', 'report'), actions=({'collect': True, 'report': True},)),
            ObservationRule('bad_recovery', 'prefix', {'value': b'BAD', 'expect': 'match'},
                disposition='stop'))))
    monitor.begin_campaign('run')
    action = observed(transport=TransportResult(b'X', acceptance='accepted'))
    first = replace(action, observation_id='first', kind='service_check',
        service_readiness='unavailable', parameters={'purpose': 'periodic'})
    again = replace(first, observation_id='again', parameters={'purpose': 'recovery', 'delay': 0})
    distinct = replace(again, observation_id='distinct', transport=TransportResult(b'X',
        received=b'BAD', receive_outcome='complete', response_boundary='declared'))
    monitor.observe(action)
    monitor.decide_attempt(context(action), (action,))
    original = monitor.observe(first)
    assert original.disposition == 'hold' and len(original.actions) == 1
    assert monitor.decide_attempt(context(action), (action, first)).probes
    repeated = monitor.observe(again)
    assert repeated.disposition == 'continue' and not repeated.actions
    assert [item.rule for item in repeated.assessments] == ['service_failure']
    assert first.observation_id in repeated.reason
    assert monitor.decide_attempt(context(action), (action, first, again)).probes
    later = monitor.observe(distinct)
    assert later.disposition == 'stop' and not later.actions
    assert {item.rule for item in later.assessments} == {'service_failure', 'bad_recovery'}


@pytest.mark.parametrize('purpose',['periodic','final','retry_check'])
@pytest.mark.parametrize('selection',['disabled_rule','disabled_observation','unmatched_replacement'])
def test_ineligible_delayed_failure_never_becomes_a_policy_trigger(purpose,selection):
    options=({'disabled_rules':('service_failure',)} if selection=='disabled_rule' else
        {'observations':('action',)} if selection=='disabled_observation' else
        {'rules':(ObservationRule('service_failure','prefix',{'value':b'BAD'}),)})
    monitor=Monitoring(configuration=MonitoringConfig(recovery_delays=(0,),retries=1,
        crash_throttle=1,**options))
    monitor.begin_campaign('run')
    action=observed(transport=TransportResult(b'X',acceptance='accepted'))
    failed=replace(action,observation_id='failed',kind='service_check',service_readiness='unavailable',
        parameters={'purpose':purpose})
    recovered=replace(failed,observation_id='recovered',service_readiness='available',
        parameters={'purpose':'recovery','delay':0})
    for obs in (action,failed,recovered):monitor.observe(obs)
    for observations in ((action,failed),(action,failed,recovered)):
        directive=monitor.decide_attempt(context(action,final=purpose=='final'),observations)
        assert directive.operation=='advance' and not directive.probes
        assert not directive.throttled and not directive.unrecovered
    assert not monitor.decisions[1].assessments
    assert monitor.summary()['consecutive']==0 and monitor.summary()['service_checks']==2


@pytest.mark.parametrize('throttle_rules,count,stopped',[
    (('bad_recovery',),1,True),(('service_failure',),1,True),((),0,False),
])
def test_explicit_recovery_anomaly_throttle_is_independent_of_other_matches(tmp_path,throttle_rules,count,stopped):
    config=MonitoringConfig(delayed_check=0,retries=0,recovery_delays=(0,),crash_throttle=1,
        health_check_mode='in_band',
        in_band={'prepared':b'PING','receive':{'cap':3,'deadline':1},
                 'predicate':{'kind':'prefix','value':b'OK'}},
        rules=(ObservationRule('bad_recovery','prefix',{'value':b'NO'}),),
        throttle_rules=throttle_rules)
    result,trace,records,_=run_campaign(tmp_path,config,payloads=(b'A',),reads=(b'NO',b'BAD'))
    assert [s[2] for s in trace if s[0]=='send']==[b'XA',b'PING',b'PING']
    assert len([s for s in trace if s[0]=='open'])==1
    checks=[r.data['observation'] for r in records if r.kind=='observation'
        and r.data['observation']['kind']=='service_check']
    assert [o['parameters']['purpose'] for o in checks]==['periodic','recovery']
    assert [o['transport']['received'] for o in checks]==[b'NO',b'BAD']
    assert all(o['service_readiness']=='unavailable' for o in checks)
    decisions={r.data['decision']['observation_id']:r.data['decision']
        for r in records if r.kind=='monitoring_decision'}
    assert {a['rule'] for a in decisions[checks[0]['observation_id']]['assessments']}=={'service_failure'}
    assert {a['rule'] for a in decisions[checks[1]['observation_id']]['assessments']}=={'service_failure','bad_recovery'}
    assert result.monitoring['consecutive']==result.monitoring['failures']==count
    assert result.monitoring['throttled']==stopped and result.monitoring['unrecovered']
    assert result.outcome==('monitoring_stopped' if stopped else 'monitoring_failed')
    if stopped:
        final = [r.data['directive'] for r in records if r.kind == 'campaign_directive'][-1]
        trigger = 'bad_recovery (prefix)' if throttle_rules == ('bad_recovery',) else 'service_failure (service_failure)'
        assert trigger in final['reason']
        assert final['facts']['throttle_trigger']['rule_id'] == throttle_rules[0]


@pytest.mark.parametrize('interval,purposes',[(2,['periodic','final']),(1,['periodic']*3)])
def test_actual_service_checks_cadence_final_and_windows(tmp_path,interval,purposes):
    result,trace,records,monitor=run_campaign(tmp_path,MonitoringConfig(check_interval=interval,delayed_check=0))
    observations=[r.data['observation'] for r in records if r.kind=='observation' and r.data['observation']['kind']=='service_check']
    assert result.outcome=='completed' and result.fuzz_tests==3
    assert [o['parameters']['purpose'] for o in observations]==purposes
    assert [o['service_readiness'] for o in observations]==['available']*len(purposes)
    assert all(o['correlation']['iteration_id'] for o in observations)
    assert len([s for s in trace if s[0]=='open'])==3+len(purposes)
    assert len([s for s in trace if s[0]=='send'])==3
    assert result.monitoring['service_checks']==len(purposes)
    start=next(r for r in records if r.kind=='campaign_start')
    assert start.data['monitoring']['configuration']['check_interval']==interval
    assert len(start.data['monitoring']['effective_rules'])>=10
    if interval==2:
        assert len(observations[0]['parameters']['window'])==2
        assert observations[1]['parameters']['window']==(observations[1]['correlation']['iteration_id'],)


def test_actual_missing_retry_preserves_exact_candidate_and_evidence(tmp_path):
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        payloads=(b'A',),receive=ReceiveRequest(cap=10,deadline=1))
    assert result.outcome=='monitoring_failed' and result.attempts==4 and result.fuzz_tests==1
    assert [s[2] for s in trace if s[0]=='send']==[b'XA']*4
    assert [r.data['directive']['wait_seconds'] for r in records if r.kind=='retry_wait']==[3,5,10]
    assert len([r for r in records if r.kind=='reconnect_attempt'])==3
    terminal=next(r.data['directive'] for r in records if r.kind=='campaign_directive' and r.data['directive']['facts'].get('retry_exhausted'))
    assert terminal['facts']['retry_exhausted'] and terminal['facts']['unused_retries']==0
    assert result.monitoring['failed_tests']==1 and result.monitoring['consecutive']==0


def test_service_only_failures_retry_each_immutable_test_count_throttle_once(tmp_path):
    # Every main exchange responds; delayed checks fail; recovery connects succeed.
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(delayed_check=0),
        reads=(b'OK',),receive=ReceiveRequest(cap=4,deadline=2),
        open_errors=(False,True,False)*12)
    assert result.outcome=='monitoring_failed'
    assert (result.fuzz_tests,result.attempts)==(3,12)
    assert [s[2] for s in trace if s[0]=='send']==[b'XA']*4+[b'XB']*4+[b'XC']*4
    assert result.monitoring['failures']==3 and result.monitoring['consecutive']==3
    assert result.monitoring['failed_tests']==3
    assert [r.data['directive']['wait_seconds'] for r in records if r.kind=='retry_wait']==[3,5,10]*3
    assert all(r.data['result']['transport']['received']==b'OK' for r in records if r.kind=='action_result')


def test_final_service_failure_resumes_only_original_last_test(tmp_path):
    # test2 cadence check succeeds; test3 final check fails once, then succeeds.
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(check_interval=2,delayed_check=0),
        open_errors=(False,False,False,False,True,False,False,False))
    assert result.outcome=='completed' and result.attempts==4
    assert [s[2] for s in trace if s[0]=='send']==[b'XA',b'XB',b'XC',b'XC']
    actions=[r.data['result'] for r in records if r.kind=='action_result']
    assert actions[-2]['iteration_id']==actions[-1]['iteration_id']
    assert actions[-2]['attempt_id'].endswith('attempt-1')
    assert actions[-1]['attempt_id'].endswith('attempt-2')
    assert actions[-2]['materialized']==actions[-1]['materialized']
    assert sum(r.kind=='final_attempt_resume' for r in records)==1


def test_failed_probe_recovery_throttle_keep_both_facts(tmp_path):
    config=MonitoringConfig(crash_throttle=1,recovery_delays=(3,5),delayed_check=0)
    result,trace,records,_=run_campaign(tmp_path,config,open_errors=(False,True,True,True))
    assert result.outcome=='monitoring_stopped' and result.fuzz_tests==1
    assert result.monitoring['throttled'] and result.monitoring['unrecovered']
    assert result.monitoring['failures']==1 and result.monitoring['service_checks']==3
    assert [r.data['probe']['delay'] for r in records if r.kind=='probe_wait']==[0,3,5]
    assert len([s for s in trace if s[0]=='send'])==1
    final=[r.data['directive'] for r in records if r.kind=='campaign_directive'][-1]
    assert final['throttled'] and final['unrecovered'] and 'threshold' in final['reason']


def test_final_in_band_uses_retained_connection_before_close(tmp_path):
    config=MonitoringConfig(check_interval=2,delayed_check=0,health_check_mode='in_band',
        in_band={'prepared':b'PING','receive':{'cap':4,'deadline':2},
                 'predicate':{'kind':'prefix','value':b'OK'}})
    result,trace,records,_=run_campaign(tmp_path,config,reads=(b'OK',))
    assert result.outcome=='completed'
    assert [(s[1],s[2]) for s in trace if s[0]=='send']==[(0,b'XA'),(1,b'XB'),(1,b'PING'),(2,b'XC'),(2,b'PING')]
    assert [r.data['observation']['parameters']['purpose'] for r in records if r.kind=='observation' and r.data['observation']['kind']=='service_check']==['periodic','final']


def test_hold_expiry_saved_before_next_send(engine_factory):
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('await','unrequested',
        disposition='hold',conditions=('assessment',),hold_timeout=.1,on_expiry='advance'),)))
    engine,trace,_,clock=engine_factory(monitoring=monitor)
    plan=positional_plan((b'X',b'Y'))
    plan=replace(plan,actions=(plan.actions[0],replace(plan.actions[1],receive=ReceiveRequest(cap=4,deadline=2))))
    request=replace(raw_request(b'X'),plan=plan,selected_actions=('1','2'))
    result=engine.execute_conversation(request)
    assert result.outcome=='completed'
    assert [s[1] for s in trace if s[0]=='offer']==[b'X',b'Y']
    assert engine.continuation.hold is None
    from bytefault.core.storage import reopen_records
    assert sum(r.kind=='monitoring_expiry' for r in reopen_records(engine.record_store.path).records)==1


def test_in_band_missing_observable_criterion_rejected():
    with pytest.raises(ContractError,match='unavailable'):
        MonitoringConfig(health_check_mode='in_band',in_band={'prepared':b'PING'})
    with pytest.raises(ContractError):
        MonitoringConfig(health_check_mode='in_band',in_band={'prepared':b'PING','receive':{'requested':False},'predicate':{'kind':'prefix','value':b'OK'}})


def test_actual_transport_monotonic_first_byte_threshold(tmp_path):
    config=MonitoringConfig(health_check_mode='disabled',rules=(ObservationRule('slow','latency',{'threshold':.1}),))
    result,trace,records,_=run_campaign(tmp_path,config,payloads=(b'A',),reads=(b'O',b'K'),
        receive=ReceiveRequest(cap=4,deadline=5,length_offset=0,length_size=1),read_delay=3)
    observation=next(r.data['observation'] for r in records if r.kind=='observation')
    fact=observation['transport']
    assert fact['first_response_at']-fact['offer_completed_at']==3
    assert fact['receive_completed_at']>fact['first_response_at']
    assert any(a['rule']=='slow' for r in records if r.kind=='monitoring_decision' for a in r.data['decision']['assessments'])
    assert result.attempts==1  # anomaly retry is opt-in


@pytest.mark.parametrize('with_healthy_middle', [False,True])
def test_actual_distinct_crashes_recovery_no_reset_and_later_health_reset(tmp_path,with_healthy_middle):
    errors=(False,True,False,False,False,False,True,False) if with_healthy_middle else (False,True,False)*2
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(crash_throttle=2,retries=0,delayed_check=0),
        payloads=(b'A',b'B',b'C') if with_healthy_middle else (b'A',b'B'),open_errors=errors)
    assert result.monitoring['failures']==2
    assert result.monitoring['consecutive']==(1 if with_healthy_middle else 2)
    assert result.monitoring['throttled']==(not with_healthy_middle)
    assert result.outcome==('monitoring_failed' if with_healthy_middle else 'monitoring_stopped')


def test_same_test_recovery_does_not_count_or_reset_and_campaign_state_resets(tmp_path):
    monitor=Monitoring(configuration=MonitoringConfig(crash_throttle=0,retries=0,delayed_check=0))
    failed,_,_,_=run_campaign(tmp_path/'A',monitor.policy.configuration,payloads=(b'A',),
        open_errors=(False,True,False),monitor=monitor)
    assert failed.monitoring['consecutive']==1 and failed.monitoring['failures']==1
    healthy,_,_,_=run_campaign(tmp_path/'B',monitor.policy.configuration,payloads=(b'B',),monitor=monitor)
    assert healthy.monitoring['consecutive']==0 and healthy.monitoring['failures']==0
    assert not healthy.monitoring['throttled']


def test_explicit_negative_and_no_receive_do_not_trigger_retry(tmp_path):
    from bytefault.core.contracts import ResponseEdge
    plan=positional_plan((b'SETUP',b'X'))
    plan=replace(plan,actions=(plan.actions[0],replace(plan.actions[1],receive=ReceiveRequest(cap=4,deadline=2),
        edges=(ResponseEdge(b'NO',None,'negative'),),unknown_target=None)))
    result,trace,_,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        payloads=(b'A',),reads=(b'NO',),plan=plan)
    assert result.attempts==1 and result.outcome=='completed'
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP',b'XA']


@pytest.mark.parametrize('point',['read','retry_wait'])
def test_stop_during_read_or_retry_wait_forbids_following_traffic(tmp_path,point):
    stopped=[]
    def step(value,app):
        if not stopped and ((point=='read' and value[0]=='read') or
            (point=='retry_wait' and value[0]=='sleep' and value[1]>0)):
            stopped.append(app.control('run','stop'))
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        receive=ReceiveRequest(cap=4,deadline=1),on_step=step)
    assert stopped and result.outcome=='stopped'
    assert len([s for s in trace if s[0]=='send'])==1
    assert not [r for r in records if r.kind=='probe_materialization']


def test_stop_from_rule_followup_while_held(engine_factory):
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('wait','unrequested',
        disposition='hold',conditions=('report',),actions=({'report':True},)),)))
    engine,trace,_,_=engine_factory(monitoring=monitor)
    engine.followup=lambda decision:engine.control('stop')
    request=replace(raw_request(b'X'),plan=positional_plan((b'X',b'Y')),selected_actions=('1','2'))
    result=engine.execute_conversation(request)
    assert result.outcome=='stopped'
    assert [s[1] for s in trace if s[0]=='offer']==[b'X']
    assert engine.continuation.hold is not None


@pytest.mark.parametrize('failure_kind',['campaign_directive','probe_result'])
def test_required_policy_or_probe_save_failure_forbids_more_traffic(tmp_path,monkeypatch,capsys,failure_kind):
    from bytefault.core.storage import LocalRecordStore
    original=LocalRecordStore.append
    def append(store,kind,identity,data):
        if kind==failure_kind:raise OSError('controlled '+kind+' save failure')
        return original(store,kind,identity,data)
    monkeypatch.setattr(LocalRecordStore,'append',append)
    capture={}
    config=MonitoringConfig(delayed_check=0,health_check_mode='in_band',
        in_band={'prepared':b'PING','receive':{'cap':4,'deadline':2},'predicate':{'kind':'prefix','value':b'OK'}})
    result,trace,records,_=run_campaign(tmp_path,config,reads=(b'OK',),capture=capture)
    assert result.outcome=='recording_failed'
    assert [s[2] for s in trace if s[0]=='send']==([b'XA'] if failure_kind=='campaign_directive' else [b'XA',b'PING'])
    failure=capture['storage_failure']
    assert failure['required_record_kind']==failure_kind
    if failure_kind=='probe_result':
        assert failure['available_materialized_bytes']==b'PING'
        assert failure['known_transport_progress']['prepared']==b'PING'
        assert failure['known_transport_progress']['received']==b'OK'
        assert failure['known_transport_identity']['probe_id']
    assert 'BYTEFAULT REQUIRED RECORDING STOP' in capsys.readouterr().err


def test_two_rule_actions_and_stale_completion_cannot_release_another_hold():
    from bytefault.fuzzers.continuation import ContinuationGate
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('wait','unrequested',
        disposition='hold',conditions=('report',),actions=({'report':True},{'report':True})),)))
    gate=ContinuationGate()
    decision=monitor.observe(observed(transport=TransportResult(b'X')))
    gate.select(decision)
    a,b=decision.actions
    def completion(action,status='succeeded'):
        return MonitoringCompletion('done:'+action.action_id,decision.decision_id,decision.observation_id,
            decision.correlation,'report',status,followup_action_id=action.action_id)
    assert gate.complete(completion(a)) and gate.hold is not None
    assert gate.complete(completion(b)) and gate.hold is None
    second=monitor.observe(observed('second',transport=TransportResult(b'Y'),test='other'))
    gate.select(second)
    assert not gate.complete(completion(a)) and gate.hold==second


@pytest.mark.parametrize('treatment,held,stopped',[('hold',True,False),('advance',False,False),('stop',True,True)])
def test_configured_failed_action_treatment(treatment,held,stopped):
    from bytefault.fuzzers.continuation import ContinuationGate
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('wait','unrequested',
        disposition='hold',conditions=('report',),on_failure=treatment),)))
    decision=monitor.observe(observed(transport=TransportResult(b'X')))
    gate=ContinuationGate();gate.select(decision)
    assert gate.complete(MonitoringCompletion('failed',decision.decision_id,decision.observation_id,
        decision.correlation,'report','failed'))
    assert (gate.hold is not None)==held and gate.stopped==stopped


def test_reopening_exhaustion_separate_from_test_attempts(tmp_path):
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),
        payloads=(b'A',),receive=ReceiveRequest(cap=4,deadline=1),open_errors=(False,True,True,True,True,True))
    assert result.outcome=='transport_failed' and result.attempts==1
    assert result.last_conversation.outcome=='transport_failed'
    assert result.monitoring['unrecovered'] and result.monitoring['failed_tests']==1
    assert len([r for r in records if r.kind=='reconnect_attempt'])==5
    assert len([s for s in trace if s[0]=='open'])==6
    decision=[r.data['directive'] for r in records if r.kind=='campaign_directive'][-1]
    assert decision['facts']['reconnect_exhausted'] and decision['facts']['unused_retries']==3


def test_configured_anomaly_retries_are_opt_in(tmp_path):
    config=MonitoringConfig(health_check_mode='disabled',retry_rules=('bad_prefix',),
        rules=(ObservationRule('bad_prefix','prefix',{'value':b'OK'}),))
    result,trace,records,_=run_campaign(tmp_path,config,payloads=(b'A',),reads=(b'NO',),
        receive=ReceiveRequest(cap=4,deadline=2))
    assert result.attempts==4 and result.monitoring['failed_tests']==1
    assert [s[2] for s in trace if s[0]=='send']==[b'XA']*4


@pytest.mark.parametrize('values',[{'hold_timeout':-1},{'on_expiry':'retry'},{'on_failure':'ignore'}])
def test_alternate_policy_invalid_hold_contract_rejected(values):
    from bytefault.fuzzers.continuation import ContinuationGate
    from bytefault.core.contracts import MonitoringDecision
    obs=observed()
    decision=MonitoringDecision('decision',obs.observation_id,obs.correlation,'hold','awaited',('assessment',),**values)
    with pytest.raises(ContractError,match='monitoring.decision'):
        ContinuationGate().select(decision)


def test_campaign_identity_is_passive_for_ordinary_submit(tmp_path,application_factory):
    from bytefault.core.contracts import CampaignIdentity
    app,traces=application_factory()
    conversation=replace(raw_request(b'X'),campaign=CampaignIdentity('metadata-only',1))
    request=ApplicationRequest(conversation,TransportRequest('offline.invalid',1234,10),str(tmp_path/'ordinary.bfr'))
    result=app.submit(request)
    assert result.outcome=='completed'
    assert [s[1] for s in traces[0][0] if s[0]=='offer']==[b'X']
    assert sum(s[0]=='close' for s in traces[0][0])==1
    assert not [r for r in app.read_records(conversation.run_id).records if r.kind=='campaign_directive']


def test_explicit_late_stop_and_conflicting_hold_preserve_other_hold():
    from bytefault.fuzzers.continuation import ContinuationGate
    monitor=Monitoring(configuration=MonitoringConfig(rules=(
        ObservationRule('later_stop','late_correlated',disposition='stop'),
        ObservationRule('await','unrequested',disposition='hold',conditions=('report',)))))
    first=observed('first');monitor.observe(first)
    hold=monitor.observe(observed('other',test='other',transport=TransportResult(b'Y')))
    gate=ContinuationGate();gate.select(hold)
    late=replace(first,observation_id='late',kind='late_response',prior_observation_id='first',
        transport=replace(first.transport,received=b'late'))
    stop=monitor.observe(late)
    assert stop.disposition=='stop' and stop.correlation==first.correlation
    gate.select(stop)
    assert gate.stopped and gate.hold==hold
    assert gate.stop_decision==stop and gate.stop_decision!=hold
    assert gate.stop_cause=='observation_decision'
    gate.select(monitor.observe(observed('after-stop',kind='heartbeat')))
    assert gate.stop_decision==stop
    holder=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('late_hold','late_correlated',
            disposition='hold',conditions=('report',)),)))
    holder.observe(first)
    late_hold=holder.observe(late)
    second_gate=ContinuationGate();second_gate.select(hold)
    with pytest.raises(ContractError,match='hold_conflict'):
        second_gate.select(late_hold)
    assert second_gate.hold==hold


def test_negative_terminal_retention_does_not_grant_persistent_setup_reuse(tmp_path):
    from bytefault.core.contracts import ResponseEdge
    plan=positional_plan((b'SETUP',b'X'))
    plan=replace(plan,actions=(plan.actions[0],replace(plan.actions[1],receive=ReceiveRequest(cap=4,deadline=2),
        edges=(ResponseEdge(b'NO',None,'negative'),),unknown_target=None)))
    result,trace,_,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),reads=(b'NO',),plan=plan,
        connection=CampaignConnection('persistent','2',('2',),('positive',)))
    assert result.outcome=='completed' and result.setup_sends==3
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP',b'XA',b'SETUP',b'XB',b'SETUP',b'XC']
    assert len([s for s in trace if s[0]=='open'])==3


def test_unknown_missing_response_policy_advances_each_candidate(tmp_path):
    from bytefault.core.contracts import ResponseEdge
    plan=positional_plan((b'SETUP',b'X'))
    plan=replace(plan,actions=(plan.actions[0],replace(plan.actions[1],receive=ReceiveRequest(cap=4,deadline=1),
        edges=(ResponseEdge(b'YES',None,'positive'),),unknown_target=None)))
    result,trace,_,_=run_campaign(tmp_path,MonitoringConfig(health_check_mode='disabled'),plan=plan)
    assert result.outcome=='monitoring_failed' and result.selected_cases==3 and result.attempts==12
    assert [s[2] for s in trace if s[0]=='send' and s[2]!=b'SETUP']==[b'XA']*4+[b'XB']*4+[b'XC']*4


def test_final_in_band_check_after_unknown_terminal_still_uses_actual_connection(tmp_path):
    from bytefault.core.contracts import ResponseEdge
    plan=positional_plan((b'SETUP',b'X'))
    plan=replace(plan,actions=(plan.actions[0],replace(plan.actions[1],receive=ReceiveRequest(cap=4,deadline=2),
        edges=(ResponseEdge(b'YES',None,'positive'),),unknown_target=None)))
    config=MonitoringConfig(check_interval=2,delayed_check=0,health_check_mode='in_band',
        in_band={'prepared':b'PING','receive':{'cap':4,'deadline':2},'predicate':{'kind':'prefix','value':b'OK'}})
    result,trace,records,_=run_campaign(tmp_path,config,plan=plan,reads=(b'NO',b'OK'))
    assert result.outcome=='unknown' and result.attempts==1
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP',b'XA',b'PING']
    probe=next(r.data['observation'] for r in records if r.kind=='observation' and r.data['observation']['kind']=='service_check')
    assert probe['parameters']['purpose']=='final'


def setup_plan():
    from bytefault.core.contracts import ResponseEdge
    plan=positional_plan((b'SETUP',b'X'))
    return replace(plan,actions=(replace(plan.actions[0],receive=ReceiveRequest(cap=8,deadline=2),
        edges=(ResponseEdge(b'READY','2','positive'),),unknown_target=None),plan.actions[1]))


def test_final_service_retry_uses_last_selected_path_not_later_failed_setup(tmp_path):
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(check_interval=2,delayed_check=0),
        plan=setup_plan(),payloads=(b'A',b'B'),stream_reads={0:(b'READY',),1:(b'BAD',),4:(b'READY',)},
        open_errors=(False,False,True,False,False,False))
    assert result.outcome=='monitoring_failed' and result.attempts==2 and result.setup_sends==3
    assert any(r.kind=='case_terminal' and r.data['result']['execution_outcome']=='unknown' for r in records)
    assert [s[2] for s in trace if s[0]=='send']==[b'SETUP',b'XA',b'SETUP',b'SETUP',b'XA']
    selected=[r.data['result'] for r in records if r.kind=='action_result' and r.data['result']['iteration_id']]
    assert selected[0]['iteration_id']==selected[1]['iteration_id']
    assert selected[0]['materialized']==selected[1]['materialized']
    service=next(r for r in records if r.kind=='observation' and r.data['observation']['kind']=='service_check')
    assert service.identity['conversation_id']==service.data['observation']['correlation']['conversation_id']
    assert service.data['observation']['parameters']['actual_connection']['probe_connection_id']


def test_final_in_band_original_connection_retired_is_attributed(tmp_path):
    config=MonitoringConfig(check_interval=2,delayed_check=0,health_check_mode='in_band',
        in_band={'prepared':b'PING','receive':{'cap':4,'deadline':2},'predicate':{'kind':'prefix','value':b'OK'}})
    with pytest.raises(ContractError,match='original selected test connection') as error:
        run_campaign(tmp_path,config,plan=setup_plan(),payloads=(b'A',b'B'),
            stream_reads={0:(b'READY',),1:(b'BAD',)})
    assert error.value.path=='probe.connection' and error.value.code=='unavailable'
    from bytefault.core.storage import reopen_records
    records=reopen_records(tmp_path/'run.bfr').records
    probe=next(r for r in records if r.kind=='probe_materialization')
    assert probe.data['actual_connection']['epoch']!=probe.data['actual_connection']['governed_epoch']
    assert probe.identity['action_id']=='2'
    assert not [r for r in records if r.kind=='probe_result']


@pytest.mark.parametrize('finish',['complete','stop'])
def test_explicit_late_hold_blocks_subsequent_unsent_offer_with_original_ids(engine_factory,finish):
    import threading
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('late_wait','late_correlated',
        disposition='hold',conditions=('report',),actions=({'report':True},)),)))
    engine,trace,_,_=engine_factory(monitoring=monitor)
    injected=[];ready=threading.Event();results=[]
    def sink(kind,identity,data,reference):
        if kind=='monitoring_decision' and not injected:
            original=monitor.observations[0]
            late=replace(original,observation_id='late',kind='late_response',prior_observation_id=original.observation_id,
                transport=replace(original.transport,received=b'LATE'))
            injected.append(late)
            engine._publish_observation(late)
            ready.set()
    engine.add_required_sink(sink)
    request=replace(raw_request(b'X'),plan=positional_plan((b'X',b'Y')),selected_actions=('1','2'))
    worker=threading.Thread(target=lambda:results.append(engine.execute_conversation(request)))
    worker.start()
    try:
        assert ready.wait(3)
        hold=engine.continuation.hold
        assert hold is not None and hold.correlation==injected[0].correlation
        assert [s[1] for s in trace if s[0]=='offer']==[b'X']
        assert engine.status().monitoring_hold==hold.decision_id
        assert engine.control('pause').outcome=='completed'
        assert engine.control('resume').outcome=='completed'
        action=hold.actions[0]
        completion=MonitoringCompletion('own',hold.decision_id,hold.observation_id,hold.correlation,
            'report','succeeded',followup_action_id=action.action_id)
        assert not engine.complete_monitoring(replace(completion,decision_id='stale'))
        if finish=='stop':engine.control('stop')
        else:assert engine.complete_monitoring(completion)
        worker.join(3)
        assert not worker.is_alive()
        assert results[0].outcome==('stopped' if finish=='stop' else 'completed')
        assert [s[1] for s in trace if s[0]=='offer']==([b'X'] if finish=='stop' else [b'X',b'Y'])
        assert any(r.kind=='monitoring_decision' and r.data['decision']['observation_id']=='late' for r in engine.record_store.snapshot().records)
    finally:
        engine.control('stop');worker.join(3)


def test_conflicting_late_hold_is_recorded_and_original_obligations_stay(engine_factory):
    monitor=Monitoring(configuration=MonitoringConfig(rules=(
        ObservationRule('ordinary_wait','unrequested',disposition='hold',conditions=('report',)),
        ObservationRule('late_wait','late_correlated',disposition='hold',conditions=('collection',)))))
    engine,trace,_,_=engine_factory(monitoring=monitor)
    original=observed(transport=TransportResult(b'X'))
    engine._publish_observation(original)
    hold=engine.continuation.hold
    late=replace(original,observation_id='late',kind='late_response',prior_observation_id=original.observation_id,
        transport=replace(original.transport,received=b'LATE'))
    with pytest.raises(ContractError,match='hold_conflict'):
        engine._publish_observation(late)
    assert engine.continuation.hold==hold and engine.continuation.stopped
    assert not trace
    failure=engine.record_store.snapshot().records[-1]
    assert failure.kind=='monitoring_failure' and failure.data['code']=='hold_conflict'
    assert failure.data['active_hold']['decision_id']==hold.decision_id


@pytest.mark.parametrize('cause',['expiry','failed_completion'])
def test_stop_cause_retains_hold_identity_after_completion_and_later_decisions(cause):
    from bytefault.fuzzers.continuation import ContinuationGate
    monitor=Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('wait','unrequested',
        disposition='hold',conditions=('report',),hold_timeout=0,on_expiry='stop',on_failure='stop'),)))
    decision=monitor.observe(observed(transport=TransportResult(b'X')))
    gate=ContinuationGate();gate.select(decision,now=10)
    completion=MonitoringCompletion('completion',decision.decision_id,decision.observation_id,
        decision.correlation,'report','failed')
    if cause=='expiry':
        assert gate.expire(decision.decision_id)
        assert gate.stop_cause=='deadline_expiry' and gate.stop_reference is None
    else:
        assert gate.complete(completion)
        assert gate.stop_cause=='completion_failed' and gate.stop_reference==completion
    assert gate.stop_decision==decision and gate.hold==decision
    assert gate.complete(replace(completion,completion_id='success',status='succeeded'))
    assert gate.hold is None
    gate.select(monitor.observe(observed('later',kind='heartbeat')))
    gate.select(replace(decision,decision_id='later-stop',disposition='stop',mode='nonblocking',
        required_conditions=(),obligations=(),reason='unrelated later stop'))
    assert gate.stopped and gate.stop_decision==decision
