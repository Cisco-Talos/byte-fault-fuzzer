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

"""Passive resume views over real acknowledged inputs and current owners."""
from dataclasses import replace
import io
from pathlib import Path
import threading
import time

import pytest

from bytefault.application import ResumeIntent, ResumeChoice
from bytefault.core.contracts import MonitoringCompletion, MonitoringDecision
from bytefault.core.storage import LocalRecordStore
from bytefault.fuzzers.cli import execute_arguments
from bytefault.monitoring import Monitoring
from bytefault.ui.application_client import ApplicationView
from bytefault.ui.plain import ApplicationPlainClient
from test_resume import killed, offered


def until(predicate):
    deadline=time.monotonic()+5
    while not predicate() and time.monotonic()<deadline: time.sleep(.005)
    assert predicate()


def test_unresolved_choices_and_pathgone_active_fresh_projection(tmp_path,campaign_storage_child,application_factory,monkeypatch):
    journal=killed(campaign_storage_child,'partialtail')
    app,traces=application_factory()
    inspection=execute_arguments(['inspect-resume',str(journal)],app)
    assert inspection.recovery_issue.kind=='incomplete' and not traces
    pending=execute_arguments(['resume-run','{"path":'+__import__('json').dumps(str(journal))+'}',
        '--records',str(tmp_path/'unresolved.bfr')],app)
    assert not traces
    result=app.submit(pending)
    view=ApplicationView(app,result.run_id,request=pending); view.refresh()
    state=view.state.resume
    assert result.outcome=='unresolved' and state['barrier']['case_number']==2 and not offered(traces)
    assert state['inherited_counts']=={'completed':1,'uncertain':1}
    assert view.state.progress['fuzz_tests']==view.state.progress['attempts']==view.state.total_bytes_sent==0
    assert state['recovery_issue'].kind=='incomplete'
    output=io.StringIO(); ApplicationPlainClient(view,stream=output).refresh()
    assert 'UNRESOLVED 2 choice required' in output.getvalue() and 'inherited completed=1' in output.getvalue()
    key=inspection.cases[1]['conversation_id']
    for disposition in ('skip','rerun'):
        selected=app.resume(ResumeIntent(pending.record_path,(ResumeChoice(key,disposition),)),
            record_path=str(tmp_path/(disposition+'.bfr')))
        before=len(offered(traces)); terminal=app.submit(selected)
        reopened=ApplicationView(app,terminal.run_id); reopened.refresh()
        assert terminal.outcome=='completed'
        assert reopened.state.resume['choices']==reopened.state.resume['acknowledged_choices']
        assert reopened.state.resume['choices'][0]['disposition']==disposition
        assert len(offered(traces))-before==(1 if disposition=='skip' else 2)
        assert reopened.state.resume['inherited_counts']['completed']==1
        assert len(reopened.state.resume['cases'])<=12
        reopened.close()
    view.close()
    # A real longer continuation keeps current row payloads out of the frame.
    from bytefault.application import ApplicationRequest
    from bytefault.core.contracts import TransportRequest,ReceiveRequest
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.monitoring import MonitoringConfig
    from test_resume import retained_prefix
    source,_=application_factory(monitoring=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled')))
    conversation=raw_request(b'W',receive=ReceiveRequest(requested=False))
    base=ApplicationRequest(conversation,TransportRequest('offline.invalid',1234,1),str(tmp_path/'long.bfr'))
    source.campaign(base,cases=(conversation,)*18)
    prefix=retained_prefix(Path(base.record_path),tmp_path/'long-prefix.bfr',lambda record:
        record.kind=='materialization' and record.identity.get('case_number')==2)
    current,_=application_factory(monitoring=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled')))
    logical=current.inspect_resume(prefix).cases[1]['conversation_id']
    continued=current.resume(ResumeIntent(prefix,(ResumeChoice(logical,'skip'),)),record_path=str(tmp_path/'long-new.bfr'))
    completed=current.submit(continued)
    window=ApplicationView(current,completed.run_id,request=continued); window.refresh()
    assert completed.attempts==16 and window.state.progress['attempts']==16
    assert len(window.state.resume['cases'])==12 and window._resume._active is None
    assert window.state.resume['cases'][-1]['case_number']==18
    assert window.state.resume['inherited_counts']=={'completed':1,'uncertain':1}
    from bytefault.ui.resume import resume_lines
    assert any('CASE window 12/12' in line for line in resume_lines(window.state.resume))
    window.close()


def test_retained_gate_pathgone_early_attach_and_bounded_projection(tmp_path,campaign_storage_child,application_factory,monkeypatch):
    journal=killed(campaign_storage_child,'hold')
    app,traces=application_factory()
    inspection=app.inspect_resume(str(journal)); hold=inspection.continuation['hold']
    # Real acknowledged irrelevant policy facts must not become a lifetime
    # projection replay list around the still-correlated inherited gate.
    from bytefault.fuzzers.inputs import contract_from_record
    typed=contract_from_record(MonitoringDecision,hold)
    with LocalRecordStore(journal) as parent:
        for number in range(40):
            parent.append('monitoring_decision',dict(hold['correlation']),{'decision':
                MonitoringDecision('irrelevant:'+str(number),typed.observation_id,typed.correlation,'continue')})
    key=inspection.cases[1]['conversation_id']
    request=app.resume(ResumeIntent(str(journal),(ResumeChoice(key,'rerun'),)),
        record_path=str(tmp_path/'held.bfr'))
    entered,release=threading.Event(),threading.Event()
    resume_entered,resume_release=threading.Event(),threading.Event()
    original=LocalRecordStore.append
    def append(store,kind,identity,data):
        if str(store.path)==request.record_path:
            if kind=='resume_start':
                resume_entered.set(); assert resume_release.wait(10)
            if kind=='campaign_start':
                entered.set(); assert release.wait(10)
        return original(store,kind,identity,data)
    monkeypatch.setattr(LocalRecordStore,'append',append)
    handle=app.start(request)
    fresh=None; view=None
    resume_projection_release,projection_release=threading.Event(),threading.Event()
    try:
        assert resume_entered.wait(5)
        engine=app._run(handle.run_id).engine
        project=engine._record_projection
        resume_projecting,projecting=threading.Event(),threading.Event()
        def delayed_projection(kind,identity,data,ref):
            if kind=='resume_start':
                resume_projecting.set(); assert resume_projection_release.wait(10)
            if kind=='campaign_start':
                projecting.set(); assert projection_release.wait(10)
                raise RuntimeError('controlled optional projection failure')
            return project(kind,identity,data,ref)
        monkeypatch.setattr(engine,'_record_projection',delayed_projection)
        fresh=ApplicationView(app,handle.run_id); fresh.refresh()
        assert not fresh.state.resume
        resume_release.set()
        assert resume_projecting.wait(5)
        fresh.refresh()  # Started before any record; recover durable resume_start without its event.
        assert fresh._resume_pending and not fresh.state.resume
        resume_projection_release.set()
        assert entered.wait(5)
        # No view is permitted to recover the former parent/sidecar hereafter.
        journal.unlink()
        sidecar=Path(str(journal)+'.preparation.bfr')
        if sidecar.exists(): sidecar.unlink()
        import bytefault.fuzzers.resuming as resuming
        monkeypatch.setattr(resuming,'_history',lambda *a:(_ for _ in ()).throw(AssertionError('parent reopen')))
        release.set()
        assert projecting.wait(5)  # Required append is acknowledged; optional projection is held.
        until(lambda:any(r.kind=='campaign_start' for r in app.read_records(handle.run_id).records))
        fresh.refresh()
        assert fresh.state.resume and fresh.state.resume['acknowledged_choices']
        projection_release.set()
        until(lambda:app.observe(handle.run_id)['projection_failed']==1)
        resets=fresh.state.projection_resets
        fresh.refresh()
        assert fresh.state.projection_resets==resets+1
        assert fresh.state.resume['acknowledged_choices']
        fresh.refresh(); assert fresh.state.projection_resets==resets+1
        reads=[]; actual_read=app.read_records
        def read(run): reads.append(run); return actual_read(run)
        monkeypatch.setattr(app,'read_records',read)
        view=ApplicationView(app,handle.run_id,request=request); view.refresh()
        assert reads==[handle.run_id]  # Inherited finding context reuses retained input.
        gate=view.state.resume['continuation']
        assert gate['hold']['decision_id']==hold['decision_id']
        assert gate['satisfied']==(('collection','one'),) and gate['deadline_state']=='unconfigured'
        import copy
        frame=copy.deepcopy(view.state)
        assert frame.resume==view.state.resume and frame.resume is not view.state.resume
        assert len(view._resume._gate_records)<=4
        from bytefault.fuzzers.resuming import retained_gate,gate_data
        assert gate_data(retained_gate(view._resume._gate_records))==view._resume._gate
        assert view.state.resume['inherited_counts']=={'completed':1,'uncertain':1}
        assert view.state.total_bytes_sent==0 and view.state.progress['attempts']==0 and not offered(traces)
        before=view.state.resume
        calls=[]; original_history=app.read_service_history
        def history(*args,**kwargs): calls.append(args); return original_history(*args,**kwargs)
        monkeypatch.setattr(app,'read_service_history',history)
        for _ in range(20): view.refresh()
        assert view.state.resume is before and len(calls)==20  # One batch; no classification on polling.
        def completion(action,condition='collection',correlation=typed.correlation):
            return MonitoringCompletion('completion:'+str(action)+condition,typed.decision_id,
                typed.observation_id,correlation,condition,'succeeded',followup_action_id=action)
        for number in range(20):
            assert not app.complete_monitoring(handle.run_id,completion('two',correlation=replace(typed.correlation,attempt_id='stale:'+str(number))))
        view.refresh(); assert view.state.resume['continuation']['hold'] and not offered(traces)
        assert len(view._resume._gate_records)<=4
        assert app.complete_monitoring(handle.run_id,completion('two'))
        view.refresh(); assert len(view.state.resume['continuation']['satisfied'])==2
        for action in ('one','two'): assert app.complete_monitoring(handle.run_id,completion(action,'report'))
        view.refresh(); assert view.state.resume['continuation']['hold'] and not offered(traces)
        assert app.complete_monitoring(handle.run_id,completion(None,'readiness'))
        assert handle.wait(5).outcome=='completed'
        view.refresh()
        assert view.state.resume['continuation']['hold'] is None
        assert view.state.progress['attempts']==2 and len(offered(traces))==2
        assert len(view._resume.cases)<=12 and view._resume._active is None and not view._resume._gate_records
        assert not hasattr(view._resume,'current')
        # Both subtle core replay semantics must survive causal storage pruning.
        from bytefault.core.records import Record
        from bytefault.ui.resume import ResumeProjection,resume_lines
        stop=MonitoringDecision('first-stop',typed.observation_id,typed.correlation,'stop',reason='original stop')
        later=replace(typed,decision_id='later-hold',hold_timeout=10)
        events=[Record('stop','monitoring_decision',{}, {'decision':stop}),
            Record('later','monitoring_decision',{}, {'decision':later}),
            Record('deadline','monitoring_gate',{}, {'decision_id':later.decision_id,'deadline':123.5})]
        for sequence in (events,events+[Record('continue','monitoring_decision',{}, {'decision':
                MonitoringDecision('irrelevant',typed.observation_id,typed.correlation,'continue')})]):
            actual=retained_gate(sequence); minimal=ResumeProjection._compact_gate(sequence,actual)
            assert gate_data(retained_gate(minimal))==gate_data(actual)
            assert len(minimal)<=3 and actual.stopped and actual.stop_reason=='original stop'
            next_record=Record('later-success','monitoring_completion',{}, {'completion':
                replace(completion('one'),decision_id=later.decision_id)})
            assert gate_data(retained_gate(minimal+[next_record]))==gate_data(retained_gate(sequence+[next_record]))
            rendered=resume_lines(dict(view.state.resume,continuation=gate_data(actual)))
            assert any('RESUME STOPPED' in line and 'original stop' in line for line in rendered)
        assert gate_data(retained_gate(events))['deadline_state']=='known'
        assert gate_data(retained_gate(sequence))['deadline_state']=='unknown'
    finally:
        resume_release.set(); resume_projection_release.set(); release.set(); projection_release.set()
        handle.control('stop'); handle.wait(5)
        if fresh: fresh.close()
        if view: view.close()
