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

"""Engine-owned probe cleanup is separate from main traffic/Monitoring facts."""
import pytest
from bytefault.application import Application
from bytefault.core.storage import LocalRecordStore,reopen_records
from bytefault.monitoring import MonitoringConfig
from test_monitoring_policy import run_campaign,PortStream,PortClock


def fail_close(monkeypatch,identities=(1,),*,pacing=False):
    close=PortStream.close
    def failed(stream):
        close(stream)
        if stream.identity in identities:
            if pacing:stream.clock.probe_pacing_failure=True
            else:raise OSError('controlled service probe close failure')
    monkeypatch.setattr(PortStream,'close',failed)
    if pacing:
        sleep=PortClock.sleep
        def failed_sleep(clock,seconds):
            if getattr(clock,'probe_pacing_failure',False):
                clock.probe_pacing_failure=False
                raise OSError('controlled probe pacing failure')
            return sleep(clock,seconds)
        monkeypatch.setattr(PortClock,'sleep',failed_sleep)


def probe_errors(result):
    return next(error for error in result.cleanup_errors if error['owner']=='probe')


@pytest.mark.parametrize('interval,purpose',[(1,'periodic'),(2,'final')])
def test_probe_close_failure_result_status_close_and_exact_history(tmp_path,monkeypatch,interval,purpose):
    fail_close(monkeypatch)
    close=Application.close;closed=[]
    def application_close(app):
        outcome=close(app);closed.append(outcome);return outcome
    monkeypatch.setattr(Application,'close',application_close)
    status={}
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(delayed_check=0,check_interval=interval),
        payloads=(b'A',),capture=status)
    assert result.outcome=='cleanup_failed' and result.execution_outcome=='completed'
    assert result.last_conversation.execution_outcome=='completed' and result.cleanup.outcome=='completed'
    assert result.fuzz_tests==result.attempts==1
    error=probe_errors(result)
    assert error['failure_total']==1 and error['omitted_count']==0
    fact=error['failures'][0]
    assert fact['probe']['purpose']==purpose and fact['correlation']['iteration_id']
    assert fact['actual_connection']['probe_connection_id']==fact['probe_id']
    assert fact['cleanup']['outcome']=='uncertain'
    assert trace.count(('close',0))==trace.count(('close',1))==1
    assert status['state']=='cleanup_failed' and status['error']==result.reason
    assert status['cleanup_errors']==result.cleanup_errors and closed[0]['outcome']=='failed'
    assert records[-1].data['result']['outcome']=='cleanup_failed'
    cleanup=next(r for r in records if r.kind=='probe_cleanup')
    assert fact['record_ref']['record_id']==cleanup.record_id
    action=next(r for r in reopen_records(str(tmp_path/'run.bfr.actions.bfr')).records if r.kind=='probe_cleanup')
    assert action.identity==cleanup.identity and action.data['action']==cleanup.data
    assert action.data['evidence_reference']['record_id']==cleanup.record_id


def test_failed_probe_open_cleanup_is_retained_without_second_close(tmp_path,monkeypatch):
    fail_close(monkeypatch)
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(delayed_check=0,retries=0,recovery_budget=0),
        payloads=(b'A',),open_errors=(False,True))
    assert result.outcome==result.execution_outcome=='monitoring_failed'
    fact=probe_errors(result)['failures'][0]
    assert fact['cleanup']['phase']=='open_failure' and trace.count(('close',1))==1
    probe=next(r for r in records if r.kind=='probe_result')
    assert probe.data['transport']['error']=='refused' and probe.data['service_readiness']=='unavailable'


def test_probe_pacing_failure_does_not_replace_completed_send(tmp_path,monkeypatch):
    fail_close(monkeypatch,pacing=True)
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(delayed_check=0),payloads=(b'A',))
    assert result.outcome=='cleanup_failed' and result.execution_outcome=='completed'
    cleanup=probe_errors(result)['failures'][0]['cleanup']
    assert cleanup['outcome']=='completed' and 'probe pacing failure' in cleanup['pacing_error']
    assert trace.count(('close',1))==1


def test_probe_cleanup_bound_has_exact_total_omissions_and_durable_refs(tmp_path,monkeypatch):
    fail_close(monkeypatch,(1,3,5,7))
    result,trace,records,_=run_campaign(tmp_path,MonitoringConfig(delayed_check=0,history_capacity=2),
        payloads=(b'A',b'B',b'C',b'D'))
    error=probe_errors(result)
    assert result.outcome=='cleanup_failed' and result.execution_outcome=='completed' and result.fuzz_tests==4
    assert (error['failure_total'],error['omitted_count'],error['history_capacity'])==(4,2,2)
    cleanup=[r for r in records if r.kind=='probe_cleanup']
    assert len(cleanup)==4 and len(error['failures'])==2
    assert [f['record_ref']['record_id'] for f in error['failures']]==[r.record_id for r in cleanup[-2:]]
    assert all(trace.count(('close',i))==1 for i in range(8))


@pytest.mark.parametrize('primary',['transport','storage','cleanup_storage','stop'])
@pytest.mark.parametrize('interval',[1,2])
def test_probe_cleanup_preserves_primary_and_unacknowledged_diagnostic(tmp_path,monkeypatch,capsys,primary,interval):
    fail_close(monkeypatch)
    if primary=='transport':
        send=PortStream.send
        def failed_send(stream,data):
            if stream.identity==0:raise OSError('primary send failed')
            return send(stream,data)
        monkeypatch.setattr(PortStream,'send',failed_send)
    failed=[]
    if primary in ('storage','cleanup_storage'):
        append=LocalRecordStore.append
        def failed_save(store,kind,identity,data):
            if kind==('probe_result' if primary=='storage' else 'probe_cleanup'):
                failed.append(kind);raise OSError('primary probe result save failure')
            return append(store,kind,identity,data)
        monkeypatch.setattr(LocalRecordStore,'append',failed_save)
    def step(value,app):
        if primary=='stop' and value[0]=='open' and value[1]==1:app.control('run','stop')
    status={}
    result,trace,records,monitor=run_campaign(tmp_path,MonitoringConfig(delayed_check=0,retries=0,check_interval=interval),
        payloads=(b'A',),capture=status,on_step=step)
    expected={'transport':'transport_failed','storage':'recording_failed',
              'cleanup_storage':'recording_failed','stop':'stopped'}[primary]
    assert result.outcome==result.execution_outcome==expected
    assert probe_errors(result)['failure_total']==1 and trace.count(('close',1))==1
    if primary=='stop':
        assert [s[2] for s in trace if s[0]=='send']==[b'XA']
        assert len([s for s in trace if s[0]=='open'])==2
        assert status['state']=='stopped' and 'operator stop requested' in result.reason
        assert not any(d.disposition=='stop' for d in monitor.decisions)
        assert not any(r.kind=='retry_wait' for r in records)
    if primary in ('storage','cleanup_storage'):
        assert failed==['probe_result' if primary=='storage' else 'probe_cleanup']
        assert not any(r.kind=='probe_cleanup' for r in records)
        if primary=='storage':
            assert status['storage_failure']['unacknowledged_probe_cleanup']['cleanup']['outcome']=='uncertain'
            assert 'unacknowledged_probe_cleanup' in capsys.readouterr().err
        else:
            assert status['storage_failure']['failed_record_data']['cleanup']['outcome']=='uncertain'
            assert status['storage_failure']['required_record_kind']=='probe_cleanup'
        assert probe_errors(result)['failures'][0]['record_ref'] is None
