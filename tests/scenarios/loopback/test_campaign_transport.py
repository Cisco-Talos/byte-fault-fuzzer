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

"""Actual campaign OS adapter; fixture peer observations remain independent."""
from dataclasses import replace
import json
import threading
import pytest
from bytefault.application import ApplicationRequest,CampaignRequest
from bytefault.core.contracts import (TransportRequest,ReceiveRequest,CampaignOptions,CampaignConnection,
    PassivePlan,ConversationAction,ResponseEdge)
from bytefault.core.storage import reopen_records
from bytefault.fuzzers.inputs import raw_request
from bytefault.monitoring import Monitoring,MonitoringConfig


def request(case,endpoint,*,receive=None,name='N'):
    conversation=replace(raw_request(b'X',receive=receive or ReceiveRequest(requested=False)),
                         run_id=name,case_id='case',conversation_id='conversation')
    return ApplicationRequest(conversation,TransportRequest(endpoint[0],endpoint[1],1),
        str(case.root/(name+'.bfr')),str(case.root/(name+'.actions.bfr')))


def generation(payloads=(b'A',b'B',b'C')):
    return {'sources':({'source_id':'S','kind':'list','options':{'payloads':payloads}},),
        'sets':({'set_id':'S','source_id':'S'},),'positions':({'position_id':'P','set_id':'S','operation':'append'},)}


def finished(case,app,request,result,peer):
    engine=app._run(result.run_id).engine
    assert not app.status(result.run_id).active and app.status(result.run_id).finalized
    assert engine.socket is engine.transport.stream is None and engine.record_store.closed
    assert result.cleanup.outcome=='completed'
    evidence,actions=reopen_records(request.record_path),reopen_records(request.log_path)
    assert evidence.issue is actions.issue is None
    assert evidence.records[-1].kind=='campaign_terminal'
    assert [r.kind for r in evidence.records]==[r.kind for r in actions.records]
    assert peer.done.wait(peer.remaining()) and peer.error is None
    peer.thread.join(peer.remaining())
    assert not peer.thread.is_alive()
    facts=[r.data['result'] for r in evidence.records if r.kind=='action_result']
    (case.root/'client-facts.json').write_text(json.dumps([{'identity':dict(r.identity),
        'accepted_hex':r.data['result']['transport']['accepted_prefix'].hex(),
        'received_hex':r.data['result']['transport']['received'].hex()} for r in evidence.records if r.kind=='action_result']),encoding='utf-8')
    (case.root/'peer-facts.json').write_text(json.dumps(peer.snapshot()),encoding='utf-8')
    return evidence,facts


@pytest.mark.parametrize('mode,connections',[('persistent',1),('fresh',3)])
def test_actual_campaign_connection_lifetime(n_case,mode,connections):
    def handler(peer,connection,index):
        for payload in ((b'XA',b'XB',b'XC') if mode=='persistent' else ((b'XA',),(b'XB',),(b'XC',))[index]):
            assert peer.recv_exact(connection,2)==payload
        peer.wait_client_end(connection)
    peer=n_case.peer(handler,count=connections)
    app=n_case.app(monitoring=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled')))
    base=request(n_case,peer.endpoint)
    worker,output=n_case.submit(app,base,operation=lambda:app.campaign(base,generation=generation(),
        options=CampaignOptions(connection=CampaignConnection(mode))))
    result=n_case.complete(worker,output)
    assert result.outcome=='completed' and result.fuzz_tests==result.attempts==3
    _,facts=finished(n_case,app,base,result,peer)
    assert [f['transport']['accepted_prefix'] for f in facts]==[b'XA',b'XB',b'XC']
    assert peer.accepted==connections and b''.join(peer.receipts)==b'XAXBXC'
    assert peer.endings==['eof']*connections


def test_actual_periodic_and_final_service_connections(n_case):
    def handler(peer,connection,index):
        if index==0:
            assert peer.recv_exact(connection,4)==b'XAXB'
        elif index==2:
            assert peer.recv_exact(connection,2)==b'XC'
        before_end=len(peer.receipts)
        peer.wait_client_end(connection)
        assert peer.receipts[before_end:]==[b'']
    peer=n_case.peer(handler,count=4)
    config=MonitoringConfig(check_interval=2,delayed_check=.01,recovery_delays=(.01,),recovery_budget=.2)
    app=n_case.app(monitoring=Monitoring(configuration=config))
    base=request(n_case,peer.endpoint)
    worker,output=n_case.submit(app,base,operation=lambda:app.campaign(base,generation=generation(),
        options=CampaignOptions(connection=CampaignConnection('persistent'))))
    result=n_case.complete(worker,output)
    evidence,facts=finished(n_case,app,base,result,peer)
    checks=[r.data['observation'] for r in evidence.records if r.kind=='observation' and r.data['observation']['kind']=='service_check']
    assert result.outcome=='completed' and result.monitoring['service_checks']==2
    assert [o['parameters']['purpose'] for o in checks]==['periodic','final']
    assert all(o['service_readiness']=='available' for o in checks)
    assert peer.accepted==4 and b''.join(peer.receipts)==b'XAXBXC'
    assert peer.endings==['eof']*4


def test_actual_deadline_retry_reopens_same_candidate(n_case):
    def handler(peer,connection,index):
        assert peer.recv_exact(connection,2)==b'XA'
        if index:peer.send_parts(connection,(b'OK',))
        peer.wait_client_end(connection)
    peer=n_case.peer(handler,count=2)
    config=MonitoringConfig(health_check_mode='disabled',retries=1,recovery_delays=(.01,),
        reconnect_attempts=1,reconnect_delay=0,recovery_budget=.2)
    app=n_case.app(monitoring=Monitoring(configuration=config))
    base=request(n_case,peer.endpoint,receive=ReceiveRequest(cap=2,deadline=.05))
    worker,output=n_case.submit(app,base,operation=lambda:app.campaign(base,generation=generation((b'A',))))
    result=n_case.complete(worker,output)
    evidence,facts=finished(n_case,app,base,result,peer)
    assert result.outcome=='completed' and result.fuzz_tests==1 and result.attempts==2
    assert facts[0]['transport']['receive_outcome']=='deadline' and facts[0]['transport']['received']==b''
    assert facts[1]['transport']['received']==b'OK'
    assert facts[0]['iteration_id']==facts[1]['iteration_id'] and facts[0]['attempt_id']!=facts[1]['attempt_id']
    assert b''.join(peer.receipts)==b'XAXA' and peer.accepted==2


def test_actual_stop_during_campaign_receive(n_case):
    def handler(peer,connection,index):
        assert peer.recv_exact(connection,2)==b'XA'
        peer.wait_client_end(connection)
    peer=n_case.peer(handler)
    app=n_case.app(monitoring=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled')))
    base=request(n_case,peer.endpoint,receive=ReceiveRequest(cap=2,deadline=1))
    worker,output=n_case.submit(app,base,operation=lambda:app.campaign(base,generation=generation()))
    assert peer.received.wait(2)
    assert app.control(base.conversation.run_id,'stop').outcome=='completed'
    result=n_case.complete(worker,output)
    _,facts=finished(n_case,app,base,result,peer)
    assert result.outcome=='stopped' and result.fuzz_tests==result.attempts==1
    assert facts[0]['transport']['receive_outcome']=='cancelled'
    assert peer.accepted==1 and b''.join(peer.receipts)==b'XA'


def test_actual_in_band_periodic_and_final_probe(n_case):
    def handler(peer,connection,index):
        assert peer.recv_exact(connection,4)==b'XAXB'
        assert peer.recv_exact(connection,4)==b'PING'
        peer.send_parts(connection,(b'OK',))
        assert peer.recv_exact(connection,2)==b'XC'
        assert peer.recv_exact(connection,4)==b'PING'
        peer.send_parts(connection,(b'OK',))
        peer.wait_client_end(connection)
    peer=n_case.peer(handler)
    config=MonitoringConfig(check_interval=2,delayed_check=.01,health_check_mode='in_band',
        in_band={'prepared':b'PING','predicate':{'kind':'prefix','value':b'OK','expect':'match'},
                 'receive':{'cap':2,'deadline':.2}})
    app=n_case.app(monitoring=Monitoring(configuration=config))
    base=request(n_case,peer.endpoint)
    worker,output=n_case.submit(app,base,operation=lambda:app.campaign(base,generation=generation(),
        options=CampaignOptions(connection=CampaignConnection('persistent'))))
    result=n_case.complete(worker,output)
    records,facts=finished(n_case,app,base,result,peer)
    checks=[r.data['observation'] for r in records.records if r.kind=='observation' and r.data['observation']['kind']=='service_check']
    assert result.outcome=='completed' and result.fuzz_tests==result.attempts==3
    assert result.monitoring['service_checks']==2 and len(checks)==2
    assert all(o['service_readiness']=='available' and o['transport']['received']==b'OK' for o in checks)
    assert peer.accepted==1 and b''.join(peer.receipts)==b'XAXBPINGXCPING'
