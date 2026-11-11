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

"""Exact local F07 child: deny networking before product import, then wait to die."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True

def deny(*args, **kwargs):
    raise AssertionError('Offline child forbids real networking and subprocesses')

def audit(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.posix_spawn',
            'os.exec', 'os.spawn', 'os.fork', 'os.forkpty', 'os.startfile', 'os.startfile/2'):
        deny()

sys.addaudithook(audit)
for name in ('create_connection', 'create_server', 'socketpair', 'fromfd', 'getaddrinfo',
             'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo', 'getfqdn'):
    if hasattr(socket, name):
        setattr(socket, name, deny)
for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
    setattr(subprocess, name, deny)
for name in ('system', 'popen', 'startfile', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
             'spawnv', 'spawnve', 'spawnvp', 'spawnvpe'):
    if hasattr(os, name):
        setattr(os, name, deny)


root, point = Path(sys.argv[1]).resolve(), sys.argv[2]
resume_fixture = point.startswith('resume_')
boundary = point.removeprefix('resume_')
if boundary=='again':boundary='postoffer'
assert Path.cwd().resolve() == root
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))
import _socket
for operation in (lambda: _socket.socket(), lambda: socket.getaddrinfo('localhost',1), lambda: subprocess.Popen(['ssh','localhost'])):
    try: operation()
    except AssertionError: pass
    else: raise AssertionError('campaign child guard escaped')
from dataclasses import replace
from bytefault.application import Application, ApplicationRequest
from bytefault.core.contracts import TransportRequest
from bytefault.core.storage import LocalRecordStore, frame_record
from bytefault.core.records import Record
from bytefault.fuzzers.inputs import raw_request
from bytefault.fuzzers.transport import EngineTransport
from bytefault.fuzzers.recording import RecordingMixin
from bytefault.monitoring import Monitoring, MonitoringConfig

class Stream:
    def __init__(self,index):self.index=index
    def settimeout(self,value):pass
    def connect(self,target):
        if point=='retry_resume' and self.index==2:raise OSError('controlled final service failure')
    def send(self,data):
        with (root/'offered').open('ab') as output:output.write(data)
        return len(data)
    def close(self):pass

streams=[]
def transport(target):
    def factory(*args):
        stream=Stream(len(streams));streams.append(stream);return stream
    return EngineTransport(target,socket_factory=factory,sleep=lambda value:None)

def ready():
    (root/'ready').write_text(point,encoding='utf-8')
    while True:time.sleep(.02)

original_append=LocalRecordStore.append
original_save=RecordingMixin._required_save

def append(store,kind,identity,data):
    second=identity.get('case_number')==2
    if str(store.path)==str(root/'campaign.bfr') and second and kind=='action_result' and boundary in ('postoffer','partialtail'):
        if boundary=='partialtail':
            frame=frame_record(Record('interrupted-record',kind,identity,data))
            assert store._stream.write(frame[:len(frame)//2])==len(frame)//2
            store._stream.flush();os.fsync(store._stream.fileno())
        ready()
    ref=original_append(store,kind,identity,data)
    if (boundary=='prepared' or boundary.startswith('partial_family')) and kind=='prepared_row' and data['ordinal']==2:
        ready()
    return ref
LocalRecordStore.append=append

def save(engine,kind,data,**kwargs):
    ref=original_save(engine,kind,data,**kwargs)
    second=engine._record_context.get('case_number')==2
    if second and ((boundary=='materialized' and kind=='materialization') or
                   (boundary=='result' and kind=='action_result') or
                   (boundary in ('hold','expiry') and kind=='monitoring_gate') or
                   (point=='retry_resume' and kind=='retry_case_resume')):
        if boundary=='hold':
            from bytefault.core.contracts import MonitoringCompletion
            hold=engine.continuation.hold
            engine.complete_monitoring(MonitoringCompletion('retained-one',hold.decision_id,
                hold.observation_id,hold.correlation,'collection','succeeded',followup_action_id='one'))
        ready() # original_save acknowledged root AND every required action sink
    return ref
RecordingMixin._required_save=save

configuration=MonitoringConfig(health_check_mode='new_connection' if point=='retry_resume' else 'disabled',
    check_interval=3,delayed_check=0,retries=1,recovery_delays=(0,),reconnect_attempts=1,reconnect_delay=0)
monitoring=Monitoring(configuration=configuration)
if boundary in ('hold','expiry'):
    from bytefault.core.contracts import MonitoringDecision, MonitoringAction
    class Policy:
        def evaluate(self, observation):
            if observation.correlation.case_id.endswith('row:2'):
                actions=tuple(MonitoringAction(key,'event',observation.observation_id,
                    observation.correlation,'followup',{'collect':True,'report':True}) for key in ('one','two'))
                return MonitoringDecision('retained-hold',observation.observation_id,
                    observation.correlation,'hold','awaited',('readiness','collection','report'),actions=actions,
                    hold_timeout=0 if boundary=='expiry' else None,
                    on_expiry='stop' if boundary=='expiry' else 'hold')
            return MonitoringDecision('continue:'+observation.observation_id,
                observation.observation_id,observation.correlation,'continue')
    monitoring=Monitoring(Policy())
app=Application(transport_factory=transport,monitoring=monitoring)
conversation=replace(raw_request(b'X'),run_id='campaign-child',case_id='case',conversation_id='conversation')
request=ApplicationRequest(conversation,TransportRequest('offline.invalid',1234,1),str(root/'campaign.bfr'))
value={'sources':({'source_id':'S','kind':'random' if resume_fixture else 'list',
    'options':{'min_len':2,'max_len':2,'count':3,'seed':913} if resume_fixture else {'payloads':(b'A',b'B')}},),
       'sets':({'set_id':'S','source_id':'S'},),'positions':({'position_id':'P','set_id':'S','operation':'append'},)}
if boundary=='prepared':
    value['sources'][0]['options'].pop('seed')
    value['sources'][0]['options']['count']=2
options=None
if boundary.startswith('partial_family'):
    from bytefault.core.contracts import Calculation,CampaignOptions
    request=replace(request,conversation=replace(conversation,
        plan=replace(conversation.plan,actions=(replace(conversation.plan.actions[0],seed=b'\0X'),)),
        repair=True,calculations=(Calculation('length','1','payload_length',0,1,payload_offset=1),)))
    options=CampaignOptions(variants=('normal','length4'),case_limit=2)
    if boundary.endswith('unseeded'):
        value['sources'][0]['options'].pop('seed')
if point=='resume_again':
    from bytefault.application import ResumeIntent,ResumeChoice
    inspection=app.inspect_resume(str(root/'source.bfr'))
    key=next(i['conversation_id'] for i in inspection.cases if i['state']=='uncertain')
    app.submit(app.resume(ResumeIntent(str(root/'source.bfr'),(ResumeChoice(key,'rerun'),)),
        record_path=str(root/'campaign.bfr')))
else:
    app.campaign(request,generation=value,options=options)
raise AssertionError('campaign boundary was not reached')
