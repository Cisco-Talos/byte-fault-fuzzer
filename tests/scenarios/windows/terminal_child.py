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

"""Bounded actual Windows terminal fixture; deny external I/O before imports."""
import ctypes
from ctypes import wintypes
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from importlib.metadata import PackageNotFoundError, version


def installed_rich_version():
    try:
        return version('rich')
    except PackageNotFoundError:
        return None

ROOT=Path(sys.argv[1]).resolve(); MODE=sys.argv[2]
REPO=Path(__file__).resolve().parents[3]
assert ROOT.parent.parent==REPO/'artifacts'/'windows-terminal'
assert MODE in ('surface','hide','no_banner','plain','fallback','natural','throw','block','sink_block','interrupt',
                'generated','formatter','stage_only','resume_rich','resume_plain')
ROOT.mkdir(parents=True,exist_ok=True)

def deny(*args,**kwargs):
    raise AssertionError('ConPTY child forbids real networking and unguarded subprocesses')

def audit(event,args):
    if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn',
            'os.exec','os.spawn','os.fork','os.forkpty','os.startfile','os.startfile/2'):
        deny()

sys.addaudithook(audit)
for name in ('create_connection','create_server','socketpair','fromfd','getaddrinfo',
        'gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo','getfqdn'):
    if hasattr(socket,name): setattr(socket,name,deny)
for name in ('Popen','run','call','check_call','check_output'): setattr(subprocess,name,deny)
for name in ('system','popen','startfile','spawnl','spawnle','spawnlp','spawnlpe','spawnv','spawnve','spawnvp','spawnvpe'):
    if hasattr(os,name): setattr(os,name,deny)
assert not any(n.startswith('bytefault') for n in sys.modules)
guard=[]
for action in (lambda:socket.socket(),lambda:subprocess.run(['ping'])):
    try: action()
    except AssertionError as exc: guard.append(str(exc))
assert len(guard)==2

# Store Python retains the outer launcher's redirected output. This fixture
# binds its own descriptors to the real attached ConPTY; production is unchanged.
import msvcrt
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
kernel.SetStdHandle.argtypes=[wintypes.DWORD,wintypes.HANDLE]
kernel.GetConsoleMode.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)]
kernel.SetConsoleMode.argtypes=[wintypes.HANDLE,wintypes.DWORD]
for descriptor,standard in ((1,-11),(2,-12)):
    fd=os.open('CONOUT$',os.O_RDWR); os.dup2(fd,descriptor); os.close(fd)
    handle=msvcrt.get_osfhandle(descriptor); assert kernel.SetStdHandle(standard,handle)
    bits=wintypes.DWORD(); assert kernel.GetConsoleMode(handle,ctypes.byref(bits))
    assert kernel.SetConsoleMode(handle,bits.value|4)
outer={key:os.environ.pop(key,None) for key in ('COLUMNS','LINES','NO_COLOR')}
outer['TERM']=os.environ.get('TERM'); os.environ['TERM']='xterm-256color'
outer['stderr_encoding']=sys.stderr.encoding
kernel.SetConsoleOutputCP(65001)
sys.stderr.reconfigure(encoding='utf-8',errors='strict')
sys.stdout.reconfigure(encoding='utf-8',errors='strict')
sys.stderr=open('CONOUT$','w',encoding='utf-8',errors='strict',buffering=1)
sys.stdout=open('CONOUT$','w',encoding='utf-8',errors='strict',buffering=1)
sys.path.insert(0,str(REPO/'src'))
if MODE=='fallback':
    import importlib.abc
    class NoRich(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname=='rich' or fullname.startswith('rich.'):
                raise ImportError('controlled optional Rich absence')
    sys.meta_path.insert(0,NoRich())
if MODE in ('plain','fallback','resume_plain'):
    console_output=sys.stderr
    class PlainOutput:
        def __getattr__(self,name): return getattr(console_output,name)
        def write(self,text):
            with (ROOT/'plain.txt').open('a',encoding='utf-8') as stream: stream.write(text)
            return console_output.write(text)
        def flush(self): return console_output.flush()
    sys.stderr=PlainOutput()

from bytefault.application import Application
from bytefault.core.contracts import (ConversationAction,ConversationRequest,PassivePlan,PreparedRow,
    ReceiveRequest,FieldLocation,Placement,PreparedContribution,SourceInvocation,Calculation)
from bytefault.core.records import encode_value,decode_value
from bytefault.core.storage import reopen_records
from bytefault.fuzzers.inputs import request_to_data
from bytefault.fuzzers.transport import EngineTransport,SendFailure
from bytefault.fuzzers import cli
from bytefault.ui import controller
from bytefault.ui.keypress import KeypressReader
import bytefault.monitoring.heartbeat as heartbeat

trace=[]; lock=threading.Lock(); release=threading.Event()
render_meta=threading.local()
def note(kind,**data):
    with lock:
        entry={'kind':kind,'at':time.monotonic(),**data}
        trace.append(entry)
        with (ROOT/'trace.jsonl').open('a',encoding='utf-8') as stream:
            stream.write(json.dumps(entry,ensure_ascii=True,default=encode_value)+'\n')

ping_count=[0]
def process(command,**options):
    assert command[0]=='ping'
    ping_count[0]+=1
    phase=ping_count[0]%7
    if phase==0: raise OSError('controlled ICMP unavailable')
    return SimpleNamespace(returncode=0 if phase<4 else 1,stdout='controlled',stderr='')
heartbeat.subprocess.run=process

connection=[0]
class Stream:
    def __init__(self,index): self.index=index
    def settimeout(self,timeout): pass
    def connect(self,target):
        connection[0]+=1; self.index=connection[0]
        note('open',index=self.index)
        if self.index==3 and MODE=='surface': raise OSError('controlled setup connection failure')
    def send(self,data):
        note('offer',index=self.index,hex=bytes(data).hex())
        time.sleep(.15 if MODE=='surface' else (.2 if MODE in ('throw','block','sink_block','interrupt') else .055))
        if self.index==2 and len(data)>1 and MODE=='surface':
            raise SendFailure('controlled partial acceptance',2)
        return len(data)
    def recv(self,cap):
        note('read',index=self.index,cap=cap)
        return b'OK'[:cap]
    def close(self): note('close',index=self.index)

def transport(request):
    stream=Stream(0)
    return EngineTransport(request,socket_factory=lambda *args:stream,sleep=lambda duration:None)

app=Application(transport_factory=transport,event_capacity=128)
original_control=app.control
def control(run_id,command):
    outcome=original_control(run_id,command)
    note('control',run_id=run_id,command=command,outcome=outcome.outcome)
    return outcome
app.control=control
cli.Application=lambda:app
original_controller=controller.TerminalController
original_build=original_controller._build
class COORD(ctypes.Structure):
    _fields_=[('X',ctypes.c_short),('Y',ctypes.c_short)]
class RECT(ctypes.Structure):
    _fields_=[('Left',ctypes.c_short),('Top',ctypes.c_short),('Right',ctypes.c_short),('Bottom',ctypes.c_short)]
class INFO(ctypes.Structure):
    _fields_=[('size',COORD),('cursor',COORD),('attrs',wintypes.WORD),('window',RECT),('maximum',COORD)]
kernel.GetConsoleScreenBufferInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(INFO)]
kernel.ReadConsoleOutputCharacterW.argtypes=[wintypes.HANDLE,wintypes.LPWSTR,wintypes.DWORD,COORD,ctypes.POINTER(wintypes.DWORD)]
kernel.ReadConsoleOutputAttribute.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.WORD),wintypes.DWORD,COORD,ctypes.POINTER(wintypes.DWORD)]
def capture_viewport():
    fd=os.open('CONOUT$',os.O_RDWR)
    try:
        handle=msvcrt.get_osfhandle(fd); info=INFO()
        assert kernel.GetConsoleScreenBufferInfo(handle,ctypes.byref(info))
        width=info.size.X; rows=info.window.Bottom-info.window.Top+1
        count=wintypes.DWORD(); chars=ctypes.create_unicode_buffer(width*rows+1)
        attrs=(wintypes.WORD*(width*rows))()
        point=COORD(0,info.window.Top)
        assert kernel.ReadConsoleOutputCharacterW(handle,chars,width*rows,point,ctypes.byref(count))
        assert kernel.ReadConsoleOutputAttribute(handle,attrs,width*rows,point,ctypes.byref(count))
        text='\n'.join(chars.value[i*width:(i+1)*width].rstrip() for i in range(rows))
        return text,list(attrs),[width,rows]
    finally:
        os.close(fd)

if MODE not in ('plain','fallback','resume_plain'):
    from rich.live import Live
    real_update=Live.update
    def actual_update(self,*args,**kwargs):
        result=real_update(self,*args,**kwargs)
        metadata=getattr(render_meta,'data',None)
        if metadata:
            text,attrs,geometry=capture_viewport()
            note('frame',**metadata,geometry=geometry,text=text,attributes=attrs)
        return result
    Live.update=actual_update

class TracedController(original_controller):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        if MODE=='surface':
            import inspect
            owner=self; underlying=self._lock
            class ObservedLock:
                def acquire(self,*args,**kwargs): return underlying.acquire(*args,**kwargs)
                def release(self):
                    frame=inspect.currentframe().f_back
                    if frame.f_code.co_name=='__exit__': frame=frame.f_back
                    if frame.f_code.co_name=='_logs':
                        values=frame.f_locals; state=values.get('st'); current=owner.session_state
                        reasons=[]
                        if state is not current: reasons.append('state_identity')
                        if values.get('revision')!=owner._log_revision: reasons.append('revision')
                        if values.get('query',current.log_search_query)!=current.log_search_query: reasons.append('query')
                        if values.get('path',current.log_file)!=current.log_file: reasons.append('path')
                        if values.get('cancel') is not None and values['cancel'].is_set(): reasons.append('cancelled')
                        if reasons: note('log_guard',line=frame.f_lineno,reasons=reasons,
                            captured_state=id(state),current_state=id(current),resets=current.projection_resets,
                            revision=values.get('revision'),current_revision=owner._log_revision)
                    return underlying.release()
                def __enter__(self): self.acquire(); return self
                def __exit__(self,*args): return self.release()
            self._lock=ObservedLock()
    def _build(self,state,tx,rx):
        import shutil
        geometry=shutil.get_terminal_size((80,24))
        if MODE=='throw':
            note('renderer_throw_entered'); raise RuntimeError('controlled actual renderer failure')
        if MODE=='block':
            note('render_block_entered'); release.wait(12)
        result=original_build(self,state,tx,rx)
        if MODE not in ('block','throw','sink_block'):
            render_meta.data=dict(screen=state.active_screen,help=state.show_help,verbosity=state.verbosity_level,
                theme=state.theme_name,render_geometry=list(geometry),case=state.current_iteration,
                variant=state.variant_id,action=state.action_id,attempt=state.attempt_id,
                intended=(state.intended or b'').hex(),receive=state.receive_outcome,
                paused=state.paused,heartbeat=state.heartbeat_alive,search=state.log_search_query,
                detail=state.log_detail_rows is not None,
                classifications=sorted({a['classification'] for finding in state.crash_records for a in finding.get('assessments',())}),
                reports=sum(bool(finding.get('reports')) for finding in state.crash_records),
                search_input=state.log_search_input,matches=state.log_search_matches[:16],match_count=len(state.log_search_matches),
                match_index=state.log_search_index,scroll=state.log_scroll_offset,
                hidden=state.hidden_fields)
            if MODE.startswith('resume_'):
                render_meta.data.update(phase=resume_phase[0],held=bool(state.resume and state.resume['continuation']['hold']),
                    inherited=state.resume.get('inherited_counts',{}),new_attempts=state.progress.get('attempts',0),
                    findings=[{key:f.get(key) for key in ('run_id','event_id','observation_id','attempt_id','reports')} for f in state.crash_records])
        return result
controller.TerminalController=TracedController
if MODE=='surface':
    from bytefault.ui.log_view import LogRows
    real_init,real_matches,real_current=LogRows.__init__,LogRows.matches,LogRows.source_current
    def index_init(self,*args,**kwargs):
        note('log_index_start',width=args[1] if len(args)>1 else kwargs.get('width'))
        try: return real_init(self,*args,**kwargs)
        finally: note('log_index_end',rows=getattr(self,'count',None),stamp=getattr(self,'source_stamp',None))
    def index_matches(self,query,**kwargs):
        note('log_matching_start',query=query)
        try: return real_matches(self,query,**kwargs)
        finally: note('log_matching_end',query=query)
    def index_current(self,*args,**kwargs):
        result=real_current(self,*args,**kwargs)
        note('log_source_verification',result=result)
        return result
    LogRows.__init__,LogRows.matches,LogRows.source_current=index_init,index_matches,index_current

old_char,old_scan=KeypressReader._handle_char,KeypressReader._handle_scan_code
def char(self,key):
    old_char(self,key); note('key',char=key,screen=self.active_screen)
def scan(self,key):
    old_scan(self,key); note('scan',scan=ord(key),screen=self.active_screen)
KeypressReader._handle_char=char; KeypressReader._handle_scan_code=scan

def resume_scenario():
    """Two affected surfaces; all operations use the actual current owners."""
    global app
    from dataclasses import replace
    from bytefault.application import ApplicationRequest,ResumeIntent,ResumeChoice
    from bytefault.core.contracts import MonitoringDecision,MonitoringAction,MonitoringCompletion
    from bytefault.fuzzers.inputs import raw_request,contract_from_record
    from bytefault.monitoring import Monitoring,MonitoringConfig,ObservationRule
    from bytefault.management.configuration import ServiceConfiguration
    from bytefault.ui.application_client import ApplicationView
    from bytefault.ui.plain import ApplicationPlainClient
    if MODE=='resume_rich':
        from rich.live import Live
        from rich.console import Console
    def wait(predicate):
        deadline=time.monotonic()+15
        while not predicate() and time.monotonic()<deadline: time.sleep(.025)
        assert predicate(),'resume fixture coordination timeout'
    if MODE=='resume_plain':
        actual_render=ApplicationPlainClient.render
        def render(client,state,updates):
            result=actual_render(client,state,updates)
            text,attrs,geometry=capture_viewport()
            note('resume_plain_frame',phase=resume_phase[0],text=text,attributes=attrs,geometry=geometry,
                held=bool(state.resume and state.resume['continuation']['hold']),
                inherited=state.resume.get('inherited_counts',{}),new_attempts=state.progress.get('attempts',0),
                reports=sum(bool(f.get('reports')) for f in state.crash_records))
            return result
        ApplicationPlainClient.render=render
    class Policy:
        count=0
        def evaluate(self,observation):
            self.count+=1
            if self.count==2:
                actions=tuple(MonitoringAction(key,'original-event',observation.observation_id,
                    observation.correlation,'followup',{'collect':True,'report':True}) for key in ('one','two'))
                return MonitoringDecision('original-hold',observation.observation_id,observation.correlation,
                    'hold','awaited',('readiness','collection','report'),actions=actions,hold_timeout=120)
            return MonitoringDecision('continue:'+observation.observation_id,observation.observation_id,observation.correlation,'continue')
    app=Application(transport_factory=transport,event_capacity=128,monitoring=Monitoring(Policy()))
    gate_control=app.control
    def trace_gate_control(run_id,command):
        outcome=gate_control(run_id,command); note('control',run_id=run_id,command=command,outcome=outcome.outcome); return outcome
    app.control=trace_gate_control
    raw=replace(raw_request(b'R',receive=ReceiveRequest(requested=False)),run_id='original-run')
    base=ApplicationRequest(raw,controller_request,str(ROOT/'parent.bfr'))
    # Reuse the maintained storage-boundary pattern: retain an acknowledged
    # gate and one completion before this case's terminal can be written.
    from bytefault.core.storage import LocalRecordStore
    terminal_entered,terminal_release=threading.Event(),threading.Event()
    original_append=LocalRecordStore.append
    def checkpoint(store,kind,identity,data):
        if str(store.path)==base.record_path and kind=='case_terminal' and identity.get('case_number')==2:
            terminal_entered.set(); assert terminal_release.wait(15)
        return original_append(store,kind,identity,data)
    LocalRecordStore.append=checkpoint
    parent=app.start(__import__('bytefault.application',fromlist=['CampaignRequest']).CampaignRequest(
        raw,controller_request,base.record_path,cases=(raw,raw,raw)))
    wait(lambda:app.status(parent.run_id)['engine'] is not None and app.status(parent.run_id)['engine'].monitoring_hold)
    assert terminal_entered.wait(5)
    inspection=app.inspect_resume(base.record_path)
    typed=contract_from_record(MonitoringDecision,inspection.continuation['hold'])
    def completion(action,condition='collection',correlation=typed.correlation):
        return MonitoringCompletion('native:'+str(action)+condition,typed.decision_id,typed.observation_id,
            correlation,condition,'succeeded',followup_action_id=action)
    assert app.complete_monitoring(parent.run_id,completion('one'))
    copy=ROOT/'retained.bfr'; copy.write_bytes(Path(base.record_path).read_bytes())
    request=app.resume(ResumeIntent(str(copy),(ResumeChoice(inspection.cases[1]['conversation_id'],'rerun'),)),
        record_path=str(ROOT/'continued.bfr'))
    parent.control('stop'); terminal_release.set()
    note('fixture_parent_terminal',outcome=parent.wait(5).outcome)
    LocalRecordStore.append=original_append
    def provider():
        def held():
            try: state=app.status(request.conversation.run_id)
            except ValueError: return False
            return state['engine'] is not None and state['engine'].monitoring_hold
        wait(held)
        copy.unlink(); Path(base.record_path).unlink()
        wait(lambda:(ROOT/'complete-gate').exists())
        before=sum(r['kind']=='offer' for r in trace)
        assert not app.complete_monitoring(request.conversation.run_id,completion('two',correlation=replace(typed.correlation,attempt_id='stale')))
        assert before==sum(r['kind']=='offer' for r in trace)
        for action,condition in (('two','collection'),('one','report'),('two','report')):
            assert app.complete_monitoring(request.conversation.run_id,completion(action,condition))
        assert before==sum(r['kind']=='offer' for r in trace)
        assert app.complete_monitoring(request.conversation.run_id,completion(None,'readiness'))
        note('exact_gate_completed',original_attempt=typed.correlation.attempt_id)
    threading.Thread(target=provider,daemon=True).start()
    resume_phase[0]='hold'
    note('ready',guard=guard,executable=sys.executable,outer_env=outer,mode=MODE,isatty=[sys.stdin.isatty(),sys.stderr.isatty()],
        python=sys.version,rich=installed_rich_version(),windows=list(sys.getwindowsversion()),terminal='Windows ConPTY')
    primary=controller.run_terminal(app,request,{'no_ui':MODE=='resume_plain'})
    assert primary.outcome=='completed' and primary.attempts==2
    note('gate_finished',outcome=primary.outcome,attempts=primary.attempts)
    app.close()
    if app.management is not None: app.management.wait(5)
    app.close()
    # An already-admitted ORIGINAL run owns this held collection. Resume does
    # not resurrect its queue or attribute its report to a new attempt.
    app=Application(transport_factory=transport,event_capacity=128,
        service_configuration=ServiceConfiguration(result_root=str(ROOT/'results'),ssh_key='controlled-key',core_write_wait=0),
        monitoring=Monitoring(configuration=MonitoringConfig(health_check_mode='disabled',rules=(
            ObservationRule('unrequested','unrequested',actions=({'collect':True,'report':True},)),))))
    late_control=app.control
    def trace_control(run_id,command):
        outcome=late_control(run_id,command); note('control',run_id=run_id,command=command,outcome=outcome.outcome); return outcome
    app.control=trace_control
    def collection(command,**kwargs):
        assert command[0]=='rsync'
        note('collection_held'); wait(lambda:(ROOT/'release-collection').exists())
        (Path(command[-1])/'core').write_bytes(b'C')
        return SimpleNamespace(returncode=0,
            stdout='BF|>f+++++++++|1|2026/10/22-15:00:57|core\nNumber of files: 2 (reg: 1, dir: 1)',
            stderr='')
    subprocess.run=collection
    late=ApplicationRequest(replace(raw_request(b'L',receive=ReceiveRequest(requested=False)),run_id='late-original'),
        controller_request,str(ROOT/'late-original.bfr'))
    assert app.submit(late).outcome=='completed'
    wait(lambda:any(r['kind']=='collection_held' for r in trace))
    original_identity=next(record.identity for record in app.read_service_history('late-original').records if record.kind=='management_request')
    continuation=app.resume(ResumeIntent(late.record_path),record_path=str(ROOT/'late-continuation.bfr'))
    def primary_completion():
        def completed():
            try: return app.status(continuation.conversation.run_id)['result'] is not None
            except ValueError: return False
        wait(completed)
        status=app.status(continuation.conversation.run_id)
        note('late_primary_complete',outcome=status['result'].outcome,active=status['active'])
    threading.Thread(target=primary_completion,daemon=True).start()
    resume_phase[0]='late'
    offers_before=sum(r['kind']=='offer' for r in trace)
    result=controller.run_terminal(app,continuation,{'no_ui':MODE=='resume_plain'})
    from bytefault.application import RunHandle
    assert result is RunHandle(app,result.run_id).wait(0) and result.outcome=='completed' and result.attempts==0
    assert app.management.status()['pending'] and not app.reporting.root.closed
    note('callable_detached',outcome=result.outcome,owners_open=True,pending=True)
    resume_phase[0]='reattached'
    view=ApplicationView(app,result.run_id)
    if MODE=='resume_rich':
        reader=KeypressReader(); panel=controller.TerminalController(view,reader,stream=sys.stderr)
        panel.start(Live(console=Console(file=sys.stderr),screen=True,auto_refresh=False,redirect_stdout=False,redirect_stderr=False))
        wait(lambda:(ROOT/'release-collection').exists())
        app.management.wait(5)
        wait(lambda:any(r.get('phase')=='reattached' and r.get('reports',0)>0 for r in trace))
        findings=next(r['findings'] for r in reversed(trace) if r.get('phase')=='reattached' and r.get('reports',0)>0)
        assert any(f['reports'] and all(f[key]==original_identity[key] for key in ('run_id','event_id','observation_id','attempt_id')) for f in findings)
        wait(lambda:(ROOT/'finish-view').exists())
        panel.stop(); view.close()
    else:
        client=ApplicationPlainClient(view,stream=sys.stderr)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            client.refresh()
            if any(f.get('reports') for f in view.state.crash_records): break
            time.sleep(.075)
        assert any(f.get('reports') and all(f[key]==original_identity[key] for key in ('run_id','event_id','observation_id','attempt_id')) for f in view.state.crash_records)
        wait(lambda:(ROOT/'finish-view').exists())
        view.close()
    assert sum(r['kind']=='offer' for r in trace)==offers_before
    note('late_identity',original={key:original_identity[key] for key in ('run_id','event_id','observation_id','attempt_id')},empty_resume_offers=0)
    assert any(r.kind=='report_outcome' for r in app.read_service_history('late-original').records)
    app.close(); app.management.wait(5); app.close()
    note('cleanup',key_reader_threads=[t.name for t in threading.enumerate() if t.name=='keypress-reader'],
        terminal_threads=[t.name for t in threading.enumerate() if t.name.startswith('bytefault-terminal')],
        management_closed=app.management.status()['closed'],root_closed=app.reporting.root.closed)
    sys.stderr.write('\nCONPTY NORMAL SCREEN RESTORED\n'); sys.stderr.flush()

if MODE.startswith('resume_'):
    from bytefault.core.contracts import TransportRequest
    resume_phase=['setup']; controller_request=TransportRequest('controlled-A',1234,1)
    resume_scenario()
    raise SystemExit(0)

if MODE=='sink_block':
    original_stderr=sys.stderr
    class BlockedOutput:
        def __getattr__(self,name): return getattr(original_stderr,name)
        def write(self,text):
            if threading.current_thread().name in ('bytefault-terminal-render','bytefault-terminal-diagnostic'):
                note('sink_block_entered'); release.wait(12)
            return original_stderr.write(text)
        def flush(self): return original_stderr.flush()
    sys.stderr=BlockedOutput()

plan=PassivePlan('neutral-Raw',1,(
    ConversationAction('S',b'S',next_action=None if MODE=='stage_only' else '__ordered__',receive=ReceiveRequest(cap=2,deadline=.2)),
    ConversationAction('A',bytes.fromhex('000061626364'),receive=ReceiveRequest(requested=False),
        fields=(FieldLocation('left',2,2),FieldLocation('right',4,2))),))
row=PreparedRow('marker-row',1,tuple(PreparedContribution(k,v,SourceInvocation(k,'literal'))
    for k,v in (('left',b'XY'),('right',b'\0\xff'),('tail',bytes(range(64))))),(
    Placement('left','left','A','replace',field_id='left'),
    Placement('right','right','A','replace',field_id='right'),Placement('tail','tail','A','append')))
conversation=ConversationRequest(plan,row,('A',),'fixture','case','conversation',True,
    (Calculation('length','A','payload_length',offset=0,size=2,payload_offset=2),))
count=12 if MODE=='surface' else (2 if MODE in ('natural','hide','no_banner','plain','fallback','formatter','stage_only') else 20)
cases=tuple(request_to_data(conversation) for _ in range(count))
policy={'health_check_mode':'disabled','retries':0,'delayed_check':0,'rules':[
    {'rule_id':'partial','kind':'send_failure','classification':'response_anomaly','actions':[{'report':True}]},
    {'rule_id':'connect','kind':'connection_failure','classification':'service_unavailable','actions':[{'report':True}]}]}
args=['controlled-A','--port','1234','--campaign-json',json.dumps(encode_value({'cases':cases})),
    '--monitoring-json',json.dumps(encode_value(policy)),'--records',str(ROOT/'run.bfr'),
    '--log-file',str(ROOT/'logs'/'nested'/'configured.bfr'),'--results',str(ROOT/'results'),
    '--heartbeat','--heartbeat-interval','.35','--ui']
if MODE=='plain': args+=['--no-ui']
if MODE=='hide': args+=['--hide-field','left','--hide-field','right']
if MODE=='no_banner': args+=['--no-test-banner']
if MODE=='generated':
    args=['controlled-A','--port','1234','--seed-hex','414243','--gen-field',
        '@1:list:58,59,5a,mode:overwrite','--gen-strategy','zip','--skip','1',
        '--records',str(ROOT/'run.bfr'),'--log-file',str(ROOT/'logs'/'nested'/'configured.bfr'),
        '--results',str(ROOT/'results'),'--no-recv','--health-check-mode','disabled','--ui']
stdout=(ROOT/'stdout.jsonl').open('w',encoding='utf-8'); sys.stdout=stdout
(ROOT/'argv.json').write_text(json.dumps(args),encoding='utf-8')
note('ready',guard=guard,executable=sys.executable,outer_env=outer,mode=MODE,argv_file=str(ROOT/'argv.json'),
    isatty=[sys.stdin.isatty(),sys.stderr.isatty()],python=sys.version,rich=installed_rich_version(),
    windows=list(sys.getwindowsversion()),terminal='Windows ConPTY',minimum_geometry=[72,22])
try:
    if MODE=='formatter':
        from bytefault.management.configuration import ServiceConfiguration
        configuration=cli.resolve_configuration(args,app)
        app.configure_services(ServiceConfiguration(result_root=str(ROOT/'results'),heartbeat=True,heartbeat_interval=.35))
        def formatter(fields,received):
            return 'CONTROLLED FORMAT left='+fields.get('left',b'').hex()+' right='+fields.get('right',b'').hex()+(
                ' receive=unrequested' if received is None else ' receive='+received.hex())
        result=controller.run_terminal(app,configuration.request,dict(configuration.options),output_formatter=formatter)
        stdout.write(json.dumps(encode_value(result))+'\n')
        code=cli.operation_exit_code(result)
        app.close(); app.management.wait(); app.close()
    else:
        code=cli.main(args)
    note('main_return',code=code,pending_terminal_threads=[t.name for t in threading.enumerate()
        if t.name.startswith('bytefault-terminal') or t.name=='keypress-reader'])
    if MODE in ('plain','fallback'):
        text,attrs,geometry=capture_viewport()
        note('plain_viewport',text=text,attributes=attrs,geometry=geometry)
    stdout.flush()
    result=decode_value(json.loads((ROOT/'stdout.jsonl').read_text(encoding='utf-8').splitlines()[0]))
    history=app.read_records(result['run_id'])
    log_history=reopen_records(ROOT/'logs'/'nested'/'configured.bfr')
    actions=[]
    for record in history.records:
        if record.kind=='action_result':
            action=record.data['result']; port=action.transport
            actions.append(dict(action=action.action_id,iteration=action.iteration_id,
                intended=action.materialized.final_bytes.hex(),offered=port.offered.hex(),
                accepted_count=port.accepted_count,accepted_prefix=port.accepted_prefix.hex(),
                acceptance=port.acceptance,received=port.received.hex(),receive_requested=port.receive_requested,
                receive_outcome=port.receive_outcome))
    note('authoritative',outcome=result['outcome'],counters={name:result[name] for name in (
        'prepared_cases','selected_cases','fuzz_tests','attempts','setup_attempts')},
        actions=actions,history_issue=history.issue,log_issue=log_history.issue,
        log_action_results=sum(record.kind=='action_result' for record in log_history.records),
        cases=[dict(number=record.data['case_number'],selected=record.data['selected'])
               for record in history.records if record.kind=='campaign_case'],
        case_outcomes=[record.data['result'].outcome for record in history.records if record.kind=='case_terminal'])
finally:
    release.set(); time.sleep(.5); stdout.flush(); stdout.close()
    note('cleanup',key_reader_threads=[t.name for t in threading.enumerate() if t.name=='keypress-reader'],
        terminal_threads=[t.name for t in threading.enumerate() if t.name.startswith('bytefault-terminal')],
        heartbeat=app.heartbeat_status('controlled-A'),management_closed=app.management.status()['closed'],
        root_closed=app.reporting.root.closed)
    sys.stderr.write('\nCONPTY NORMAL SCREEN RESTORED\n'); sys.stderr.flush()
raise SystemExit(code)
