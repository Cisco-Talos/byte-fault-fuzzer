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

"""Application-client projection and fault checks; actual keyboard/resize is T."""
from dataclasses import replace
import io
import threading
import time
import sys
from types import ModuleType,SimpleNamespace

import pytest

from bytefault.core.contracts import FinalFieldLocation,MaterializedAction
from bytefault.ui.application_client import ApplicationView,readable_log
from bytefault.ui.controller import TerminalController,run_terminal
from bytefault.ui.keypress import KeypressReader
from test_reporting_collection import literal,reporting_monitor,await_followup
from test_followup_heartbeat import wait_until,request


def test_current_fields_no_receive_projection_gap_and_binary_log(tmp_path,application_factory):
    app,traces=application_factory(event_capacity=1,stream_options={'reads':(b'OK',b'SENTINEL')})
    req=literal(tmp_path)
    app.submit(req)
    view=ApplicationView(app,req.conversation.run_id,request=req)
    view.refresh()
    st=view.state
    assert st.intended==bytes.fromhex('0005585900ff5a')
    assert st.current_field_bytes=={'left':b'XY','right':b'\0\xff'}
    assert [(f['offset'],f['size']) for f in st.current_fields]==[(2,2),(4,2)]
    assert st.last_received is None and st.receive_outcome=='unrequested'
    assert st.acceptance=='accepted' and st.accepted_count==7
    assert traces[0][1].reads==[b'SENTINEL']
    assert st.action_id=='A' and st.attempt_id.endswith('A:attempt-1')
    assert st.total_bytes_sent==8 and st.total_bytes_received==2
    updates=tuple(view.action_updates)
    view.refresh()
    assert st.total_bytes_sent==8  # readback ahead of optional cursor is not double-counted
    from bytefault.ui.plain import ApplicationPlainClient
    output=io.StringIO(); plain=ApplicationPlainClient(view,stream=output)
    plain.render(st,updates); plain.render(st,()); plain.render(st,updates)
    assert output.getvalue().count('ACCEPTED_PREFIX ')==2
    lines,issue=readable_log(st.log_file,72)
    assert not issue and any('action_result' in line for line in lines)
    assert any('0005585900ff5a' in line for line in lines)
    assert all(len(line)<=64 for line in lines)
    view.state.last_received=b'view-only'
    assert app.status(st.run_id)['engine'].last_transport.received==b''
    view.close()
    assert app.status(st.run_id)['finalized']


def test_final_field_unknown_empty_and_legacy_are_distinct(application_factory):
    app,_=application_factory()
    view=ApplicationView(app,'unused')
    output=MaterializedAction('A',b'AB',b'ZAB',final_fields=(
        FinalFieldLocation('A','outbound','moved',1,2),
        FinalFieldLocation('A','outbound','empty',3,0),
        FinalFieldLocation('A','outbound','partial',1,None),
        FinalFieldLocation('A','outbound','unknown',None,None)))
    view._materialized(output)
    assert view.state.current_field_bytes=={'moved':b'AB','empty':b''}
    assert [f['value'] for f in view.state.current_fields]==[b'AB',b'',None,None]
    view._materialized(replace(output,final_fields=None))
    assert not view.state.final_fields_available and view.state.current_fields==[]
    view._materialized(replace(output,final_fields=()))
    assert view.state.final_fields_available and view.state.current_fields==[]


def test_plain_api_bytes_setup_banner_and_header_only_hiding(tmp_path,application_factory):
    traces=[]
    for name,ui in (('api',False),('plain',True)):
        app,trace=application_factory(stream_options={'reads':(b'OK',b'SENTINEL')})
        req=literal(tmp_path,name)
        if ui:
            output=io.StringIO()
            result=run_terminal(app,req,{'no_ui':True,'test_banner':False,'hide_field':['left']},stream=output)
            text=output.getvalue()
            assert '-'*72 not in text and 'Test 1' in text
            assert 'left=' not in text and 'right=00ff' in text
            assert '0005585900ff5a' in text and 'receive=unrequested' in text
            assert 'action=S' in text and 'action=A' in text
            assert 'Setup run=' in text and 'stage=' in text and 'ACCEPTED_PREFIX 0005585900ff5a' in text
            assert text.count('Setup run=')==1 and text.count('Test 1 run=')==1
            assert 'PROGRESS case=1' in text and 'tests=unknown attempts=1 setup=1' in text
            assert 'total unknown' in text and 'view-rate=' in text
            assert 'SUMMARY outcome=completed' in text and 'known-accepted-bytes=8 received-bytes=2 potential=0' in text
        else:
            result=app.submit(req)
        assert result.outcome=='completed'
        traces.append([entry for stream,_,_ in trace for entry in stream if entry[0] in ('offer','read','close')])
    assert traces[0]==traces[1]
    from bytefault.application import ApplicationRequest
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.core.contracts import ReceiveRequest,TransportRequest
    from bytefault.fuzzers.transport import SendFailure
    partial,_=application_factory(stream_options={'sends':(SendFailure('controlled partial send',2),)})
    req=ApplicationRequest(raw_request(b'ABCDE',receive=ReceiveRequest(requested=False)),
        TransportRequest('controlled-A',1234,1),str(tmp_path/'partial.bfr'))
    output=io.StringIO()
    run_terminal(partial,req,{'no_ui':True},stream=output)
    assert 'OFFERED 4142434445' in output.getvalue()
    assert 'known-accepted-bytes=2' in output.getvalue() and 'offered-bytes=2' not in output.getvalue()


def test_late_actual_report_retains_original_finding_after_view_detach(tmp_path,application_factory):
    from bytefault.management.configuration import ServiceConfiguration
    app,_=application_factory(monitoring=reporting_monitor(),
        service_configuration=ServiceConfiguration(result_root=str(tmp_path/'results')),
        stream_options={'reads':(b'OK',)})
    req=literal(tmp_path)
    app.submit(req)
    view=ApplicationView(app,req.conversation.run_id,request=req)
    view.refresh(); view.close()
    await_followup(app)
    reopened=ApplicationView(app,req.conversation.run_id,request=req)
    reopened.refresh()
    findings=reopened.state.crash_records
    reports=[r for r in findings if r.get('reports')]
    assert reports and all(r['run_id']==req.conversation.run_id and r['action_id']=='A' for r in reports)
    assert all(r['report_status']=='succeeded' for r in reports)
    assert all(r['classification']=='response_anomaly' for r in reports)
    assert reopened.state.crash_count==0


def test_frozen_live_report_projects_into_rich_frame(tmp_path,application_factory):
    from rich.console import Console
    from bytefault.core.contracts import ValueSnapshot
    from bytefault.core.storage import LocalRecordStore
    from bytefault.management import Management
    from bytefault.reporting import ReportOutcome

    store=LocalRecordStore(tmp_path/'service.bfr')
    management=Management(store)
    app,_=application_factory(management=management)
    req=literal(tmp_path); app.submit(req)
    run=req.conversation.run_id
    identity={'run_id':run,'observation_id':'late-core','event_id':'late-event',
        'conversation_id':req.conversation.conversation_id,'action_id':'A'}
    outcome=ReportOutcome('late-report','late-event','A','succeeded','late/REPORT.md',
        acquired_core_count=2,acquired_cores=(
            {'name':'alpha [first]','name_status':'exact','path':'late/core-alpha'},
            {'name':'beta','name_status':'exact','path':'late/core-beta'}))
    store.append('report_outcome',identity,{'outcome':outcome})
    source=app.read_service_history(run).records[-1].data['outcome'].acquired_cores
    assert isinstance(source[0],ValueSnapshot)

    view=ApplicationView(app,run,request=req)
    view.state.active_screen='crashes'
    controller=TerminalController(view,KeypressReader())
    projector=threading.Thread(target=controller._project,daemon=True)
    projector.start()
    try:
        wait_until(lambda: controller._frame is not None,timeout=2)
        with controller._lock:
            frame=controller._frame
        finding=next(r for r in frame[1].crash_records if r['observation_id']=='late-core')
        assert finding['event_id']=='late-event' and finding['reports']==['late/REPORT.md']
        assert finding['acquired_cores']==tuple(map(dict,source))
        output=io.StringIO()
        Console(file=output,width=120,height=40,color_system=None).print(
            controller._build(frame[1],frame[2],frame[3]))
        rendered=output.getvalue()
        assert 'MULTIPLE CORES ACQUIRED 2' in rendered
        assert "'alpha [first]': core-alpha" in rendered
        assert "'beta': core-beta" in rendered and 'late/REPORT.md' in rendered
        assert isinstance(source[0],ValueSnapshot)
    finally:
        controller._done.set(); projector.join(2)
        view.close(); app.close(); management.close(); management.wait(5); store.close()


@pytest.mark.parametrize('provider_kind', ['local', 'opaque'])
def test_service_history_view_poll_rebuild_and_reader_issues(tmp_path,application_factory,monkeypatch,provider_kind):
    """Real caller history: cheap stable polls, full rebuilds and late facts."""
    from bytefault.core.records import Record,RecoveryIssue,RecoveryResult
    from bytefault.core.storage import LocalRecordStore,frame_record
    from bytefault.management import Management
    from bytefault.reporting import ReportOutcome
    store=LocalRecordStore(tmp_path/'caller.bfr')
    class CallerStore:
        def __init__(self):
            self.path,self.calls,self.override,self.issue=store.path,0,None,None
        def snapshot(self):
            self.calls+=1
            recovered=store.snapshot()
            if self.override or self.issue:
                records=tuple(replace(record,data={'outcome':{
                    **dict(record.data['outcome']),'location':self.override}})
                    if self.override and record.kind=='report_outcome' else record for record in recovered.records)
                return RecoveryResult(records,recovered.refs,self.issue or recovered.issue)
            return recovered
        def append(self,*args,**kwargs): return store.append(*args,**kwargs)
        def close(self): store.close()
    provider=store if provider_kind=='local' else CallerStore()
    management=Management(provider)
    app,_=application_factory(management=management,event_capacity=1)
    req=literal(tmp_path); app.submit(req)
    run=req.conversation.run_id
    identity={'run_id':run,'observation_id':'service-only','event_id':'event',
        'conversation_id':req.conversation.conversation_id,'action_id':'A'}
    store.append('management_pending',identity,{})
    calls=[]; original=LocalRecordStore.snapshot
    def snapshot(owner):
        calls.append(str(owner.path)); return original(owner)
    monkeypatch.setattr(LocalRecordStore,'snapshot',snapshot)
    def legacy(*args,**kwargs): raise AssertionError('routine view used fresh legacy recovery')
    monkeypatch.setattr(app,'service_record_refs',legacy)
    monkeypatch.setattr(app,'read_service_records',legacy)
    import bytefault.application as application_module
    original_reader=application_module.reopen_records
    def reader(path):
        if provider_kind=='opaque' and str(path)==str(store.path):
            raise AssertionError('opaque recovery replaced by a filesystem reader')
        return original_reader(path)
    monkeypatch.setattr(application_module,'reopen_records',reader)
    view=ApplicationView(app,run,request=req); fresh=None
    def service_findings():
        return [r for r in view.state.crash_records if r['observation_id']=='service-only']
    try:
        view.refresh(); assert len(calls)==1
        assert view.state.crash_records[-1]['followup']=='pending'
        for _ in range(20): view.refresh()
        assert len(calls)==(21 if provider_kind=='opaque' else 1)
        if provider_kind=='opaque': assert provider.calls==21
        outcome=ReportOutcome('report','event','A','succeeded','late/REPORT.md',
            acquired_core_count=2, acquired_cores=(
                {'name':'alpha [first]', 'name_status':'exact', 'path':'late/core-alpha'},
                {'name':'beta', 'name_status':'exact', 'path':'late/core-beta'}))
        store.append('report_outcome',identity,{'outcome':outcome})
        store.append('report_outcome',dict(identity,run_id='unrelated',observation_id='other'),{'outcome':outcome})
        view.refresh(); assert len(calls)==(22 if provider_kind=='opaque' else 2)
        assert [r['reports'] for r in service_findings()]==[['late/REPORT.md']]
        assert service_findings()[0]['acquired_core_count']==2
        assert [core['name'] for core in service_findings()[0]['acquired_cores']]==['alpha [first]','beta']
        from bytefault.ui.plain import ApplicationPlainClient
        from bytefault.ui.rich_renderables import build_crash_table
        output=io.StringIO(); ApplicationPlainClient(view,stream=output).render(view.state,())
        assert 'MULTIPLE CORES ACQUIRED 2' in output.getvalue()
        assert "CORE 'alpha [first]' late/core-alpha" in output.getvalue()
        assert "CORE 'beta' late/core-beta" in output.getvalue()
        rich_cells=build_crash_table(view.state.crash_records).columns[2]._cells
        assert any('MULTIPLE CORES ACQUIRED 2' in cell.plain and
            "'alpha [first]': core-alpha" in cell.plain and
            "'beta': core-beta" in cell.plain and
            'late/REPORT.md' in cell.plain for cell in rich_cells)
        assert not any(r['observation_id']=='other' for r in view.state.crash_records)
        generation=dict(view._service_generations)
        lines,matches=['leased source'],[0]
        view.state.log_lines=lines; view.state.log_search_matches=matches
        view.cursor=0; view.refresh()  # Actual dropped-event rebuild, not a synthetic reset flag.
        assert view.state.projection_resets==1 and len(calls)==(23 if provider_kind=='opaque' else 2)
        assert view.state.log_lines is lines and view.state.log_search_matches is matches
        assert view.state.crash_records[-1]['reports']==['late/REPORT.md']
        fresh=ApplicationView(app,run,request=req); fresh.refresh()
        assert fresh.state.crash_records[-1]['reports']==['late/REPORT.md']
        assert len(calls)==(24 if provider_kind=='opaque' else 2)
        store.close(); saved=store.path.read_bytes()
        store.path.write_bytes(saved+b'BFR1')
        view.refresh()
        assert view._service_generations==generation  # Valid-prefix append retains attribution.
        assert str(store.path) in view.state.degraded and 'incomplete' in view.state.degraded
        # Empty valid prefix must invalidate old offset/report facts and show its issue.
        view.state.degraded+='\nindependent display issue'
        store.path.write_bytes(b'BFR1'); view.refresh()
        assert not service_findings() and not view._service_offsets
        assert view.state.projection_resets==2 and 'incomplete' in view.state.degraded
        assert 'independent display issue' in view.state.degraded
        for refresh in (False,True):
            before=provider.calls if provider_kind=='opaque' else 0
            history=app.read_service_history(run,refresh=refresh)
            assert not history.records and not history.refs
            assert dict(history.issues)[str(store.path)].kind=='incomplete'
            assert str(store.path) in dict(history.generations)
            if provider_kind=='opaque': assert provider.calls==before+1
        assert view.state.log_lines is lines and view.state.log_search_matches is matches
        replacement=Record('replacement','report_outcome',identity,{'outcome':replace(outcome,location='new/REPORT.md')})
        store.path.write_bytes(frame_record(replacement)); view.refresh()
        assert [r['reports'] for r in service_findings()]==[['new/REPORT.md']]
        assert 'service reader' not in view.state.degraded
        assert 'independent display issue' in view.state.degraded
        if provider_kind=='opaque':
            # Actual returned custom data is authoritative despite identical
            # path metadata and different records in the underlying file.
            provider.override='custom/REPORT.md'
            provider.path=tmp_path/'declared-source.bfr'
            provider.issue=RecoveryIssue('incomplete',0,'custom source diagnostic')
            for refresh in (False,True):
                before=provider.calls
                history=app.read_service_history(run,refresh=refresh)
                assert history.records[0].data['outcome']['location']=='custom/REPORT.md'
                assert history.refs[0].path==str(store.path)
                assert history.issues==((str(provider.path),provider.issue),)
                assert provider.calls==before+1
            view.refresh()
            assert [r['reports'] for r in service_findings()]==[['custom/REPORT.md']]
            assert str(provider.path) in view.state.degraded and 'custom source diagnostic' in view.state.degraded
            provider.path=store.path; provider.issue=None
            provider.override=None
            view.refresh()
            assert [r['reports'] for r in service_findings()]==[['new/REPORT.md']]
        with store.path.open('ab') as stream:
            stream.write(frame_record(Record('late','report_outcome',identity,
                {'outcome':replace(outcome,location='late-again/REPORT.md')})))
        view.refresh()
        assert service_findings()[0]['reports']==['new/REPORT.md','late-again/REPORT.md']
        view.state.degraded='independent display issue'
        store.path.write_bytes(b''); view.refresh()
        assert not service_findings() and view.state.degraded=='independent display issue'
        app.close(); assert not management.status()['finalized']
    finally:
        view.close()
        if fresh: fresh.close()
        app.close(); management.close(); management.wait(5); store.close()


@pytest.mark.parametrize('fault',['blocked','throwing','sink_blocked','sink_throwing'])
def test_controls_and_required_history_survive_renderer_fault(tmp_path,application_factory,fault):
    app,traces=application_factory()
    req=request(tmp_path,two=True)
    entered,release,send_entered,send_release=(threading.Event() for _ in range(4))
    factory=app.transport_factory
    def transport(target):
        adapter=factory(target)
        stream=traces[-1][1]; send=stream.send
        def held(data):
            count=send(data); send_entered.set(); assert send_release.wait(5)
            return count
        stream.send=held
        return adapter
    app.transport_factory=transport
    class Reader(KeypressReader):
        def start(self): pass
    class Display:
        def update(self,*args,**kwargs):
            entered.set()
            if fault=='throwing':
                raise RuntimeError('controlled renderer exception')
            if fault.startswith('sink_'):
                output.write('frame')
            else:
                release.wait(5)
    class Sink(io.StringIO):
        def write(self,text):
            if fault=='sink_throwing':
                raise OSError('controlled output failure')
            if fault=='sink_blocked':
                release.wait(5)
            return super().write(text)
    handle=app.start(req)
    assert send_entered.wait(2)
    reader=Reader(); output=Sink()
    controller=TerminalController(ApplicationView(app,handle.run_id,request=req),reader,
        stream=output,renderer=lambda *args:'frame')
    controller.start(Display())
    try:
        assert entered.wait(2)
        wait_until(lambda: bool(controller.session_state.degraded))
        reader._handle_char(' ')
        wait_until(lambda: app.status(handle.run_id)['engine'].paused)
        reader._handle_char('q')
        wait_until(lambda: app.status(handle.run_id)['stop_requested'])
        send_release.set()
        wait_until(lambda: not app.status(handle.run_id)['active'])
        start=time.monotonic(); pending=controller.stop()
        assert time.monotonic()-start<1.2
        assert bool(pending)==(fault in ('blocked','sink_blocked'))
        assert app.read_records(handle.run_id).records
        assert controller.session_state.degraded
    finally:
        release.set(); send_release.set(); controller.stop()


@pytest.mark.parametrize('rich',[False,True])
def test_primary_returns_while_optional_history_projection_is_held(tmp_path,application_factory,monkeypatch,rich):
    app,traces=application_factory(stream_options={'reads':(b'OK',)})
    req=literal(tmp_path)
    entered,release=threading.Event(),threading.Event()
    original=app.read_records
    def held(run_id):
        entered.set(); assert release.wait(5)
        return original(run_id)
    app.read_records=held
    monkeypatch.setattr(KeypressReader,'start',lambda self:None)
    if rich:
        package=ModuleType('rich'); package.__path__=[]
        class Live:
            def __init__(self,**kwargs): pass
            def start(self): pass
            def update(self,*args,**kwargs): pass
            def stop(self): pass
        monkeypatch.setitem(sys.modules,'rich',package)
        monkeypatch.setitem(sys.modules,'rich.console',SimpleNamespace(Console=lambda **kwargs:object()))
        monkeypatch.setitem(sys.modules,'rich.live',SimpleNamespace(Live=Live))
    results=[]
    caller=threading.Thread(target=lambda:results.append(run_terminal(app,req,{'no_ui':not rich},
        stream=io.StringIO(),renderer=lambda *args:'frame')),daemon=True)
    start=time.monotonic(); caller.start()
    try:
        assert entered.wait(2)
        caller.join(1.5)
        assert not caller.is_alive() and results[0].outcome=='completed'
        assert time.monotonic()-start<1.8
        assert len([entry for trace,_,_ in traces for entry in trace if entry[0]=='offer'])==2
    finally:
        release.set(); caller.join(2)


def test_dense_log_search_is_complete_and_actual_controls_remain_responsive(tmp_path,application_factory,monkeypatch):
    """Dense log search and held-send input behavior at full cardinality."""
    from bytefault.application import ApplicationRequest
    from bytefault.core.contracts import ReceiveRequest,TransportRequest
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.ui.log_view import LogRows
    # Preserve the original Windows CRLF fixture bytes on every test host.
    path=tmp_path/'log.txt'; path.write_bytes((b'a'*120+b'\r\n')*20000)
    assert path.stat().st_size==2440000
    app,traces=application_factory()
    entered,release,searching=threading.Event(),threading.Event(),threading.Event()
    factory=app.transport_factory
    def transport(target):
        adapter=factory(target); send=traces[-1][1].send
        def held(data):
            result=send(data); entered.set(); assert release.wait(25)
            return result
        traces[-1][1].send=held
        return adapter
    app.transport_factory=transport
    req=ApplicationRequest(raw_request(b'X',receive=ReceiveRequest(requested=False)),
        TransportRequest('controlled-A',1234,1),str(tmp_path/'run.bfr'))
    handle=app.start(req); assert entered.wait(2)
    view=ApplicationView(app,handle.run_id,request=req)
    view.refresh(); view.state.log_file=str(path)
    rows=LogRows(path,120); view.state.log_lines=rows
    info=path.stat(); view._log_stamp=(info.st_size,info.st_mtime_ns,120)
    monkeypatch.setattr('bytefault.ui.controller.shutil.get_terminal_size',lambda *args:SimpleNamespace(columns=120,lines=35))
    calls=[]; original=LogRows.matches
    def observed(self,query,**kwargs):
        calls.append((query,threading.current_thread().name)); searching.set()
        return original(self,query,**kwargs)
    monkeypatch.setattr(LogRows,'matches',observed)
    class Reader(KeypressReader):
        def start(self): pass
    reader=Reader(); reader._handle_char('>'); reader._handle_char('>')
    controller=TerminalController(view,reader,stream=io.StringIO(),renderer=lambda *args:'frame')
    controller.start(SimpleNamespace(update=lambda *args,**kwargs:None))
    completed=None
    try:
        for key in '/a\r': reader._handle_char(key)
        assert searching.wait(2)
        wait_until(lambda: not view.state.log_search_pending and len(view.state.log_search_matches)==2400000,timeout=15)
        completed=view.state.log_search_matches
        assert completed[0]==0 and completed[111]==0 and completed[112]==1 and completed[-1]==39999
        reader._handle_char('n'); wait_until(lambda:view.state.log_search_index==1)
        reader._handle_char('p'); wait_until(lambda:view.state.log_search_index==0)
        reader._handle_scan_code(chr(0x4f)); wait_until(lambda:view.state.log_scroll_offset==-1)
        reader._handle_scan_code(chr(0x47)); wait_until(lambda:view.state.log_scroll_offset==0)
        searching.clear(); count=len(calls)
        for key in '/a\r': reader._handle_char(key)
        wait_until(lambda:len(calls)>count)
        # No inserted search delay: pause/q run during actual dense matching.
        assert view.state.log_search_pending
        start=time.monotonic(); reader._handle_char(' ')
        wait_until(lambda:app.status(handle.run_id)['engine'].paused,timeout=.4)
        reader._handle_char('q')
        wait_until(lambda:app.status(handle.run_id)['stop_requested'],timeout=.4)
        assert time.monotonic()-start<.8
        wait_until(lambda:not view.state.log_search_pending)
        stopped_calls=len(calls); time.sleep(.15)
        assert len(calls)==stopped_calls  # no canceled-job restarts while send is still held
        assert all(name=='bytefault-terminal-log' for query,name in calls)
        assert completed[-1]==39999  # an old immutable frame's lease remains usable
        release.set(); assert handle.wait(3).outcome=='stopped'
        start=time.monotonic(); assert not controller.stop()
        assert time.monotonic()-start<1.5
        assert app.read_records(handle.run_id).records
    finally:
        release.set(); controller.stop(); handle.wait(3); view.close()


def test_search_replacement_gap_cancel_and_detach_reject_stale_results(tmp_path,application_factory,monkeypatch):
    from bytefault.ui.log_view import LogRows
    first=tmp_path/'first.txt'; first.write_text('x'*62+'BOUNDARY'+'y'*80,encoding='ascii')
    second=tmp_path/'second.txt'; second.write_text('NEW\nother\nNEW\ncancel\n',encoding='ascii')
    app,_=application_factory(event_capacity=1); req=literal(tmp_path); app.submit(req)
    view=ApplicationView(app,req.conversation.run_id,request=req)
    view.refresh(); view.state.log_file=str(first)
    reader=KeypressReader(); reader._handle_char('>'); reader._handle_char('>')
    monkeypatch.setattr(reader,'start',lambda:None)
    width=[72]
    monkeypatch.setattr('bytefault.ui.controller.shutil.get_terminal_size',lambda *args:SimpleNamespace(columns=width[0],lines=22))
    old_ready,old_release,cancel_ready,cancel_release=(threading.Event() for _ in range(4))
    original=LogRows.matches
    def held_after_real_scan(self,query,**kwargs):
        result=original(self,query,**kwargs)
        if query=='BOUNDARY': old_ready.set(); assert old_release.wait(5)
        if query=='cancel': cancel_ready.set(); assert cancel_release.wait(5)
        return result
    monkeypatch.setattr(LogRows,'matches',held_after_real_scan)
    controller=TerminalController(view,reader,stream=io.StringIO(),renderer=lambda *args:'frame')
    controller.start(SimpleNamespace(update=lambda *args,**kwargs:None))
    publications=[]
    setter=type(view.state).__setattr__
    def record_publication(state,name,value):
        if state is view.state and name=='log_search_matches' and value:
            publications.append((state.log_search_query,len(value)))
        setter(state,name,value)
    monkeypatch.setattr(type(view.state),'__setattr__',record_publication)
    try:
        for key in '/BOUNDARY\r': reader._handle_char(key)
        assert old_ready.wait(2)
        # Same path/query, changed content while the actual old scan is held.
        # A one-match old answer must never publish as the current two-match file.
        first.write_text('BOUNDARY\nBOUNDARY\n',encoding='ascii')
        old_release.set()
        wait_until(lambda:not view.state.log_search_pending and len(view.state.log_search_matches)==2)
        assert ('BOUNDARY',1) not in publications
        old_ready.clear(); old_release.clear()
        for key in '/BOUNDARY\r': reader._handle_char(key)
        assert old_ready.wait(2)
        before=view.state
        with controller._lock:
            view.cursor=0  # force actual bounded-event-gap readback
            view.state.log_file=str(second)
        width[0]=120
        for key in '/NEW\r': reader._handle_char(key)
        wait_until(lambda:view.state is not before and view.state.log_search_query=='NEW')
        old_release.set()
        wait_until(lambda:not view.state.log_search_pending and len(view.state.log_search_matches)==2)
        assert view.state.log_search_matches[:]==[0,2]
        lease=__import__('copy').deepcopy(view.state)
        reader._handle_char('n'); wait_until(lambda:view.state.log_search_index==1)
        assert lease.log_lines[0]=='NEW' and lease.log_search_matches[:]==[0,2]
        for key in '/cancel\r': reader._handle_char(key)
        assert cancel_ready.wait(2)
        reader._handle_char('\x1b')
        wait_until(lambda:view.state.log_search_issue=='cancelled')
        cancel_release.set()
        wait_until(lambda:not view.state.log_search_pending)
        assert view.state.log_search_matches==[]
        assert lease.log_search_matches[:]==[0,2]
        for key in '/NEW\r': reader._handle_char(key)
        wait_until(lambda:not view.state.log_search_pending and len(view.state.log_search_matches)==2)
        assert view.state.log_search_issue==''
        inherited=threading.Event()
        direct=LogRows(first,72,cancelled=inherited.is_set)
        inherited.set()
        with pytest.raises(InterruptedError): direct.matches('BOUNDARY')
        direct.close()
        import textwrap
        from bytefault.ui.log_view import wrapped_rows
        logical=(' word-'*900+'a'*9000+'\t rest\n')*2
        assert list(wrapped_rows(logical,64))==textwrap.wrap(logical,64,replace_whitespace=False,
            drop_whitespace=False,expand_tabs=False)
        for wrap_width,logical in ((64,'a'*3969+'-'+'b'*5000),(16,'a'*4063+'ab-cd'+'z'*5000)):
            assert list(wrapped_rows(logical,wrap_width))==textwrap.wrap(logical,wrap_width,replace_whitespace=False,
                drop_whitespace=False,expand_tabs=False)
        unicode_path=tmp_path/'unicode.txt'; unicode_path.write_text('ß'*40+'MATCH',encoding='utf-8')
        unicode_rows=LogRows(unicode_path,24)
        unicode_matches=unicode_rows.matches('match'); assert unicode_matches[:]==[2]
        unicode_matches=unicode_rows.matches('SS'); assert len(unicode_matches)==40 and unicode_matches[-1]==2
        unicode_rows.close()
        unicode_path.write_text('a'+'ß'*5000+'MATCH',encoding='utf-8')
        unicode_rows=LogRows(unicode_path,24)
        coordinate_checks=[0]
        def cancel_coordinates():
            coordinate_checks[0]+=1
            return coordinate_checks[0]>3
        with pytest.raises(InterruptedError): unicode_rows.matches('MATCH',cancelled=cancel_coordinates)
        unicode_rows.close()
        from bytefault.core.storage import LocalRecordStore
        growing=tmp_path/'growing.bfr'; store=LocalRecordStore(growing)
        store.append('initial',{}, {'marker':'BOUNDARY'})
        prefix=LogRows(growing,72)
        store.append('later',{}, {'marker':'NEW'})
        assert prefix.source_current(growing)
        assert any('initial' in line for line in prefix) and not any('later' in line for line in prefix)
        store.close()
        growing.write_bytes(b'rewritten-larger-source'+b'x'*10000)
        assert not prefix.source_current(growing)
        prefix.close()
        single=tmp_path/'single.txt'; single.write_text('a'*2400000,encoding='ascii')
        checks=[0]
        def cancel_long_line():
            checks[0]+=1
            return checks[0]>3
        with pytest.raises(InterruptedError): LogRows(single,72,cancelled=cancel_long_line)
        checks[0]=0
        with pytest.raises(InterruptedError): list(wrapped_rows('a'*2400000,64,cancelled=cancel_long_line))
        from pathlib import Path
        cache_failures=[]; opened=Path.open
        def fail_cache(path,*args,**kwargs):
            if path.suffix=='.source' and args and args[0]=='wb':
                cache_failures.append(path)
                raise OSError('controlled temporary snapshot output failure')
            return opened(path,*args,**kwargs)
        bad_source=tmp_path/'cache-error.txt'; bad_source.write_text('NEW\n',encoding='ascii')
        with monkeypatch.context() as broken:
            broken.setattr(Path,'open',fail_cache)
            with controller._lock:
                view.state.log_file=str(bad_source)
                controller._process_log_signals(reader)
            wait_until(lambda:'temporary snapshot output failure' in view.state.degraded)
            attempts=len(cache_failures); time.sleep(.15)
            assert attempts==1 and len(cache_failures)==attempts
            assert all(not path.exists() and not path.with_suffix('.sqlite').exists() for path in cache_failures)
        with controller._lock:
            view.state.log_file=str(second)
            controller._process_log_signals(reader)
        wait_until(lambda:not view.state.log_index_pending and view.state.log_index_ready)
        cancel_ready.clear(); cancel_release.clear()
        for key in '/cancel\r': reader._handle_char(key)
        assert cancel_ready.wait(2)
        started=time.monotonic(); pending=controller.stop()
        assert time.monotonic()-started<1.5 and 'bytefault-terminal-log' in pending
        view.close(); cancel_release.set()
        for thread in controller._threads: thread.join(1)
        assert view.state.log_lines==[] and view.state.log_search_matches==[]
        assert lease.log_lines[0]=='NEW' and lease.log_search_matches[:]==[0,2]
    finally:
        old_release.set(); cancel_release.set(); controller.stop(); view.close()


@pytest.mark.parametrize('rich',[False,True,'unavailable'])
@pytest.mark.parametrize('resumed',[False,True])
def test_callable_quit_detaches_completed_primary_with_owned_followup_alive(tmp_path,application_factory,monkeypatch,rich,resumed):
    """A real-owner trigger for both current presentation branches."""
    if rich is True: pytest.importorskip('rich')
    # The NoUi boundary test unloads UI modules. Patch the same current reader
    # class that run_terminal imports when attaching, rather than a collected one.
    from bytefault.ui.keypress import KeypressReader as CurrentKeypressReader
    from test_followup_heartbeat import collection_port,configure
    entered,release,ready=(threading.Event() for _ in range(3))
    collection_port(monkeypatch,gates=((entered,release),))
    app,traces=application_factory(monitoring=reporting_monitor(collect=True),
        service_configuration=configure(tmp_path),stream_options={'reads':(b'OK',)})
    req=literal(tmp_path)
    original_run=req.conversation.run_id
    if resumed:
        from bytefault.application import ResumeIntent
        assert app.submit(req).outcome=='completed' and entered.wait(5)
        req=app.resume(ResumeIntent(req.record_path),record_path=str(tmp_path/'continuation.bfr'))
    handles=[]; readers=[]; results=[]; errors=[]; controls=[]
    original_start,original_control=app.start,app.control
    def start(request):
        handle=original_start(request); handles.append(handle); return handle
    def control(run,command):
        result=original_control(run,command); controls.append(result); return result
    def reader_start(reader): readers.append(reader); ready.set()
    monkeypatch.setattr(app,'start',start); monkeypatch.setattr(app,'control',control)
    monkeypatch.setattr(CurrentKeypressReader,'start',reader_start)
    monkeypatch.setattr(sys,'stdin',SimpleNamespace(isatty=lambda:True))
    if rich=='unavailable':
        import builtins
        original_import=builtins.__import__
        def without_rich(name,*args,**kwargs):
            if name=='rich' or name.startswith('rich.'):
                raise ImportError('controlled missing optional Rich')
            return original_import(name,*args,**kwargs)
        monkeypatch.setattr(builtins,'__import__',without_rich)
    def call():
        try: results.append(run_terminal(app,req,{'no_ui':not rich},stream=io.StringIO()))
        except BaseException as error: errors.append(error)
    caller=threading.Thread(target=call,daemon=True); caller.start()
    fresh=None
    try:
        assert entered.wait(5) and ready.wait(2)
        primary=handles[0].wait(3)
        assert primary.outcome=='completed' and not app.status(handles[0].run_id)['active']
        assert app.status(handles[0].run_id)['followup']['pending'] and caller.is_alive()
        if rich is not True:
            readers[0]._handle_scan_code(chr(0x3E))
            readers[0]._handle_char('/')
        started=time.monotonic(); readers[0]._handle_char('q'); caller.join(.75)
        assert not caller.is_alive() and time.monotonic()-started<.9 and not errors
        assert results[0] is primary and controls[0].outcome=='rejected'
        assert app.status(handles[0].run_id)['followup']['pending'] and not release.is_set()
        assert not app.management.status()['closed'] and not app.reporting.root.closed
        assert app.read_service_records(original_run)
        fresh=ApplicationView(app,handles[0].run_id); fresh.refresh()
        if resumed:
            assert fresh.state.resume['inherited_counts']=={'completed':1}
            assert fresh.state.total_bytes_sent==fresh.state.progress['attempts']==0
        release.set(); await_followup(app); fresh.refresh()
        assert any(finding.get('reports') for finding in fresh.state.crash_records)
        assert all(finding['run_id']==original_run for finding in fresh.state.crash_records)
        assert any(record.kind=='report_outcome' for record in app.read_service_records(original_run))
        assert not app.management.status()['closed'] and not app.reporting.root.closed
        assert [item[1] for trace,_,_ in traces for item in trace if item[0]=='offer']==[b'S',bytes.fromhex('0005585900ff5a')]
    finally:
        release.set(); caller.join(5)
        if fresh: fresh.close()
        app.management.wait(5); app.close()


def test_dashboard_progress_history_help_and_v4_exchange(tmp_path,application_factory,monkeypatch):
    from rich.console import Console
    from bytefault.ui.rich_renderables import build_dashboard,build_log_screen,build_progress_bars,_format_entry_v4
    from bytefault.ui.state import ViewState
    monkeypatch.setattr('bytefault.ui.rich_renderables.shutil.get_terminal_size',
        lambda *args:SimpleNamespace(columns=100,lines=30))
    def shown(renderable):
        output=io.StringIO()
        Console(file=output,width=100,height=30,color_system=None).print(renderable)
        return output.getvalue()

    st=ViewState(protocol='raw',host='offline.invalid',port=1234)
    st.progress={'case_limit':None,'prepared_cases':3,'selected_cases':2,'omitted_cases':1,
        'fuzz_tests':2,'attempts':2,'setup_attempts':0}
    st.current_iteration=3
    footer=shown(build_progress_bars(st))
    assert '███' in footer and 'total unknown' in footer
    assert 'prepared=3 selected=2 omitted=1 tests=2' in footer
    st.progress['case_limit']=10
    bounded=shown(build_progress_bars(st))
    assert 'Case limit 3/10' in bounded and 'ETA --:--:--' in bounded
    assert '30.0%' in bounded  # A declared preparation bound, not a selected-test total.
    st.progress['case_limit']=None
    dashboard=shown(build_dashboard(st))
    assert 'Waiting' in dashboard and '███' in dashboard
    assert '─' in dashboard[dashboard.index('Waiting'):dashboard.index('███')]
    st.active_screen='log'; st.show_help=True; st.log_file='sentinel-log-path'
    help_text=shown(build_log_screen(st))
    assert 'BYTEFAULT HELP' in help_text and 'sentinel-log-path' not in help_text
    assert 'LINE 1-' not in help_text and 'FOLLOW' not in help_text

    app,_=application_factory(stream_options={'reads':(b'OK',)})
    req=literal(tmp_path); app.submit(req)
    view=ApplicationView(app,req.conversation.run_id,request=req)
    view.refresh()
    selected=next(entry for entry in view.state.recent_tests if entry.entry_type=='test')
    assert [(direction,action) for direction,action,_ in selected.conversation_log]==[
        ('->','S'),('<-','S')]
    detail=_format_entry_v4(selected,100).plain
    assert detail.count('Offered A')==1 and 'Offer S' in detail and 'Receive S' in detail
    assert 'Receive A' not in detail and '<- A' not in detail
    view.state.verbosity_level=4
    history=shown(build_dashboard(view.state))
    assert 'offered=7 accepted=7' not in history and history.count('meaning=uninterpreted')==1
    view.close(); app.close()


def test_rates_exclude_paused_month(application_factory):
    app,_=application_factory()
    view=ApplicationView(app,'unused')
    st=view.state; st.progress={'attempts':0}
    view._sample_rates(st,0)
    st.total_bytes_sent=3600; st.total_bytes_received=1800; st.progress['attempts']=360
    st.paused=True; view._sample_rates(st,3600)
    rates=(st.tx_bytes_per_second,st.rx_bytes_per_second,st.tests_per_second)
    assert rates==(1.0,.5,.1)
    month=30*24*3600
    view._sample_rates(st,3600+month)
    assert (st.tx_bytes_per_second,st.rx_bytes_per_second,st.tests_per_second)==rates
    st.paused=False; view._sample_rates(st,3600+month)
    st.total_bytes_sent=7200; st.total_bytes_received=3600; st.progress['attempts']=720
    view._sample_rates(st,7200+month)
    assert (st.tx_bytes_per_second,st.rx_bytes_per_second,st.tests_per_second)==rates
    view.close(); app.close()


@pytest.mark.parametrize('query', ('', 'needle'))
def test_log_search_before_index_and_after_append(tmp_path, query):
    path = tmp_path / 'search.log'
    path.write_text('needle first\nother\n', encoding='utf-8')
    view = ApplicationView(SimpleNamespace(), 'fixture', options={'log_file': str(path)})
    try:
        state = view.state
        state.log_search_query = query
        state.log_search_matches = [99]
        state.log_search_index = 99
        view.search_matches()
        assert state.log_search_matches == [] and state.log_search_index == 0
        state.log_search_query = 'Needle'
        view.refresh_log(80)
        assert list(state.log_search_matches) == [0]
        matches = state.log_search_matches
        with path.open('a', encoding='utf-8') as stream:
            stream.write('another needle\n')
        view.refresh_log(80)
        assert list(state.log_search_matches) == [0, 2] and list(matches) == [0]
        state.log_search_query = 'absent'
        state.log_search_index = 1
        view.search_matches()
        assert not state.log_search_matches and state.log_search_index == 0
    finally:
        view.close()


def test_framed_log_compact_rows_exact_search_and_append(tmp_path):
    from bytefault.core.storage import LocalRecordStore,reopen_records
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'growing.actions.bfr'; store=LocalRecordStore(path)
    for number in range(80):
        store.append('action_result',{'run_id':'run','case_id':str(number),
            'conversation_id':'conversation','case_number':number},
            {'payload':b'\xde\xad\xbe\xef'+b'X'*1024})
    rows=LogRows(path,72)
    try:
        original=rows.snapshot()
        assert len(original)<80*6  # Bounded display rows despite full binary evidence.
        matches=original.matches('deadbeef')
        assert len(matches)==80 and matches[0]==0
        assert not any('deadbeef' in line for line in original[:])
        exact=original.detail(matches[0],64)
        location=exact.row_at_offset(exact.text.index('deadbeef'))
        assert 'deadbeef' in ''.join(exact[location:location+2])
        source_before=path.read_bytes()
        store.append('action_result',{'run_id':'run','case_id':'80',
            'conversation_id':'conversation','case_number':80},{'payload':b'\xca\xfe\xba\xbe'})
        assert rows.extend(path)
        current=rows.snapshot()
        assert len(current)>len(original) and len(original)<len(current)
        assert current.matches('cafebabe')[:]==[len(original)]
        assert not original.matches('cafebabe')
        assert original[-1]==current[len(original)-1]
        assert path.read_bytes().startswith(source_before)
        assert len(reopen_records(path).records)==81
    finally:
        store.close(); rows.close()


def test_large_framed_append_reuses_rows_and_scans_new_matches(tmp_path,monkeypatch):
    import statistics
    from bytefault.ui import log_view
    from bytefault.logging import ActionLog
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'large.actions.bfr'
    log=ActionLog.open(path,owner='run')
    for number in range(50):
        log('summary',{'case':number},{'payload':'X'*(1024*1024),'marker':'ordinary'})
    assert 50*1024*1024<=path.stat().st_size<51*1024*1024
    progress=lambda:log.append_progress()
    rows=LogRows(path,80,append_progress=progress)
    app=SimpleNamespace(action_log_progress=lambda run_id,selected:
        log.append_progress() if str(path)==str(selected) else None)
    view=ApplicationView(app,'fixture',options={'log_file':str(path)})
    try:
        before=rows.snapshot()
        assert len(before)<=150 and before.logical_count==50
        assert rows._trusted_progress is None
        assert rows.source_current(path)
        assert rows._trusted_progress is not None
        matches=before.matches('append-only')
        stable=matches.snapshot()
        view.state.log_lines=before
        view.state.log_search_query='append-only'
        view.state.log_search_matches=stable
        view._log_stamp=before.source_stamp
        view._log_match_query='append-only'
        prefix_checks=[]; search_scans=[]
        timings={'extend':[],'index':[],'decode':[],'matches':[]}
        original,original_matches=LogRows._prefix_matches,LogRows.matches
        original_extend,original_index,original_decode=(LogRows.extend,LogRows._index,
            log_view.reopen_records)
        def timed(kind,operation,*args,**kwargs):
            started=time.monotonic()
            try: return operation(*args,**kwargs)
            finally: timings[kind].append(time.monotonic()-started)
        def observed(self,*args,**kwargs):
            prefix_checks.append(1)
            return original(self,*args,**kwargs)
        def observed_matches(self,query,**kwargs):
            search_scans.append((query,kwargs.get('logical_start',0),kwargs.get('result') is not None))
            return timed('matches',original_matches,self,query,**kwargs)
        monkeypatch.setattr(LogRows,'_prefix_matches',observed)
        monkeypatch.setattr(LogRows,'matches',observed_matches)
        monkeypatch.setattr(LogRows,'extend',lambda self,*args,**kwargs:
            timed('extend',original_extend,self,*args,**kwargs))
        monkeypatch.setattr(LogRows,'_index',lambda self,*args,**kwargs:
            timed('index',original_index,self,*args,**kwargs))
        monkeypatch.setattr(log_view,'reopen_records',lambda *args,**kwargs:
            timed('decode',original_decode,*args,**kwargs))
        import os
        from bytefault.ui import theme
        from bytefault.ui.rich_renderables import build_log_screen
        original_theme=theme.get_theme_name()
        reader=KeypressReader()
        reader._handle_scan_code(chr(0x3E))
        controller=TerminalController(view,reader)
        controller._log_requested_source=(view.state.log_file,80)
        revision=controller._log_revision
        try:
            with monkeypatch.context() as scoped:
                scoped.setattr('shutil.get_terminal_size',lambda *args:os.terminal_size((80,24)))
                for _ in range(6):
                    reader._handle_char('t')
                    waits=iter((False,True))
                    controller._done=SimpleNamespace(wait=lambda timeout:next(waits))
                    controller._controls()
                    view.refresh_log(80)
                    assert build_log_screen(view.state) is not None
                    assert view.state.log_lines is before
                    assert view.state.log_search_matches is stable
                    assert controller._log_revision==revision
            assert all(not values for values in timings.values())
            assert not prefix_checks and not search_scans
        finally:
            theme.apply_theme(original_theme)
        elapsed=[]
        for number in range(100):
            log('summary',{'case':50+number},
                {'payload':'append-only' if number==99 else 'ordinary','marker':number})
            started=time.monotonic(); view.refresh_log(80)
            elapsed.append(time.monotonic()-started)
        after=view.state.log_lines
        assert len(after)<=len(before)+300 and after.logical_count==150
        assert (len(stable),len(view.state.log_search_matches))==(0,1)
        assert view.state.log_search_matches[0]>=len(before)
        assert prefix_checks==[]  # Every app-owned append uses the bound writer token.
        assert search_scans==[('append-only',50+n,True) for n in range(100)]
        assert sum(elapsed)<5  # Generous control bound for 100 guarded 50 MiB-log refreshes.
        print(f'50 MiB framed log, 100 app-owned appends: {sum(elapsed):.3f}s refresh total; '
            f'{max(elapsed):.3f}s max; {len(prefix_checks)} prefix scans; '
            f'first/last 10 median {statistics.median(elapsed[:10]):.3f}/'
            f'{statistics.median(elapsed[-10:]):.3f}s; '
            f'extend/index/decode/matches totals '+
            '/'.join(f'{sum(timings[name]):.3f}s' for name in ('extend','index','decode','matches')))
    finally:
        view.close(); rows.close(); log.close()


def test_run_owned_log_progress_binds_exact_path_and_open_owner(tmp_path,application_factory):
    from pathlib import Path
    from bytefault.ui.log_view import LogRows
    app,traces=application_factory()
    req=literal(tmp_path)
    entered,release=threading.Event(),threading.Event()
    factory=app.transport_factory
    def transport(target):
        adapter=factory(target)
        stream=traces[-1][1]
        original=stream.send
        def held(data):
            result=original(data); entered.set(); assert release.wait(5)
            return result
        stream.send=held
        return adapter
    app.transport_factory=transport
    handle=app.start(req)
    path=req.log_path or req.record_path+'.actions.bfr'
    rows=None
    try:
        assert entered.wait(2)
        token=app.action_log_progress(handle.run_id,path)
        assert token is not None and token.path==str(Path(path).resolve())
        assert token.committed_end==Path(path).stat().st_size
        assert app.action_log_progress(handle.run_id,tmp_path/'other.actions.bfr') is None
        assert app.action_log_progress('unknown',path) is None
        rows=LogRows(path,80,append_progress=lambda:app.action_log_progress(handle.run_id,path))
        assert rows._trusted_progress is None
        assert rows.source_current(path)
        assert rows._trusted_progress==token
        release.set(); assert handle.wait(3) is not None
        assert app.action_log_progress(handle.run_id,path) is None
    finally:
        release.set()
        if rows is not None: rows.close()
        app.close()


@pytest.mark.parametrize('interval,duration',[(.005,1.5),(.075,1.0)])
def test_active_log_publishes_acknowledged_prefix_during_growth(
        tmp_path,monkeypatch,interval,duration):
    from bytefault.logging import ActionLog
    path=tmp_path/'active.actions.bfr'
    log=ActionLog.open(path,owner='run')
    log('summary',{}, {'marker':'initial'})
    app=SimpleNamespace(action_log_progress=lambda run,selected:
        log.append_progress() if str(selected)==str(path) else None)
    view=ApplicationView(app,'growth',options={'log_file':str(path)})
    view.refresh=lambda:None  # Isolate the real Log worker from unrelated run projection.
    controls=[]; view.control=lambda command:controls.append(command)
    reader=KeypressReader(); monkeypatch.setattr(reader,'start',lambda:None)
    reader._handle_scan_code(chr(0x3E))
    controller=TerminalController(view,reader,stream=io.StringIO(),renderer=lambda *args:'frame')
    stop=threading.Event(); written=[]; errors=[]
    def produce():
        try:
            while not stop.is_set():
                number=len(written)
                log('summary',{'ordinal':number},{'marker':'stream-marker'})
                written.append(number)
                stop.wait(interval)
        except BaseException as exc:
            errors.append(exc); stop.set()
    producer=threading.Thread(target=produce,name='guarded-log-producer')
    controller.start(SimpleNamespace(update=lambda *args,**kwargs:None))
    try:
        wait_until(lambda:view.state.log_index_ready,timeout=3)
        for key in '/stream-marker\r': reader._handle_char(key)
        wait_until(lambda:view.state.log_search_query=='stream-marker',timeout=2)
        producer.start()
        published=[]; started=time.monotonic()
        while time.monotonic()-started<duration:
            published.append((len(written),view.state.log_lines.logical_count-1,
                len(view.state.log_search_matches)))
            if time.monotonic()-started>duration/2 and not controls:
                reader._handle_char(' ')
            time.sleep(.025)
        assert producer.is_alive() and not errors
        assert any(0<count<=written for written,count,_ in published)
        advances={count for _,count,_ in published if count>0}
        assert len(advances)>=3
        assert len(written)>next(count for _,count,_ in published if count>0)
        assert controls==['pause']
        stop.set(); producer.join(3)
        assert not producer.is_alive() and not errors
        wait_until(lambda:view.state.log_lines.logical_count==len(written)+1 and
            len(view.state.log_search_matches)==len(written),timeout=3)
        assert len(view.state.log_lines)<=3*(len(written)+1)
        last=view.state.log_search_matches[-1]
        assert 'stream-marker' in view.state.log_lines.detail(last,80).text
        print(f'active Log interval={interval:.3f}s: {len(written)} acknowledged, '
            f'{len(advances)} distinct published boundaries during producer, exact final search')
    finally:
        stop.set()
        if producer.ident is not None: producer.join(3)
        controller.stop(); view.close(); log.close()


def test_direct_log_refresh_publishes_during_growth(tmp_path):
    from bytefault.logging import ActionLog
    path=tmp_path/'direct-active.actions.bfr'
    log=ActionLog.open(path,owner='run')
    log('summary',{}, {'marker':'initial'})
    app=SimpleNamespace(action_log_progress=lambda run,selected:
        log.append_progress() if str(selected)==str(path) else None)
    view=ApplicationView(app,'growth',options={'log_file':str(path)})
    view.state.log_search_query='stream-marker'
    view.refresh_log(80)
    stop=threading.Event(); written=[]; errors=[]
    def produce():
        try:
            while not stop.is_set():
                number=len(written)
                log('summary',{'ordinal':number},{'marker':'stream-marker'})
                written.append(number)
                stop.wait(.005)
        except BaseException as exc:
            errors.append(exc); stop.set()
    producer=threading.Thread(target=produce,name='guarded-direct-log-producer')
    producer.start(); published=[]; started=time.monotonic()
    try:
        while time.monotonic()-started<1.5:
            view.refresh_log(80)
            published.append((len(written),view.state.log_lines.logical_count-1,
                len(view.state.log_search_matches)))
            time.sleep(.02)
        assert producer.is_alive() and not errors
        advances={count for _,count,_ in published if count>0}
        assert len(advances)>=3 and len(written)>min(advances)
        stop.set(); producer.join(3)
        assert not producer.is_alive() and not errors
        view.refresh_log(80)
        assert view.state.log_lines.logical_count==len(written)+1
        assert len(view.state.log_search_matches)==len(written)
        assert 'stream-marker' in view.state.log_lines.detail(view.state.log_search_matches[-1],80).text
        print(f'direct active Log: {len(written)} acknowledged, '
            f'{len(advances)} distinct published boundaries during producer, exact final search')
    finally:
        stop.set(); producer.join(3)
        view.close(); log.close()


def test_owned_append_during_index_publishes_first_finite_boundary(tmp_path,monkeypatch):
    from bytefault.logging import ActionLog
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'overlap.actions.bfr'; log=ActionLog.open(path,owner='run')
    log('summary',{}, {'marker':'initial'})
    rows=LogRows(path,80,append_progress=log.append_progress)
    try:
        assert rows.source_current(path)
        retained=rows.snapshot()
        log('summary',{}, {'marker':'first-delta'})
        original=rows._index; appended=[False]
        def overlap(*args,**kwargs):
            result=original(*args,**kwargs)
            if not appended[0]:
                appended[0]=True
                log('summary',{}, {'marker':'second-delta'})
            return result
        monkeypatch.setattr(rows,'_index',overlap)
        assert rows.extend(path)
        first=rows.snapshot()
        assert first.logical_count==2 and first.source_stamp[0]<path.stat().st_size
        assert len(first.matches('first-delta'))==1 and not first.matches('second-delta')
        assert retained.logical_count==1 and not retained.matches('first-delta')
        assert rows.extend(path)
        final=rows.snapshot()
        assert final.logical_count==3 and len(final.matches('second-delta'))==1
        assert first.logical_count==2 and not first.matches('second-delta')
    finally:
        rows.close(); log.close()


def test_owned_initial_snapshot_excludes_unacknowledged_partial_tail(tmp_path):
    from dataclasses import replace
    from bytefault.core.records import Record
    from bytefault.core.storage import frame_record
    from bytefault.logging import AppendProgress
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'owned-partial.actions.bfr'
    first=frame_record(Record('one','summary',{}, {'marker':'initial'}))
    second=frame_record(Record('two','summary',{}, {'marker':'after-ack'}))
    path.write_bytes(first+second[:10])
    info=path.stat()
    token=[AppendProgress('owned-writer',str(path.resolve()),info.st_dev,info.st_ino,
        len(first),0,1,info.st_mtime_ns)]
    rows=LogRows(path,80,append_progress=lambda:token[0])
    try:
        assert rows.source_stamp[0]==len(first)
        assert rows.source_current(path)
        before=rows.snapshot()
        assert before.logical_count==1 and not before.issue and not before.matches('after-ack')
        with path.open('ab') as stream: stream.write(second[10:])
        token[0]=replace(token[0],committed_end=len(first)+len(second),
            appended_bytes=len(second),append_count=2,mtime_ns=path.stat().st_mtime_ns)
        assert rows.extend(path)
        assert rows.snapshot().logical_count==2
        assert len(rows.snapshot().matches('after-ack'))==1
        assert before.logical_count==1 and not before.matches('after-ack')
    finally:
        rows.close()


def test_unowned_rewrite_and_closed_owner_keep_exact_prefix_check(tmp_path,monkeypatch):
    from bytefault.core.records import Record
    from bytefault.core.storage import frame_record
    from bytefault.logging import ActionLog
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'rewrite.actions.bfr'
    first=frame_record(Record('one','summary',{}, {'marker':'first'}))
    second=frame_record(Record('two','summary',{}, {'marker':'second'}))
    path.write_bytes(first+second)
    rows=LogRows(path,80)
    try:
        original=rows.snapshot()
        identity=path.stat().st_ino
        with path.open('r+b') as stream:
            stream.seek(20); stream.write(b'Q')
        with path.open('ab') as stream:
            stream.write(frame_record(Record('three','summary',{}, {'marker':'later'})))
        assert path.stat().st_ino==identity
        assert not rows.extend(path)
        assert original.matches('first') and not original.matches('later')
    finally:
        rows.close()

    owned=tmp_path/'closed.actions.bfr'
    log=ActionLog.open(owned,owner='run')
    log('summary',{}, {'marker':'first'})
    rows=LogRows(owned,80,append_progress=log.append_progress)
    try:
        assert rows.source_current(owned)
        assert rows._trusted_progress is not None
        retained=rows.snapshot()
        log('summary',{}, {'marker':'cancelled-then-indexed'})
        with pytest.raises(InterruptedError):
            rows.extend(owned,cancelled=lambda:True,append_progress=log.append_progress)
        assert len(rows.snapshot())==len(retained)
        assert rows.extend(owned,append_progress=log.append_progress)
        checked=[]; original_check=LogRows._prefix_matches
        def observed(self,*args,**kwargs):
            checked.append(1)
            return original_check(self,*args,**kwargs)
        monkeypatch.setattr(LogRows,'_prefix_matches',observed)
        log.end('run')
        with owned.open('ab') as stream:
            stream.write(frame_record(Record('after-close','summary',{}, {'marker':'later'})))
        assert rows.extend(owned)
        assert checked==[1] and len(rows.snapshot().matches('later'))==1
        replacement=tmp_path/'replacement.actions.bfr'
        replacement.write_bytes(frame_record(Record('replacement','summary',{}, {'marker':'new-file'})))
        replacement.replace(owned)
        assert not rows.extend(owned)
    finally:
        rows.close(); log.close()

    prevalidated=tmp_path/'prevalidation.actions.bfr'
    log=ActionLog.open(prevalidated,owner='run')
    log('summary',{}, {'marker':'before-validation'})
    rows=LogRows(prevalidated,80,append_progress=log.append_progress)
    try:
        assert rows._trusted_progress is None
        with prevalidated.open('r+b') as stream:
            stream.seek(20); stream.write(b'Q')
        assert not rows.source_current(prevalidated)
        assert rows._trusted_progress is None
    finally:
        rows.close(); log.close()


def test_direct_refresh_discards_invalid_source_snapshot(tmp_path,monkeypatch):
    from bytefault.core.records import Record
    from bytefault.core.storage import frame_record
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'changing.actions.bfr'
    path.write_bytes(frame_record(Record('one','summary',{}, {'marker':'before'})))
    view=ApplicationView(None,'fixture',options={'log_file':str(path)})
    created=[]; original=LogRows.source_current
    def changed(self,target,**kwargs):
        created.append((self.path,self._source_path))
        with path.open('r+b') as stream:
            stream.seek(20); stream.write(b'Q')
        return original(self,target,**kwargs)
    monkeypatch.setattr(LogRows,'source_current',changed)
    try:
        view.refresh_log(80)
        assert not view.state.log_index_ready and not view.state.log_lines
        assert created and all(not cache.exists() for paths in created for cache in paths)
    finally:
        view.close()


def test_snapshot_copy_rejects_mid_copy_truncation(tmp_path,monkeypatch):
    import builtins
    from bytefault.core.records import Record
    from bytefault.core.storage import frame_record
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'truncated-while-copying.actions.bfr'
    path.write_bytes(frame_record(Record('one','summary',{}, {'payload':'X'*200000})))
    original_open=builtins.open
    class TruncatingReader:
        def __init__(self,stream): self.stream,self.truncated=stream,False
        def __enter__(self): self.stream.__enter__(); return self
        def __exit__(self,*args): return self.stream.__exit__(*args)
        def fileno(self): return self.stream.fileno()
        def read(self,size):
            chunk=self.stream.read(size)
            if chunk and not self.truncated:
                self.truncated=True
                with original_open(path,'r+b') as writer: writer.truncate(len(chunk))
            return chunk
    def opened(target,mode='r',*args,**kwargs):
        stream=original_open(target,mode,*args,**kwargs)
        return TruncatingReader(stream) if str(target)==str(path) and mode=='rb' else stream
    monkeypatch.setattr(builtins,'open',opened)
    with pytest.raises(InterruptedError,match='truncated during snapshot copy'):
        LogRows(path,80)


def test_log_extension_waits_for_complete_frame(tmp_path):
    from bytefault.core.records import Record
    from bytefault.core.storage import frame_record
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'partial.actions.bfr'
    first=frame_record(Record('first','summary',{}, {'marker':'first'}))
    second=frame_record(Record('second','summary',{}, {'marker':'late-frame'}))
    path.write_bytes(first+second[:10])
    rows=LogRows(path,72)
    try:
        before=rows.snapshot()
        assert len(before.matches('first'))==1 and not before.matches('late-frame')
        assert rows.issue and 'incomplete' in rows.issue
        with path.open('ab') as stream: stream.write(second[10:])
        with pytest.raises(InterruptedError): rows.extend(path,cancelled=lambda:True)
        assert len(rows.snapshot())==len(before)
        assert rows.extend(path)
        after=rows.snapshot()
        assert len(after.matches('late-frame'))==1 and not after.issue
        assert not before.matches('late-frame')
        path.write_bytes(b'changed-prefix'+path.read_bytes())
        assert not rows.extend(path)
    finally:
        rows.close()


def test_log_index_survives_page_exit_and_extends_after_append(tmp_path,application_factory,monkeypatch):
    from bytefault.core.storage import LocalRecordStore
    from bytefault.ui.log_view import LogRows
    path=tmp_path/'live.actions.bfr'; store=LocalRecordStore(path)
    store.append('action_result',{'run_id':'run','case_id':'1',
        'conversation_id':'conversation','case_number':1},{'payload':b'first'})
    app,_=application_factory(); req=literal(tmp_path); app.submit(req)
    view=ApplicationView(app,req.conversation.run_id,request=req); view.refresh()
    view.state.log_file=str(path)
    reader=KeypressReader(); reader._handle_scan_code(chr(0x3E))
    monkeypatch.setattr(reader,'start',lambda:None)
    monkeypatch.setattr('bytefault.ui.controller.shutil.get_terminal_size',
        lambda *args:SimpleNamespace(columns=80,lines=24))
    entered,release=threading.Event(),threading.Event()
    initial=[0]; extensions=[0]; search_scans=[]; source_checks=[]
    original_init,original_index,original_extend=LogRows.__init__,LogRows._index,LogRows.extend
    original_matches,original_source_current=LogRows.matches,LogRows.source_current
    def counted_init(self,*args,**kwargs):
        initial[0]+=1
        return original_init(self,*args,**kwargs)
    def held_index(self,*args,**kwargs):
        if not entered.is_set():
            entered.set(); assert release.wait(5)
        return original_index(self,*args,**kwargs)
    def counted_extend(self,*args,**kwargs):
        extensions[0]+=1
        return original_extend(self,*args,**kwargs)
    def counted_matches(self,query,**kwargs):
        search_scans.append((query,kwargs.get('logical_start',0),kwargs.get('result') is not None))
        return original_matches(self,query,**kwargs)
    def counted_source_current(self,*args,**kwargs):
        source_checks.append(1)
        return original_source_current(self,*args,**kwargs)
    monkeypatch.setattr(LogRows,'__init__',counted_init)
    monkeypatch.setattr(LogRows,'_index',held_index)
    monkeypatch.setattr(LogRows,'extend',counted_extend)
    monkeypatch.setattr(LogRows,'matches',counted_matches)
    monkeypatch.setattr(LogRows,'source_current',counted_source_current)
    controller=TerminalController(view,reader,stream=io.StringIO(),renderer=lambda *args:'frame')
    controller.start(SimpleNamespace(update=lambda *args,**kwargs:None))
    try:
        assert entered.wait(2)
        started=time.monotonic(); reader._handle_scan_code(chr(0x3C))
        wait_until(lambda:view.state.active_screen=='dashboard',timeout=.4)
        assert time.monotonic()-started<.5
        release.set()
        wait_until(lambda:view.state.log_index_ready,timeout=3)
        before=len(view.state.log_lines)
        reader._handle_scan_code(chr(0x3E))
        wait_until(lambda:view.state.active_screen=='log',timeout=.4)
        for key in '/action_result\r': reader._handle_char(key)
        wait_until(lambda:len(view.state.log_search_matches)==1)
        old_matches=view.state.log_search_matches
        checks_before=len(source_checks)
        reader._handle_scan_code(chr(0x3C))
        wait_until(lambda:view.state.active_screen=='dashboard',timeout=.4)
        store.append('action_result',{'run_id':'run','case_id':'2',
            'conversation_id':'conversation','case_number':2},{'payload':b'first second','marker':'second'})
        wait_until(lambda:len(view.state.log_lines)>before,timeout=3)
        wait_until(lambda:len(view.state.log_search_matches)==2,timeout=3)
        assert len(old_matches)==1 and search_scans[-1]==('action_result',1,True)
        assert len(source_checks)==checks_before
        reader._handle_scan_code(chr(0x3E))
        wait_until(lambda:view.state.active_screen=='log',timeout=.4)
        assert initial==[1] and extensions[0]>=1
        reader._handle_scan_code(chr(0x47))
        wait_until(lambda:view.state.log_scroll_offset==0,timeout=.4)
        assert view.state.log_lines.matches('second')[:]==[before]
        for key in '/second\r': reader._handle_char(key)
        wait_until(lambda:len(view.state.log_search_matches)==1 and view.state.log_match_in_record)
        reader._handle_char('d')
        wait_until(lambda:view.state.log_detail_rows is not None,timeout=.4)
        detail=view.state.log_detail_rows
        offset=view.state.log_detail_scroll_offset
        assert 'second' in ''.join(detail[offset:offset+5])
        reader._handle_char('d')
        wait_until(lambda:view.state.log_detail_rows is None,timeout=.4)
    finally:
        release.set(); controller.stop(); view.close(); store.close(); app.close()
