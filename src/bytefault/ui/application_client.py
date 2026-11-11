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

"""Read-only, bounded terminal projection of application events and records.

No Rich dependency. Missing optional events refresh from acknowledged history;
view detachment never owns run, service, heartbeat or required-log lifetime.
"""
from collections import deque
from collections.abc import Mapping
from dataclasses import fields
import json
from pathlib import Path
import textwrap
import time

from bytefault.core.records import encode_value
from bytefault.core.storage import reopen_records, MAGIC
from bytefault.ui.state import ViewState, RingBufferEntry


def value(obj, name, default=None):
    return obj.get(name, default) if isinstance(obj, Mapping) else getattr(obj, name, default)


def readable_log(path, width=120, *, mapping=False):
    """Decode required BFR or ordinary text without opening a writer.

    Wrap exact hex so vertical log navigation can reach every byte. Reader issues
    remain visible; a partial live frame is never misread as ordinary text.
    """
    if not path:
        return (['(no log file specified)'],'',[],[]) if mapping else (['(no log file specified)'],'')
    try:
        with open(path, 'rb') as stream:
            framed = stream.read(4) == MAGIC
        if framed:
            recovered = reopen_records(path)
            lines = []
            for record in recovered.records:
                lines.append(record.record_id + ' ' + record.kind)
                lines.extend(json.dumps(encode_value({'identity':record.identity,
                    'data':record.data}), ensure_ascii=True, indent=2).splitlines())
            issue = str(recovered.issue) if recovered.issue else ''
            if issue:
                lines.append('READER ' + issue)
        else:
            lines, issue = Path(path).read_text(encoding='utf-8', errors='replace').splitlines(), ''
        wrapped,offsets = [],[]
        for line in lines:
            offsets.append(len(wrapped))
            wrapped.extend(textwrap.wrap(line, max(16, width-8), replace_whitespace=False,
                drop_whitespace=False,expand_tabs=False) or [''])
        return (wrapped,issue,lines,offsets) if mapping else (wrapped,issue)
    except OSError as exc:
        result=([f'(log unavailable: {exc})'],str(exc))
        return (*result,[],[]) if mapping else result


class ApplicationView:
    def __init__(self, application, run_id, *, request=None, options=None):
        self.application, self.run_id = application, run_id
        self.request, self.options = request, dict(options or {})
        self.cursor, self.snapshot, self.detached = 0, None, False
        self.state = self._initial_state()
        self.tx_history, self.rx_history = deque(maxlen=500), deque(maxlen=500)
        self._service_offsets = {}
        self._service_generations, self._service_issue = {}, ''
        self._dropped, self._first, self._log_stamp = 0, True, None
        self._projection_failed = 0
        self._log_match_query = None
        self._record_offset = -1
        self.action_updates = deque(maxlen=200)
        self._started = time.monotonic()
        self._rate_baseline = None
        self._rate_sample_time = None
        self._rate_was_paused = False
        self._active_rate_seconds = 0.0
        self._selected_actions = ()
        self._refresh_records=None
        self._resume = None
        self._resume_pending = False
        self._resume_probe_open = request is None
        self._resume_payload = value(request, 'resume')
        if self._resume_payload is not None:
            self._start_resume()

    def _start_resume(self):
        from bytefault.ui.resume import ResumeProjection
        self._resume = ResumeProjection(self._resume_payload,self.run_id)
        self.state.resume = self._resume.snapshot()

    def _discover_resume(self,records):
        if self._resume_payload is None:
            for record in records:
                kind=value(record,'kind')
                if kind=='resume_start':
                    self._resume_pending=True
                if kind=='campaign_start':
                    self._resume_probe_open=False
                    self._resume_pending=False
                    supplied=value(record,'data').get('application_request')
                    payload=value(supplied,'resume')
                    if payload is not None:
                        self._resume_payload=payload
                        self._start_resume()
                        break

    def _initial_state(self):
        st = ViewState(run_id=self.run_id)
        st.verbosity_level = min(4, self.options.get('verbose',0))
        if self.options.get('debug'):
            st.verbosity_level = max(3,st.verbosity_level)
        st.hidden_fields = list(self.options.get('hide_field') or ())
        st.test_banner = self.options.get('test_banner',True)
        st.cmd_args = ' '.join(self.options.get('argv',()))
        if self.request is not None:
            st.host, st.port = self.request.transport.host,self.request.transport.port
            st.protocol = self.request.conversation.plan.declaration_id
            st.log_file = self.request.log_path or self.request.record_path+'.actions.bfr'
        else:
            st.log_file = self.options.get('log_file','') or ''
        st.start_time = time.time()
        return st

    def _reset(self):
        old, self.state = self.state, self._initial_state()
        for name in ('verbosity_level','rain_enabled','show_help','active_screen','hidden_fields',
                'log_scroll_offset','log_search_query','log_search_input','log_search_active',
                'log_search_matches','log_search_index','log_search_pending','log_search_issue',
                'log_detail_rows','log_detail_scroll_offset','log_match_in_record',
                'log_file','log_lines','log_issue','log_index_ready','log_index_pending',
                'degraded','control_outcome','theme_name'):
            setattr(self.state,name,getattr(old,name))
        self.state.projection_resets = old.projection_resets+1
        self.tx_history.clear(); self.rx_history.clear(); self._service_offsets.clear()
        if self._resume_payload is not None:
            self._start_resume()

    def refresh(self):
        self._attached()
        self.action_updates.clear()
        batch = self.application.observe(self.run_id, after=self.cursor)
        failed=batch.get('projection_failed',0)
        reset = (self._first or batch['dropped_before']>self.cursor or
            batch['projection_dropped']!=self._dropped or failed!=self._projection_failed)
        if not reset and self._resume is None and (self._resume_probe_open or self._resume_pending):
            # Required campaign_start may be durable before its optional event is
            # projected. Probe only this current run's file and reread on growth.
            refs=self.application.record_refs(self.run_id)
            if refs:
                try:
                    reset=Path(refs[-1].path).stat().st_size>self._record_offset
                except OSError:
                    pass
        recovered = self.application.read_records(self.run_id) if reset else None
        self._refresh_records=recovered.records if recovered is not None else None
        if recovered is not None:
            self._discover_resume(recovered.records)
        had_resume=self._resume is not None
        self._discover_resume(batch['events'])
        if not had_resume and self._resume is not None and recovered is None:
            # A view may attach before campaign_start is acknowledged. Recover
            # the preceding resume_start too when its payload arrives normally.
            reset=True
            recovered=self.application.read_records(self.run_id)
        history = self.application.read_service_history(None if self._resume is not None else self.run_id)
        generations = dict(history.generations)
        changed = any(generations.get(path)!=generation
            for path,generation in self._service_generations.items())
        reset = reset or changed
        if reset:
            if not self._first:
                self._reset()
            recovered = recovered or self.application.read_records(self.run_id)
            self._refresh_records=recovered.records
            for record in recovered.records:
                if self._resume is not None:
                    self._resume.record(record.kind,record.identity,record.data,record.record_id)
                self._record(record.kind,record.identity,record.data)
            if recovered.refs:
                ref=recovered.refs[-1]
                self._record_offset=ref.offset+ref.length
            if recovered.issue and recovered.issue.kind!='not_found':
                self.state.degraded = 'record reader: '+str(recovered.issue)
        else:
            for event in batch['events']:
                ref=event.get('record_ref')
                if ref is None or ref.offset>=self._record_offset:
                    if self._resume is not None:
                        self._resume.record(event['kind'],event['identity'],event['data'],
                            ref.record_id if ref is not None else 'event:'+str(event['sequence']))
                    self._record(event['kind'],event['identity'],event['data'])
                    if ref is not None:
                        self._record_offset=ref.offset+ref.length
        self._first,self.cursor,self._dropped,self._projection_failed = (
            False,batch['cursor'],batch['projection_dropped'],failed)
        self.snapshot = batch['status']
        st,engine = self.state,self.snapshot['engine']
        st.execution_state = self.snapshot['state']
        st.run_active=self.snapshot.get('active',False)
        st.paused = bool(value(engine,'paused',False))
        st.monitoring_hold = value(engine,'monitoring_hold')
        now = time.monotonic()
        st.elapsed_seconds = now-self._started
        self._sample_rates(st,now)
        hb = self.snapshot.get('heartbeat') or {}
        st.heartbeat_enabled,st.heartbeat_alive = hb.get('enabled',False),hb.get('alive')
        st.heartbeat_error = hb.get('error') or ''
        st.followup_pending = len((self.snapshot.get('followup') or {}).get('pending',()))
        if self._resume is not None:
            st.resume=self._resume.snapshot()
            # Inherited assessments retain their original identities and bytes,
            # without replaying inherited sends into current counters/history.
            if reset:
                inherited=deque((record for record in self._resume.history if record.kind=='monitoring_decision'),maxlen=200)
                current_potential=st.crash_count
                for record in inherited:
                    self._record(record.kind,record.identity,record.data)
                st.crash_count=current_potential
        pairs={}
        for record,ref in zip(history.records,history.refs):
            identity=record.identity
            if (identity.get('run_id')==self.run_id or self._resume is not None and
                    identity.get('observation_id') in self._resume.related.get(identity.get('run_id'),())):
                pairs[(ref.path,ref.offset)]=(record,ref)
        for record,ref in (pairs[key] for key in sorted(pairs)):
            if ref.offset>=self._service_offsets.get(ref.path,-1):
                self._service_record(record.kind,record.identity,record.data)
                self._service_offsets[ref.path] = ref.offset+ref.length
        self._service_generations = generations
        # Reader issues belong to this snapshot even with no valid records.
        # Replace only our previous diagnostic, retaining unrelated degradation.
        diagnostics = [line for line in st.degraded.splitlines() if line!=self._service_issue]
        issues=dict(history.issues)
        self._service_issue = '; '.join(f'service reader {path}: {issue}' for path,issue in issues.items())
        if self._service_issue:
            diagnostics.append(self._service_issue)
        st.degraded = '\n'.join(diagnostics)
        self._refresh_records=None
        return batch

    def _sample_rates(self,st,now):
        """Use only active view time for cumulative action rates and ETA."""
        totals=(st.total_bytes_sent,st.total_bytes_received,st.progress.get('attempts',0))
        if self._rate_baseline is None:
            self._rate_baseline=totals
        elif not self._rate_was_paused:
            # The previous sample was active. Charge its interval once when a
            # pause begins, then freeze the denominator until the first resume
            # sample; polling while paused cannot dilute the displayed rates.
            self._active_rate_seconds += now-self._rate_sample_time
        self._rate_sample_time=now
        self._rate_was_paused=st.paused
        if self._active_rate_seconds>0:
            st.tx_bytes_per_second=(totals[0]-self._rate_baseline[0])/self._active_rate_seconds
            st.rx_bytes_per_second=(totals[1]-self._rate_baseline[1])/self._active_rate_seconds
            st.tests_per_second=(totals[2]-self._rate_baseline[2])/self._active_rate_seconds

    def _log_append_progress(self,path):
        reader=getattr(self.application,'action_log_progress',None)
        return reader(self.run_id,path) if reader is not None else None

    def refresh_log(self,width=120,*,cancelled=lambda:False):
        st = self.state
        try:
            info = Path(st.log_file).stat()
            stamp = (info.st_size,info.st_mtime_ns,width)
        except OSError:
            stamp = (None,width)
        if stamp!=self._log_stamp:
            from bytefault.ui.log_view import LogRows,LogRowsLease,LogMatches,LogMatchesLease
            try:
                current=st.log_lines
                previous_matches=st.log_search_matches
                rows=current.owner if isinstance(current,LogRowsLease) else current
                progress=lambda:self._log_append_progress(st.log_file)
                extended=(isinstance(rows,LogRows) and rows.source_stamp is not None and
                          rows.source_stamp[2]==width and rows.extend(st.log_file,cancelled=cancelled,
                                                                       append_progress=progress))
                if not extended:
                    rows=LogRows(st.log_file,width,cancelled=cancelled,append_progress=progress)
                    try:
                        if not rows.source_current(st.log_file,cancelled=cancelled):
                            rows.close()
                            return
                    except BaseException:
                        rows.close()
                        raise
                elif not rows.boundary_current(st.log_file,append_progress=progress,
                                               cancelled=cancelled):
                    return
            except InterruptedError:
                return
            st.log_lines,st.log_issue=rows.snapshot(),rows.issue
            st.log_index_ready=True
            self._log_stamp = rows.source_stamp or stamp
            query=st.log_search_query.casefold()
            if (extended and isinstance(current,LogRowsLease) and current.owner is rows and
                    self._log_match_query==query and
                    isinstance(previous_matches,(LogMatches,LogMatchesLease))):
                owner=(previous_matches.owner if isinstance(previous_matches,LogMatchesLease)
                       else previous_matches)
                st.log_search_matches=st.log_lines.matches(query,
                    logical_start=current.logical_count,result=owner).snapshot()
                st.log_search_index=(st.log_search_index%len(st.log_search_matches)
                    if st.log_search_matches else 0)
            else:
                self.search_matches()

    def search_matches(self):
        st = self.state
        query = st.log_search_query.casefold()
        self._log_match_query=query
        if hasattr(st.log_lines,'matches'):
            st.log_search_matches=st.log_lines.matches(query).snapshot()
            st.log_search_index=st.log_search_index%len(st.log_search_matches) if st.log_search_matches else 0
            return
        # LogRows owns searchable content; pre-index placeholders have no matches.
        st.log_search_matches=[]
        st.log_search_index=0

    def _identity(self,identity):
        for name in ('case_id','conversation_id','variant_id','stage_id','action_id','attempt_id'):
            setattr(self.state,name,identity.get(name) or '')
        if identity.get('case_number') is not None:
            self.state.current_iteration = identity['case_number']

    def _materialized(self,materialized):
        st = self.state
        st.intended,st.current_field_bytes,st.current_fields = materialized.final_bytes,{},[]
        st.final_fields_available = value(materialized,'final_fields') is not None
        for item in value(materialized,'final_fields') or ():
            field = dict(item) if isinstance(item,Mapping) else {f.name:getattr(item,f.name) for f in fields(item)}
            known = field['offset'] is not None and field['size'] is not None
            field['value'] = materialized.final_bytes[field['offset']:field['offset']+field['size']] if known else None
            st.current_fields.append(field)
            if known:
                st.current_field_bytes[field['field_id']] = field['value']
        st.packet_schema = {'final_fields':st.current_fields,'fields':[
            {'name':f['field_id'],'size':f['size']} for f in st.current_fields]}
        if not st.current_fields:
            st.current_field_bytes = {'raw':materialized.final_bytes}

    def _record(self,kind,identity,data):
        st = self.state
        if kind=='campaign_start':
            st.total_iterations=None
            st.progress={'case_limit':value(data.get('options'),'case_limit'),'prepared_cases':0,
                'selected_cases':0,'omitted_cases':0,'prepared_variants':0,'selected_variants':0,
                'fuzz_tests':0,'attempts':0,'setup_attempts':0,'setup_sends':0}
        elif kind=='campaign_case':
            st.progress['prepared_cases']+=1
            st.progress['prepared_variants']+=len(data['requests'])
            st.progress['selected_cases' if data['selected'] else 'omitted_cases']+=1
            if data['selected']:
                st.progress['selected_variants']+=len(data['requests'])
        elif kind=='campaign_directive':
            st.progress['fuzz_tests']=data['context'].executed_test_number
        elif kind in ('case_start','retry_case_resume'):
            self._identity(identity)
            request=data['request']
            self._selected_actions=request.selected_actions
            st.protocol=request.plan.declaration_id
            if not identity.get('case_number'):
                st.current_iteration=request.row.ordinal
            transport=data.get('transport')
            if transport is not None:
                st.host,st.port=transport.host,transport.port
            st.last_sent=st.last_received=st.intended=None
            st.current_field_bytes={}; st.current_fields=[]; st.packet_schema=None
            st.acceptance,st.receive_outcome,st.response_meaning='not_offered','unrequested','uninterpreted'
            st.accepted_count,st.accepted_prefix,st.current_selected=0,b'',False
            st.conversation_log=[]
        elif kind=='materialization':
            self._identity(identity); self._materialized(data['materialized'])
            st.current_selected=identity.get('action_id') in self._selected_actions
            st.last_sent=st.last_received=None
            st.acceptance,st.accepted_count='not_offered',0
            st.accepted_prefix=b''
            st.receive_outcome='pending' if value(data.get('receive'),'requested',False) else 'unrequested'
            st.response_meaning='uninterpreted'
        elif kind=='action_result':
            self._identity(identity)
            result=data['result']; transport=result.transport
            st.current_selected=result.iteration_id is not None
            name='attempts' if st.current_selected else 'setup_attempts'
            st.progress[name]=st.progress.get(name,0)+1
            if not st.current_selected and transport.acceptance!='not_offered':
                st.progress['setup_sends']=st.progress.get('setup_sends',0)+1
            self._materialized(result.materialized)
            st.last_sent=transport.offered
            st.last_received=transport.received if transport.receive_requested else None
            st.acceptance,st.accepted_count=transport.acceptance,transport.accepted_count
            st.accepted_prefix=transport.accepted_prefix
            st.receive_outcome,st.response_meaning=transport.receive_outcome,result.response_meaning
            st.total_bytes_sent+=transport.accepted_count or 0
            st.total_bytes_received+=len(transport.received)
            self.tx_history.append(float(transport.accepted_count or 0)); self.rx_history.append(float(len(transport.received)))
            preceding_exchanges=list(st.conversation_log)
            st.conversation_log.append(('->',result.action_id,transport.offered))
            if transport.receive_requested:
                st.conversation_log.append(('<-',result.action_id,transport.received))
            st.recent_tests.append(RingBufferEntry(time.time(),st.current_iteration,'test' if result.iteration_id else 'setup',
                sent_bytes=transport.offered,recv_bytes=st.last_received,sent_len=len(transport.offered),
                recv_len=len(transport.received),result={'acceptance':transport.acceptance,
                    'receive_outcome':transport.receive_outcome,'meaning':result.response_meaning,
                    'action_id':result.action_id,'stage_id':result.stage_id,'attempt_id':result.attempt_id,
                    'iteration_id':result.iteration_id,'intended':transport.prepared,
                    'accepted_prefix':transport.accepted_prefix,'accepted_count':transport.accepted_count,
                    'receive_requested':transport.receive_requested},
                field_bytes=dict(st.current_field_bytes),conversation_log=preceding_exchanges,schema=st.packet_schema))
            self.action_updates.append({name:getattr(st,name) for name in (
                'current_iteration','run_id','case_id','variant_id','action_id','attempt_id','intended',
                'last_sent','last_received','acceptance','accepted_count','accepted_prefix','stage_id','receive_outcome','response_meaning',
                'current_fields','current_field_bytes')} | {'iteration_id':result.iteration_id})
            if transport.error:
                st.recent_tests.append(RingBufferEntry(time.time(),st.current_iteration,'error',message=transport.error))
        elif kind=='monitoring_decision':
            decision=data['decision']
            for assessment in decision.assessments:
                self._finding(assessment.assessment_id,assessment.observation_id,assessment.correlation,
                    classification=assessment.classification,uncertainty=assessment.uncertainty,
                    rule=assessment.rule,reason=decision.reason)
            for action in decision.actions:
                self._finding(action.event_id,action.observation_id,action.correlation,event_id=action.event_id)
        elif kind in ('case_terminal','campaign_terminal','application_terminal'):
            st.exit_reason=value(data.get('result'),'outcome',data.get('state',''))
            if kind=='campaign_terminal':
                result=data['result']
                for name in ('prepared_cases','selected_cases','omitted_cases','fuzz_tests','attempts',
                        'setup_attempts','setup_sends','prepared_variants','selected_variants','executed_variants'):
                    st.progress[name]=getattr(result,name)
                st.progress['final']=True

    def _finding(self,key,observation_id,correlation,**updates):
        st=self.state
        record=next((r for r in st.crash_records if r['observation_id']==observation_id),None)
        if record is None:
            current=(value(correlation,'conversation_id')==st.conversation_id and
                value(correlation,'attempt_id')==st.attempt_id)
            payload,number=(st.intended,st.current_iteration) if current else self._historical_action(correlation)
            record={'key':key,'observation_id':observation_id,'timestamp':time.time(),
                'run_id':value(correlation,'run_id',self.run_id),'case_id':value(correlation,'case_id',''),
                'conversation_id':value(correlation,'conversation_id',''),'action_id':value(correlation,'action_id',''),
                'attempt_id':value(correlation,'attempt_id',''),'iteration':number,
                'classification':'unclassified','uncertainty':'unknown','reports':[],
                'payload_hex':payload.hex() if payload is not None else None,'has_core':False}
            st.crash_records.append(record); del st.crash_records[:-200]
        was_crash=any(a['classification']=='potential_crash' for a in record.get('assessments',()))
        if 'classification' in updates:
            record.setdefault('assessments',[]).append({k:updates[k] for k in ('classification','uncertainty','rule')})
        if not was_crash and updates.get('classification')=='potential_crash':
            st.crash_count+=1
        record.update(updates)
        return record

    def _historical_action(self,correlation):
        """Recover a late/evicted finding's own bytes without retaining every case."""
        payload,number=None,None
        if self._resume is not None:
            historical=self._resume.historical(correlation)
            if historical is not None: return historical
        if self._refresh_records is None:
            self._refresh_records=self.application.read_records(self.run_id).records
        for record in self._refresh_records:
            identity=record.identity
            if identity.get('conversation_id')!=value(correlation,'conversation_id'):
                continue
            if record.kind=='case_start':
                number=identity.get('case_number') or record.data['request'].row.ordinal
            if (identity.get('action_id'),identity.get('attempt_id'))!=(value(correlation,'action_id'),value(correlation,'attempt_id')):
                continue
            if record.kind=='action_result':
                payload=record.data['result'].materialized.final_bytes
            elif record.kind=='materialization':
                payload=record.data['materialized'].final_bytes
        return payload,number

    def _service_record(self,kind,identity,data):
        if kind not in ('management_pending','management_completion','management_outcome','report_outcome','collection_outcome'):
            return
        action,completion,outcome=data.get('action'),data.get('completion'),data.get('outcome')
        correlation=value(action,'correlation',value(completion,'correlation',identity))
        observation=identity.get('observation_id') or value(action,'observation_id',value(completion,'observation_id',''))
        if not observation:
            return
        record=self._finding(identity.get('event_id') or observation,observation,correlation)
        if identity.get('event_id'):
            record['event_id']=identity['event_id']
        if kind=='management_pending':
            record['followup']='pending'
        elif completion is not None:
            record[value(completion,'condition')]=value(completion,'status')
        elif kind=='collection_outcome':
            record['collection']=data['collection'].status
            record['has_core']=bool(data['collection'].artifacts)
        if outcome is not None:
            report=value(outcome,'report') if kind=='management_outcome' else outcome
            if report is not None:
                record['report_status']=value(report,'status')
                # Required records expose immutable snapshots; keep only plain
                # display values in state so Rich can copy a complete frame.
                cores=tuple(dict(core) for core in (value(report,'acquired_cores',()) or ()))
                record['acquired_cores']=cores
                record['acquired_core_count']=len(cores)
                record['has_core']=record['has_core'] or bool(cores)
                location=value(report,'location')
                if location and location not in record['reports']:
                    record['reports'].append(location)
                record['crash_dir']=str(Path(location).parent) if location else ''
            record['followup']='completed'

    def control(self,command):
        self._attached()
        return self.application.control(self.run_id,command)

    def _attached(self):
        if self.detached:
            raise RuntimeError('application view is detached')

    def close(self):
        self.detached=True
        self.state.log_search_matches=[]
        self.state.log_lines=[]

    detach=close
