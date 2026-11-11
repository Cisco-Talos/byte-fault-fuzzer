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

"""Passive resume presentation using the accepted history classifiers.

This adapter never reads a parent path, creates inputs, or completes a gate.
Only current acknowledged records advance the prepared continuation display.
"""
from collections import Counter, OrderedDict
from collections.abc import Mapping

from bytefault.core.records import Record
from bytefault.fuzzers.resuming import _cases, retained_gate, gate_data


def get(value, name, default=None):
    return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)


def presentation(value):
    """Copy-safe bounded presentation values, never the retained history graph."""
    if isinstance(value,Mapping): return {key:presentation(item) for key,item in value.items()}
    if isinstance(value,(list,tuple)): return tuple(presentation(item) for item in value)
    return value


def gate_presentation(gate):
    """Identity/status projection, excluding historical observation payloads."""
    def identity(value):
        if value is None: return None
        names=('completion_id','observation_id','directive_id','decision_id','correlation',
            'condition','status','followup_action_id','reason')
        result={name:presentation(get(value,name)) for name in names if get(value,name) is not None}
        result['reference_type']=('completion' if get(value,'completion_id') is not None else
            'directive' if get(value,'directive_id') is not None else
            'decision' if get(value,'decision_id') is not None else 'observation')
        return result
    result={name:presentation(gate[name]) for name in ('satisfied','deadline','deadline_state','stopped','stop_cause','stop_reason')}
    hold=gate['hold']
    result['hold']=({name:presentation(get(hold,name)) for name in
        ('decision_id','observation_id','correlation','obligations','required_conditions','hold_timeout','on_expiry','on_failure')}
        if hold is not None else None)
    result['stop_decision']=identity(gate['stop_decision'])
    result['stop_reference']=identity(gate['stop_reference'])
    return result


class ResumeProjection:
    WINDOW = 12
    CASE_KINDS = frozenset(('campaign_case', 'case_start', 'retry_case_resume', 'case_terminal', 'resume_start'))
    GATE_KINDS = frozenset(('monitoring_decision', 'monitoring_gate', 'monitoring_completion',
        'monitoring_expiry_result', 'monitoring_failure', 'campaign_directive', 'campaign_setup_directive'))

    def __init__(self, payload, run_id):
        self.payload, self.run_id = payload, run_id
        self.history = tuple(Record(**dict(record)) for record in payload['history'])
        baseline = _cases(self.history, payload['root'])
        self.inherited_counts = dict(Counter(case['state'] for case in baseline.values()))
        self.inherited_total = len(baseline)
        self.cases = OrderedDict()
        # Prior terminal examples plus the work requiring an operator's attention.
        ordered = sorted(baseline.values(),key=lambda case:case['state'] in ('completed','finished'))
        self._cases_window(reversed(ordered[:self.WINDOW]))
        self.related = {}
        for record in self.history:
            if record.kind == 'monitoring_decision':
                decision = record.data['decision']
                correlation = get(decision, 'correlation')
                self.related.setdefault(get(correlation, 'run_id'), set()).add(get(decision, 'observation_id'))
        self.related.pop(run_id, None)
        self._historical = OrderedDict()
        number=None
        for record in self.history:
            if record.kind=='case_start':
                number=record.identity.get('case_number') or get(get(record.data,'request'),'row')['ordinal']
            if record.kind in ('materialization','action_result'):
                materialized=record.data['materialized'] if record.kind=='materialization' else record.data['result']['materialized']
                self._remember(record.identity,(materialized['final_bytes'],record.identity.get('case_number') or number))
        self._active = None
        gate = retained_gate(self.history)
        self._gate = gate_data(gate)
        self._gate_records = []
        if gate.hold is not None or gate.stopped:
            self._gate_records = self._compact_gate([r for r in self.history if r.kind in self.GATE_KINDS],gate)
        self._acknowledged = ()
        self._result = None
        self._state = self._snapshot()

    def _remember(self,correlation,result):
        key=tuple(get(correlation,name) for name in ('conversation_id','action_id','attempt_id'))
        self._historical.pop(key,None); self._historical[key]=result
        while len(self._historical)>200: self._historical.popitem(last=False)

    def historical(self,correlation):
        key=tuple(get(correlation,name) for name in ('conversation_id','action_id','attempt_id'))
        if key in self._historical: return self._historical[key]
        number=None; payload=None; found=False
        for record in self.history:
            if record.identity.get('conversation_id')!=key[0]: continue
            found=True
            if record.kind=='case_start': number=record.identity.get('case_number') or record.data['request']['row']['ordinal']
            if tuple(record.identity.get(name) for name in ('action_id','attempt_id'))!=key[1:]: continue
            if record.kind=='materialization': payload=record.data['materialized']['final_bytes']
            elif record.kind=='action_result': payload=record.data['result']['materialized']['final_bytes']
        if found:
            self._remember(correlation,(payload,number))
            return payload,number
        return None

    def _cases_window(self,cases):
        for case in cases:
            key=case['conversation_id']
            self.cases.pop(key,None)
            self.cases[key]=dict(conversation_id=key,case_number=case['case_number'],
                variant_id=case['variant_id'],state=case['state'],
                execution_run_id=get(case.get('request'),'run_id'),
                execution_case_id=get(case.get('request'),'case_id'),
                execution_conversation_id=get(case.get('request'),'conversation_id'))
            while len(self.cases)>self.WINDOW:
                self.cases.popitem(last=False)

    @staticmethod
    def _compact_gate(records,gate):
        """Minimize real causal records by equivalence under the core classifier.

        This also retains an earlier first stop when a later hold was selected.
        No guessed checkpoint or independent gate transition logic is involved.
        Current work is bounded by the active obligations and latched stop;
        unchanged/no-op events never enter this cache.
        """
        if gate.hold is None and not gate.stopped:
            return []
        from bytefault.core.contracts import ContractError
        target=gate_data(gate)
        retained=list(records); partitions=2
        while retained:
            size=max(1,(len(retained)+partitions-1)//partitions)
            reduced=False
            for start in range(0,len(retained),size):
                candidate=retained[:start]+retained[start+size:]
                try: same=gate_data(retained_gate(candidate))==target
                except ContractError: same=False
                if same:
                    retained=candidate; partitions=max(2,partitions-1); reduced=True; break
            if not reduced:
                if size==1: break
                partitions=min(len(retained),partitions*2)
        return retained

    def record(self, kind, identity, data, record_id):
        if kind not in self.CASE_KINDS | self.GATE_KINDS | {'campaign_terminal'}:
            return
        record=Record(record_id,kind,identity,data)
        if kind=='resume_start':
            self._acknowledged=data['choices']
            classified=_cases(self.history+(record,),self.payload['root'])
            ordered=sorted(classified.values(),key=lambda case:case['state'] in ('completed','finished'))
            self.cases.clear(); self._cases_window(reversed(ordered[:self.WINDOW]))
        elif kind in self.CASE_KINDS:
            records=(self._active,record) if kind=='case_terminal' and self._active is not None else (record,)
            self._cases_window(_cases(records).values())
            if kind in ('case_start','retry_case_resume'): self._active=record
            elif kind=='case_terminal': self._active=None
        if kind in self.GATE_KINDS:
            records=self._gate_records+[record]
            gate=retained_gate(records)
            state=gate_data(gate)
            if state!=self._gate:
                self._gate_records=self._compact_gate(records,gate)
                self._gate=state
        if kind == 'campaign_terminal':
            self._result = data['result']
        self._state=self._snapshot()

    def snapshot(self):
        return self._state

    def _snapshot(self):
        terminal = get(self._result, 'resume') or {}
        from bytefault.core.records import RecoveryIssue
        def issue(value):
            return RecoveryIssue(**dict(value)) if isinstance(value,Mapping) else value
        return presentation(dict(logical_run_id=self.payload['root']['conversation']['run_id'],
            run_id=self.run_id, source_path=self.payload['source_path'],
            inherited_counts=self.inherited_counts, inherited_total=self.inherited_total,
            cases=tuple(self.cases.values()),case_window=self.WINDOW,
            choices=self.payload['choices'], acknowledged_choices=self._acknowledged,
            recovery_issue=issue(self.payload['recovery_issue']),
            preparation_issue=issue(self.payload['root'].get('retained_preparation', {}).get('recovery_issue')),
            continuation=gate_presentation(self._gate), barrier=terminal.get('barrier'),
            outcome=get(self._result, 'outcome')))


def resume_lines(resume, *, details=True,progress=None,accepted_bytes=0):
    """One vocabulary for Plain and Rich; identities remain exact in details."""
    if not resume:
        return []
    counts = resume['inherited_counts']
    lines = ['RESUME inherited ' + ' '.join(f'{name}={counts.get(name,0)}' for name in
        ('completed','finished','not_started','uncertain','skipped'))]
    progress=progress or {}
    lines.append('NEW tests='+str(progress.get('fuzz_tests',0))+' attempts='+str(progress.get('attempts',0))+
        ' known-accepted-bytes='+str(accepted_bytes))
    lines.append('NEW execution='+resume['run_id']+' | original='+resume['logical_run_id'])
    if details:
        lines.append(f"CASE window {len(resume['cases'])}/{resume['case_window']}; inherited known={resume['inherited_total']}; full history: inspect-resume/log")
        for case in resume['cases']:
            lines.append(f"CASE {case['case_number']} variant={case['variant_id']} {case['state']} "
                f"logical={case['conversation_id']} execution={case['execution_conversation_id']}")
        for choice in resume['choices']:
            acknowledged = any(dict(item)==dict(choice) for item in resume['acknowledged_choices'])
            lines.append('CHOICE '+choice['conversation_id']+' '+choice['disposition']+
                (' acknowledged' if acknowledged else 'selected; not acknowledged'))
    else:
        lines.append('CASES '+ ' | '.join(f"{case['case_number']}/{case['variant_id']} {case['state']}"
            for case in resume['cases'][:4]) + (' | …' if len(resume['cases'])>4 else ''))
        for choice in resume['choices']:
            acknowledged = any(dict(item)==dict(choice) for item in resume['acknowledged_choices'])
            lines.append('CHOICE '+choice['disposition']+(' acknowledged' if acknowledged else ' selected; not acknowledged'))
    for name in ('recovery_issue','preparation_issue'):
        if resume[name]: lines.append('RESUME '+name+' '+str(resume[name]))
    if resume['barrier']:
        lines.append('UNRESOLVED '+str(resume['barrier']['case_number'])+' choice required: rerun or skip')
    gate = resume['continuation']
    if gate['stopped']:
        lines.append('RESUME STOPPED cause='+str(gate['stop_cause'])+' reason='+str(gate['stop_reason']))
        if details and gate['stop_reference'] is not None:
            lines.append('STOP reference='+str(gate['stop_reference']))
    hold = gate['hold']
    if hold:
        corr = get(hold,'correlation')
        lines.append('HOLD '+get(hold,'decision_id')+' deadline='+gate['deadline_state']+
            ((' '+str(gate['deadline'])) if gate['deadline'] is not None else ''))
        if details:
            lines.append('ORIGINAL run='+get(corr,'run_id')+' attempt='+get(corr,'attempt_id'))
        successes = set(gate['satisfied'])
        for obligation in get(hold,'obligations',()):
            condition, action = get(obligation,'condition'), get(obligation,'followup_action_id')
            lines.append('WAIT '+condition+' action='+str(action)+' '+
                ('succeeded' if (condition,action) in successes else 'pending external completion'))
    return lines
