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

"""Interrupted history -> ordinary numbered campaign input, never a sender."""
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

from bytefault.core.contracts import (CampaignIdentity, CampaignOptions, ContractError,
    MonitoringDecision, MonitoringCompletion, TransportRequest, freeze)
from bytefault.core.records import Record
from bytefault.core.provenance import pack
from bytefault.core.storage import reopen_records
from bytefault.fuzzers.inputs import contract_from_record, request_from_record, request_to_data
from bytefault.fuzzers.saved_cases import prepare_case
from bytefault.fuzzers.continuation import ContinuationGate


@dataclass(frozen=True)
class ResumeInspection:
    run_id: str
    cases: tuple
    recovery_issue: object
    continuation: Mapping
    preparation_issue: object = None


def _origin(request):
    value = request.original_request.get('resume', {})
    return value if isinstance(value, Mapping) else {}


def _canonical(request):
    while True:
        saved = request.original_request.get('saved_case', {})
        resume = _origin(request)
        if 'original_input' in resume:
            request = resume['original_input']
        elif isinstance(saved, Mapping) and 'original_request' in saved:
            request = saved['original_request']
        else:
            return request
        if isinstance(request, Mapping): request = request_from_record(request)


def _reproducible(configuration):
    configuration = configuration or {}
    random_specs = [s.get('options', {}) for s in configuration.get('sources', ())
        if s['kind'] in ('random', 'sweep', 'mutate')]
    random_specs += [t.get('options', {}) for s in configuration.get('sets', ())
        for t in s.get('transforms', ()) if t['kind'] == 'mutate']
    return (all(s.get('seed') is not None or 'rng_state' in s for s in random_specs) and
        all('offset_range' not in p or p.get('offset_seed') is not None
            for p in configuration.get('positions', ())))


def _history(path):
    recovered = reopen_records(path)
    consumed = [str(Path(path).resolve())]
    if not recovered.records:
        issue = recovered.issue
        raise ContractError('resume.records', issue.kind if issue else 'missing_evidence',
                            issue.reason if issue else 'acknowledged run history required')
    current = recovered.records
    starts = [r for r in current if r.kind == 'campaign_start']
    if starts:
        start = starts[0]
        supplied = start.data.get('application_request')
        if not isinstance(supplied, Mapping):
            raise ContractError('resume.request', 'missing_evidence', 'original application request required')
        previous = supplied.get('resume')
        if previous is not None:
            root = dict(previous['root'])
            records = tuple(Record(**dict(r)) for r in previous['history']) + current
        else:
            root, records = dict(supplied), current
        if root.get('generation') is not None:
            preparation_path = str(Path(supplied['record_path'] + '.preparation.bfr').resolve())
            preparation = reopen_records(preparation_path)
            prior = root.get('retained_preparation', {})
            if (preparation.records or preparation.issue and preparation.issue.kind != 'not_found' or
                    Path(preparation_path).is_file()):
                consumed.append(preparation_path)
            if preparation.records or preparation.issue and preparation.issue.kind != 'not_found':
                root['retained_preparation'] = {'path': preparation_path,
                    'records': tuple(prior.get('records', ())) + preparation.records,
                    'references': tuple(prior.get('references', ())) + preparation.refs,
                    'replayed_paths': tuple(prior.get('replayed_paths', ())) +
                        ((preparation_path,) if previous is not None else ()),
                    'recovery_issue': preparation.issue or prior.get('recovery_issue')}
    else:
        start = next((r for r in current if r.kind == 'case_start'), None)
        if start is None:
            raise ContractError('resume.request', 'missing_evidence', 'case/campaign start required')
        root = {'conversation': start.data['request'], 'transport': start.data['transport'],
                'record_path': str(path), 'log_path': None, 'cases': (), 'generation': None,
                'options': freeze(CampaignOptions()), 'monitoring_configuration': None, 'single_case': True}
        records = current
    if len({r.record_id for r in records}) != len(records):
        raise ContractError('resume.records', 'corrupt', 'duplicate history record identities')
    original = _original_request(root, record_path=str(path) + '.unused', log_path=None)
    from bytefault.core.validation import typed
    from bytefault.fuzzers.campaign import validate_campaign
    typed(original.transport, TransportRequest, 'resume.transport')
    validate_campaign(original.options, original.conversation.plan)
    return freeze(root), records, recovered, tuple(consumed)


def _cases(records, root=None):
    """Logical keys survive new execution identities; acknowledgement order wins."""
    cases, aliases = {}, {}
    if root is not None and root.get('retained_preparation'):
        from bytefault.core.contracts import PreparedRow
        from bytefault.fuzzers.generated_inputs import _baseline, campaign_conversation
        from bytefault.fuzzers.conversation import validate_conversation
        baseline = _baseline(request_from_record(root['conversation']))
        options = contract_from_record(CampaignOptions, root['options'])
        preparation = root['retained_preparation']
        expected = {}
        for record in records:
            values = (record.data.get('requests', ()) if record.kind == 'campaign_case' else
                (record.data['request'],) if record.kind in ('case_start','retry_case_resume') else ())
            for value in values:
                request = request_from_record(value)
                expected.setdefault(_origin(request).get('logical_conversation_id', request.conversation_id),
                                    _canonical(request))
        invalid_replay = set()
        for value, reference in zip(preparation['records'], preparation['references']):
            record = Record(**dict(value))
            if record.kind != 'prepared_row': continue
            number = record.data['ordinal']
            variant = next((v for v in options.variants if record.data['conversation_id'].endswith(':variant:' + v)), None)
            if variant is None:
                raise ContractError('resume.prepared_row', 'corrupt', 'missing declared variant association')
            row = contract_from_record(PreparedRow, record.data['row'], path='resume.prepared_row')
            request = replace(baseline, row=row, case_id=f'{baseline.case_id}:row:{number}',
                conversation_id=record.data['conversation_id'])
            request = campaign_conversation(request, baseline.run_id, number, variant,
                options.variants.index(variant)+1, len(options.variants))
            request = replace(request, original_request={**dict(request.original_request), 'generation': {
                'configuration': root['generation'], 'base_request': baseline,
                'baseline_conversation': baseline, 'preparation_path': preparation['path'],
                'prepared_row_reference': reference}})
            materials = validate_conversation(request)
            key = request.conversation_id
            replay_path = reference['path'] if isinstance(reference, Mapping) else reference.path
            if replay_path in preparation.get('replayed_paths', ()):
                prior = request_from_record(cases[key]['request']) if key in cases else expected.get(key)
                if prior is not None and request.row != _canonical(prior).row:
                    invalid_replay.add(replay_path)
                if key not in cases and (not _reproducible(root['generation']) or replay_path in invalid_replay):
                    continue
            if key in cases:
                continue  # Source replay cannot replace an older retained choice.
            aliases[key] = key
            cases[key] = {'conversation_id': key, 'case_number': number, 'variant_id': variant,
                'state': 'not_started', 'request': freeze(request),
                'intended': {m.action_id: m.final_bytes for m in materials},
                'records': (record,), 'last_record_id': record.record_id,
                'preparation_reference': reference}
    for record in records:
        requests = (record.data.get('requests', ()) if record.kind == 'campaign_case' else
                    (record.data.get('request'),) if record.kind in ('case_start', 'retry_case_resume') else ())
        for request_index, value in enumerate(requests):
            request = request_from_record(value)
            if record.kind in ('case_start', 'retry_case_resume') and any(
                    getattr(request, name) != record.identity.get(name)
                    for name in ('run_id', 'case_id', 'conversation_id')):
                raise ContractError('resume.records', 'corrupt', 'request/record identity association differs')
            origin = _origin(request)
            key = origin.get('logical_conversation_id', request.conversation_id)
            aliases[request.conversation_id] = key
            item = cases.setdefault(key, {'conversation_id': key,
                'case_number': request.campaign.case_number if request.campaign else request.row.ordinal,
                'variant_id': request.campaign.variant_id if request.campaign else 'normal',
                'state': 'not_started', 'request': value, 'intended': {}, 'records': ()})
            item['request'] = value
            mats = record.data.get('materialized', ())
            if record.kind == 'campaign_case':
                mats = mats[request_index] if request_index < len(mats) else ()
            if mats:
                item['intended'] = {m['action_id']: m['final_bytes'] for m in mats}
        key = aliases.get(record.identity.get('conversation_id'))
        if key in cases:
            item = cases[key]
            item['records'] += (record,)
            if record.kind in ('case_start', 'retry_case_resume'):
                item['state'] = 'uncertain'
            elif record.kind == 'case_terminal':
                item['state'] = 'completed' if record.data['result']['outcome'] == 'completed' else 'finished'
                item['terminal'] = record.data['result']
            elif record.kind == 'materialization':
                mat = record.data['materialized']
                item['intended'][mat['action_id']] = mat['final_bytes']
            elif record.kind == 'action_result':
                mat = record.data['result']['materialized']
                item['intended'][mat['action_id']] = mat['final_bytes']
            item['last_record_id'] = record.record_id
        if record.kind == 'resume_start':
            for choice in record.data['choices']:
                if choice['disposition'] == 'skip' and choice['conversation_id'] in cases:
                    cases[choice['conversation_id']]['state'] = 'skipped'
    return cases


def retained_gate(records):
    gate = ContinuationGate()
    for record in records:
        if record.kind == 'monitoring_decision':
            decision = contract_from_record(MonitoringDecision, record.data['decision'], path='resume.hold')
            # Old histories without a deadline checkpoint keep their hold; a
            # missing clock boundary is never permission to expire it.
            gate.select(decision, now=0)
            if gate.hold is not None:
                gate.deadline = None
        elif record.kind == 'monitoring_gate':
            if gate.hold is not None and record.data['decision_id'] == gate.hold.decision_id:
                gate.deadline = record.data['deadline']
        elif record.kind == 'monitoring_completion':
            gate.complete(contract_from_record(MonitoringCompletion, record.data['completion'], path='resume.completion'))
        elif record.kind == 'monitoring_expiry_result' and record.data['applied']:
            gate.expire(record.data['decision_id'])
        elif record.kind == 'monitoring_failure':
            from bytefault.core.contracts import Observation
            observation = record.data.get('observation')
            gate.stop(cause='monitoring_failure', reason=record.data['error'], reference=
                contract_from_record(Observation, observation) if observation is not None else None)
        elif record.kind in ('campaign_directive', 'campaign_setup_directive'):
            directive = record.data['directive']
            if directive['operation'] == 'stop':
                from bytefault.core.contracts import CampaignDirective
                gate.stop(contract_from_record(CampaignDirective, directive),
                    cause='setup_directive' if record.kind=='campaign_setup_directive' else 'campaign_directive')
    return gate


def gate_data(gate):
    return freeze({'hold': gate.hold, 'satisfied': tuple(sorted(gate.satisfied, key=repr)),
        'deadline': gate.deadline, 'deadline_state': ('known' if gate.deadline is not None else
            'unknown' if gate.hold is not None and gate.hold.hold_timeout is not None else 'unconfigured'),
        'stopped': gate.stopped,
        'stop_decision': gate.stop_decision, 'stop_cause': gate.stop_cause,
        'stop_reason': gate.stop_reason, 'stop_reference': gate.stop_reference})


def inspect_resume(path):
    try:
        root, records, recovered, _ = _history(path)
        return ResumeInspection(root['conversation']['run_id'], tuple(freeze({
            k: v for k, v in item.items() if k not in ('request', 'intended', 'records')})
            for item in _cases(records, root).values()), recovered.issue, gate_data(retained_gate(records)),
            root.get('retained_preparation', {}).get('recovery_issue'))
    except (TypeError, ValueError, KeyError, AttributeError, OSError) as exc:
        if isinstance(exc, ContractError): raise
        raise ContractError('resume.records', 'malformed', str(exc)) from exc


def _original_request(root, *, record_path, log_path):
    from bytefault.application import CampaignRequest
    from bytefault.monitoring.configuration import configuration_from_data
    configuration = root.get('monitoring_configuration')
    return CampaignRequest(request_from_record(root['conversation']),
        contract_from_record(TransportRequest, root['transport']), record_path, log_path,
        contract_from_record(CampaignOptions, root.get('options', freeze(CampaignOptions()))),
        root.get('generation'), tuple(request_from_record(r) for r in root.get('cases', ())),
        configuration_from_data(configuration) if configuration is not None else None)


def prepare_resume(application, intent, *, record_path, log_path, transport):
    try:
        return _prepare_resume(application, intent, record_path=record_path, log_path=log_path, transport=transport)
    except (TypeError, ValueError, KeyError, AttributeError, OSError) as exc:
        if isinstance(exc, ContractError): raise
        raise ContractError('resume.intent', 'malformed', str(exc)) from exc


def current_input_options(request):
    """Select dependencies of this continuation before service writers attach.

    Read declared options only; never derive bytes, sample sources or search
    arbitrary history/provenance for filesystem-looking strings.
    """
    from bytefault.fuzzers.campaign import selected_case
    from bytefault.fuzzers.saved_cases import derivation_request, fresh_source_spec
    retained = request.resume
    records = tuple(Record(**dict(r)) for r in retained['history'])
    items = _cases(records, retained['root'])
    choices = {c['conversation_id']: c for c in retained['choices']}
    options = []
    generation = retained['root'].get('generation')
    known = sorted(items.values(), key=lambda i: (i['case_number'], request.options.variants.index(i['variant_id'])))
    for number in sorted({i['case_number'] for i in known}):
        if not selected_case(request.options, number): continue
        family = {i['variant_id']: i for i in known if i['case_number'] == number}
        if set(family) != set(request.options.variants):
            return (*options, generation), True
        for variant in request.options.variants:
            item = family[variant]
            choice = choices.get(item['conversation_id'])
            if (item['state'] in ('completed', 'finished', 'skipped') or
                    choice and choice['disposition'] == 'skip'):
                continue
            if item['state'] == 'uncertain' and choice is None:
                return tuple(options), False
            for step in choice['steps'] if choice else ():
                if step['choice'] != 'fresh_dynamic': continue
                recipe = derivation_request(request_from_record(item['request']))
                used = {p.contribution_id for p in recipe.row.placements + recipe.row.final_overrides
                        if p.action_id == step['action_id']}
                for contribution in recipe.row.contributions:
                    if contribution.contribution_id not in used: continue
                    options.append(fresh_source_spec(contribution).options)
                    if step['reapply_mutations']:
                        options.extend(m.options for m in contribution.mutators)
    if (retained['root'].get('single_case') or
            any(r.kind == 'campaign_terminal' and
                r.data['result'].get('execution_outcome', r.data['result']['outcome']) == 'completed' and
                not r.data['result'].get('missing_cases') for r in records) or
            any(r['kind'] == 'preparation_terminal' and r['data']['summary']['status'] in ('exhausted', 'bounded')
                for r in retained['root'].get('retained_preparation', {}).get('records', ()))):
        return tuple(options), False
    return (*options, generation), True


def _prepare_resume(application, intent, *, record_path, log_path, transport):
    from bytefault.application import ResumeIntent, ResumeChoice, ResumeRequest, SavedStepIntent
    if (not isinstance(intent, ResumeIntent) or not isinstance(intent.path, str) or not intent.path or
            not isinstance(intent.choices, tuple)):
        raise ContractError('resume.intent', 'invalid', 'typed path/choices intent required')
    root, records, recovered, consumed = _history(intent.path)
    items = _cases(records, root)
    seen = set()
    for choice in intent.choices:
        if (not isinstance(choice, ResumeChoice) or not isinstance(choice.conversation_id, str) or
                not choice.conversation_id or choice.disposition not in ('rerun', 'skip') or
                not isinstance(choice.steps, tuple) or any(not isinstance(s, SavedStepIntent) for s in choice.steps)):
            raise ContractError('resume.choices', 'invalid', 'typed rerun/skip choices required')
        if choice.conversation_id in seen:
            raise ContractError('resume.choices', 'duplicate', choice.conversation_id)
        seen.add(choice.conversation_id)
        if choice.conversation_id not in items:
            raise ContractError('resume.choices', 'unknown_case', choice.conversation_id)
        if items[choice.conversation_id]['state'] != 'uncertain':
            raise ContractError('resume.choices', 'not_uncertain', 'completed/finished/unsent work cannot receive an uncertain disposition')
        if choice.disposition == 'skip' and choice.steps:
            raise ContractError('resume.choices', 'conflicting_input', 'skip does not derive action bytes')
    run_id = str(uuid4())
    from bytefault.paths import run_path
    destination = record_path or str(run_path(run_id))
    outputs = (destination, log_path or destination + '.actions.bfr')
    protected = (intent.path, str(intent.path) + '.actions.bfr', root['record_path'],
                 root.get('log_path') or root['record_path'] + '.actions.bfr')
    for output in outputs:
        path = Path(output).resolve()
        if path.exists():
            raise ContractError('resume.destinations', 'already_exists', str(path))
        if any(path == Path(p).resolve() for p in protected):
            raise ContractError('resume.destinations', 'source_collision', str(path))
    original = _original_request(root, record_path=destination, log_path=log_path)
    # Preserve the ordinary policy configuration even when the original caller
    # supplied the application default rather than a per-request configuration.
    if original.monitoring_configuration is None:
        start = next((r for r in records if r.kind == 'campaign_start'), None)
        configuration = start.data.get('monitoring', {}).get('configuration') if start else None
        if isinstance(configuration, Mapping):
            from bytefault.monitoring.configuration import configuration_from_data
            original = replace(original, monitoring_configuration=configuration_from_data(configuration))
    base = replace(original.conversation, run_id=run_id, case_id='resume:' + run_id,
                   conversation_id='resume:' + run_id, input_files=consumed)
    request = ResumeRequest(base, original.transport if transport is None else transport, destination, log_path,
        original.options, None, (), original.monitoring_configuration,
        pack({'root': root, 'history': records, 'source_path': str(Path(intent.path).resolve()),
         'references': recovered.refs, 'recovery_issue': recovered.issue,
         'choices': intent.choices, 'continuation': gate_data(retained_gate(records))}))
    if original.generation is not None and current_input_options(request)[1]:
        preflight = application._campaign_families(replace(original,
            conversation=replace(original.conversation, input_files=base.input_files)))
        preflight.close()
    return request


def restore_continuation(engine, request):
    records = tuple(Record(**dict(r)) for r in request.resume['history'])
    gate = retained_gate(records)
    engine._record_request = request.conversation
    engine._record_context = {'run_id': request.conversation.run_id, 'campaign_id': request.conversation.run_id}
    engine._required_save('resume_start', {'source_path': request.resume['source_path'],
        'source_references': request.resume['references'], 'recovery_issue': request.resume['recovery_issue'],
        'choices': request.resume['choices'], 'continuation': gate_data(gate),
        'policy': 'uncertain_requires_explicit_rerun_or_skip'})
    engine.continuation = gate
    if gate.hold is not None:
        engine._required_save('resume_followup_pending', {'decision': gate.hold,
            'satisfied': tuple(sorted(gate.satisfied, key=repr)),
            'management_attached': getattr(engine, 'followup', None) is not None,
            'state': 'awaiting_correlated_owner_completion',
            'reason': 'retained work is not completed or re-dispatched by process restart'})


class ResumeFamilies:
    """Filter logical history before ordinary dispatch, retaining original numbers."""
    preparation = None

    def __init__(self, application, request):
        self.application, self.request = application, request
        self.records = tuple(Record(**dict(r)) for r in request.resume['history'])
        self.items = _cases(self.records, request.resume['root'])
        self.choices = {c['conversation_id']: c for c in request.resume['choices']}
        self.barrier = None
        self.closed = False
        self._cancelled = lambda: False
        self._source = None
        self._iterator = self._families()
        self.literal_items = ()
        root = request.resume['root']
        if root.get('generation') is None:
            original = _original_request(root, record_path=request.record_path, log_path=request.log_path)
            original = replace(original, conversation=replace(original.conversation,
                input_files=request.conversation.input_files))
            source = application._campaign_families(original)
            projected = []
            for value in source.literal_items:
                item = dict(value)
                if root.get('single_case'):
                    item.update(case_number=original.conversation.row.ordinal,
                        case_id=original.conversation.case_id,
                        conversation_id=original.conversation.conversation_id)
                retained = next((i for i in self.items.values() if
                    (i['case_number'], i['variant_id']) == (item['case_number'], item['variant_id'])), None)
                if retained is not None and item['state'] != 'omitted':
                    key, state = retained['conversation_id'], retained['state']
                    chosen = self.choices.get(key, {}).get('disposition')
                    item.update(logical_conversation_id=key,
                        state=('skipped' if chosen == 'skip' else
                               'unresolved' if state == 'uncertain' and chosen is None else
                               'not_started' if state == 'uncertain' else
                               retained.get('terminal', {}).get('outcome', state)))
                    if state in ('completed', 'finished'):
                        item['result'] = retained.get('terminal')
                    elif 'terminal' in retained:
                        item['previous_result'] = retained['terminal']
                projected.append(item)
            source.close()
            self.literal_items = tuple(projected)
        self.retained_numbers = {item['case_number'] for item in self.items.values()
            if item['state'] in ('completed', 'finished', 'skipped') or
               self.choices.get(item['conversation_id'], {}).get('disposition') == 'skip'}

    def __iter__(self): return self
    def __next__(self):
        if self._cancelled(): raise StopIteration
        try:
            return next(self._iterator)
        except (TypeError, ValueError, KeyError, AttributeError, OSError) as exc:
            if isinstance(exc, ContractError): raise
            raise ContractError('resume.input', 'malformed', str(exc)) from exc
    def set_cancelled(self, predicate):
        self._cancelled = predicate
        if self._source is not None: self._source.set_cancelled(predicate)
    def close(self):
        if self.closed: return
        self.closed = True
        try: self._iterator.close()
        finally:
            if self._source is not None: self._source.close()

    def _prepared(self, value, item=None):
        original = request_from_record(value)
        key = item['conversation_id'] if item else original.conversation_id
        choice = self.choices.get(key)
        if item and item['state'] == 'uncertain' and choice is None:
            self.barrier = freeze({'conversation_id': key, 'case_number': item['case_number'],
                                  'state': 'unresolved', 'last_record_id': item.get('last_record_id')})
            return None
        if item and (item['state'] in ('completed', 'finished', 'skipped') or
                     choice and choice['disposition'] == 'skip'):
            return False
        if item:
            from bytefault.application import SavedStepIntent
            steps = tuple(SavedStepIntent(**dict(s)) for s in choice['steps']) if choice else ()
            data = {'format': 'bytefault.case', 'version': 1, 'request': request_to_data(original),
                'transport': request_to_data(self.request.transport),
                'intended': {k: v.hex() for k, v in item['intended'].items()},
                'origin': request_to_data(pack({'path': self.request.resume['source_path'],
                    'records': item['records'], 'logical_conversation_id': key}))}
            prepared, _ = prepare_case(data, steps=steps)
        else:
            prepared = replace(original, case_id=str(uuid4()), conversation_id=str(uuid4()), input_files=())
            def choices(values, action_id):
                return tuple(replace(c, iteration_id=prepared.conversation_id + ':' + action_id)
                    if c.scope == 'per_test' else c for c in values)
            row = prepared.row
            locations = row.placements + row.final_overrides
            contributions = tuple(replace(c, random_choices=choices(c.random_choices,
                next(p.action_id for p in locations if p.contribution_id == c.contribution_id)))
                for c in row.contributions)
            prepared = replace(prepared, row=replace(row, contributions=contributions,
                placements=tuple(replace(p, random_choices=choices(p.random_choices, p.action_id)) for p in row.placements),
                final_overrides=tuple(replace(p, random_choices=choices(p.random_choices, p.action_id)) for p in row.final_overrides)))
        identity = original.campaign or CampaignIdentity(self.request.conversation.run_id,
                                                        original.row.ordinal)
        return replace(prepared, run_id=self.request.conversation.run_id,
            campaign=replace(identity, campaign_id=self.request.conversation.run_id),
            original_request=pack({**dict(prepared.original_request), 'resume': {
                'logical_run_id': self.request.resume['root']['conversation']['run_id'],
                'logical_case_id': _origin(original).get('logical_case_id', original.case_id),
                'logical_conversation_id': key, 'previous_identity': {
                    'run_id': original.run_id, 'case_id': original.case_id, 'conversation_id': original.conversation_id},
                'original_input': original,
                'disposition': choice['disposition'] if choice else 'unsent'}}))

    def _families(self):
        from bytefault.fuzzers.campaign import selected_case
        known = sorted(self.items.values(), key=lambda i: (i['case_number'],
            self.request.options.variants.index(i['variant_id'])))
        numbers = sorted({i['case_number'] for i in known})
        for number in numbers:
            if self._cancelled(): return
            if not selected_case(self.request.options, number): continue
            items = {i['variant_id']: i for i in known if i['case_number'] == number}
            complete = None
            if set(items) != set(self.request.options.variants):
                self._ensure_source()
                while True:
                    try:
                        complete = self._next_source()
                    except StopIteration as exc:
                        raise ContractError('resume.variants', 'missing_evidence',
                            'original complete variant family is unavailable') from exc
                    current = complete[0].campaign.case_number
                    if current >= number: break
                if current != number or self._prefix_mismatch:
                    raise ContractError('resume.variants', 'missing_evidence',
                        'remaining variant needs the original source/random sequence before any family offer')
            family = []
            for variant in self.request.options.variants:
                item = items.get(variant)
                value = item['request'] if item else freeze(next(c for c in complete if c.campaign.variant_id == variant))
                prepared = self._prepared(value, item)
                if prepared is None: return
                if prepared is not False: family.append(prepared)
            if family: yield tuple(family)
        if self.request.resume['root'].get('single_case'):
            return
        if any(r.kind == 'campaign_terminal' and
               r.data['result'].get('execution_outcome', r.data['result']['outcome']) == 'completed' and
               not r.data['result'].get('missing_cases') for r in self.records):
            return
        if any(r['kind'] == 'preparation_terminal' and
               r['data']['summary']['status'] in ('exhausted', 'bounded')
               for r in self.request.resume['root'].get('retained_preparation', {}).get('records', ())):
            return
        # Later source values need the original full construction sequence. This
        # advances local preparation only; all acknowledged work remains omitted.
        self._ensure_source()
        while True:
            try:
                family = self._next_source()
            except StopIteration:
                return
            number = family[0].campaign.case_number
            if number in numbers:
                continue
            if not selected_case(self.request.options, number): continue
            if self._prefix_mismatch:
                raise ContractError('resume.generation', 'missing_evidence',
                    'source/random sequence differs from retained prefix; later values cannot be reproduced')
            prepared = tuple(self._prepared(freeze(c)) for c in family)
            yield prepared

    def _ensure_source(self):
        if self._source is not None: return
        original = _original_request(self.request.resume['root'],
            record_path=self.request.record_path, log_path=self.request.log_path)
        original = replace(original, conversation=replace(original.conversation,
            input_files=self.request.conversation.input_files))
        self._source = self.application._campaign_families(original)
        self.preparation = self._source.preparation
        self._source.set_cancelled(self._cancelled)
        # Coincidental equality of an unseeded prefix is not evidence of its RNG
        # state. This matters only if an unknown later value/sibling is needed.
        self._prefix_mismatch = not _reproducible(original.generation)

    def _next_source(self):
        family = next(self._source)
        for candidate in family:
            item = self.items.get(candidate.conversation_id)
            if item is None: continue
            prior = _canonical(request_from_record(item['request']))
            if candidate.row != prior.row:
                self._prefix_mismatch = True
        return family
