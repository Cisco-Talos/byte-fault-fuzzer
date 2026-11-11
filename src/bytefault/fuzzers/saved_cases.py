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

"""Portable case inputs prepared for the ordinary conversation executor.

No target I/O, report packaging or alternate execution path lives here.
"""
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from bytefault.core.contracts import (ContractError, TransportRequest, PreparedRow,
    PreparedContribution, SourceInvocation, Placement, SelectionIntent, ConversationRequest, freeze)
from bytefault.core.json_values import load_json
from bytefault.core.storage import reopen_records
from bytefault.core.validation import validate_request, passive
from bytefault.core.provenance import pack
from bytefault.fuzzers.declarations import SUPPORTED_CAPABILITIES
from bytefault.fuzzers.inputs import (request_to_data, request_from_data,
    value_from_data, request_from_record, contract_from_record)


def portable_case(path, record_id):
    """Select a retained case; valid prefix evidence survives a damaged tail."""
    try:
        return _portable_case(path, record_id)
    except (TypeError, ValueError, KeyError, AttributeError, OSError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError('saved_case.records', 'malformed', str(exc)) from exc


def case_history(recovered, key):
    """Flat case evidence with explicit links to earlier derived contexts.

    The journal remains authoritative. Re-embedding a context's own history and
    portable origin would recursively copy every earlier context into the next.
    Preserve its exact identity/reference, not another copy of that envelope.
    """
    names = ('run_id', 'case_id', 'conversation_id')
    records, references = [], []
    for record, reference in zip(recovered.records, recovered.refs):
        if tuple(record.identity.get(name) for name in names) != key:
            continue
        references.append(reference)
        if record.kind == 'report_context':
            records.append(freeze({'record_id': record.record_id, 'kind': record.kind,
                'identity': record.identity, 'version': record.version,
                'projection': 'reference_only', 'record_reference': reference,
                'data': {'decision_id': record.data.get('decision_id')}}))
        else:
            records.append(record)
    return tuple(records), tuple(references)


def _portable_case(path, record_id):
    recovered = reopen_records(path)
    selected = next((r for r in recovered.records if r.record_id == record_id), None)
    if selected is None:
        if recovered.issue is not None:
            raise ContractError('saved_case.records', recovered.issue.kind, recovered.issue.reason)
        raise ContractError('saved_case.record_id', 'not_found', str(record_id))
    names = ('run_id', 'case_id', 'conversation_id')
    key = tuple(selected.identity.get(n) for n in names)
    if any(not value for value in key):
        raise ContractError('saved_case.record_id', 'not_case_record', str(record_id))
    records, references = case_history(recovered, key)
    start = next((r for r in records if r.kind == 'case_start'), None)
    if start is None:
        raise ContractError('saved_case.request', 'missing_evidence', 'acknowledged case_start required')
    request = request_from_record(start.data.get('request'))
    intended = {}
    for materialized in start.data.get('materialized', ()):
        action_id, data = materialized.get('action_id'), materialized.get('final_bytes')
        if action_id in intended or type(data) is not bytes:
            raise ContractError('saved_case.materialized', 'malformed', 'unique intended action bytes required')
        intended[action_id] = data.hex()
    # A caller can select a later attempt's record, including replayed setup.
    # Retain the latest prepared bytes at that exact acknowledged boundary;
    # unattempted actions still use their case-start intended materialization.
    for record in records:
        materialized = (record.data.get('materialized') if record.kind == 'materialization' else
                        record.data.get('result', {}).get('materialized') if record.kind == 'action_result' else None)
        if materialized is not None:
            action_id, value = materialized.get('action_id'), materialized.get('final_bytes')
            if action_id not in intended or type(value) is not bytes:
                raise ContractError('saved_case.materialized', 'malformed', 'known action and exact prepared bytes required')
            intended[action_id] = value.hex()
        if record.record_id == record_id:
            break
    # Configuration and original decisions remain origin evidence. They are not
    # injected into a new executor as current Monitoring decisions or responses.
    roots = tuple(r for r in recovered.records if r.kind in ('campaign_start', 'application_start')
                  and r.identity.get('run_id') == key[0])
    return {'format': 'bytefault.case', 'version': 1,
        'request': request_to_data(request),
        'transport': request_to_data(contract_from_record(TransportRequest, start.data.get('transport'),
                                                         path='saved_case.transport')),
        'intended': intended,
        'origin': request_to_data(pack({'path': str(path), 'record_id': record_id,
            'identity': selected.identity, 'case_start': start.record_id,
            'byte_selection': 'latest_prepared_at_selected_record',
            'history_projection': 'flat_case_v1',
            'references': references, 'records': records, 'run_records': roots,
            'recovery_issue': recovered.issue}))}


def load_case(path, record_id=''):
    try:
        with Path(path).open('rb') as stream:
            prefix = stream.read(4)
        if prefix.startswith(b'BFR'):
            return portable_case(path, record_id)
        return load_json(Path(path).read_text(encoding='utf-8'), path='saved_case.input')
    except (OSError, UnicodeError) as exc:
        raise ContractError('saved_case.path', 'unavailable_input', str(exc)) from exc


class _FreshRun:
    """One saved preparation's existing source/mutator run state.

    Generated input owns one source and transformation runtime per identified
    set. Action-specific contribution IDs identify deliveries, not fresh runs.
    """
    def __init__(self):
        self.resources = ExitStack()
        self.sources, self.mutators = {}, {}
        self.needed, self.reused = {}, set()
        self.sample_number = 0

    def __enter__(self):
        self.resources.__enter__()
        return self

    def __exit__(self, *exception):
        return self.resources.__exit__(*exception)

    def configure(self, request, configuration):
        for contribution in request.row.contributions:
            key = (contribution.set_id, contribution.source.source_id)
            index = contribution.source_result.index if contribution.source_result else contribution.set_index
            self.needed.setdefault(key, set()).add(index)
        for declared in configuration.get('sets', ()):
            if declared.get('pool_mode', 'fresh') == 'reuse':
                self.reused.add(declared['set_id'])

    def candidate(self, contribution, spec, iteration, datasets):
        from bytefault.generators.sources import open_source
        key = (contribution.set_id, spec.source_id)
        if key not in self.sources:
            stream = open_source(spec, datasets=datasets)
            self.resources.callback(stream.close)
            candidates = stream.candidates()
            self.resources.callback(candidates.close)
            self.sources[key] = {'spec': spec, 'stream': stream, 'iterator': candidates,
                'index': 0, 'candidates': {}, 'used': set()}
        state = self.sources[key]
        if state['spec'] != spec:
            raise ContractError('saved_case.source.' + spec.source_id, 'conflicting_input',
                                'one identified source run requires consistent declared options')
        index = contribution.source_result.index if contribution.source_result else contribution.set_index
        try:
            while state['index'] < index:
                selected = next(state['iterator'])
                state['index'] += 1
                # Cache only indices present in this finite saved input, rather
                # than retaining every skipped source candidate.
                if state['index'] in self.needed[key]:
                    state['candidates'][state['index']] = selected
        except StopIteration as exc:
            raise ContractError('saved_case.source.' + spec.source_id, 'missing_candidate', str(index)) from exc
        candidate = state['candidates'][index]
        reuse = contribution.set_id in self.reused
        if index in state['used'] and not reuse:
            candidate = state['stream'].refresh(candidate, iteration)
        else:
            candidate = replace(candidate, random_choices=tuple(replace(c,
                iteration_id=iteration if c.scope == 'per_test' else None) for c in candidate.random_choices))
        state['used'].add(index)
        if reuse:
            candidate = replace(candidate, random_choices=tuple(replace(c,
                scope='sample_once', iteration_id=None) for c in candidate.random_choices))
        if not reuse or candidate.result.sample_id is None:
            self.sample_number += 1
            candidate = replace(candidate, result=replace(candidate.result,
                sample_id=f'{iteration}:source:{spec.source_id}:sample:{self.sample_number}'))
        if reuse:
            state['candidates'][index] = candidate
        return candidate

    def transform(self, set_id, spec, data, iteration, *, context=None):
        from bytefault.generators.transforms import MutationPipeline
        key = (set_id, spec.mutator_id)
        if key not in self.mutators:
            self.mutators[key] = (spec, MutationPipeline((spec,)))
        declared, pipeline = self.mutators[key]
        if declared != spec:
            raise ContractError('saved_case.mutators.' + spec.mutator_id, 'conflicting_input',
                                'one identified mutator run requires consistent declared options')
        return pipeline.apply(data, iteration, context=context)


def fresh_source_spec(contribution):
    """Normalize a retained source recipe without opening or sampling its port."""
    from bytefault.generators.sources import SourceSpec
    source = contribution.source
    options = dict(source.options)
    kind = options.pop('kind', None)
    if kind is None:
        kind = {'whole_file': 'file', 'line_file': 'file', 'iterator': 'iter',
                'mutation': 'mutate', 'seed_directory': 'seed'}.get(source.mode, source.mode)
    if kind == 'literal' and 'data' not in options:
        if contribution.source_result is not None:
            options['data'] = contribution.source_result.data
        elif not contribution.mutators:
            options['data'] = contribution.data
        else:
            raise ContractError('saved_case.source', 'missing_evidence', 'unmutated literal source bytes required')
    if kind == 'file':
        options.setdefault('path', source.input_reference)
        options.setdefault('source_mode', 'lines' if source.mode == 'line_file' else 'whole')
    return SourceSpec(source.source_id, kind, options, source.input_reference)


def _fresh_contribution(contribution, *, reapply, source_reference, iteration, run, datasets=None, action_id=None):
    """Invoke supported current source and transformation ports unchanged."""
    from bytefault.generators.transforms import TransformSpec
    source = contribution.source
    if source_reference is not None and source_reference not in (
            source.source_id, source.input_reference, source.options.get('path')):
        raise ContractError('saved_case.dynamic_source_reference', 'unknown_source', source_reference)
    candidate = run.candidate(contribution, fresh_source_spec(contribution), iteration, datasets)
    if not reapply:
        return replace(contribution, data=candidate.data, source=candidate.source,
            source_result=candidate.result, random_choices=candidate.random_choices,
            mutators=(), mutator_results=())
    transforms = []
    for mutation in contribution.mutators:
        opts = dict(mutation.options)
        kind = opts.pop('kind', None)
        # This is descriptive invocation metadata, not an input option.
        opts.pop('decision_mapping', None)
        opts.pop('resolved_context', None)
        if kind is None:
            raise ContractError('saved_case.mutators.' + mutation.mutator_id,
                                'unsupported_capability', 'declared current transformation kind required')
        transforms.append(TransformSpec(mutation.mutator_id, kind, opts))
    data, invocations, results, choices = candidate.data, (), (), candidate.random_choices
    for spec in transforms:
        transformed = run.transform(contribution.set_id, spec, data, iteration, context={'action_id': action_id})
        if transformed.disposition != 'accepted':
            raise ContractError('saved_case.mutators', 'excluded_input', transformed.disposition)
        data = transformed.data
        invocations += transformed.mutators
        results += transformed.results
        choices += transformed.random_choices
    return replace(contribution, data=data, source=candidate.source,
        source_result=candidate.result, mutators=invocations,
        mutator_results=results, random_choices=choices)


def prepare_case(data, *, mode='literal', steps=(), no_receive=False):
    """Return a new conversation/transport, retaining exact origin evidence."""
    try:
        with _FreshRun() as run:
            return _prepare_case(data, mode=mode, steps=steps, no_receive=no_receive, run=run)
    except (TypeError, ValueError, KeyError, AttributeError, OSError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError('saved_case.input', 'malformed', str(exc)) from exc


def derivation_request(request):
    """Resolve retained declarative intent, not a later literal execution row.

    Links are self-contained passive values in both old inline records and the
    shared provenance DAG. Immediate execution/request links remain untouched.
    """
    seen = set()
    while True:
        if id(request) in seen:
            raise ContractError('saved_case.derivation', 'cyclic_ancestry', 'request ancestry repeats')
        seen.add(id(request))
        current = request_from_record(request) if isinstance(request, Mapping) else request
        if not isinstance(current, ConversationRequest):
            raise ContractError('saved_case.derivation', 'malformed', 'retained conversation request required')
        saved = current.original_request.get('saved_case', {})
        resume = current.original_request.get('resume', {})
        if isinstance(saved, Mapping) and 'derivation_request' in saved:
            request = saved['derivation_request']
        elif isinstance(resume, Mapping) and 'original_input' in resume:
            request = resume['original_input']
        elif isinstance(saved, Mapping) and 'original_request' in saved:
            request = saved['original_request']
        else:
            return current


def _prepare_case(data, *, mode, steps, no_receive, run):
    if not isinstance(data, Mapping) or data.get('format') != 'bytefault.case':
        raise ContractError('saved_case.input', 'malformed', 'bytefault.case object required')
    if type(data.get('version')) is not int or data['version'] != 1:
        raise ContractError('saved_case.version', 'unsupported_version', repr(data.get('version')))
    if set(data) != {'format', 'version', 'request', 'transport', 'intended', 'origin'}:
        raise ContractError('saved_case.input', 'malformed', 'complete portable case members required')
    if mode not in ('literal', 'fresh_dynamic') or type(no_receive) is not bool:
        raise ContractError('saved_case.intent', 'invalid', 'literal/fresh_dynamic and boolean receive choice required')
    request = request_from_data(data['request'])
    target = value_from_data(data['transport'])
    if not isinstance(target, TransportRequest):
        raise ContractError('saved_case.transport', 'malformed', 'typed transport required')
    origin = value_from_data(data['origin'])
    passive(origin, 'saved_case.origin')
    if not isinstance(data['intended'], Mapping):
        raise ContractError('saved_case.intended', 'malformed', 'action to exact hex bytes mapping required')
    actions = {a.action_id for a in request.plan.actions}
    if set(data['intended']) - actions:
        raise ContractError('saved_case.intended', 'unknown_action', 'intended bytes name an undeclared action')
    choices = {}
    for step in steps:
        if (not isinstance(step.action_id, str) or step.action_id not in actions or
                step.choice not in ('recorded', 'fresh_dynamic') or type(step.reapply_mutations) is not bool or
                (step.dynamic_source_reference is not None and not isinstance(step.dynamic_source_reference, str))):
            raise ContractError('saved_case.steps', 'invalid', 'known outbound action and explicit supported choice required')
        if step.action_id in choices:
            raise ContractError('saved_case.steps', 'duplicate', step.action_id)
        if step.choice == 'recorded' and (step.reapply_mutations or step.dynamic_source_reference is not None):
            raise ContractError('saved_case.steps.' + step.action_id, 'conflicting_input',
                                'recorded selects exact bytes; derivation options require fresh_dynamic')
        choices[step.action_id] = step
    from bytefault.application import SavedStepIntent
    recipe = derivation_request(request)
    recipe_actions = {action.action_id: action for action in recipe.plan.actions}
    generation = recipe.original_request.get('generation', {})
    configuration = generation.get('configuration', {}) if isinstance(generation, Mapping) else {}
    if not isinstance(configuration, Mapping):
        configuration = {}
    run.configure(recipe, configuration)
    datasets = configuration.get('datasets') if isinstance(configuration, Mapping) else None
    contributions, placements, final, calculations = [], [], [], []
    resolved_steps, derivations = [], []
    run_id, case_id, conversation_id = (str(uuid4()) for _ in range(3))
    selected = set(request.selected_actions)
    fresh_actions = {}
    for action in request.plan.actions:
        choice = choices.get(action.action_id, SavedStepIntent(action.action_id,
                    'recorded' if mode == 'literal' else 'fresh_dynamic'))
        resolved_steps.append(choice)
        namespace = f'saved:{len(action.action_id)}:{action.action_id}:'
        if choice.choice == 'recorded':
            try:
                text = data['intended'][action.action_id]
                if not isinstance(text, str):
                    raise ValueError('hex string required')
                exact = bytes.fromhex(text)
            except KeyError as exc:
                raise ContractError('saved_case.intended.' + action.action_id, 'missing_evidence',
                                    'recorded intended bytes required') from exc
            except ValueError as exc:
                raise ContractError('saved_case.intended.' + action.action_id, 'malformed', str(exc)) from exc
            # Setup actions cannot carry row edits: their seeds become the exact
            # retained intended bytes. The untouched original plan stays in origin.
            if action.action_id not in selected:
                continue
            cid = namespace + 'literal'
            contributions.append(PreparedContribution(cid, exact, SourceInvocation(cid, 'literal')))
            final.append(Placement(cid, cid, action.action_id, 'replace', 0, len(action.seed)))
            continue
        if action.action_id not in recipe_actions:
            raise ContractError('saved_case.derivation.' + action.action_id, 'missing_evidence',
                                'original declared action required for fresh derivation')
        fresh_actions[action.action_id] = recipe_actions[action.action_id]
        used = tuple(p for p in recipe.row.placements + recipe.row.final_overrides
                     if p.action_id == action.action_id)
        if choice.dynamic_source_reference is not None and not used:
            raise ContractError('saved_case.steps.' + action.action_id, 'unknown_source',
                                choice.dynamic_source_reference)
        ids = {p.contribution_id for p in used}
        for contribution in recipe.row.contributions:
            if contribution.contribution_id not in ids:
                continue
            fresh = _fresh_contribution(contribution, reapply=choice.reapply_mutations,
                source_reference=choice.dynamic_source_reference,
                iteration=conversation_id + ':' + action.action_id,
                run=run, datasets=datasets, action_id=action.action_id)
            derivations.append({'action_id': action.action_id,
                'contribution_id': contribution.contribution_id,
                'source': fresh.source, 'source_result': fresh.source_result,
                'source_changed': (fresh.source_result.data != contribution.source_result.data
                    if contribution.source_result is not None else None),
                'reapply_mutations': choice.reapply_mutations,
                'mutator_results': fresh.mutator_results})
            contributions.append(replace(fresh, contribution_id=namespace + contribution.contribution_id))
        def placement(p):
            return replace(p, placement_id=namespace + p.placement_id,
                contribution_id=namespace + p.contribution_id,
                random_choices=tuple(replace(c, iteration_id=conversation_id + ':' + action.action_id)
                    if c.scope == 'per_test' else c for c in p.random_choices))
        placements.extend(placement(p) for p in recipe.row.placements if p.action_id == action.action_id)
        final.extend(placement(p) for p in recipe.row.final_overrides if p.action_id == action.action_id)
        calculations.extend(c for c in recipe.calculations if c.action_id == action.action_id)
    def prepared_action(action):
        choice = choices.get(action.action_id)
        recorded = (choice.choice == 'recorded') if choice else mode == 'literal'
        if not recorded:
            action = fresh_actions[action.action_id]
        if recorded and action.action_id not in selected:
            try:
                action = replace(action, seed=bytes.fromhex(data['intended'][action.action_id]))
            except (KeyError, TypeError, ValueError) as exc:
                raise ContractError('saved_case.intended.' + action.action_id, 'missing_evidence', str(exc)) from exc
        if no_receive and action.action_id in selected:
            action = replace(action, receive=replace(action.receive, requested=False))
        return action
    row = PreparedRow('saved-input', request.row.ordinal, tuple(contributions), tuple(placements),
                      SelectionIntent(), tuple(final))
    original = {**dict(request.original_request), 'saved_case': {
        'origin': origin, 'original_request': request, 'derivation_request': recipe, 'mode': mode,
        'steps': tuple(resolved_steps), 'fresh_derivations': tuple(derivations),
        'intended': data['intended'], 'no_receive': no_receive}}
    prepared = replace(request, plan=replace(request.plan, actions=tuple(prepared_action(a) for a in request.plan.actions)),
        row=row, calculations=tuple(calculations), repair=recipe.repair if fresh_actions else request.repair,
        run_id=run_id, case_id=case_id,
        conversation_id=conversation_id, campaign=None, input_files=(), original_request=pack(original))
    validate_request(prepared, SUPPORTED_CAPABILITIES)
    return prepared, target
