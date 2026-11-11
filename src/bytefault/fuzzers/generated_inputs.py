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

"""Source-driven preparation, with fuzzer-owned placement and ordinary requests.

Composition/transformations stay in their owners. This module does not send,
retry, schedule or reinterpret conversations.
"""
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
import random
import threading
import sys

from bytefault.core.contracts import (ContractError, PreparedRow, Placement,
    RandomChoice, SelectionIntent, SourceInvocation, PreparedContribution, CampaignIdentity, freeze)
from bytefault.core.validation import passive, validate_request
from bytefault.core.storage import LocalRecordStore
from bytefault.core.byte_edits import materialize
from bytefault.core.records import (RecordRef, RequiredServiceSaveFailure,
    emit_recording_diagnostic)
from bytefault.fuzzers.declarations import SUPPORTED_CAPABILITIES
from bytefault.fuzzers.composer import CandidateSet, CandidateBinding, CandidateComposer, PreparationCancelled
from bytefault.generators.sources import SourceSpec, open_source
from bytefault.generators.transforms import TransformSpec


def _mapping(value, path, allowed, required=()):
    if not isinstance(value, Mapping) or set(value) - set(allowed) or set(required) - set(value):
        raise ContractError(path, 'malformed', 'expected fields ' + repr(tuple(allowed)))
    return value


def configuration(value):
    """Own immutable passive configuration; source opening remains lazy."""
    passive(value, 'generation')
    _mapping(value, 'generation', ('sources', 'sets', 'positions', 'strategy', 'datasets'),
             ('sources', 'sets', 'positions'))
    result = freeze(value)
    for group, fields, required in (
        ('sources', ('source_id', 'kind', 'options', 'reference'), ('source_id', 'kind')),
        ('sets', ('set_id', 'source_id', 'transforms', 'pool_mode'), ('set_id', 'source_id')),
        ('positions', ('position_id', 'set_id', 'operation', 'offset', 'end', 'baseline',
                       'action_ids', 'buffer_id', 'coordinate', 'offset_range', 'offset_scope', 'offset_seed', 'field_id'),
                      ('position_id', 'set_id', 'operation'))):
        if not isinstance(result[group], tuple) or not result[group]:
            raise ContractError('generation.' + group, 'required', 'nonempty ordered sequence required')
        for item in result[group]:
            _mapping(item, 'generation.' + group, fields, required)
        identity = {'sources': 'source_id', 'sets': 'set_id', 'positions': 'position_id'}[group]
        ids = [item[identity] for item in result[group]]
        if any(not isinstance(key, str) or not key for key in ids) or len(set(ids)) != len(ids):
            raise ContractError('generation.' + group, 'duplicate_identity', 'unique nonempty identities required')
        for item in result[group]:
            for key in ('source_id', 'set_id'):
                if key in item and (not isinstance(item[key], str) or not item[key]):
                    raise ContractError('generation.' + group + '.' + key, 'malformed', 'nonempty string required')
    if not isinstance(result.get('strategy', 'single'), str):
        raise ContractError('generation.strategy', 'malformed', 'strategy name required')
    source_ids = {s['source_id'] for s in result['sources']}
    set_ids = {s['set_id'] for s in result['sets']}
    if any(s['source_id'] not in source_ids for s in result['sets']):
        raise ContractError('generation.sets', 'unknown_source', 'set names missing source')
    if {p['set_id'] for p in result['positions']} != set_ids:
        raise ContractError('generation.positions', 'unknown_set', 'positions must bind every supplied set')
    for item in result['sets']:
        transforms = item.get('transforms', ())
        path = 'generation.sets.' + item['set_id'] + '.transforms'
        if not isinstance(transforms, tuple):
            raise ContractError(path, 'malformed', 'ordered transform sequence required')
        for index, transform in enumerate(transforms):
            _mapping(transform, path + '.' + str(index), ('mutator_id', 'kind', 'options'), ('mutator_id', 'kind'))
            if any(not isinstance(transform[key], str) or not transform[key] for key in ('mutator_id', 'kind')):
                raise ContractError(path + '.' + str(index), 'malformed', 'nonempty mutator identity and kind required')
            if not isinstance(transform.get('options', {}), Mapping):
                raise ContractError(path + '.' + str(index) + '.options', 'malformed', 'mapping required')
    return result


def _baseline(conversation):
    """Use an exact whole input as the baseline for generated placements."""
    intent = conversation.original_request.get('protocol_input', {})
    seed = intent.get('seed') if isinstance(intent, Mapping) else None
    row = conversation.row
    if (type(seed) is bytes and intent.get('supplied_conversation') is None and
            len(conversation.plan.actions) == 1 and row == PreparedRow('row-1', 1,
                (PreparedContribution('whole-input', seed, SourceInvocation('whole-input', 'literal')),),
                final_overrides=(Placement('whole-input', 'whole-input',
                    conversation.plan.actions[0].action_id, 'replace', 0, len(conversation.plan.actions[0].seed)),))):
        return replace(conversation, plan=replace(conversation.plan, actions=(
            replace(conversation.plan.actions[0], seed=seed),)), row=PreparedRow('baseline', 1))
    return conversation


def _baseline_actions(conversation):
    """Actual bytes/spans before generated edits, with final overrides still late.

    This is accounting, not a replacement execution plan: original source/edit
    provenance remains in the request and the engine applies it exactly once.
    Calculations follow generated edits and therefore are not evaluated here.
    """
    row = replace(conversation.row, final_overrides=())
    result = {}
    for action in conversation.plan.actions:
        prepared = materialize(action, row)
        spans = {(f.buffer_id, f.field_id): f for f in prepared.final_fields}
        fields = tuple(replace(f, offset=spans[(f.buffer_id, f.field_id)].offset,
                               size=spans[(f.buffer_id, f.field_id)].size)
                       if f.buffer_id == action.buffer_id else f for f in action.fields)
        result[action.action_id] = replace(action, seed=prepared.final_bytes, fields=fields)
    return result


def row_path(path, ordinal):
    path = Path(path)
    return str(path.with_name(path.stem + f'.row-{ordinal:06d}' + (path.suffix or '.bfr')))


def _span(position, action):
    """Resolve passive metadata for baseline accounting, not source selection."""
    name = position.get('field_id')
    if name is None:
        return position.get('offset'), len(action.seed) if position.get('end') == 'seed' else position.get('end')
    if (not isinstance(name, str) or not name or position.get('offset') is not None or
            position.get('end') is not None or position['operation'] == 'append' or
            any(key in position for key in ('offset_range', 'offset_scope', 'offset_seed'))):
        raise ContractError('generation.positions.field_id', 'ambiguous_coordinate', 'named field and raw coordinates are exclusive')
    field = next((f for f in action.fields if f.field_id == name and
                  f.buffer_id == position.get('buffer_id', 'outbound')), None)
    if field is None:
        raise ContractError('generation.positions.field_id', 'unknown_field', action.action_id + ':' + name)
    if (field.offset is None or (position['operation'] == 'replace' and field.size is None) or
            field.offset > len(action.seed) or
            (field.size is not None and field.offset + field.size > len(action.seed))):
        raise ContractError('generation.positions.field_id', 'unknown_field_location', action.action_id + ':' + name)
    return field.offset, field.offset + field.size if field.size is not None else None


def campaign_conversation(conversation, campaign_id, case_number, variant, variant_number, variant_count):
    """Apply a construction identity before any transport; retry never calls this."""
    construction = (case_number - 1) * variant_count + variant_number
    calculations = tuple(replace(c, sequence_ordinal=construction) if c.rule == 'sequence' else c
                         for c in conversation.calculations)
    if variant == 'length4':
        known = {c.action_id for c in calculations if c.rule == 'payload_length'}
        if any(a not in known for a in conversation.selected_actions):
            raise ContractError('campaign.variants', 'variant_unavailable',
                                'length4 requires a declared length calculation for each selected action')
        calculations = tuple(replace(c, override_value=4) if c.rule == 'payload_length'
            and c.action_id in conversation.selected_actions else c for c in calculations)
    identity = CampaignIdentity(campaign_id, case_number, variant, variant_number)
    return replace(conversation, run_id=campaign_id, calculations=calculations, campaign=identity)


class PreparedStream:
    """Closeable lazy preparation with bounded in-memory progress, durable facts."""
    def __init__(self, application, base, supplied, limit=None, *, campaign=None):
        application._identity(base)
        application._validate_transport(base.transport)
        if base.log_path is not None and (not isinstance(base.log_path, str) or not base.log_path):
            raise ContractError('generation.log_path', 'invalid', 'nonempty path or None required')
        if limit is not None and (type(limit) is not int or limit < 0):
            raise ContractError('generation.limit', 'invalid', 'nonnegative explicit row limit or None required')
        self.application, self.base = application, base
        self.campaign = campaign
        self.source_cases = 0
        self.configuration, self.limit = configuration(supplied), limit
        self.preparation_id = base.conversation.run_id + ':preparation'
        if not isinstance(base.record_path, str) or not base.record_path:
            raise ContractError('generation.record_path', 'required', 'required preparation evidence destination')
        self.path = base.record_path + '.preparation.bfr'
        self.state, self.reason, self.prepared_rows, self.dispositions = 'ready', '', 0, 0
        self.last_reference = None
        self.cleanup_errors = ()
        self._cancelled, self._done = threading.Event(), False
        # The execution lock owns consumer/close exclusion; cancellation stays cooperative.
        self._execution = threading.Lock()
        self._iterator = self._prepare()
        from bytefault.core.input_files import inventory
        self._input_paths, self._input_directories = inventory(files=base.conversation.input_files)
        for source in self.configuration['sources']:
            options = source.get('options', {})
            if not isinstance(options, Mapping):
                raise ContractError('generation.sources.options', 'malformed', 'source options mapping required')
            try:
                if source['kind'] == 'file' and isinstance(options.get('path'), str):
                    self._input_paths.add(Path(options['path']).resolve())
                files = options.get('seed_files', ())
                for path in files if isinstance(files, tuple) else ():
                    if isinstance(path, str):
                        self._input_paths.add(Path(path).resolve())
                if isinstance(options.get('seed_directory'), str):
                    directory = Path(options['seed_directory']).resolve()
                    self._input_directories.add(directory)
                    if directory.is_dir():
                        self._input_paths.update(p.resolve() for p in directory.iterdir() if p.is_file())
            except (OSError, ValueError) as error:
                raise ContractError('sources.' + source['source_id'], 'source_configuration', str(error)) from error
        self._check_destinations(self.path, row_path(base.record_path, 1),
            row_path(base.log_path, 1) if base.log_path else row_path(base.record_path, 1) + '.actions.bfr')

    def _check_destinations(self, *paths):
        for path in paths:
            try:
                target = Path(path)
                resolved = target.resolve()
                alias = (resolved.exists() and any(p.exists() and resolved.samefile(p) for p in self._input_paths))
                collision = (alias or resolved in self._input_paths or resolved.parent in self._input_directories or
                             target.parent.resolve() in self._input_directories)
            except (OSError, ValueError) as error:
                raise ContractError('generation.destinations', 'path_error', str(error)) from error
            if collision:
                raise ContractError('generation.destinations', 'source_collision',
                    'evidence destination aliases a source input or immediate seed-directory entry: ' + str(target))

    @property
    def summary(self):
        return freeze({'operation': 'prepare', 'preparation_id': self.preparation_id,
            'record_path': self.path, 'status': self.state, 'reason': self.reason,
            'prepared_rows': self.prepared_rows, 'source_cases': self.source_cases, 'dispositions': self.dispositions,
            'last_reference': self.last_reference, 'cleanup_errors': self.cleanup_errors})

    def __iter__(self):
        return self

    def __next__(self):
        if self._done:
            raise StopIteration
        if not self._execution.acquire(blocking=False):
            raise ContractError('generation', 'busy', 'one preparation consumer at a time')
        try:
            return next(self._iterator)
        except StopIteration:
            self._done = True
            raise
        except BaseException:
            self._done = True
            raise
        finally:
            self._execution.release()
            if self._done:
                with self.application._lock:
                    self.application._preparations.pop(self.preparation_id, None)

    def close(self):
        self._cancelled.set()
        if not self._done and self._execution.acquire(blocking=False):
            try:
                self._iterator.close()
            finally:
                self._done = True
                self._execution.release()
                if self.state == 'ready':
                    self.state = 'cancelled'
                with self.application._lock:
                    self.application._preparations.pop(self.preparation_id, None)

    def cancelled(self):
        return (self._cancelled.is_set() or self.application._closed or
                getattr(self, '_external_cancelled', lambda: False)())

    def _prepare(self):
        store, rows, sources, failed_save = None, None, [], False
        identity = {'preparation_id': self.preparation_id, 'run_id': self.base.conversation.run_id}

        def save(kind, data):
            nonlocal failed_save
            try:
                ref = store.append(kind, identity, data)
                if not isinstance(ref, RecordRef):
                    raise OSError('required preparation store returned no RecordRef acknowledgement')
                self.last_reference = ref
                return ref
            except Exception as error:
                failed_save = True
                self.state, self.reason = 'recording_failed', str(error)
                diagnostic = {'reason': str(error), 'required_record_kind': kind,
                    'identity': identity, 'original_request': self.base.conversation.original_request,
                    'application_request': self.base, 'generation_configuration': self.configuration,
                    'available_preparation_fact': data, 'last_retained_record': self.last_reference,
                    'missing_evidence': kind + ' not acknowledged; further preparation/delivery withheld'}
                raise RequiredServiceSaveFailure(diagnostic, emit_recording_diagnostic(diagnostic)) from error

        def disposition(value):
            save('source_disposition', {'disposition': value})
            self.dispositions += 1

        try:
            if self.cancelled():
                self.state = 'cancelled'
                return
            try:
                store = LocalRecordStore(self.path)
            except Exception as error:
                # Use the same independent required-evidence failure delivery.
                class FailedStore:
                    def append(self, *args):
                        raise error
                store = FailedStore()
                save('preparation_open', {'path': self.path})
            self.state = 'preparing'
            start = save('preparation_start', {'request': self.base, 'configuration': self.configuration,
                                               'limit': self.limit})
            baseline = _baseline(self.base.conversation)
            validate_request(baseline, SUPPORTED_CAPABILITIES)
            for contribution in baseline.row.contributions:
                if any(c.scope == 'per_test' for c in contribution.random_choices):
                    raise ContractError('generation.baseline', 'unrefreshable_random',
                        'put per-test source/mutator choices in generation configuration')
            if any(c.scope == 'per_test' for p in baseline.row.placements + baseline.row.final_overrides
                   for c in p.random_choices):
                raise ContractError('generation.baseline', 'unrefreshable_random',
                    'put per-test placement choices in generation configuration')
            source_specs = {s['source_id']: SourceSpec(**dict(s)) for s in self.configuration['sources']}
            sets = []
            for supplied in self.configuration['sets']:
                source = open_source(source_specs[supplied['source_id']], datasets=self.configuration.get('datasets'))
                sources.append(source)
                transforms = tuple(TransformSpec(**dict(t)) for t in supplied.get('transforms', ()))
                sets.append(CandidateSet(supplied['set_id'], source, transforms, supplied.get('pool_mode', 'fresh')))
            positions = self.configuration['positions']
            actions = _baseline_actions(baseline)
            offsets, held_offsets = {}, {}
            bindings = []
            for p in positions:
                selected = p.get('action_ids', baseline.selected_actions)
                if (not isinstance(selected, tuple) or not selected or
                        any(not isinstance(a, str) for a in selected) or len(set(selected)) != len(selected) or any(
                        a not in baseline.selected_actions for a in selected)):
                    raise ContractError('generation.positions.action_ids', 'unknown_action', 'selected action IDs required')
                operation = p['operation']
                if operation not in ('insert', 'overwrite', 'replace', 'append'):
                    raise ContractError('generation.positions.operation', 'unsupported_operation', operation)
                if p.get('buffer_id', 'outbound') != 'outbound' or p.get('coordinate', 'working') != 'working':
                    raise ContractError('generation.positions', 'unsupported_coordinate', 'working outbound bytes required')
                if 'baseline' in p and type(p['baseline']) is not bytes:
                    raise ContractError('generation.positions.baseline', 'malformed', 'exact bytes required')
                if p.get('offset_seed') is not None and type(p['offset_seed']) is not int:
                    raise ContractError('generation.positions.offset_seed', 'malformed', 'integer seed or None required')
                if p.get('field_id') is not None:
                    for action_id in selected:
                        _span(p, actions[action_id])
                elif operation == 'append':
                    if p.get('offset') is not None or p.get('end') is not None or 'offset_range' in p:
                        raise ContractError('generation.positions', 'ambiguous_coordinate', 'append has no offset/range')
                else:
                    offset = p.get('offset')
                    if type(offset) is not int or offset < 0:
                        raise ContractError('generation.positions.offset', 'invalid', 'nonnegative offset required')
                    end = p.get('end')
                    if operation == 'replace':
                        if end != 'seed' and (type(end) is not int or end < offset):
                            raise ContractError('generation.positions.end', 'invalid', 'ordered explicit replacement range required')
                    elif end is not None:
                        raise ContractError('generation.positions.end', 'ambiguous_coordinate', 'end applies only to replace')
                if 'offset_range' in p:
                    bounds = p['offset_range']
                    scope = p.get('offset_scope', 'per_test')
                    if (not isinstance(bounds, tuple) or len(bounds) != 2 or
                            any(type(n) is not int or n < 0 for n in bounds) or bounds[0] > bounds[1] or
                            scope not in ('sample_once', 'per_test') or
                            (operation == 'replace' and p['end'] != 'seed' and bounds[1] > p['end'])):
                        raise ContractError('generation.positions.offset_range', 'invalid', 'ordered start bounds and scope required')
                    offsets[p['position_id']] = random.Random(p.get('offset_seed'))
                elif 'offset_scope' in p or 'offset_seed' in p:
                    raise ContractError('generation.positions.offset_range', 'required', 'random offset options require bounds')
                # Baseline is metadata for inactive positions, never an edit.
                data = p.get('baseline')
                if data is None:
                    lo, hi = _span(p, actions[selected[0]])
                    data = (actions[selected[0]].seed[lo:hi]
                            if operation == 'replace' else b'')
                if 'baseline' in p:
                    for action_id in selected:
                        seed = actions[action_id].seed
                        lo, hi = _span(p, actions[action_id])
                        actual = (seed[lo:hi] if operation == 'replace' else
                                  seed[lo:lo + len(data)] if operation == 'overwrite' else b'')
                        if data != actual:
                            raise ContractError('generation.positions.baseline', 'conflicting_baseline',
                                                'supplied inactive baseline differs from declared seed span')
                bindings.append(CandidateBinding(p['position_id'], p['set_id'], data))
            composer = CandidateComposer(sets, bindings, self.configuration.get('strategy', 'single'),
                disposition_sink=disposition, cancelled=self.cancelled)
            rows = composer.rows()
            while not self.cancelled():
                if self.limit is not None and self.source_cases >= self.limit:
                    self.state = 'bounded'
                    break
                try:
                    row = next(rows)
                except StopIteration:
                    self.state = 'cancelled' if self.cancelled() else 'exhausted'
                    break
                ordinal = row.ordinal
                self.source_cases += 1
                variants = self.campaign.variants if self.campaign is not None else ('normal',)
                for variant_number, variant in enumerate(variants, 1):
                    output_ordinal = (ordinal - 1) * len(variants) + variant_number
                    conversation_id = f'{baseline.conversation_id}:row:{ordinal}'
                    if self.campaign is not None:
                        conversation_id += ':variant:' + variant
                    contributions = list(baseline.row.contributions)
                    placements = list(baseline.row.placements)
                    resolved_bindings, full_selections, dimensions = [], {}, []
                    for action in baseline.plan.actions:
                        if action.action_id not in baseline.selected_actions:
                            continue
                        wanted = tuple(p['position_id'] for p in positions
                                       if action.action_id in p.get('action_ids', baseline.selected_actions))
                        if not wanted:
                            continue
                        iteration = f'{conversation_id}:{action.action_id}'
                        prepared = row.resolve(iteration, wanted, context={'action_id': action.action_id})
                        before_generation = actions[action.action_id]
                        per_action_baselines = {}
                        for p in positions:
                            if p['position_id'] in wanted:
                                lo, end = _span(p, before_generation)
                                per_action_baselines[p['position_id']] = (
                                    before_generation.seed[lo:end] if p['operation'] == 'replace' else
                                    before_generation.seed[lo:lo + len(p['baseline'])]
                                    if p['operation'] == 'overwrite' and 'baseline' in p else b'')
                        prepared = replace(prepared, selection=replace(prepared.selection, bindings=tuple(
                            replace(b, baseline=per_action_baselines[b.placement_id]) for b in prepared.selection.bindings)))
                        full_selections[action.action_id] = {'selection': prepared.selection,
                            'unmodified_seed': before_generation.seed}
                        active = [b for b in prepared.selection.bindings if b.choice != 'baseline']
                        used = {b.contribution_id for b in active}
                        namespace = f'generated-action:{len(action.action_id)}:{action.action_id}:'
                        for c in prepared.contributions:
                            if c.contribution_id in used:
                                contributions.append(replace(c, contribution_id=namespace + c.contribution_id))
                        by_position = {b.placement_id: b for b in active}
                        for p in positions:
                            if p['position_id'] not in by_position:
                                continue
                            b = by_position[p['position_id']]
                            pid, cid = namespace + p['position_id'], namespace + b.contribution_id
                            offset, choices = p.get('offset'), ()
                            if p['position_id'] in offsets:
                                bounds, scope = p['offset_range'], p.get('offset_scope', 'per_test')
                                key = p['position_id']
                                if scope == 'sample_once' and key in held_offsets:
                                    offset = held_offsets[key]
                                else:
                                    offset = offsets[key].randrange(bounds[0], bounds[1] + 1)
                                    if scope == 'sample_once':
                                        held_offsets[key] = offset
                                choices = (RandomChoice(pid + ':offset', 'placement', 'offset', bounds,
                                    scope, offset, iteration if scope == 'per_test' else None),)
                            end = len(before_generation.seed) if p.get('end') == 'seed' else p.get('end')
                            placements.append(Placement(pid, cid, action.action_id, p['operation'], offset,
                                end, p.get('buffer_id', 'outbound'), p.get('coordinate', 'working'), choices,
                                p.get('field_id')))
                            resolved_bindings.append(replace(b, placement_id=pid, contribution_id=cid))
                            if b.set_id not in dimensions:
                                dimensions.append(b.set_id)
                    selection = SelectionIntent(prepared.selection.strategy, tuple(resolved_bindings),
                        tuple(key for key in composer.dimension_order if key in dimensions),
                        bounds={**dict(row.bounds), 'declared_dimension_order': composer.dimension_order,
                                'per_action_selection': full_selections},
                        exhaustion=composer.exhaustion)
                    combined = PreparedRow(row.row_id, ordinal, tuple(contributions), tuple(placements),
                        selection, baseline.row.final_overrides)
                    conv = replace(baseline, row=combined, run_id=f'{baseline.run_id}:row:{ordinal}',
                        case_id=f'{baseline.case_id}:row:{ordinal}', conversation_id=conversation_id)
                    if self.campaign is not None:
                        conv = campaign_conversation(conv, baseline.run_id, ordinal, variant, variant_number, len(variants))
                    validate_request(conv, SUPPORTED_CAPABILITIES)
                    destination = row_path(self.base.record_path, output_ordinal)
                    log_destination = row_path(self.base.log_path, output_ordinal) if self.base.log_path else None
                    self._check_destinations(destination, log_destination or destination + '.actions.bfr')
                    ref = save('prepared_row', {'row': combined, 'conversation_id': conversation_id,
                        'selected_actions': conv.selected_actions, 'ordinal': ordinal})
                    original = {**dict(conv.original_request), 'generation': {
                        'configuration': self.configuration, 'base_request': self.base.conversation,
                        'baseline_conversation': baseline, 'preparation_path': self.path,
                        'preparation_start': start, 'prepared_row_reference': ref, 'limit': self.limit}}
                    conv = replace(conv, original_request=original)
                    request = replace(self.base, conversation=conv, record_path=destination, log_path=log_destination)
                    if self.cancelled():
                        self.state = 'cancelled'
                        break
                    self.prepared_rows += 1
                    yield request
            if self.cancelled():
                self.state = 'cancelled'
        except PreparationCancelled:
            self.state = 'cancelled'
            return
        except GeneratorExit:
            self.state = 'cancelled'
            raise
        except BaseException as error:
            refusal = (ContractError('generation.preparation', 'preparation_failed',
                       type(error).__name__ + ': ' + str(error))
                       if isinstance(error, (TypeError, KeyError, OverflowError, MemoryError, OSError))
                       and not isinstance(error, (ContractError, RequiredServiceSaveFailure)) else error)
            if not failed_save:
                self.state, self.reason = 'failed', str(refusal)
                save('preparation_error', {'error': str(refusal), 'error_type': type(error).__name__,
                    'path': getattr(refusal, 'path', None), 'code': getattr(refusal, 'code', None),
                    'partial': getattr(error, 'partial', None),
                    'failed_mutator': getattr(error, 'failed_mutator', None)})
            if refusal is not error:
                raise refusal from error
            raise
        finally:
            primary = sys.exc_info()[1]
            failures = []
            for owner, resource in [('rows', rows), *((s.spec.source_id, s) for s in sources)]:
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException as error:
                        failures.append({'owner': owner, 'error': str(error), 'error_type': type(error).__name__})
            if failures:
                self.cleanup_errors = tuple(failures)
                if not failed_save:
                    self.state, self.reason = 'failed', self.reason or 'source preparation cleanup failed'
            terminal_error = None
            if store is not None:
                try:
                    if not failed_save:
                        save('preparation_terminal', {'summary': self.summary, 'store_close': 'not_yet_attempted'})
                except BaseException as error:
                    terminal_error = error
                finally:
                    if hasattr(store, 'close'):
                        try:
                            store.close()
                        except BaseException as error:
                            self.cleanup_errors += ({'owner': 'preparation_store', 'error': str(error),
                                                     'error_type': type(error).__name__},)
                            if not failed_save:
                                self.state, self.reason = 'failed', self.reason or str(error)
                            emit_recording_diagnostic({'reason': str(error), 'required_record_kind': 'preparation_close',
                                'identity': identity, 'generation_configuration': self.configuration,
                                'summary': self.summary, 'last_retained_record': self.last_reference,
                                'missing_evidence': 'preparation store close did not return; local cleanup uncertain'})
            if terminal_error is not None:
                raise terminal_error
            if self.cleanup_errors and (primary is None or isinstance(primary, GeneratorExit)):
                raise ContractError('generation.cleanup', 'cleanup_failed', repr(self.cleanup_errors))


class GeneratedOperation:
    """Lazy ordinary validation/submission; no campaign policy or result backlog."""
    def __init__(self, application, prepared, operation):
        self.application, self.prepared, self.operation = application, prepared, operation
        self.processed_rows = self.fuzz_sends = self.setup_sends = 0
        self.outcome, self.reason, self._ended = None, '', False
        self.cleanup_errors = ()

    @property
    def summary(self):
        return freeze({**dict(self.prepared.summary), 'operation': self.operation,
            'status': self.outcome if self.outcome is not None else self.prepared.state,
            'reason': self.reason if self.outcome is not None else self.prepared.reason,
            'preparation_status': self.prepared.state, 'preparation_reason': self.prepared.reason,
            'processed_rows': self.processed_rows, 'fuzz_sends': self.fuzz_sends,
            'setup_sends': self.setup_sends, 'operation_cleanup_errors': self.cleanup_errors})

    def _capture_cleanup(self, error):
        self.cleanup_errors += ({'error': str(error), 'error_type': type(error).__name__,
            'path': getattr(error, 'path', None), 'code': getattr(error, 'code', None),
            'diagnostic': getattr(error, 'diagnostic', None),
            'preparation_summary': self.prepared.summary},)

    def __iter__(self):
        return self

    def __next__(self):
        if self._ended:
            raise StopIteration
        try:
            request = next(self.prepared)
            if self.application._closed:
                self.close()
                raise StopIteration
            value = getattr(self.application, self.operation)(request)
            self.processed_rows += 1
            if self.operation == 'submit':
                self.fuzz_sends += sum(a.iteration_id is not None and a.transport.acceptance != 'not_offered'
                                       for a in value.actions)
                self.setup_sends += sum(a.iteration_id is None and a.transport.acceptance != 'not_offered'
                                        for a in value.actions)
                if value.outcome != 'completed':
                    self.outcome, self.reason, self._ended = value.outcome, value.reason, True
                    try:
                        self.prepared.close()
                    except Exception as cleanup:
                        self._capture_cleanup(cleanup)
            return value
        except StopIteration:
            self._ended = True
            raise
        except BaseException as error:
            self.outcome, self.reason = getattr(error, 'status', 'failed'), str(error)
            try:
                self.close()
            except BaseException as cleanup:
                self._capture_cleanup(cleanup)
                error.add_note('Additional generated preparation cleanup failure: ' + str(cleanup))
            raise

    def close(self):
        self._ended = True
        self.prepared.close()
