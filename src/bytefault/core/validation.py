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

"""Validation of supplied values. No module discovery or execution belongs here."""
from dataclasses import fields, is_dataclass
from collections.abc import Mapping
import math
import types
from typing import Any, get_args, get_origin, get_type_hints, Union

from .contracts import (ContractError, PassivePlan, ConversationRequest, ReceiveRequest,
                        RandomChoice)


def validate_followup_action(action):
    """Validate a selected follow-up action without dispatching services."""
    from .contracts import MonitoringAction
    typed(action, MonitoringAction, 'management.action')
    passive(action, 'management.action')
    if action.kind != 'followup':
        fail('management.action.kind', 'unavailable', 'only followup actions are supported')
    if set(action.parameters) - {'collect', 'report', 'cleanup'}:
        fail('management.action.parameters', 'unsupported_field', 'collect/report/cleanup supported')
    if any(type(value) is not bool for value in action.parameters.values()):
        fail('management.action.parameters', 'invalid', 'collect/report/cleanup must be booleans')
    if action.parameters.get('cleanup') and not action.parameters.get('collect'):
        fail('management.action.parameters.cleanup', 'invalid', 'cleanup requires selected collection')
    for name in ('action_id', 'event_id', 'observation_id'):
        if not isinstance(getattr(action, name), str) or not getattr(action, name):
            fail('management.action.' + name, 'invalid_identity', 'nonempty string required')
    return action


def resolve_wait_obligations(decision):
    """Resolve declared wait conditions against the selected passive work.

    Monitoring uses this value operation to publish concrete obligations. A
    collection/report condition covers every selected enabled operation of that
    kind; a condition with no selected producer remains explicitly external.
    """
    from .contracts import MonitoringDecision, MonitoringObligation
    typed(decision, MonitoringDecision, 'monitoring.decision')
    passive(decision, 'monitoring.decision')
    unique((decision.decision_id,), 'monitoring.decision.identity')
    unique((decision.observation_id,), 'monitoring.decision.observation')
    if decision.hold_timeout is not None and (type(decision.hold_timeout) not in (int, float) or
            not math.isfinite(decision.hold_timeout) or decision.hold_timeout < 0):
        fail('monitoring.decision.hold_timeout', 'invalid', 'finite nonnegative timeout required')
    if decision.on_expiry not in ('hold', 'stop', 'advance') or decision.on_failure not in ('hold', 'stop', 'advance'):
        fail('monitoring.decision.treatment', 'invalid', 'hold, stop or advance required')
    if decision.disposition not in ('continue', 'hold', 'stop') or decision.mode not in ('awaited', 'nonblocking'):
        fail('monitoring.decision', 'invalid_decision', 'unsupported disposition/mode')
    if decision.disposition == 'hold' and (decision.mode != 'awaited' or not decision.required_conditions):
        fail('monitoring.decision', 'invalid_decision', 'hold needs explicit awaited conditions')
    if decision.disposition == 'continue' and decision.mode == 'awaited' and decision.required_conditions:
        fail('monitoring.decision', 'invalid_decision', 'pending awaited conditions require hold')
    unique(decision.required_conditions, 'monitoring.decision.conditions')
    unique([action.action_id for action in decision.actions], 'monitoring.decision.actions')
    for action in decision.actions:
        validate_followup_action(action)
        if action.observation_id != decision.observation_id or action.correlation != decision.correlation:
            fail('monitoring.decision.actions', 'correlation', 'selected work must identify the decision facts')
    obligations = []
    for condition in decision.required_conditions:
        option = {'collection': 'collect', 'report': 'report'}.get(condition)
        producers = tuple(action.action_id for action in decision.actions
                          if option is not None and action.parameters.get(option, False))
        obligations.extend(MonitoringObligation(condition, identity)
                           for identity in (producers or (None,)))
    return tuple(obligations)


def collection_blocks_required_followup(actions, conditions, *, earlier_collection=False):
    """Whether FIFO Management must finish Collection before an awaited result."""
    parameters = [getattr(action, 'parameters', action) for action in actions]
    if 'collection' in conditions and any(action.get('collect') for action in parameters):
        return True
    if 'report' not in conditions:
        return False
    report_indices = [index for index, action in enumerate(parameters)
        if action.get('report')]
    return bool(report_indices and (earlier_collection or any(
        action.get('collect') for action in parameters[:report_indices[-1] + 1])))


def validate_wait_obligations(decision):
    expected = resolve_wait_obligations(decision)
    if decision.obligations != expected:
        fail('monitoring.decision.obligations', 'unresolved_wait',
             'Monitoring must resolve every selected required action and external condition')
    return decision

def typed(value, expected, path):
    """Dataclass annotations are an admission schema, including nested records."""
    if expected is Any:
        return
    origin, args = get_origin(expected), get_args(expected)
    if origin in (Union, types.UnionType):
        for alternative in args:
            try:
                typed(value, alternative, path)
                return
            except ContractError:
                pass
        fail(path, 'malformed', f'expected {expected}')
    elif origin is tuple:
        if not isinstance(value, tuple):
            fail(path, 'malformed', 'immutable tuple required')
        if args and args[-1] is Ellipsis:
            for i, item in enumerate(value):
                typed(item, args[0], f'{path}[{i}]')
        else:
            if len(value) != len(args):
                fail(path, 'malformed', 'tuple arity mismatch')
            for i, (item, annotation) in enumerate(zip(value, args)):
                typed(item, annotation, f'{path}[{i}]')
    elif expected is float:
        if type(value) not in (int, float):
            fail(path, 'malformed', 'number required')
    elif isinstance(expected, type):
        matches = type(value) is expected if expected in (int, bool, bytes, str) else isinstance(value, expected)
        if not matches:
            fail(path, 'malformed', f'expected {expected.__name__}')


def fail(path, code, message):
    raise ContractError(path, code, message)


def passive(value, path='request'):
    from bytefault.core.provenance import is_view
    if is_view(value):
        return  # Closed checked immutable node tables contain only passive values.
    if callable(value):
        fail(path, 'executable_value', 'callbacks/classes/readers/factories are forbidden')
    if is_dataclass(value):
        hints = get_type_hints(type(value))
        for f in fields(value):
            typed(getattr(value, f.name), hints[f.name], f'{path}.{f.name}')
            passive(getattr(value, f.name), f'{path}.{f.name}')
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                fail(path, 'malformed', 'data keys must be strings')
            passive(item, f'{path}.{key}')
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            passive(item, f'{path}[{i}]')
    elif value is not None and not isinstance(value, (str, int, float, bool, bytes)):
        fail(path, 'malformed', f'not a passive value: {type(value).__name__}')
    elif isinstance(value, float) and not math.isfinite(value):
        fail(path, 'malformed', 'non-finite number')


def unique(values, path):
    if any(not isinstance(v, str) or not v for v in values):
        fail(path, 'malformed', 'identities must be nonempty strings')
    if len(set(values)) != len(values):
        fail(path, 'duplicate_identity', 'identities must be unique')


def integer(value, path, minimum=0):
    if type(value) is not int or value < minimum:
        fail(path, 'malformed', f'expected integer >= {minimum}')


def validate_plan(plan, capabilities=frozenset()):
    passive(plan, 'plan')
    if not isinstance(plan, PassivePlan):
        fail('plan', 'malformed', 'expected PassivePlan')
    if type(plan.version) is not int or plan.version != 1:
        fail('plan.version', 'unsupported_version', str(plan.version))
    unique([plan.declaration_id], 'plan.declaration_id')
    unique(list(plan.stages), 'plan.stages')
    unique([c.name for c in plan.required_capabilities], 'plan.capabilities')
    for cap in plan.required_capabilities:
        if cap.name not in capabilities:
            fail(f'plan.capabilities.{cap.name}', 'unsupported_capability', cap.name)
        if cap.parameters:
            fail(f'plan.capabilities.{cap.name}', 'unsupported_parameters', 'no parameters supported in v1')
    if not plan.actions:
        fail('plan.actions', 'malformed', 'at least one action is required')
    ids = [a.action_id for a in plan.actions]
    unique(ids, 'plan.actions')
    if plan.entry_action is not None and plan.entry_action not in ids:
        fail('plan.entry_action', 'unknown_action', str(plan.entry_action))
    for action in plan.actions:
        path = f'plan.actions.{action.action_id}'
        if action.kind != 'send':
            fail(path + '.kind', 'unsupported_capability', action.kind)
        if type(action.seed) is not bytes:
            fail(path + '.seed', 'malformed', 'exact bytes required')
        if action.stage_id and action.stage_id not in plan.stages:
            fail(path + '.stage_id', 'unknown_stage', action.stage_id)
        if action.buffer_id != 'outbound':
            fail(path + '.buffer_id', 'unsupported_buffer', action.buffer_id)
        field_keys = set()
        for location in action.fields:
            field_path = path + '.fields.' + location.field_id
            unique([location.field_id], field_path + '.field_id')
            unique([location.buffer_id], field_path + '.buffer_id')
            key = (location.buffer_id, location.field_id)
            if key in field_keys:
                fail(field_path, 'duplicate_identity', 'field identity is scoped by action and buffer')
            field_keys.add(key)
            if location.offset is not None:
                integer(location.offset, field_path + '.offset')
            if location.size is not None:
                integer(location.size, field_path + '.size')
        receive = action.receive
        if not isinstance(receive, ReceiveRequest) or type(receive.requested) is not bool:
            fail(path + '.receive', 'malformed', 'expected ReceiveRequest')
        integer(receive.cap, path + '.receive.cap', 1)
        if not isinstance(receive.deadline, (int, float)) or receive.deadline <= 0:
            fail(path + '.receive.deadline', 'malformed', 'positive deadline required')
        if receive.length_offset is not None:
            integer(receive.length_offset, path + '.receive.length_offset')
            integer(receive.length_size, path + '.receive.length_size', 1)
            if receive.length_offset + receive.length_size > receive.cap:
                fail(path + '.receive', 'malformed', 'length header exceeds cap')
        if receive.length_endian not in ('big', 'little') or receive.length_counts not in ('body', 'full', 'packet'):
            fail(path + '.receive', 'malformed', 'unsupported receive length convention')
        response_keys = []
        for location in action.response_fields:
            field_path = path + '.response_fields.' + location.field_id
            unique([location.field_id], field_path + '.field_id')
            response_keys.append(location.field_id)
            if location.offset is not None:
                integer(location.offset, field_path + '.offset')
            if location.size is not None:
                integer(location.size, field_path + '.size', 1)
        unique(response_keys, path + '.response_fields')
        selectors = {edge.field_id for edge in action.edges}
        if len(selectors) > 1:
            fail(path + '.edges', 'ambiguous_condition', 'one whole-response or declared field selector per action required')
        literals = [edge.literal for edge in action.edges]
        if len(set(literals)) != len(literals):
            fail(path + '.edges', 'ambiguous_condition', 'duplicate response literal')
        if action.edges and not receive.requested:
            fail(path + '.edges', 'contradictory_condition', 'response edges require a receive')
        for edge in action.edges:
            if type(edge.literal) is not bytes or not edge.meaning:
                fail(path + '.edges', 'malformed', 'literal bytes and declared meaning required')
            if edge.field_id is not None:
                if edge.field_id not in response_keys:
                    fail(path + '.edges.field_id', 'unknown_field', str(edge.field_id))
                location = next(f for f in action.response_fields if f.field_id == edge.field_id)
                if location.size is not None and len(edge.literal) != location.size:
                    fail(path + '.edges.literal', 'conflicting_extent', 'field literal must equal declared field size')
        for target in [edge.target for edge in action.edges] + [action.unknown_target]:
            if target is not None and target not in ids:
                fail(path + '.edges', 'unknown_action', str(target))
        if action.next_action not in (None, '__ordered__') and action.next_action not in ids:
            fail(path + '.next_action', 'unknown_action', action.next_action)
        if action.edges and action.next_action != '__ordered__':
            fail(path, 'contradictory_condition', 'conditional edges already determine continuation')
    # The executor admits finite acyclic paths only; never guesses loops.
    graph = {}
    for i, action in enumerate(plan.actions):
        graph[action.action_id] = ([e.target for e in action.edges] + [action.unknown_target]
            if action.edges else [action.next_action if action.next_action != '__ordered__'
                else (ids[i + 1] if i + 1 < len(ids) else None)])
    active, done = set(), set()
    def visit(key):
        if key in active:
            fail('plan.actions', 'unsupported_cycle', 'loop execution remains unavailable')
        if key is None or key in done:
            return
        active.add(key)
        for target in graph[key]:
            visit(target)
        active.remove(key)
        done.add(key)
    for key in ids:
        visit(key)
    return plan


def validate_random(choices, path):
    unique([c.choice_id for c in choices], path)
    keys = set()
    for choice in choices:
        if not isinstance(choice, RandomChoice) or choice.owner not in ('source', 'mutator', 'placement'):
            fail(path, 'malformed', 'random choice owner is required')
        if choice.scope not in ('sample_once', 'per_test'):
            fail(path, 'contradictory_scope', choice.scope)
        if len(choice.bounds) != 2 or any(type(n) is not int for n in choice.bounds) or choice.bounds[0] > choice.bounds[1]:
            fail(path, 'malformed', 'ordered integer bounds required')
        key = (choice.owner, choice.option)
        if key in keys:
            fail(path, 'contradictory_scope', f'duplicate random option {key}')
        keys.add(key)


def validate_request(request, capabilities=frozenset()):
    passive(request)
    if not isinstance(request, ConversationRequest):
        fail('request', 'malformed', 'expected ConversationRequest; executable clients are unavailable')
    validate_plan(request.plan, capabilities)
    from .input_files import validate_files
    validate_files(request.input_files)
    for name in ('run_id', 'case_id', 'conversation_id'):
        unique([getattr(request, name)], name)
    if request.campaign is not None:
        unique([request.campaign.campaign_id], 'campaign.campaign_id')
        integer(request.campaign.case_number, 'campaign.case_number', 1)
        integer(request.campaign.variant_number, 'campaign.variant_number', 1)
        if request.campaign.variant_id not in ('normal', 'length4'):
            fail('campaign.variant_id', 'unsupported_variant', 'normal or length4 required')
    row = request.row
    unique([row.row_id], 'row.row_id')
    integer(row.ordinal, 'row.ordinal', 1)
    ids = [a.action_id for a in request.plan.actions]
    unique(list(request.selected_actions), 'selected_actions')
    if not request.selected_actions or any(key not in ids for key in request.selected_actions):
        fail('selected_actions', 'unknown_action', 'explicit unambiguous selected sends required')
    unique([c.contribution_id for c in row.contributions], 'row.contributions')
    contributions = {c.contribution_id: c for c in row.contributions}
    for c in row.contributions:
        if type(c.data) is not bytes or c.source.mode not in ('literal', 'file', 'whole_file',
                'line_file', 'list', 'dataset', 'seed_directory', 'generator', 'iterator',
                'random', 'sweep', 'edge', 'mutation', 'prepared'):
            fail('row.contributions', 'malformed', 'exact prepared bytes and source mode required')
        unique([c.source.source_id], 'row.contributions.source_id')
        unique([m.mutator_id for m in c.mutators], 'row.contributions.mutators')
        integer(c.set_index, 'row.contributions.set_index', 1)
        validate_random(c.random_choices, 'row.contributions.random_choices')
        if c.source_result is not None:
            if c.source_result.source_id != c.source.source_id:
                fail('row.contributions.source_result', 'contradictory_source', 'source result identity mismatch')
            integer(c.source_result.index, 'row.contributions.source_result.index', 1)
            if c.source_result.sample_id is not None:
                unique([c.source_result.sample_id], 'row.contributions.source_result.sample_id')
        if c.mutator_results:
            if tuple(r.mutator_id for r in c.mutator_results) != tuple(m.mutator_id for m in c.mutators):
                fail('row.contributions.mutator_results', 'contradictory_source', 'mutator result order mismatch')
            for previous, current in zip(c.mutator_results, c.mutator_results[1:]):
                if previous.output_data != current.input_data:
                    fail('row.contributions.mutator_results', 'contradictory_source', 'disconnected transformation chain')
            if c.source_result is not None and c.source_result.data != c.mutator_results[0].input_data:
                fail('row.contributions.source_result', 'contradictory_source', 'source output differs from first mutation input')
            if c.mutator_results[-1].output_data != c.data:
                fail('row.contributions.data', 'contradictory_source', 'prepared bytes differ from last mutation output')
        elif c.source_result is not None and not c.mutators and c.source_result.data != c.data:
            fail('row.contributions.data', 'contradictory_source', 'prepared bytes differ from source output')
    placements = row.placements + row.final_overrides
    unique([p.placement_id for p in placements], 'row.placements')
    for p in placements:
        path = f'row.placements.{p.placement_id}'
        if p.contribution_id not in contributions:
            fail(path, 'unknown_contribution', p.contribution_id)
        if p.action_id not in request.selected_actions:
            fail(path, 'ambiguous_action', 'placement must identify a selected outbound action')
        if p.buffer_id != 'outbound':
            fail(path, 'unsupported_buffer', p.buffer_id)
        if p.coordinate != 'working':
            fail(path, 'unsupported_coordinate', 'working outbound coordinates required')
        if p.operation not in ('insert', 'overwrite', 'replace', 'append'):
            fail(path, 'unsupported_operation', p.operation)
        if type(p.include_in_field) is not bool:
            fail(path + '.include_in_field', 'malformed', 'exact boolean required')
        if p.include_in_field and (p.operation != 'insert' or p.field_id is None):
            fail(path + '.include_in_field', 'ambiguous_coordinate', 'only an explicit named insert can extend its field')
        if p.field_id is not None:
            unique([p.field_id], path + '.field_id')
            action = next(a for a in request.plan.actions if a.action_id == p.action_id)
            location = next((f for f in action.fields if f.field_id == p.field_id and
                             f.buffer_id == p.buffer_id), None)
            if location is None:
                fail(path + '.field_id', 'unknown_field', p.field_id)
            if p.offset is not None or p.end is not None or p.operation == 'append':
                fail(path, 'ambiguous_coordinate', 'named field and explicit offset/range/append are exclusive')
            if location.offset is None or (p.operation == 'replace' and location.size is None):
                fail(path + '.field_id', 'unknown_field_location', p.field_id)
            if (location.offset > len(action.seed) or
                    (location.size is not None and location.offset + location.size > len(action.seed))):
                fail(path + '.field_id', 'unknown_field_location', 'span exceeds current seed')
        elif p.operation == 'append':
            if p.offset is not None or p.end is not None:
                fail(path, 'ambiguous_coordinate', 'append has no explicit offset/range')
        else:
            integer(p.offset, path + '.offset')
            if p.operation == 'replace':
                integer(p.end, path + '.end')
                if p.end < p.offset:
                    fail(path, 'malformed', 'range end precedes start')
            elif p.end is not None:
                fail(path, 'ambiguous_coordinate', 'end applies only to replace')
        validate_random(p.random_choices, path + '.random_choices')
        for choice in p.random_choices:
            expected = f'{request.conversation_id}:{p.action_id}'
            if choice.scope == 'per_test' and choice.iteration_id not in (None, expected):
                fail(path, 'contradictory_scope', 'resolved placement choice belongs to a different iteration')
    for contribution in row.contributions:
        action_ids = {p.action_id for p in placements if p.contribution_id == contribution.contribution_id}
        if not action_ids:
            fail('row.contributions', 'unplaced_contribution', contribution.contribution_id)
        for choice in contribution.random_choices:
            if choice.scope == 'per_test':
                if len(action_ids) != 1:
                    fail('row.contributions.random_choices', 'contradictory_scope',
                         'per-test choices need a separate prepared contribution for each send')
                expected = f'{request.conversation_id}:{next(iter(action_ids))}'
                if choice.iteration_id not in (None, expected):
                    fail('row.contributions.random_choices', 'contradictory_scope',
                         'resolved source/mutator choice belongs to a different iteration')
    selection = row.selection
    if selection.strategy not in ('prepared', 'one_position', 'shared', 'zip', 'finite_product', 'retained_single', 'hybrid_product'):
        fail('row.selection.strategy', 'unsupported_strategy', selection.strategy)
    integer(selection.skip, 'row.selection.skip')
    if row.ordinal <= selection.skip or (selection.selected_cases and row.ordinal not in selection.selected_cases):
        fail('row.ordinal', 'unselected_row', 'caller supplied a row excluded by recorded intent')
    for number in selection.selected_cases:
        integer(number, 'row.selection.selected_cases', 1)
    unique([b.placement_id for b in selection.bindings], 'row.selection.bindings')
    by_id = {p.placement_id: p for p in placements}
    for binding in selection.bindings:
        if binding.placement_id not in by_id or binding.contribution_id not in contributions:
            fail('row.selection.bindings', 'contradictory_binding', 'binding must name an existing placement/contribution')
        p = by_id[binding.placement_id]
        c = contributions[binding.contribution_id]
        if p.contribution_id != c.contribution_id or binding.set_id != c.set_id:
            fail('row.selection.bindings', 'contradictory_binding', 'binding disagrees with prepared row')
        if binding.choice not in ('selected', 'baseline', 'held', 'shared') or type(binding.baseline) is not bytes:
            fail('row.selection.bindings', 'malformed', 'explicit baseline bytes and choice required')
        if binding.choice == 'baseline' and c.data != binding.baseline:
            fail('row.selection.bindings', 'contradictory_binding', 'baseline contribution differs from its baseline')
    unique(list(selection.dimension_order), 'row.selection.dimension_order')
    if selection.strategy in ('finite_product', 'hybrid_product') and set(selection.dimension_order) != {b.set_id for b in selection.bindings}:
        fail('row.selection.dimension_order', 'contradictory_binding', 'dimension order must name each bound set')
    if selection.strategy == 'shared':
        for action_id in request.selected_actions:
            shared = {b.contribution_id for b in selection.bindings if by_id[b.placement_id].action_id == action_id}
            if len(shared) > 1:
                fail('row.selection.bindings', 'contradictory_binding',
                    'shared strategy must use one prepared contribution within each selected send')
    unique([c.calculation_id for c in request.calculations], 'calculations')
    for c in request.calculations:
        if c.action_id not in ids:
            fail('calculations', 'unknown_action', c.action_id)
        if c.override_value is not None:
            integer(c.override_value, 'calculations.override_value')
            if c.rule != 'payload_length':
                fail('calculations.override_value', 'unsupported_capability', 'override requires known payload_length')
        if c.rule == 'sequence':
            integer(c.sequence_start, 'calculations.sequence_start')
            if type(c.sequence_step) is not int:
                fail('calculations.sequence_step', 'malformed', 'signed integer step required')
            if c.sequence_wrap is not None:
                integer(c.sequence_wrap, 'calculations.sequence_wrap', 1)
            if c.sequence_ordinal is not None:
                integer(c.sequence_ordinal, 'calculations.sequence_ordinal', 1)
        from .calculations import SUPPORTED_RULES, calculation_problem
        if c.required and c.rule not in SUPPORTED_RULES:
            fail('calculations', 'unsupported_capability', c.rule)
        if c.buffer_id != 'outbound':
            fail('calculations.buffer_id', 'unsupported_buffer', c.buffer_id)
        if c.destination not in ('fixed', 'field', 'append'):
            fail('calculations.destination', 'unsupported_destination', c.destination)
        if c.field_id is not None and c.offset is not None:
            fail('calculations', 'ambiguous_coordinate', 'named and fixed destinations are exclusive')
        if c.destination == 'append' and (c.offset is not None or c.field_id is not None):
            fail('calculations', 'ambiguous_coordinate', 'append has no field/offset')
        if c.destination == 'field' and c.field_id is None:
            fail('calculations.field_id', 'required', 'field destination needs a field identity')
        if c.offset is not None:
            integer(c.offset, 'calculations.offset')
        if c.size is not None:
            integer(c.size, 'calculations.size', 1)
        if c.payload_offset is not None:
            integer(c.payload_offset, 'calculations.payload_offset')
        if c.endian not in ('big', 'little'):
            fail('calculations.endian', 'malformed', c.endian)
        if type(c.range_start) is not int or (c.range_end is not None and type(c.range_end) is not int):
            fail('calculations.range', 'malformed', 'integer bounds or open end required')
        action = next(a for a in request.plan.actions if a.action_id == c.action_id)
        problem = calculation_problem(c, action)
        if c.required and problem:
            fail('calculations.' + c.calculation_id, 'unsupported_capability', problem)
    return request
