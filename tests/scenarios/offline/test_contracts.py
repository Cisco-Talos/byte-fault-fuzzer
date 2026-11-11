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

from dataclasses import replace
import json
import pytest


def make_request(strategy='prepared'):
    from bytefault.core.contracts import (PassivePlan, ConversationAction, PreparedRow,
        PreparedContribution, SourceInvocation, MutatorInvocation, MutatorResult, SourceResult,
        RandomChoice, Placement, PositionBinding, SelectionIntent, ConversationRequest)
    contributions = tuple(PreparedContribution(f'C{i}', value,
        SourceInvocation(f'source{i}', mode, 'retained.module', {'encoding': 'raw'}, f'input-{i}'),
        (MutatorInvocation(f'mutator{i}', 'retained.mutator', {'operation': 'identity'}),),
        f'set{i}', i + 1,
        (RandomChoice(f'length{i}', 'source', 'length', (1, 20), 'sample_once', 1),
         RandomChoice(f'bytes{i}', 'mutator', 'bytes', (0, 255), resolved=value)),
        SourceResult(f'source{i}', value, i + 1, f'input-{i}'),
        (MutatorResult(f'mutator{i}', value, value, 'identity'),))
        for i, (value, mode) in enumerate(zip((b'X', b'Y', b'Z'), ('whole_file', 'line_file', 'dataset'))))
    placements = tuple(Placement(f'P{i}', f'C{i}', 'A6', 'append',
        random_choices=(RandomChoice(f'offset{i}', 'placement', 'offset', (0, 100), resolved=10),))
        for i in range(3))
    selection = SelectionIntent(strategy, tuple(PositionBinding(f'P{i}', f'set{i}', f'C{i}', b'base')
        for i in range(3)), ('set0', 'set1', 'set2') if strategy in ('finite_product', 'hybrid_product') else (),
        (2, 4), 1, 1234, {'limit': 10}, 'shortest' if strategy == 'zip' else 'finite')
    plan = PassivePlan('neutral', 1, tuple(ConversationAction(f'A{i}', b'ABC', f'S{min(i, 5)}')
        for i in range(7)), tuple(f'S{i}' for i in range(6)))
    return ConversationRequest(plan, PreparedRow('row2', 2, contributions, placements, selection),
        ('A6',), 'run', 'case2', 'conversation', original_request={'password': 'marker-X', 'seed': b'\0\xff'})


def test_stages_rows_and_random_scopes(engine_factory):
    from bytefault.core.validation import validate_request
    from bytefault.fuzzers.inputs import request_from_data, request_to_data
    # Prepared strategy intent is preserved; this offline check does not enumerate candidate sets.
    for strategy in ('prepared', 'one_position', 'zip', 'finite_product', 'retained_single', 'hybrid_product'):
        request = make_request(strategy)
        assert validate_request(request) is request
        decoded = request_from_data(json.loads(json.dumps(request_to_data(request))))
        assert decoded == request
        assert decoded.row.contributions[0].random_choices[1].scope == 'per_test'
    request = make_request()
    shared = replace(request.row.contributions[0], set_id='shared')
    from bytefault.core.contracts import PositionBinding
    row = replace(request.row, contributions=(shared,),
        placements=tuple(replace(p, contribution_id='C0') for p in request.row.placements),
        selection=replace(request.row.selection, strategy='shared', bindings=tuple(
            PositionBinding(p.placement_id, 'shared', 'C0', b'base', 'shared') for p in request.row.placements)))
    assert validate_request(replace(request, row=row))
    engine, trace, _, _ = engine_factory()
    result = engine.execute_conversation(request)
    assert [a.action_id for a in result.actions] == [f'A{i}' for i in range(7)]
    assert result.actions[-1].materialized.final_bytes == b'ABCXYZ'
    assert sum(a.iteration_id is not None for a in result.actions) == 1


def test_attributed_invalid_contracts(engine_factory):
    from bytefault.core.contracts import ContractError
    from bytefault.core.validation import validate_request
    base = make_request()
    p = base.row.placements[0]
    c = base.row.contributions[0]
    bad_values = [
        replace(base, row='invalid'),
        replace(base, plan=replace(base.plan, actions=('invalid',))),
        replace(base, plan=replace(base.plan, required_capabilities=('invalid',))),
        replace(base, selected_actions=('missing',)),
        replace(base, row=replace(base.row, contributions=(c, c))),
        replace(base, row=replace(base.row, placements=(replace(p, buffer_id='payload'),))),
        replace(base, row=replace(base.row, placements=(replace(p, coordinate='original'),))),
        replace(base, row=replace(base.row, contributions=(replace(c, random_choices=(
            replace(c.random_choices[0], scope='contradiction'),)),))),
        replace(base, row=replace(base.row, selection=replace(base.row.selection, bindings=(
            replace(base.row.selection.bindings[0], contribution_id='C1'),)))),
        replace(base, row=replace(base.row, ordinal=0)),
    ]
    engine, trace, _, _ = engine_factory()
    for bad in bad_values:
        with pytest.raises(ContractError) as error:
            engine.execute_conversation(bad)
        assert error.value.path and error.value.code
        assert not trace
    from bytefault.core.contracts import SourceInvocation
    for mode in ('literal', 'file', 'whole_file', 'line_file', 'list', 'dataset', 'seed_directory',
                 'generator', 'iterator', 'random', 'sweep', 'edge', 'mutation', 'prepared'):
        source = SourceInvocation('source0', mode, options={'exact-mode': mode})
        assert validate_request(replace(base, row=replace(base.row,
            contributions=(replace(c, source=source),) + base.row.contributions[1:])))


def test_random_resolution_owns_nested_values():
    from bytefault.core.contracts import RandomChoice
    from bytefault.fuzzers.inputs import request_from_data, request_to_data
    original = {'held': [b'X', {'positions': [1, 2]}]}
    choice = RandomChoice('nested', 'source', 'held', (0, 255), 'sample_once', original)
    request = make_request()
    contribution = replace(request.row.contributions[0], random_choices=(choice,))
    request = replace(request, row=replace(request.row,
        contributions=(contribution,) + request.row.contributions[1:]))
    encoded = request_to_data(request)
    original['held'][1]['positions'].append(3)
    original['held'][0] = b'changed'
    original['new'] = 'caller mutation'
    assert choice.resolved['held'][0] == b'X'
    assert choice.resolved['held'][1]['positions'] == (1, 2)
    assert 'new' not in choice.resolved
    assert request_to_data(request) == encoded
    assert request_from_data(json.loads(json.dumps(encoded))) == request
    with pytest.raises(TypeError):
        choice.resolved['held'] = ()
    with pytest.raises(TypeError):
        choice.resolved['held'][1]['positions'][0] = 99
