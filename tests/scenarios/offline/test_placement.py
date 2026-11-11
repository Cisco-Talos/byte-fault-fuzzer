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
import pytest


def placement_request(seed, operations, *, final=(), calculations=(), repair=False):
    from bytefault.core.contracts import (PreparedContribution, SourceInvocation, PreparedRow,
        Placement)
    from bytefault.fuzzers.inputs import raw_request
    request = raw_request(seed)
    contributions = tuple(PreparedContribution(f'C{i}', data, SourceInvocation(f'S{i}', 'literal'))
        for i, (_, data, _, _) in enumerate(operations + final))
    placements = tuple(Placement(f'P{i}', f'C{i}', '1', operation, offset, end)
        for i, (operation, _, offset, end) in enumerate(operations + final))
    return replace(request, row=PreparedRow('row1', 1, contributions,
        placements[:len(operations)], final_overrides=placements[len(operations):]),
        calculations=calculations, repair=repair)


def sent(engine, request):
    result = engine.execute_conversation(request)
    assert result.outcome == 'completed'
    assert len(result.actions) == 1
    return result.actions[0]


def test_exact_ordered_engine_placement(engine_factory):
    for operation, offset, end, expected in (
            ('insert', 1, None, b'AZBC'), ('overwrite', 1, None, b'AZC'),
            ('replace', 1, 3, b'AZ'), ('insert', 5, None, b'ABC\0\0Z')):
        engine, trace, _, _ = engine_factory()
        result = sent(engine, placement_request(b'ABC', ((operation, b'Z', offset, end),)))
        assert result.transport.prepared == result.transport.offered == expected
        assert [t for t in trace if t[0] == 'offer'] == [('offer', expected)]
    engine, trace, _, _ = engine_factory()
    request = placement_request(b'U=aa;P=bb', (
        ('replace', b'XXX', 2, 4), ('replace', b'Y', 8, 10), ('append', b'ZZ', None, None)))
    result = sent(engine, request)
    assert result.transport.offered == b'U=XXX;P=YZZ'
    assert [p.span for p in result.materialized.placements] == [(2, 4), (8, 10), (9, 9)]
    assert [p.data for p in result.materialized.placements] == [b'XXX', b'Y', b'ZZ']
    assert [t for t in trace if t[0] == 'offer'] == [('offer', b'U=XXX;P=YZZ')]
    assert result.iteration_id is not None
    engine, trace, _, _ = engine_factory()
    result = sent(engine, placement_request(b'ABC', (
        ('overwrite', b'X', 1, None), ('overwrite', b'Y', 1, None))))
    assert result.transport.offered == b'AYC'
    assert len(result.materialized.placements) == 2


def test_final_calculation_override(engine_factory):
    from bytefault.core.contracts import Calculation, ContractError
    calculation = Calculation('length', '1', 'payload_length', 0, 2, 'big', 2)
    request = placement_request(b'\x00\x01A', (('append', b'BC', None, None),),
        calculations=(calculation,), repair=True)
    engine, _, _, _ = engine_factory()
    assert sent(engine, request).transport.offered == b'\x00\x03ABC'
    engine, _, _, _ = engine_factory()
    override = placement_request(b'\x00\x01A', (('append', b'BC', None, None),),
        final=(('overwrite', b'\xff\xff', 0, None),), calculations=(calculation,), repair=True)
    assert sent(engine, override).transport.offered == b'\xff\xffABC'
    engine, _, _, _ = engine_factory()
    assert sent(engine, replace(request, repair=False)).transport.offered == b'\x00\x01ABC'
    engine, _, _, _ = engine_factory()
    unknown = replace(request, calculations=(replace(calculation, rule='unknown'),))
    result = sent(engine, unknown)
    assert result.transport.offered == b'\x00\x01ABC'
    assert result.materialized.calculations == (('length', 'unavailable_rule_or_location'),)
    engine, trace, _, _ = engine_factory()
    with pytest.raises(ContractError, match='unsupported_capability'):
        engine.execute_conversation(replace(unknown, calculations=(replace(unknown.calculations[0], required=True),)))
    assert not trace
    # Ordinary explicit field edits also override repair, even after later shifts.
    engine, _, _, _ = engine_factory()
    ordinary = placement_request(b'\x00\x01A', (
        ('overwrite', b'\xff\xff', 0, None), ('append', b'BC', None, None)),
        calculations=(calculation,), repair=True)
    result = sent(engine, ordinary)
    assert result.transport.offered == b'\xff\xffABC'
    assert result.materialized.calculations == (('length', 'explicit_edit'),)
    engine, _, _, _ = engine_factory()
    shifted = placement_request(b'\x00\x01A', (
        ('insert', b'Q', 0, None), ('append', b'BC', None, None)),
        calculations=(calculation,), repair=True)
    assert sent(engine, shifted).transport.offered == b'Q\x00\x03ABC'
