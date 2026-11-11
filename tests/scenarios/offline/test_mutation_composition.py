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

"""Independent bytes/rows and controlled decisions under the offline pre-import guard."""
from dataclasses import replace
import itertools
import json
import random

import pytest

from bytefault.core.contracts import (ContractError, ConversationAction, ConversationRequest,
    PassivePlan, Placement, PositionBinding, PreparedRow, SelectionIntent)
from bytefault.core.validation import validate_request
from bytefault.fuzzers.composer import (CandidateBinding, CandidateComposer, CandidateSet,
    FuzzComposer, PreparationCancelled)
from bytefault.generators.mutator import Mutator, MutatorGenerator
from bytefault.generators.sources import SourceSpec, SourceStream, open_source
from bytefault.generators.random_bytes import RandomBytesGenerator
from bytefault.generators.transforms import MutationPipeline, TransformSpec


def values(set_id, payloads, transforms=(), pool_mode='fresh'):
    return CandidateSet(set_id, open_source(SourceSpec(set_id, 'list', {'payloads': payloads})), transforms, pool_mode)


def row_values(row):
    result = row.resolve(f'case:{row.ordinal}:send')
    data = {c.contribution_id: c.data for c in result.contributions}
    return tuple(data[b.contribution_id] for b in result.selection.bindings)


@pytest.mark.parametrize('strategy,expected', [
    ('zip', [(b'a', b'1'), (b'b', b'2')]),
    ('cartesian', [(b'a', b'1'), (b'a', b'2'), (b'a', b'3'), (b'b', b'1'), (b'b', b'2'), (b'b', b'3')]),
    ('single', [(b'a', b'1'), (b'b', b'1'), (b'a', b'1'), (b'a', b'2'), (b'a', b'3')]),
])
def test_exact_distinct_set_oracles(strategy, expected):
    composer = CandidateComposer([values('X', [b'a', b'b']), values('Y', [b'1', b'2', b'3'])],
        [CandidateBinding('X', 'X', b'x0'), CandidateBinding('Y', 'Y', b'y0')], strategy)
    rows = list(composer.rows())
    assert [row_values(row) for row in rows] == expected
    assert [row.ordinal for row in rows] == list(range(1, len(expected) + 1))
    assert rows[0].resolve('test').selection.dimension_order == ('X', 'Y')


@pytest.mark.parametrize('strategy,expected', [
    ('one-position', [(b'a', b'y0'), (b'b', b'y0'), (b'x0', b'a'), (b'x0', b'b')]),
    ('broadcast', [(b'a', b'a'), (b'b', b'b')]),
])
def test_exact_shared_set_oracles(strategy, expected):
    composer = CandidateComposer([values('S', [b'a', b'b'])],
        [CandidateBinding('X', 'S', b'x0'), CandidateBinding('Y', 'S', b'y0')], strategy)
    assert [row_values(row) for row in composer.rows()] == expected


@pytest.mark.parametrize('operation,seed,draws,expected', [
    ('flip_bit', b'AB', [0, 1, 0], b'AC'),
    ('flip_byte', b'AB', [0, 0, 255], b'\xffB'),
    ('arith_byte', b'\xffB', [0, 0, 3], b'\x00B'),
    ('insert_byte', b'AB', [0, 1, 0], b'A\x00B'),
    ('delete_byte', b'AB', [0, 0], b'B'),
    ('duplicate_slice', b'AB', [0, 0, 1, 0], b'BAB'),
])
def test_every_mutation_operation_exact_bytes(operation, seed, draws, expected):
    sequence = iter(draws)
    actual = []
    def draw(name, lo, hi):
        value = next(sequence)
        assert lo <= value <= hi
        actual.append((name, value))
        return value
    mutator = Mutator(draw=draw, operations=(operation,))
    assert mutator.mutate_once(seed) == expected
    assert mutator.last_operation == operation
    assert actual[0] == ('operation', 0)


def test_requested_maximum_all_operations_and_fallback_history():
    for operation in ('flip_bit', 'flip_byte', 'arith_byte', 'insert_byte', 'delete_byte', 'duplicate_slice'):
        mutator = Mutator(random.Random(7), 2, operations=(operation,))
        assert len(mutator.mutate_once(b'ABCDE')) <= 2
    pipeline = MutationPipeline([TransformSpec('m', 'mutate', {'operation': 'insert_byte', 'max_len': 1, 'seed': 1})])
    result = pipeline.apply(b'AB', 'iteration')
    assert len(result.data) == 1
    assert result.results[0].input_data == b'AB'
    assert result.results[0].transformation == 'mutate:flip_byte:selected=insert_byte'
    assert Mutator(max_len=0).mutate_once(b'oversized') == b''
    with pytest.raises(ValueError, match='operation'):
        Mutator(operations=[])


def test_seed_cycles_count_and_separate_mutation_result():
    source = open_source(SourceSpec('seeds', 'mutate', {'seeds': (b'A', b'BC'), 'count': 5, 'seed': 7}))
    assert [c.data for c in source.candidates()] == [b'A', b'BC', b'A', b'BC', b'A']
    composer = CandidateComposer([CandidateSet('S', source)], [CandidateBinding('X', 'S')])
    rows = [r.resolve(f'{r.ordinal}:action') for r in composer.rows()]
    assert len(rows) == 5
    assert [r.contributions[0].source_result.data for r in rows] == [b'A', b'BC', b'A', b'BC', b'A']
    assert all(r.contributions[0].mutator_results for r in rows)
    assert all(r.contributions[0].mutator_results[0].input_data == r.contributions[0].source_result.data for r in rows)


def test_mutation_generator_snapshots_exact_seeds_once():
    seeds = [b'AB', b'CD']
    gen = MutatorGenerator(seeds, 3, random.Random(1))
    seeds.clear()
    assert len(list(gen.generate())) == 3
    with pytest.raises(ValueError, match='exact bytes'):
        MutatorGenerator([bytearray(b'A')])


def test_explicit_text_hex_trim_encoding_reordering_and_words():
    specs = [TransformSpec('trim_unicode', 'text_trim'),
        TransformSpec('codec', 'text', {'from_encoding': 'utf-8', 'to_encoding': 'utf-16le'}),
        TransformSpec('reverse', 'reverse')]
    result = MutationPipeline(specs).apply('\u00a0A\u00e9\u00a0'.encode())
    assert result.data == b'\x00\xe9\x00A'
    assert [r.input_data for r in result.results] == ['\u00a0A\u00e9\u00a0'.encode(), 'A\u00e9'.encode(), b'A\x00\xe9\x00']
    assert MutationPipeline([TransformSpec('hex', 'hex_decode')]).apply(b'0x41 \\x42').data == b'AB'
    assert MutationPipeline([TransformSpec('hex', 'hex_encode', {'uppercase': True})]).apply(b'\xff\x00').data == b'FF00'
    assert MutationPipeline([TransformSpec('order', 'reorder', {'indices': (2, 0, 1)})]).apply(b'ABC').data == b'CAB'
    assert MutationPipeline([TransformSpec('word', 'word', {'index': 1})]).apply(b' alpha  beta ').data == b'beta'
    assert MutationPipeline([TransformSpec('t', 'trim', {'chars_hex': '00'})]).apply(b'\x00 \x00').data == b' '


def test_prepend_append_pad_are_attributed_byte_transforms():
    pipeline = MutationPipeline([TransformSpec('pad', 'pad', {'length': 3, 'value': 255}),
        TransformSpec('prefix', 'prepend', {'data': b'P'}), TransformSpec('suffix', 'append', {'data_hex': '00'})])
    result = pipeline.apply(b'A')
    assert result.data == b'P\xff\xffA\x00'
    assert [r.output_data for r in result.results] == [b'\xff\xffA', b'P\xff\xffA', b'P\xff\xffA\x00']


def filter_specs():
    return (TransformSpec('trim', 'text_trim'), TransformSpec('comment', 'filter_comments'), TransformSpec('empty', 'filter_empty'))


def test_standalone_filter_returns_exact_disposition_without_network_or_sink():
    result = MutationPipeline(filter_specs()).apply(b' #comment ')
    assert result.disposition == 'excluded:comment'
    assert result.data == b'#comment'
    assert result.results[0].input_data == b' #comment '
    assert result.results[-1].output_data == b'#comment'


def test_composition_filters_records_before_selection_preserves_trailing_dispositions():
    events = []
    composer = CandidateComposer([values('S', [b'# first', b' A ', b'', b'B', b'#last'], filter_specs())],
        [CandidateBinding('X', 'S'), CandidateBinding('Y', 'S')], 'broadcast', disposition_sink=events.append)
    rows = list(composer.rows())
    assert [row_values(row) for row in rows] == [(b'A', b'A'), (b'B', b'B')]
    assert [e.source_result.index for e in events] == [1, 3, 5]
    assert [e.source_result.data for e in events] == [b'# first', b'', b'#last']
    assert rows[0].resolve('send').contributions[0].source_result.index == 2
    assert rows[0].resolve('send').contributions[0].set_index == 1


def test_single_pins_first_accepted_and_all_filtered_is_empty_with_dispositions():
    events = []
    composer = CandidateComposer([values('X', [b'#', b'a', b'b'], filter_specs()), values('Y', [b'1'])],
        [CandidateBinding('X', 'X'), CandidateBinding('Y', 'Y')], disposition_sink=events.append)
    assert [row_values(r) for r in composer.rows()] == [(b'a', b'1'), (b'b', b'1'), (b'a', b'1')]
    assert len(events) == 1
    composer = CandidateComposer([values('S', [b'#', b''], filter_specs())], [CandidateBinding('X', 'S')], disposition_sink=events.append)
    assert list(composer.rows()) == []
    assert len(events) == 3
    with pytest.raises(ContractError, match='missing_disposition_sink'):
        CandidateComposer([values('S', [b''], filter_specs())], [CandidateBinding('X', 'S')])


@pytest.mark.parametrize('strategy', ['zip', 'cartesian', 'hybrid-cartesian'])
def test_empty_dimension_has_zero_rows(strategy):
    composer = CandidateComposer([values('X', []), values('Y', [b'1'])],
        [CandidateBinding('X', 'X'), CandidateBinding('Y', 'Y')], strategy)
    assert list(composer.rows()) == []


def test_single_empty_inactive_baseline_and_missing_baseline_error():
    bindings = [CandidateBinding('X', 'X', b'x0'), CandidateBinding('Y', 'Y', b'y0')]
    composer = CandidateComposer([values('X', []), values('Y', [b'1', b'2'])], bindings)
    assert [row_values(r) for r in composer.rows()] == [(b'x0', b'1'), (b'x0', b'2')]
    composer = CandidateComposer([values('X', []), values('Y', [b'1'])], [CandidateBinding('X', 'X'), CandidateBinding('Y', 'Y')])
    with pytest.raises(ContractError, match='missing_baseline'):
        list(composer.rows())


def test_lazy_unbounded_prefix_and_explicit_hybrid_advancement():
    source = open_source(SourceSpec('random', 'random', {'min_len': 1, 'max_len': 1, 'seed': 3}))
    composer = CandidateComposer([CandidateSet('R', source)], [CandidateBinding('X', 'R')], 'broadcast')
    rows = composer.rows()
    assert len([row_values(r) for r in itertools.islice(rows, 3)]) == 3
    rows.close()
    with pytest.raises(ContractError, match='unbounded_pool'):
        CandidateComposer([CandidateSet('R', source)], [CandidateBinding('X', 'R')], 'cartesian')
    with pytest.raises(ContractError, match='finite source'):
        CandidateComposer([CandidateSet('R', source)], [CandidateBinding('X', 'R')], 'hybrid-cartesian')
    composer = CandidateComposer([values('X', [b'a', b'b']), CandidateSet('R', source)],
        [CandidateBinding('X', 'X'), CandidateBinding('Y', 'R')], 'hybrid-cartesian')
    rows = [r.resolve(f'c:{r.ordinal}:s') for r in composer.rows()]
    assert len(rows) == 2
    assert [r.contributions[1].source_result.index for r in rows] == [1, 2]


def test_per_test_mutation_held_operation_fresh_values_and_seed_sequence():
    spec = TransformSpec('m', 'mutate', {'operation': 'flip_byte', 'seed': 7,
        'scopes': {'operation': 'sample_once', 'index': 'sample_once'}})
    pipeline = MutationPipeline([spec])
    results = [pipeline.apply(b'AB', f'case:{i}:send') for i in range(3)]
    expected_rng = random.Random(7)
    operation_unit = expected_rng.random()
    index_unit = expected_rng.random()
    index = int(index_unit * 2)
    expected_values = [expected_rng.randrange(256) for _ in range(3)]
    expected = [bytes([value, 66]) if index == 0 else bytes([65, value]) for value in expected_values]
    assert [r.data for r in results] == expected
    assert tuple(results[0].mutators[0].options['decision_mapping']['operation']) == ('flip_byte',)
    assert tuple(results[0].mutators[0].options['decision_mapping']['delta']) == (-3, -2, -1, 1, 2, 3)
    for i, result in enumerate(results):
        assert [c.scope for c in result.random_choices] == ['sample_once', 'sample_once', 'per_test']
        assert dict(result.random_choices[0].resolved) == {'unit': operation_unit, 'value': 0}
        assert dict(result.random_choices[1].resolved) == {'unit': index_unit, 'value': index}
        assert result.random_choices[-1].iteration_id == f'case:{i}:send'
    duplicate = MutationPipeline([spec])
    assert [duplicate.apply(b'AB').data for _ in range(3)] == expected


def test_held_normalized_mutation_maps_narrowing_widening_and_singletons():
    pipeline = MutationPipeline([TransformSpec('m', 'mutate', {'operation': 'flip_bit', 'scope': 'sample_once'})])
    class Draws:
        def __init__(self):
            self.units, self.calls = iter((0.0, 0.75, 0.5)), 0
        def random(self):
            self.calls += 1
            return next(self.units)
    draws = Draws()
    pipeline._rngs['m'] = draws
    results = [pipeline.apply(seed) for seed in (b'ABCD', b'abcdefgh', b'Q')]
    assert [r.data for r in results] == [b'ABCT', b'abcdefwh', b'A']
    assert draws.calls == 3
    assert results[0].mutators[0].options['decision_mapping']['slice_length'] == 'length=value+1'
    assert [r.random_choices[1].bounds for r in results] == [(0, 3), (0, 7), (0, 0)]
    assert [dict(r.random_choices[1].resolved) for r in results] == [
        {'unit': 0.75, 'value': 3}, {'unit': 0.75, 'value': 6}, {'unit': 0.75, 'value': 0}]
    assert all(r.random_choices[1].iteration_id is None for r in results)
    assert results[-1].results[0].input_data == b'Q'


def test_held_index_is_independent_of_fresh_operation_and_mutation_value():
    pipeline = MutationPipeline([TransformSpec('m', 'mutate', {'operations': ('flip_byte', 'insert_byte'),
        'scopes': {'index': 'sample_once'}})])
    class Draws:
        def __init__(self):
            self.values, self.units = iter((0, 90, 1, 82)), 0
        def randrange(self, lo, hi):
            value = next(self.values)
            assert lo <= value < hi
            return value
        def random(self):
            self.units += 1
            return 0.75
    draws = Draws()
    pipeline._rngs['m'] = draws
    first, second = pipeline.apply(b'AB', 'one'), pipeline.apply(b'AB', 'two')
    assert [first.data, second.data] == [b'AZ', b'ABR']
    assert draws.units == 1
    assert first.random_choices[1].bounds == (0, 1)
    assert second.random_choices[1].bounds == (0, 2)
    assert [c.iteration_id for c in second.random_choices] == ['two', None, 'two']


def test_direct_mutation_source_adapter_retains_raw_seeds_and_exact_rng_state_parity():
    original_rng = random.Random(23)
    # Adapt an already-used RNG, proving continuation rather than seed restart.
    original_rng.random()
    state = original_rng.getstate()
    original = MutatorGenerator([b'AB', b'CD'], 6, original_rng, max_len=4)
    source = SourceStream.from_generator(original, 'direct')
    assert [c.data for c in source.candidates()] == [b'AB', b'CD', b'AB', b'CD', b'AB', b'CD']
    assert original_rng.getstate() == state
    composer = CandidateComposer([CandidateSet('S', source)], [CandidateBinding('X', 'S')])
    contributions = [r.resolve(f'conv:{r.ordinal}').contributions[0] for r in composer.rows()]
    reference_rng = random.Random()
    reference_rng.setstate(state)
    reference = list(MutatorGenerator([b'AB', b'CD'], 6, reference_rng, max_len=4).generate())
    assert [c.data for c in contributions] == reference
    assert [c.source_result.data for c in contributions] == [b'AB', b'CD', b'AB', b'CD', b'AB', b'CD']
    assert all(len(c.mutators) == len(c.mutator_results) == 1 for c in contributions)
    assert all(c.mutator_results[0].input_data == c.source_result.data for c in contributions)
    assert all(c.mutator_results[0].output_data == c.data for c in contributions)
    assert tuple(contributions[0].mutators[0].options['rng_state']) == state
    assert original_rng.getstate() == state
    facade = [data['X'] for data, progress in FuzzComposer().compose({'X': original})]
    assert facade == reference


def test_broadcast_transforms_once_each_send_and_subset_does_not_draw_unrelated():
    transforms = (TransformSpec('m', 'mutate', {'operation': 'flip_byte', 'seed': 9}),)
    composer = CandidateComposer([values('S', [b'A'], transforms)],
        [CandidateBinding('X', 'S'), CandidateBinding('Y', 'S')], 'broadcast')
    row = next(composer.rows())
    first, second = row.resolve('conv:one'), row.resolve('conv:two')
    assert len(first.contributions) == len(second.contributions) == 1
    assert {b.contribution_id for b in first.selection.bindings} == {first.contributions[0].contribution_id}
    assert first.contributions[0].random_choices[-1].iteration_id == 'conv:one'
    assert second.contributions[0].random_choices[-1].iteration_id == 'conv:two'
    composer = CandidateComposer([values('X', [b'A'], transforms), values('Y', [b'B'], transforms)],
        [CandidateBinding('X', 'X'), CandidateBinding('Y', 'Y')], 'zip')
    row = next(composer.rows())
    assert row.resolve('conv:one', position_ids=[]).contributions == ()
    only_y = row.resolve('conv:two', position_ids=['Y'])
    assert len(only_y.contributions) == 1
    assert only_y.selection.bindings[0].placement_id == 'Y'
    assert only_y.contributions[0].random_choices[-1].resolved == first.contributions[0].random_choices[-1].resolved


def test_cartesian_explicit_source_pool_reuse_and_fresh_downstream_mutation():
    def make(pool_mode):
        source = open_source(SourceSpec('R', 'random', {'min_len': 2, 'max_len': 2, 'count': 1, 'seed': 4}))
        return CandidateComposer([CandidateSet('R', source, (TransformSpec('m', 'mutate', {'operation': 'flip_byte', 'seed': 7}),), pool_mode),
            values('Y', [b'1', b'2'])], [CandidateBinding('X', 'R'), CandidateBinding('Y', 'Y')], 'cartesian')
    with pytest.raises(ContractError, match='pool_mode=reuse'):
        list(make('fresh').rows())
    rows = [r.resolve(f'case:{r.ordinal}:send') for r in make('reuse').rows()]
    first, second = [r.contributions[0] for r in rows]
    assert first.source_result == second.source_result
    assert all(c.scope == 'sample_once' and c.iteration_id is None for c in first.random_choices if c.owner == 'source')
    assert all(c.scope == 'per_test' for c in first.random_choices if c.owner == 'mutator')
    assert rows[0].selection.bounds['source_pool_modes']['R'] == 'reuse'
    assert first.source.options['kind'] == 'random'


def test_retained_single_and_additional_sends_refresh_random_source_without_freezing_first_index():
    source = open_source(SourceSpec('R', 'random', {'min_len': 1, 'max_len': 1, 'count': 1, 'seed': 7}))
    composer = CandidateComposer([values('X', [b'a', b'b']), CandidateSet('R', source)],
        [CandidateBinding('X', 'X'), CandidateBinding('Y', 'R')], 'single')
    rows = composer.rows()
    first = next(rows)
    one = first.resolve('conv:one', position_ids=['Y']).contributions[0]
    two = first.resolve('conv:two', position_ids=['Y']).contributions[0]
    next_row = next(rows).resolve('conv2:one', position_ids=['Y']).contributions[0]
    reference = open_source(SourceSpec('reference', 'random', {'min_len': 1, 'max_len': 1, 'count': 3, 'seed': 7}))
    assert [one.data, two.data, next_row.data] == list(reference.generate())
    assert [one.source_result.index, two.source_result.index, next_row.source_result.index] == [1, 1, 1]
    assert [c.iteration_id for c in two.random_choices] == ['conv:two', 'conv:two']
    rows.close()


def test_one_position_explicit_reused_source_pool_keeps_indexed_values_across_positions():
    source = open_source(SourceSpec('R', 'random', {'min_len': 1, 'max_len': 1, 'count': 2, 'seed': 7}))
    composer = CandidateComposer([CandidateSet('R', source, pool_mode='reuse')],
        [CandidateBinding('X', 'R', b'x0'), CandidateBinding('Y', 'R', b'y0')], 'one-position')
    output = [row_values(row) for row in composer.rows()]
    assert output == [(output[0][0], b'y0'), (output[1][0], b'y0'), (b'x0', output[0][0]), (b'x0', output[1][0])]


def test_all_filtered_unbounded_source_checks_cancellation_and_closes():
    from bytefault.generators.base import FuzzGenerator
    closed = []
    class Forever(FuzzGenerator):
        def count(self): return None
        def metadata(self): return {'type': 'provided'}
        def generate(self):
            try:
                while True:
                    yield b'#comment'
            finally:
                closed.append(True)
    events = []
    composer = CandidateComposer([CandidateSet('S', SourceStream.from_generator(Forever()), filter_specs())],
        [CandidateBinding('X', 'S')], 'broadcast', disposition_sink=events.append,
        cancelled=lambda: len(events) == 3)
    assert list(composer.rows()) == []
    assert len(events) == 3 and closed == [True]


def test_transform_failure_preserves_actual_source_partial_outputs_and_failed_intent():
    events = []
    transforms = (TransformSpec('trim', 'trim'), TransformSpec('decode', 'hex_decode'))
    composer = CandidateComposer([values('S', [b' broken '], transforms)],
        [CandidateBinding('X', 'S')], disposition_sink=events.append)
    row = next(composer.rows())
    with pytest.raises(ContractError, match='mutators.decode'):
        row.resolve('conv:send')
    assert len(events) == 1
    assert events[0].source_result.data == b' broken '
    assert events[0].mutator_results[0].output_data == b'broken'
    assert [m.mutator_id for m in events[0].mutators] == ['trim', 'decode']
    assert events[0].reason.startswith('error:')


class ScriptedRandomSource(RandomBytesGenerator):
    def __init__(self, draws, count):
        super().__init__(1, 1, count)
        self.draws, self.samples_read = iter(draws), 0

    def sample(self, *, length=None):
        self.samples_read += 1
        data = next(self.draws)
        return data, (('length', (1, 1), 'per_test', 1),
            ('content', (0, 255), 'per_test', data))


def scripted_source(draws, count):
    return SourceStream(SourceSpec('random', 'random', {'count': count}),
        ScriptedRandomSource(draws, count), 'random')


def test_fresh_random_filtered_stream_selects_survivors_with_raw_index_and_sample_history():
    events = []
    source = scripted_source([b'#', b'A', b'#', b'B'], 4)
    composer = CandidateComposer([CandidateSet('S', source, (TransformSpec('comment', 'filter_comments'),))],
        [CandidateBinding('X', 'S')], 'broadcast', disposition_sink=events.append)
    results = [r.resolve(f'conv:{r.ordinal}') for r in composer.rows()]
    assert [r.contributions[0].data for r in results] == [b'A', b'B']
    assert [r.contributions[0].source_result.index for r in results] == [2, 4]
    assert [r.contributions[0].set_index for r in results] == [1, 2]
    assert [e.source_result.index for e in events] == [1, 3]
    assert [e.source_result.sample_id for e in events] == ['1:S:6:random:sample:1', '1:S:6:random:sample:3']
    assert [r.contributions[0].source_result.sample_id for r in results] == ['1:S:6:random:sample:2', '1:S:6:random:sample:4']


def test_refreshed_source_retries_filter_rejections_preserves_index_and_records_each_attempt():
    events = []
    source = scripted_source([b'A', b'#', b'#', b'B'], 1)
    composer = CandidateComposer([CandidateSet('S', source, (TransformSpec('comment', 'filter_comments'),))],
        [CandidateBinding('X', 'S')], 'broadcast', disposition_sink=events.append)
    rows = composer.rows()
    row = next(rows)
    first, second = row.resolve('conv:one'), row.resolve('conv:two')
    one, two = first.contributions[0], second.contributions[0]
    assert [one.data, two.data] == [b'A', b'B']
    assert one.source_result.index == two.source_result.index == 1
    assert [e.source_result.data for e in events] == [b'#', b'#']
    assert [e.source_result.sample_id for e in events] == ['1:S:6:random:sample:2', '1:S:6:random:sample:3']
    assert two.source_result.sample_id == '1:S:6:random:sample:4'
    assert all(c.iteration_id == 'conv:two' for e in events for c in e.random_choices)
    assert two.mutator_results[-1].input_data == two.source_result.data == b'B'
    rows.close()


def test_refreshed_random_mutation_prefix_is_reapplied_before_filter_and_suffix():
    events = []
    transforms = (TransformSpec('mutation', 'mutate', {'operation': 'flip_byte'}),
        TransformSpec('comment', 'filter_comments'), TransformSpec('append', 'append', {'data': b'!'}))
    composer = CandidateComposer([values('S', [b'A'], transforms)], [CandidateBinding('X', 'S')],
        'broadcast', disposition_sink=events.append)
    class Draws:
        def __init__(self): self.values = iter((0, 0, 90, 0, 0, 35, 0, 0, 66))
        def randrange(self, lo, hi):
            value = next(self.values)
            assert lo <= value < hi
            return value
    composer._sets['S'].pipeline._rngs['mutation'] = Draws()
    rows = composer.rows()
    row = next(rows)
    first, second = row.resolve('conv:one'), row.resolve('conv:two')
    assert [first.contributions[0].data, second.contributions[0].data] == [b'Z!', b'B!']
    assert events[0].source_result.data == b'A'
    assert [r.output_data for r in events[0].mutator_results] == [b'#', b'#']
    assert [r.input_data for r in second.contributions[0].mutator_results] == [b'A', b'B', b'B']
    assert [c.iteration_id for c in second.contributions[0].random_choices] == ['conv:two'] * 3
    rows.close()


def test_filtered_refresh_cancellation_discards_entire_incomplete_row():
    events = []
    source = scripted_source([b'A', b'#', b'#'], 1)
    composer = CandidateComposer([values('X', [b'first']),
        CandidateSet('S', source, (TransformSpec('comment', 'filter_comments'),))],
        [CandidateBinding('X', 'X'), CandidateBinding('Y', 'S')], 'zip',
        disposition_sink=events.append, cancelled=lambda: len(events) == 2)
    rows = composer.rows()
    row = next(rows)
    assert [c.data for c in row.resolve('one').contributions] == [b'first', b'A']
    with pytest.raises(PreparationCancelled):
        row.resolve('two')
    assert len(events) == 2 and source.generator.samples_read == 3
    rows.close()


def test_random_filtered_cartesian_still_requires_explicit_reused_selection_pool():
    def make(mode):
        return CandidateComposer([CandidateSet('S', scripted_source([b'#', b'A'], 2),
            (TransformSpec('comment', 'filter_comments'),), mode)], [CandidateBinding('X', 'S')],
            'cartesian', disposition_sink=lambda event: None)
    with pytest.raises(ContractError, match='pool_mode=reuse'):
        list(make('fresh').rows())
    rows = make('reuse').rows()
    row = next(rows)
    first, second = row.resolve('one').contributions[0], row.resolve('two').contributions[0]
    assert first.source_result == second.source_result
    assert first.source_result.sample_id == '1:S:6:random:sample:2'
    assert all(c.scope == 'sample_once' for c in second.random_choices)
    rows.close()


def test_sample_identity_request_roundtrip_legacy_default_and_required_disposition_store(tmp_path):
    from bytefault.fuzzers.inputs import raw_request, request_to_data, request_from_data
    from bytefault.core.storage import LocalRecordStore, reopen_records
    events = []
    composer = CandidateComposer([values('S', [b'#', b'Z'], (TransformSpec('comment', 'filter_comments'),))],
        [CandidateBinding('X', 'S')], 'broadcast', disposition_sink=events.append)
    rows = composer.rows()
    row = next(rows)
    request = raw_request(b'ABC')
    prepared = row.resolve(f'{request.conversation_id}:1')
    prepared = replace(prepared, placements=(Placement('X', prepared.contributions[0].contribution_id, '1', 'append'),))
    request = replace(request, row=prepared)
    encoded = request_to_data(request)
    assert request_from_data(json.loads(json.dumps(encoded))) == request
    encoded['fields']['row']['fields']['contributions']['$tuple'][0]['fields']['source_result']['fields'].pop('sample_id')
    legacy = request_from_data(json.loads(json.dumps(encoded)))
    assert legacy.row.contributions[0].source_result.sample_id is None
    assert legacy.row.contributions[0].source_result.data == b'Z'
    path = tmp_path / 'disposition.bfr'
    store = LocalRecordStore(path)
    store.append('source_disposition', {'preparation_id': 'test'}, {'disposition': events[0]})
    store.close()
    restored = reopen_records(path).records[0].data['disposition']['source_result']
    assert restored['data'] == b'#' and restored['index'] == 1
    assert restored['sample_id'] == events[0].source_result.sample_id
    malformed = replace(prepared.contributions[0], source_result=replace(prepared.contributions[0].source_result, sample_id=''))
    with pytest.raises(ContractError, match='sample_id'):
        validate_request(replace(request, row=replace(prepared, contributions=(malformed,))))
    rows.close()


@pytest.mark.parametrize('scope', ['sample_once', 'per_test'])
def test_parser_mutation_byte_facade_and_attached_pipeline_share_actual_scope(scope):
    from bytefault.generators.cli_parser import parse_gen_field
    spec = f'@0:mutate:41424344,count:5,seed:17,mutation_scope:{scope}'
    target, direct = parse_gen_field(spec)
    assert isinstance(direct, MutatorGenerator)
    expected = list(direct.generate())
    _, attached = parse_gen_field(spec)
    source = SourceStream.from_generator(attached)
    composer = CandidateComposer([CandidateSet('S', source)], [CandidateBinding('X', 'S')])
    results = [r.resolve(f'conv:{r.ordinal}').contributions[0] for r in composer.rows()]
    assert [c.data for c in results] == expected
    assert all(c.source_result.data == b'ABCD' for c in results)
    assert all(c.scope == scope for result in results for c in result.random_choices)
    if scope == 'sample_once':
        assert expected == [expected[0]] * 5
        assert all('unit' in c.resolved for result in results for c in result.random_choices)
    else:
        assert expected == list(Mutator(random.Random(17)).generate(b'ABCD', 5))


@pytest.mark.parametrize('scope', ['sample_once', 'per_test'])
def test_prefix_consumed_parser_mutation_adapter_retains_current_rng_and_held_units(scope):
    from bytefault.generators.cli_parser import parse_gen_field
    _, generator = parse_gen_field(f'@0:mutate:41424344,count:4,seed:17,mutation_scope:{scope}')
    prefix = generator.generate()
    next(prefix)
    state = generator._mutator.rng.getstate()
    source = SourceStream.from_generator(generator)
    assert source.spec.options['rng_state'] == state
    if scope == 'sample_once':
        assert source.spec.options['mutation_held']
    composer = CandidateComposer([CandidateSet('S', source)], [CandidateBinding('X', 'S')])
    actual = [r.resolve(f'conv:{r.ordinal}').contributions[0].data for r in composer.rows()]
    assert generator._mutator.rng.getstate() == state
    assert list(generator.generate()) == actual
    prefix.close()


def test_sample_identity_components_are_unambiguous_with_colons():
    def sample(set_id, source_id):
        source = open_source(SourceSpec(source_id, 'literal', {'data': b'A'}))
        composer = CandidateComposer([CandidateSet(set_id, source)], [CandidateBinding('P', set_id)])
        rows = composer.rows()
        try:
            return next(rows).resolve('send').contributions[0].source_result.sample_id
        finally:
            rows.close()
    assert sample('a:b', 'c') != sample('a', 'b:c')


def test_shared_validator_accepts_separate_selected_send_contributions_and_rejects_split_within_send():
    composer = CandidateComposer([values('S', [b'A'])], [CandidateBinding('X', 'S'), CandidateBinding('Y', 'S')], 'broadcast')
    row = next(composer.rows())
    one, two = row.resolve('conv:one'), row.resolve('conv:two')
    c1, c2 = replace(one.contributions[0], contribution_id='one'), replace(two.contributions[0], contribution_id='two')
    placements = (Placement('one-x', 'one', 'one', 'append'), Placement('one-y', 'one', 'one', 'append'),
        Placement('two-x', 'two', 'two', 'append'))
    bindings = tuple(PositionBinding(p.placement_id, 'S', p.contribution_id, choice='shared') for p in placements)
    prepared = PreparedRow('row', 1, (c1, c2), placements, SelectionIntent('shared', bindings))
    plan = PassivePlan('neutral', 1, (ConversationAction('one', b''), ConversationAction('two', b'')))
    request = ConversationRequest(plan, prepared, ('one', 'two'), 'run', 'case', 'conv')
    validate_request(request, frozenset())
    broken = replace(prepared, placements=placements[:-1] + (replace(placements[-1], action_id='one'),))
    with pytest.raises(ContractError, match='within each selected send'):
        validate_request(replace(request, row=broken), frozenset())
