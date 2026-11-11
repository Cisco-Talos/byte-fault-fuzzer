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

"""Independent exact source oracles under the offline pre-import guard."""
import builtins
import itertools
import random
from pathlib import Path

import pytest

from bytefault.core.contracts import ContractError
from bytefault.generators import (FileGenerator, ListGenerator, IteratorGenerator,
    RandomBytesGenerator, EdgeCaseGenerator, SweepGenerator,
    SourceSpec, SourceStream, open_source)
from bytefault.generators.cli_parser import parse_gen_field, parse_source_field, GenFieldParseError
from bytefault.fuzzers.byte_mask import ByteMask
from bytefault.fuzzers.helpers import _load_seed_file
from bytefault.generators.base import FuzzGenerator


@pytest.mark.parametrize('data', [b'', b'00ff', b' \x00\xff\x80#hello\r\n\n ', b'41\n42\n'])
def test_whole_file_exact_unmodified(tmp_path, data, application_factory, monkeypatch):
    path = tmp_path / 'input'
    path.write_bytes(data)
    target, spec, placement = parse_source_field(f'@1:file:{path},mode:overwrite')
    stream = open_source(spec)
    candidate, = stream.candidates()
    assert target == '@1' and placement == {'mode': 'overwrite'}
    assert stream.finite and stream.known_count == 1
    assert candidate.data == data
    assert candidate.result.index == 1
    assert candidate.source.mode == 'whole_file'
    assert candidate.source.input_reference == str(path)
    assert path.read_bytes() == data
    if data == b'41\n42\n':
        from bytefault.generators.transforms import MutationPipeline, TransformSpec
        _, lines, _ = parse_source_field(f'payload:file:{path},source_mode:lines')
        candidates = tuple(open_source(lines).candidates())
        assert [c.data for c in candidates] == [b'41', b'42']
        decoder = MutationPipeline((TransformSpec('hex','hex_decode'),))
        assert [decoder.apply(c.data).data for c in candidates] == [b'A', b'B']
        # Execute the documented argument construction through the shared
        # dispatcher with the fixture-owned transport.
        import json
        document = (Path(__file__).resolve().parents[3] / 'src/bytefault/protocols/raw/docs/USAGE.md').read_text()
        config_text = document.split('```json\n',1)[1].split('```',1)[0]
        config = json.loads(config_text)
        config['sources'][0]['options']['path'] = str(path)
        (tmp_path / 'hex-lines.json').write_text(json.dumps(config),encoding='utf-8')
        code = document.split('```python\n',1)[1].split('```',1)[0]
        code = code.replace('<DEVICE_IP>','offline.invalid').replace('<PORT>','1234')
        assert code.count('app = Application()') == 1
        code = code.replace('app = Application()', 'app = supplied_app', 1)
        monkeypatch.chdir(tmp_path)
        app, traces = application_factory()
        namespace = {'supplied_app': app}
        exec(compile(code,'Raw USAGE hex-lines example','exec'),namespace)
        assert namespace['result'].outcome == 'completed' and namespace['result'].fuzz_tests == 2
        assert [step[1] for trace, _, _ in traces for step in trace if step[0] == 'offer'] == [b'A',b'B']


@pytest.mark.parametrize('data,delimiter,expected', [
    (b'A\n\nB\n', b'\n', [b'A', b'', b'B']),
    (b'', b'\n', []), (b'\n', b'\n', [b'']),
    (b'\n\n', b'\n', [b'', b'']),
    (b'A\r\n\nB\r\nC', b'\n', [b'A\r', b'', b'B\r', b'C']),
    (b'A\r\n\r\nB\r\nC', b'\r\n', [b'A', b'', b'B', b'C']),
    (b'\xff\x00xyzxyz\x80xyzend', b'xyz', [b'\xff\x00', b'', b'\x80', b'end']),
    (b'aaaaa', b'aa', [b'', b'', b'a']),
    (b'a\x00\xffa\x00\xff', b'a\x00\xff', [b'', b'']),
])
@pytest.mark.parametrize('chunk_size', [1, 2, 4, 65536])
def test_incremental_binary_records(tmp_path, data, delimiter, expected, chunk_size):
    path = tmp_path / 'records'
    path.write_bytes(data)
    source = open_source(SourceSpec('records', 'file', {'path': str(path),
        'source_mode': 'lines', 'delimiter': delimiter, 'chunk_size': chunk_size}))
    assert source.finite and source.known_count is None
    assert [candidate.data for candidate in source.candidates()] == expected
    assert source.count() == len(expected)
    assert path.read_bytes() == data


def test_prefix_does_not_read_whole_record_source(tmp_path, monkeypatch):
    path = tmp_path / 'large'
    data = b'one\n' + b'X' * 100000
    path.write_bytes(data)
    ordinary_open = builtins.open
    read_sizes = []
    class Reader:
        def __init__(self, wrapped): self.wrapped = wrapped
        def __enter__(self): return self
        def __exit__(self, *args): self.wrapped.close()
        def read(self, size=-1):
            assert size == 8
            result = self.wrapped.read(size)
            read_sizes.append(len(result))
            return result
    monkeypatch.setattr(builtins, 'open', lambda name, mode: Reader(ordinary_open(name, mode)))
    source = open_source(SourceSpec('prefix', 'file', {'path': str(path), 'source_mode': 'lines', 'chunk_size': 8}))
    records = source.candidates()
    assert next(records).data == b'one'
    assert read_sizes == [8]
    records.close()


def test_stream_close_releases_prefix_file(tmp_path, monkeypatch):
    path = tmp_path / 'prefix'
    path.write_bytes(b'A\nB\nC\n')
    ordinary_open = builtins.open
    handles = []
    def track(name, mode):
        handle = ordinary_open(name, mode)
        handles.append(handle)
        return handle
    monkeypatch.setattr(builtins, 'open', track)
    source = open_source(SourceSpec('prefix', 'file', {'path': str(path), 'source_mode': 'lines'}))
    assert source.next_candidate().data == b'A'
    assert len(handles) == 1 and not handles[0].closed
    source.close()
    assert handles[0].closed
    source.close()


def test_list_modifiers_and_structured_losslessness(tmp_path):
    target, generator = parse_gen_field('@1:list:5a,00ff,mode:overwrite')
    assert target == '@1' and generator.injection_mode == 'overwrite'
    assert list(generator.generate()) == [b'Z', b'\0\xff']
    empty = open_source(SourceSpec('list', 'list', {'payloads': (b'', b' ', b'\0\xff')}))
    assert [candidate.data for candidate in empty.candidates()] == [b'', b' ', b'\0\xff']
    mutable = [b'A', b'B']
    generator = ListGenerator(mutable)
    mutable.reverse()
    assert list(generator.generate()) == [b'A', b'B']
    path = tmp_path / 'a,b'
    path.write_bytes(b'bytes')
    with pytest.raises(GenFieldParseError, match='SourceSpec'):
        parse_source_field(f'@1:file:{path}')
    assert list(open_source(SourceSpec('file', 'file', {'path': str(path)})).generate()) == [b'bytes']


@pytest.mark.parametrize('spec', [
    '@1:list:5a,mode:unknown', '@-1:list:5a', '@1:list:5a,mode:overwrite,mode:insert',
    '@1:list:5a,', '@1:list:5a,width:1', '@1:random:1-2,count:-1',
    '@1:file:missing,source_mode:lines,delimiter_hex:', '@1:file:missing,delimiter_hex:0a',
    'x:list:5a,mode:overwrite', '@1:iter:5-1', '@1:edge:accidental',
])
def test_attributed_parser_configuration_failures(spec):
    with pytest.raises((GenFieldParseError, ContractError)):
        target, source, placement = parse_source_field(spec)
        open_source(source)


def test_data_only_dataset_order_subset_and_empty():
    datasets = {'neutral': {'all': [b'2', b'1', b'2'], 'vendor.x': [b'\xff', b''], 'empty': []}}
    _, spec, _ = parse_source_field('@1:dataset:neutral.vendor.x,mode:overwrite')
    assert list(open_source(spec, datasets=datasets).generate()) == [b'\xff', b'']
    _, generator = parse_gen_field('@1:dataset:neutral', datasets=datasets)
    assert list(generator.generate()) == [b'2', b'1', b'2']
    empty = open_source(SourceSpec('empty', 'dataset', {'name': 'neutral', 'subset': 'empty'}), datasets=datasets)
    assert empty.count() == 0 and list(empty.generate()) == []
    with pytest.raises(ContractError, match='data-only'):
        open_source(spec, datasets=object())


def test_iterator_mask_width_start_fill_edge_and_public_sweep():
    generator = IteratorGenerator(ByteMask([(254, 258)], [255]), width=2, endian='little', start_value=256)
    assert list(generator.generate()) == [b'\0\x01', b'\x01\x01', b'\x02\x01']
    _, generator = parse_gen_field('@0:iter:0x01-0x03,exclude:0x02,width:3,fill')
    assert list(generator.generate()) == [b'\x01' * 3, b'\x03' * 3]
    expected = [0, 1, 2, 15, 16, 31, 32, 63, 64, 65, 126, 127, 128, 129, 191, 192, 254, 255]
    assert list(EdgeCaseGenerator().generate()) == [bytes([n]) for n in expected]
    _, sweep = parse_gen_field('@0:sweep:0-4,step:2,seed:17')
    assert isinstance(sweep, SweepGenerator)
    assert [len(payload) for payload in sweep.generate()] == [0, 2, 4]
    _, wide = parse_gen_field('@0:iter:0x100-0x101')
    assert list(wide.generate()) == [b'\x01\0', b'\x01\x01']


def test_binary_and_explicit_hex_seed_inputs_sorted_directory(tmp_path):
    (tmp_path / 'b').write_bytes(b'00ff')
    (tmp_path / 'a').write_bytes(b'\x00\xff')
    (tmp_path / 'ignored-dir').mkdir()
    source = open_source(SourceSpec('seeds', 'seed', {'seed_directory': str(tmp_path)}))
    values = list(source.candidates())
    assert [value.data for value in values] == [b'\0\xff', b'00ff']
    assert [Path(value.result.input_reference).name for value in values] == ['a', 'b']
    assert _load_seed_file(str(tmp_path / 'b')) == b'00ff'
    assert _load_seed_file(str(tmp_path / 'b'), encoding='hex') == b'\0\xff'
    source = open_source(SourceSpec('hex', 'seed', {'seed_files': (str(tmp_path / 'b'),), 'seed_encoding': 'hex'}))
    assert list(source.generate()) == [b'\0\xff']
    source = open_source(SourceSpec('mutate', 'mutate', {'seeds': (b'A', b'B'), 'count': 5}))
    assert list(source.generate()) == [b'A', b'B', b'A', b'B', b'A']
    assert source.source.mode == 'mutation'


class ControlledRandom(random.Random):
    def __init__(self):
        super().__init__(0)
        self.calls = []
        self.counter = 0
    def randint(self, lo, hi):
        self.calls.append(('randint', lo, hi))
        result = lo + self.counter % (hi - lo + 1)
        self.counter += 1
        return result
    def randrange(self, size):
        self.calls.append(('byte', size))
        result = self.counter % size
        self.counter += 1
        return result
    def randbytes(self, length):
        self.calls.append(('randbytes', length))
        result = bytes((self.counter + index) % 256 for index in range(length))
        self.counter += length
        return result


def test_independent_held_length_fresh_content_and_range():
    rng = ControlledRandom()
    generator = RandomBytesGenerator(2, 4, 3, rng, length_scope='sample_once',
        range_choices=((0, 3), (250, 255)), range_scope='per_test')
    source = SourceStream.from_generator(generator, 'random')
    values = [source.next_candidate(f'iteration-{i}') for i in range(3)]
    assert all(len(value.data) == 2 for value in values)
    assert len([call for call in rng.calls if call == ('randint', 2, 4)]) == 1
    assert len([call for call in rng.calls if call == ('randint', 0, 1)]) == 3
    assert len([call for call in rng.calls if call[0] == 'byte']) == 6
    for i, value in enumerate(values):
        assert [(choice.option, choice.scope) for choice in value.random_choices] == [
            ('length', 'sample_once'), ('range', 'per_test'), ('content', 'per_test')]
        assert value.random_choices[0].iteration_id is None
        assert value.random_choices[2].iteration_id == f'iteration-{i}'
        lo, hi = value.random_choices[1].resolved['bounds']
        assert all(lo <= byte <= hi for byte in value.data)


def test_held_content_and_seeded_sequences_and_refresh():
    rng = ControlledRandom()
    generator = RandomBytesGenerator(2, 4, 3, rng, length_scope='sample_once', content_scope='sample_once')
    values = list(generator.generate())
    assert values == [values[0]] * 3
    assert rng.calls == [('randint', 2, 4), ('randbytes', 4)]
    spec = SourceSpec('seeded', 'random', {'min_len': 2, 'max_len': 4, 'count': 5, 'seed': 42})
    first, second = open_source(spec), open_source(spec)
    assert list(first.generate()) == list(second.generate())
    first = open_source(spec)
    candidate = first.next_candidate('first')
    refreshed = first.refresh(candidate, 'second')
    assert candidate.index == refreshed.index == 1
    assert all(choice.iteration_id == 'second' for choice in refreshed.random_choices)
    reference = list(open_source(spec).generate())
    assert [candidate.data, refreshed.data] == reference[:2]
    assert not open_source(SourceSpec('infinite', 'random', {'min_len': 0, 'max_len': 0})).finite
    # Repeats from singleton ranges remain valid while draw count proves refresh.
    rng = ControlledRandom()
    generator = RandomBytesGenerator(1, 1, 3, rng, byte_range=(7, 7))
    assert list(generator.generate()) == [b'\x07'] * 3
    assert rng.calls == [('byte', 1)] * 3


def test_random_scope_errors_and_sweep_attribution():
    with pytest.raises(ContractError, match='contradictory_scope'):
        open_source(SourceSpec('bad', 'random', {'min_len': 1, 'max_len': 3, 'content_scope': 'sample_once',
            'range_choices': ((0, 3), (128, 131))}))
    source = open_source(SourceSpec('sweep', 'sweep', {'start': 2, 'stop': 4, 'step': 2,
        'seed': 7, 'range_choices': ((0, 3), (128, 130)), 'range_scope': 'sample_once'}))
    candidates = list(source.candidates('packet'))
    assert [len(candidate.data) for candidate in candidates] == [2, 4]
    assert all(candidate.random_choices[0].scope == 'sample_once' for candidate in candidates)
    assert len(source.refresh(candidates[0], 'next').data) == 2


def test_source_failure_is_attributed(tmp_path):
    path = tmp_path / 'source'
    path.write_bytes(b'good')
    source = open_source(SourceSpec('removed', 'file', {'path': str(path)}))
    path.unlink()
    with pytest.raises(ContractError, match='sources.removed'):
        next(source.candidates())


def test_retained_generator_facade_distinguishes_unbounded():
    class Custom(FuzzGenerator):
        def __init__(self, limit): self.limit = limit
        def generate(self):
            for index in itertools.count():
                if self.limit is not None and index >= self.limit:
                    return
                yield bytes([index % 256])
        def count(self): return self.limit
        def metadata(self): return {'type': 'custom'}
    finite = SourceStream.from_generator(Custom(2), 'finite')
    unbounded = SourceStream.from_generator(Custom(None), 'unbounded')
    assert finite.finite and finite.known_count == 2
    assert not unbounded.finite and unbounded.known_count is None
    assert [value.data for value in itertools.islice(unbounded.candidates(), 3)] == [b'\0', b'\x01', b'\x02']


def test_wide_numeric_range_prefix_and_cheap_exact_counts(monkeypatch):
    def forbidden_materialization(*args):
        raise AssertionError('numeric source must not materialize mask members')
    monkeypatch.setattr(ByteMask, 'get_values', forbidden_materialization)
    source = open_source(SourceSpec('wide', 'iter', {'ranges': ((0, (1 << 64) - 1),),
        'excludes': (2, (1 << 64) - 2), 'width': 8}))
    assert source.finite
    assert source.count() == source.known_count == (1 << 64) - 2
    assert [candidate.data for candidate in itertools.islice(source.candidates(), 4)] == [
        b'\0' * 8, b'\0' * 7 + b'\x01', b'\0' * 7 + b'\x03', b'\0' * 7 + b'\x04']
    tail = IteratorGenerator(ByteMask([(0, (1 << 64) - 1)], []), width=8,
        start_value=(1 << 64) - 2)
    assert tail.count() == 2
    assert list(tail.generate()) == [b'\xff' * 7 + b'\xfe', b'\xff' * 8]


def test_lazy_masks_preserve_overlap_exclusions_start_and_snapshot():
    mask = ByteMask([(8, 9), (3, 5), (1, 4)], [4])
    assert mask.get_values() == [8, 9, 3, 5, 1, 2, 3]
    resumed = IteratorGenerator(mask, start_value=3)
    assert list(resumed.generate()) == [b'\x03', b'\x05', b'\x01', b'\x02', b'\x03']
    assert resumed.count() == 5
    for missing in (4, 99):
        fallback = IteratorGenerator(mask, start_value=missing)
        assert fallback.count() == 7
        assert list(fallback.generate()) == [bytes([n]) for n in (8, 9, 3, 5, 1, 2, 3)]
    mask.excludes.add(3)
    assert list(resumed.generate()) == [b'\x03', b'\x05', b'\x01', b'\x02', b'\x03']


def test_finite_supplied_sequences_reject_one_shot_without_consumption():
    from bytefault.generators.sources import SeedGenerator
    payloads = iter((b'A', b'B'))
    with pytest.raises(ValueError, match='finite supplied sequence'):
        ListGenerator(payloads)
    assert next(payloads) == b'A'
    seeds = iter((b'A', b'B'))
    with pytest.raises(ValueError, match='finite supplied sequences'):
        SeedGenerator(seeds)
    assert next(seeds) == b'A'
    ranges = iter(((0, 2),))
    with pytest.raises(ValueError, match='finite supplied sequences'):
        ByteMask(ranges, [])
    assert next(ranges) == (0, 2)
    excludes = iter((1, 2))
    with pytest.raises(ValueError, match='finite supplied sequences'):
        ByteMask([(0, 3)], excludes)
    assert next(excludes) == 1
    with pytest.raises(ContractError, match='sources.one-shot.options.*tuple_iterator'):
        open_source(SourceSpec('one-shot', 'list', {'payloads': iter((b'A', b'B'))}))


def test_repeat_each_seed_grouping_and_selected_file_references(tmp_path):
    path = tmp_path / 'external'
    path.write_bytes(b'F')
    options = {'seeds': (b'A', b'B'), 'seed_files': (str(path),)}
    cycled = list(open_source(SourceSpec('cycle', 'seed', dict(options, count=7))).candidates())
    grouped = list(open_source(SourceSpec('groups', 'seed', dict(options, repeat_each=2))).candidates())
    assert [candidate.data for candidate in cycled] == [b'A', b'B', b'F', b'A', b'B', b'F', b'A']
    assert [candidate.data for candidate in grouped] == [b'A', b'A', b'B', b'B', b'F', b'F']
    assert [candidate.result.input_reference for candidate in grouped] == [None, None, None, None, str(path), str(path)]
    assert [candidate.result.input_reference for candidate in cycled] == [None, None, str(path), None, None, str(path), None]
    bounded = open_source(SourceSpec('bounded', 'seed', dict(options, repeat_each=2, count=8)))
    assert list(bounded.generate()) == [b'A', b'A', b'B', b'B', b'F', b'F', b'A', b'A']


def test_unrestricted_seeded_bytes_preserve_prior_randbytes_algorithm():
    reference = random.Random(42)
    expected = [reference.randbytes(3) for _ in range(4)]
    generator = RandomBytesGenerator(3, 3, count_limit=4, rng=random.Random(42))
    assert list(generator.generate()) == expected
    selected_full = RandomBytesGenerator(3, 3, count_limit=4, rng=random.Random(42),
        range_choices=((0, 255),))
    assert list(selected_full.generate()) == expected
    trace = ControlledRandom()
    assert len(RandomBytesGenerator(1024, 1024, 1, trace).sample()[0]) == 1024
    assert trace.calls == [('randbytes', 1024)]


def test_held_reservoir_with_fresh_lengths_records_prefix_and_full_choice():
    trace = ControlledRandom()
    source = SourceStream.from_generator(RandomBytesGenerator(1, 3, 3, trace,
        content_scope='sample_once'), 'reservoir')
    candidates = [source.next_candidate(f'packet-{index}') for index in range(3)]
    assert [candidate.data for candidate in candidates] == [b'\x01', b'\x01\x02', b'\x01\x02\x03']
    assert trace.calls == [('randint', 1, 3), ('randbytes', 3), ('randint', 1, 3), ('randint', 1, 3)]
    assert [candidate.random_choices[0].resolved for candidate in candidates] == [1, 2, 3]
    assert [candidate.random_choices[1].resolved for candidate in candidates] == [b'\x01\x02\x03'] * 3
    assert all(candidate.random_choices[1].scope == 'sample_once' for candidate in candidates)
    assert all(candidate.result.data == candidate.random_choices[1].resolved[:candidate.random_choices[0].resolved]
               for candidate in candidates)
    # Fixed/held alphabet remains compatible with that reservoir policy.
    source = open_source(SourceSpec('held', 'random', {'min_len': 1, 'max_len': 3, 'count': 3,
        'seed': 4, 'content_scope': 'sample_once', 'range_scope': 'sample_once',
        'range_choices': ((0, 2), (253, 255))}))
    values = list(source.candidates())
    assert all(value.data == values[0].random_choices[-1].resolved[:len(value.data)] for value in values)
    with pytest.raises(ValueError, match='outside configured payload bounds'):
        RandomBytesGenerator(1, 3, content_scope='sample_once').sample(length=4)


def test_sweep_held_reservoir_preserves_indexed_prefix_lengths():
    trace = ControlledRandom()
    source = SourceStream.from_generator(SweepGenerator(1, 3, rng=trace, content_scope='sample_once'), 'sweep')
    candidates = list(source.candidates())
    assert [candidate.data for candidate in candidates] == [b'\0', b'\0\x01', b'\0\x01\x02']
    assert trace.calls == [('randbytes', 3)]
    assert [candidate.random_choices[0].resolved for candidate in candidates] == [b'\0\x01\x02'] * 3
    assert source.refresh(candidates[0], 'another').data == b'\0'
    assert trace.calls == [('randbytes', 3)]


@pytest.mark.parametrize('value', ['input.bin', b'input.bin', ('valid', 3), ('',)])
def test_malformed_seed_file_collection_is_attributed(value):
    with pytest.raises(ContractError, match='seed_files requires a finite supplied sequence'):
        open_source(SourceSpec('bad-files', 'seed', {'seed_files': value}))


def test_direct_mutator_generator_adapter_exposes_raw_seeds_and_rng_state():
    from bytefault.generators.mutator import MutatorGenerator
    generator = MutatorGenerator([b'ABC', b'DEF'], count_limit=3, rng=random.Random(11), max_len=8)
    expected_state = generator._mutator.rng.getstate()
    source = SourceStream.from_generator(generator, 'adapted-mutation')
    candidates = list(source.candidates())
    assert source.spec.kind == 'mutate'
    assert [candidate.result.data for candidate in candidates] == [b'ABC', b'DEF', b'ABC']
    assert source.spec.options['rng_state'] == expected_state
    assert generator._mutator.rng.getstate() == expected_state
    assert source.spec.options['max_len'] == 8
