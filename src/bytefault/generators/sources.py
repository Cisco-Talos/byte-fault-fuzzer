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

"""Identified source specifications and lazy, attributed candidate streams.

These are generator-side inputs and outputs. They never place packet bytes,
transform records, import executable dataset plugins or perform network I/O.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
import random

from bytefault.core.contracts import RandomChoice, SourceInvocation, SourceResult, freeze
from bytefault.core.validation import ContractError
from bytefault.fuzzers.byte_mask import ByteMask
from bytefault.fuzzers.helpers import _load_seed_file
from bytefault.generators.base import FuzzGenerator
from bytefault.generators.edge_case import EdgeCaseGenerator
from bytefault.generators.file_gen import FileGenerator
from bytefault.generators.iterator import IteratorGenerator
from bytefault.generators.list_gen import ListGenerator
from bytefault.generators.random_bytes import RandomBytesGenerator
from bytefault.generators.sweep import SweepGenerator


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    kind: str
    options: Mapping = field(default_factory=dict)
    reference: str | None = None

    def __post_init__(self):
        try:
            if not isinstance(self.options, Mapping):
                raise ValueError('source options must be a passive mapping')
            object.__setattr__(self, 'options', freeze(self.options))
        except (TypeError, ValueError, MemoryError) as error:
            raise ContractError(f'sources.{self.source_id}.options', 'source_configuration', str(error)) from error


@dataclass(frozen=True)
class SourceCandidate:
    source: SourceInvocation
    result: SourceResult
    random_choices: tuple[RandomChoice, ...] = ()

    @property
    def data(self):
        return self.result.data

    @property
    def index(self):
        return self.result.index

    @property
    def source_id(self):
        return self.source.source_id


class SeedGenerator(FuzzGenerator):
    """Original seed bytes only; optional mutation is a separate stage.

    File seeds are read individually as selected, directory entries are sorted
    by filename. Counting lists names but never loads seed contents.
    """
    def __init__(self, seeds=(), files=(), *, encoding='binary', count=None, repeat_each=1):
        if encoding not in ('binary', 'hex'):
            raise ValueError('seed_encoding must be binary or hex')
        if count is not None and (type(count) is not int or count < 0):
            raise ValueError('count must be nonnegative')
        if type(repeat_each) is not int or repeat_each < 1:
            raise ValueError('repeat_each must be a positive integer')
        if (not isinstance(seeds, Sequence) or not isinstance(files, Sequence)
                or isinstance(files, (str, bytes))):
            raise ValueError('seeds and seed files require finite supplied sequences')
        seeds, files = tuple(seeds), tuple(files)
        if any(not isinstance(path, str) or not path for path in files):
            raise ValueError('seed files must be nonempty path strings')
        if any(type(seed) is not bytes for seed in seeds):
            raise ValueError('seeds must be exact bytes')
        self.seeds, self.files, self.encoding = tuple(seeds), tuple(files), encoding
        self.repeat_each = repeat_each
        if not self.seeds and not self.files:
            raise ValueError('at least one seed required')
        self.limit = (len(self.seeds) + len(self.files)) * repeat_each if count is None else count or None

    def selected_index(self, candidate_index):
        return ((candidate_index - 1) // self.repeat_each) % (len(self.seeds) + len(self.files))

    def generate(self):
        index = 0
        while self.limit is None or index < self.limit:
            selected = self.selected_index(index + 1)
            yield (self.seeds[selected] if selected < len(self.seeds) else
                   _load_seed_file(self.files[selected - len(self.seeds)], encoding=self.encoding))
            index += 1

    def count(self):
        return self.limit

    def metadata(self):
        return {'type': 'seed', 'seed_encoding': self.encoding, 'files': self.files,
                'seed_count': len(self.seeds) + len(self.files), 'count': self.limit,
                'repeat_each': self.repeat_each}


class SourceStream:
    """One run's source state, including held choices and advancing RNG state.

    ``candidates`` starts source enumeration and advances that run's RNG; opening
    the same SourceSpec creates a fresh reproducible run when seeded. ``refresh``
    redraws random properties for an identified candidate without index changes.
    Explicit Cartesian reuse uses the original candidate without refreshing it.
    """
    def __init__(self, spec: SourceSpec, generator: FuzzGenerator, mode: str):
        self.spec, self.generator = spec, generator
        self.source = SourceInvocation(spec.source_id, mode,
            'bytefault.generators.mutator' if spec.kind == 'mutate' else type(generator).__module__,
            dict(spec.options, kind=spec.kind), spec.reference or spec.options.get('path') or spec.options.get('seed_directory'))
        self._cursor = None

    @classmethod
    def from_generator(cls, generator, source_id='generator'):
        spec = getattr(generator, 'source_spec', None)
        from bytefault.generators.mutator import MutatorGenerator
        if isinstance(generator, MutatorGenerator) and (spec is None or generator._pipeline is not None):
            options = dict(spec.options) if spec is not None else {
                'seeds': tuple(generator._seeds), 'count': generator._count_limit or 0,
                'max_len': generator._mutator.max_len}
            options.pop('seed', None)
            options.update(mutation_scope=generator._mutation_scope,
                rng_state=generator._mutator.rng.getstate())
            if generator._pipeline is not None:
                options['mutation_held'] = tuple((name, occurrence, unit)
                    for (identity, name, occurrence), unit in generator._pipeline._held.items())
            return open_source(SourceSpec(spec.source_id if spec is not None else source_id,
                'mutate', options, spec.reference if spec is not None else None))
        if spec is not None:
            if spec.kind == 'mutate':
                return open_source(spec)
            mode = _mode(spec.kind, spec.options)
        else:
            spec = SourceSpec(source_id, 'generator', generator.metadata())
            mode = 'generator'
        return cls(spec, generator, mode)

    def _candidate(self, index, sample, iteration_id=None):
        data, choices = sample
        if type(data) is not bytes:
            raise ValueError('source returned non-byte candidate')
        resolved = tuple(RandomChoice(f'{self.spec.source_id}:{option}', 'source', option,
            bounds, scope, value, iteration_id if scope == 'per_test' else None)
            for option, bounds, scope, value in choices)
        reference = self.source.input_reference
        if isinstance(self.generator, SeedGenerator):
            reference = self.spec.reference
            seed_index = self.generator.selected_index(index)
            if seed_index >= len(self.generator.seeds):
                reference = self.generator.files[seed_index - len(self.generator.seeds)]
        return SourceCandidate(self.source, SourceResult(self.spec.source_id, data, index, reference), resolved)

    def candidates(self, iteration_id=None):
        samples = self.generator.samples()
        try:
            for index, sample in enumerate(samples, 1):
                identity = iteration_id(index) if callable(iteration_id) else iteration_id
                yield self._candidate(index, sample, identity)
        except (OSError, ValueError, OverflowError, MemoryError) as error:
            raise ContractError(f'sources.{self.spec.source_id}', 'source_failed', str(error)) from error
        finally:
            close = getattr(samples, 'close', None)
            if close is not None:
                close()

    def close(self):
        if self._cursor is not None:
            self._cursor.close()
            self._cursor = None

    def next_candidate(self, iteration_id=None):
        if self._cursor is None:
            self._cursor = self.candidates()
        candidate = next(self._cursor)
        return self._with_iteration(candidate, iteration_id)

    @staticmethod
    def _with_iteration(candidate, iteration_id):
        choices = tuple(RandomChoice(c.choice_id, c.owner, c.option, c.bounds,
            c.scope, c.resolved, iteration_id if c.scope == 'per_test' else None)
            for c in candidate.random_choices)
        return SourceCandidate(candidate.source, candidate.result, choices)

    def refresh(self, candidate: SourceCandidate, iteration_id=None):
        if candidate.source.source_id != self.spec.source_id:
            raise ContractError(f'sources.{self.spec.source_id}', 'contradictory_source', 'refresh identity differs')
        try:
            if isinstance(self.generator, SweepGenerator):
                return self._candidate(candidate.index, self.generator.sample(index=candidate.index), iteration_id)
            if isinstance(self.generator, RandomBytesGenerator):
                return self._candidate(candidate.index, self.generator.sample(), iteration_id)
            return self._with_iteration(candidate, iteration_id)
        except (ValueError, OverflowError, MemoryError) as error:
            raise ContractError(f'sources.{self.spec.source_id}', 'source_failed', str(error)) from error

    def generate(self):
        candidates = self.candidates()
        try:
            for candidate in candidates:
                yield candidate.data
        finally:
            candidates.close()

    def count(self):
        try:
            return self.generator.count()
        except (OSError, ValueError) as error:
            raise ContractError(f'sources.{self.spec.source_id}', 'source_failed', str(error)) from error

    @property
    def finite(self):
        if isinstance(self.generator, FileGenerator):
            return True
        return self.generator.count() is not None

    @property
    def known_count(self):
        """Cheap cardinality only; None also denotes unscanned finite lines."""
        if isinstance(self.generator, FileGenerator) and self.generator._source_mode == 'lines':
            return None
        return self.generator.count()

    def metadata(self):
        return dict(self.generator.metadata(), source_id=self.spec.source_id, kind=self.spec.kind)


def _mode(kind, options):
    if kind == 'file':
        return 'line_file' if options.get('source_mode', 'whole') == 'lines' else 'whole_file'
    return {'iter': 'iterator', 'edge': 'edge', 'mutate': 'mutation',
            'seed': 'seed_directory' if 'seed_directory' in options else 'file'}.get(kind, kind)


def open_source(spec: SourceSpec, *, datasets=None) -> SourceStream:
    """Validate one lossless spec and open its lazy generator-backed run."""
    path = f'sources.{getattr(spec, "source_id", "?")}'
    try:
        if not isinstance(spec, SourceSpec) or not spec.source_id or not isinstance(spec.source_id, str):
            raise ValueError('nonempty source_id and SourceSpec required')
        options = dict(spec.options)
        kind = spec.kind
        rng = random.Random(options['seed']) if options.get('seed') is not None else None
        random_keys = ('length_scope', 'content_scope', 'range_scope', 'byte_range', 'range_choices', 'exclude_bytes')
        common_random = {key: options[key] for key in random_keys if key in options}
        accepted = {
            'literal': {'data'}, 'list': {'payloads'},
            'file': {'path', 'source_mode', 'delimiter', 'chunk_size'},
            'dataset': {'name', 'subset'},
            'iter': {'ranges', 'excludes', 'width', 'endian', 'start_value', 'fill'},
            'edge': {'width', 'endian'},
            'random': {'min_len', 'max_len', 'count', 'seed', *random_keys},
            'sweep': {'start', 'stop', 'step', 'seed', *random_keys},
            'seed': {'seeds', 'seed_files', 'seed_directory', 'seed_encoding', 'count', 'repeat_each'},
            'mutate': {'seeds', 'seed_files', 'seed_directory', 'seed_encoding', 'count', 'repeat_each', 'seed', 'rng_state', 'max_len', 'mutation_scope', 'mutation_held'},
        }
        if kind not in accepted:
            raise ValueError(f'unknown source kind {kind!r}')
        unknown = set(options) - accepted[kind]
        if unknown:
            raise ValueError(f'unknown source options: {sorted(unknown)}')
        if kind == 'mutate' and 'rng_state' in options:
            if options.get('seed') is not None:
                raise ValueError('choose mutation seed or rng_state')
            try:
                random.Random().setstate(options['rng_state'])
            except (TypeError, ValueError, IndexError) as error:
                raise ValueError(f'invalid mutation rng_state: {error}') from error
        if kind == 'literal':
            generator = ListGenerator([options['data']])
        elif kind == 'list':
            generator = ListGenerator(options.get('payloads', ()))
        elif kind == 'file':
            generator = FileGenerator(**options)
        elif kind == 'dataset':
            name, subset = options['name'], options.get('subset', 'all')
            if not isinstance(datasets, Mapping) or name not in datasets or not isinstance(datasets[name], Mapping) or subset not in datasets[name]:
                raise ValueError(f'unknown data-only dataset/subset {name!r}/{subset!r}')
            generator = ListGenerator(datasets[name][subset])
        elif kind == 'iter':
            generator = IteratorGenerator(ByteMask(options['ranges'], options.get('excludes', ())),
                width=options.get('width', 1), endian=options.get('endian', 'big'),
                start_value=options.get('start_value'), fill=options.get('fill', False))
        elif kind == 'edge':
            generator = EdgeCaseGenerator(**options)
        elif kind == 'random':
            generator = RandomBytesGenerator(options.get('min_len', 1), options.get('max_len', 256),
                options.get('count'), rng, **common_random)
        elif kind == 'sweep':
            common_random.pop('length_scope', None)
            generator = SweepGenerator(options['start'], options['stop'], options.get('step', 1), rng, **common_random)
        else:
            supplied_files = options.get('seed_files', ())
            if (not isinstance(supplied_files, Sequence) or isinstance(supplied_files, (str, bytes))
                    or any(not isinstance(path, str) or not path for path in supplied_files)):
                raise ValueError('seed_files requires a finite supplied sequence')
            files = list(supplied_files)
            if 'seed_directory' in options:
                directory = Path(options['seed_directory'])
                if not directory.is_dir():
                    raise ValueError(f'seed directory not found: {directory}')
                files.extend(str(entry) for entry in sorted(directory.iterdir(), key=lambda entry: entry.name) if entry.is_file())
            generator = SeedGenerator(options.get('seeds', ()), files,
                encoding=options.get('seed_encoding', 'binary'), count=options.get('count', 100 if kind == 'mutate' else None),
                repeat_each=options.get('repeat_each', 1))
        generator.source_spec = spec
        return SourceStream(spec, generator, _mode(kind, options))
    except (ValueError, TypeError, KeyError, OSError, OverflowError, MemoryError) as error:
        raise ContractError(path, 'source_configuration', str(error)) from error
