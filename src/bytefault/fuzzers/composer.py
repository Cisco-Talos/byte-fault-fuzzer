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

"""Mutator-owned candidate selection; packet placement remains fuzzer-owned."""
from __future__ import annotations
from dataclasses import dataclass, replace
import itertools
from bytefault.core.contracts import (ContractError, PositionBinding, PreparedContribution,
    PreparedRow, SelectionIntent, SourceInvocation, SourceResult)
from bytefault.generators.sources import SourceStream
from bytefault.generators.transforms import MutationPipeline, PreparationDisposition, TransformSpec


@dataclass(frozen=True)
class CandidateSet:
    set_id: str
    source: SourceStream
    transforms: tuple[TransformSpec, ...] = ()
    pool_mode: str = 'fresh'


@dataclass(frozen=True)
class CandidateBinding:
    position_id: str
    set_id: str
    baseline: bytes | None = None


@dataclass
class _Entry:
    candidate: object
    prefix: object
    accepted_index: int
    used: bool = False


_STRATEGIES = {'single': 'retained_single', 'one-position': 'one_position',
    'broadcast': 'shared', 'zip': 'zip', 'cartesian': 'finite_product',
    'hybrid-cartesian': 'hybrid_product'}


class PreparationCancelled(Exception):
    """Internal cancellation: discard the incomplete row without delivering it."""


def _choices(choices, iteration_id, *, reuse=False):
    return tuple(replace(c, scope='sample_once' if reuse else c.scope,
        iteration_id=None if reuse or c.scope == 'sample_once' else iteration_id) for c in choices)


class ComposedRow:
    """Identified selection, resolved separately for each selected send."""
    def __init__(self, composer, ordinal, selections, bounds):
        self.composer, self.ordinal = composer, ordinal
        self.row_id, self.selections, self.bounds = f'generated:{ordinal}', tuple(selections), bounds

    def resolve(self, iteration_id=None, position_ids=None, *, context=None):
        if self.composer.cancelled():
            raise PreparationCancelled()
        wanted = None if position_ids is None else set(position_ids)
        known = {binding.position_id for binding, entry, choice in self.selections}
        if wanted is not None and wanted - known:
            raise ContractError('composition.positions', 'unknown_position', str(sorted(wanted - known)))
        contributions, bindings, resolved = [], [], {}
        for binding, entry, choice in self.selections:
            if self.composer.cancelled():
                raise PreparationCancelled()
            if wanted is not None and binding.position_id not in wanted:
                continue
            runtime = self.composer._sets[binding.set_id]
            key = (binding.set_id, id(entry)) if choice == 'shared' else binding.position_id
            if key not in resolved:
                cid = f'{self.row_id}:{binding.set_id}:{len(contributions) + 1}'
                if entry is None:
                    if binding.baseline is None:
                        raise ContractError(f'composition.{binding.position_id}', 'missing_baseline',
                            'empty inactive source requires an explicit baseline')
                    source = SourceInvocation(f'baseline:{binding.position_id}', 'literal',
                        options={'position_id': binding.position_id, 'baseline': True})
                    contribution = PreparedContribution(cid, binding.baseline, source, set_id=binding.set_id,
                        source_result=SourceResult(source.source_id, binding.baseline, 1))
                else:
                    candidate, prefix = runtime.resolve_source(entry, iteration_id)
                    try:
                        suffix = runtime.pipeline.apply(prefix.data, iteration_id, start=runtime.boundary, context=context)
                    except ContractError as error:
                        runtime.record_error(candidate, error, prefix)
                        raise
                    contribution = PreparedContribution(cid, suffix.data, candidate.source,
                        prefix.mutators + suffix.mutators, binding.set_id, entry.accepted_index,
                        candidate.random_choices + prefix.random_choices + suffix.random_choices,
                        candidate.result, prefix.results + suffix.results)
                resolved[key] = contribution
                contributions.append(contribution)
            contribution = resolved[key]
            bindings.append(PositionBinding(binding.position_id, binding.set_id, contribution.contribution_id,
                binding.baseline if binding.baseline is not None else b'', choice))
        dimensions = tuple(k for k in self.composer.dimension_order if any(b.set_id == k for b in bindings))
        if self.composer.cancelled():
            raise PreparationCancelled()
        return PreparedRow(self.row_id, self.ordinal, tuple(contributions), selection=SelectionIntent(
            _STRATEGIES[self.composer.strategy], tuple(bindings), dimensions,
            bounds=self.bounds, exhaustion=self.composer.exhaustion))


class _SetRun:
    def __init__(self, spec, owner):
        self.spec, self.owner = spec, owner
        self._sample_ordinal = 0
        transforms = tuple(spec.transforms)
        if spec.source.spec.kind == 'mutate':
            opts = spec.source.spec.options
            mutation_options = {'max_len': opts.get('max_len'), 'scope': opts.get('mutation_scope', 'per_test')}
            if 'rng_state' in opts:
                mutation_options['rng_state'] = opts['rng_state']
            else:
                mutation_options['seed'] = opts.get('seed')
            if 'mutation_held' in opts:
                mutation_options['held_decisions'] = opts['mutation_held']
            transforms = (TransformSpec(f'{spec.set_id}:mutation', 'mutate', mutation_options),) + transforms
        self.pipeline = MutationPipeline(transforms)
        self.boundary = self.pipeline.last_filter + 1
        if self.boundary and owner.disposition_sink is None:
            raise ContractError(f'composition.{spec.set_id}', 'missing_disposition_sink',
                'composed filters require a sink for every excluded source record')
        if spec.pool_mode not in ('fresh', 'reuse'):
            raise ContractError(f'composition.{spec.set_id}', 'invalid_pool_mode', spec.pool_mode)

    def identify(self, candidate):
        self._sample_ordinal += 1
        set_id, source_id = self.spec.set_id, candidate.source_id
        return replace(candidate, result=replace(candidate.result,
            sample_id=f'{len(set_id)}:{set_id}:{len(source_id)}:{source_id}:sample:{self._sample_ordinal}'))

    def rejected(self, candidate, prefix):
        reuse = self.spec.pool_mode == 'reuse'
        choices = _choices(candidate.random_choices + prefix.random_choices, None, reuse=True) if reuse else candidate.random_choices + prefix.random_choices
        self.owner.disposition_sink(PreparationDisposition(self.spec.set_id,
            candidate.source, candidate.result, prefix.mutators, prefix.results,
            choices, prefix.disposition))

    def accepted(self):
        candidates, index = self.spec.source.candidates(), 0
        try:
            while not self.owner.cancelled():
                try:
                    candidate = self.identify(next(candidates))
                except StopIteration:
                    return
                try:
                    prefix = self.pipeline.apply(candidate.data, stop=self.boundary)
                except ContractError as error:
                    self.record_error(candidate, error)
                    raise
                if prefix.disposition != 'accepted':
                    self.rejected(candidate, prefix)
                    continue
                index += 1
                yield _Entry(candidate, prefix, index)
        finally:
            candidates.close()

    def resolve_source(self, entry, iteration_id):
        reuse = self.spec.pool_mode == 'reuse'
        candidate = entry.candidate
        if entry.used and not reuse:
            while not self.owner.cancelled():
                candidate = self.identify(self.spec.source.refresh(entry.candidate, iteration_id))
                try:
                    prefix = self.pipeline.apply(candidate.data, iteration_id, stop=self.boundary)
                except ContractError as error:
                    self.record_error(candidate, error)
                    raise
                if prefix.disposition == 'accepted':
                    break
                self.rejected(candidate, prefix)
            else:
                raise PreparationCancelled()
        else:
            candidate = replace(candidate, random_choices=_choices(candidate.random_choices, iteration_id, reuse=reuse))
            prefix = entry.prefix
        prefix = replace(prefix, random_choices=_choices(prefix.random_choices, iteration_id, reuse=reuse))
        entry.used = True
        return candidate, prefix

    def record_error(self, candidate, error, prefix=None):
        if self.owner.disposition_sink is None:
            return
        partial = getattr(error, 'partial', None)
        mutators = (() if prefix is None else prefix.mutators) + (() if partial is None else partial.mutators)
        results = (() if prefix is None else prefix.results) + (() if partial is None else partial.results)
        choices = candidate.random_choices + (() if prefix is None else prefix.random_choices) + (() if partial is None else partial.random_choices)
        failed = getattr(error, 'failed_mutator', None)
        self.owner.disposition_sink(PreparationDisposition(self.spec.set_id, candidate.source,
            candidate.result, mutators + (() if failed is None else (failed,)), results, choices, 'error:' + str(error)))


class CandidateComposer:
    """Lazy rows except explicitly finite indexed source pools.

    Source/filter prefix reuse is distinct from fresh downstream transforms.
    Cancellation is checked per source record, including excluded records.
    """
    def __init__(self, sets, bindings, strategy='single', *, disposition_sink=None, cancelled=None):
        sets = tuple(sets.values()) if isinstance(sets, dict) else tuple(sets)
        self.bindings, self.strategy = tuple(bindings), strategy
        self.disposition_sink, self.cancelled = disposition_sink, cancelled or (lambda: False)
        if strategy not in _STRATEGIES:
            raise ContractError('composition.strategy', 'unsupported_strategy', str(strategy))
        if len({s.set_id for s in sets}) != len(sets) or any(not s.set_id for s in sets):
            raise ContractError('composition.sets', 'duplicate_identity', 'unique nonempty set identities required')
        if len({b.position_id for b in self.bindings}) != len(self.bindings) or any(not b.position_id for b in self.bindings):
            raise ContractError('composition.bindings', 'duplicate_identity', 'unique nonempty position identities required')
        by_id = {s.set_id: s for s in sets}
        if {b.set_id for b in self.bindings} - set(by_id):
            raise ContractError('composition.bindings', 'unknown_set', 'binding names missing set')
        if any(b.baseline is not None and type(b.baseline) is not bytes for b in self.bindings):
            raise ContractError('composition.baseline', 'malformed', 'baseline must be exact bytes')
        self.dimension_order = tuple(dict.fromkeys(b.set_id for b in self.bindings))
        if strategy in ('broadcast', 'one-position') and len(self.dimension_order) > 1:
            raise ContractError('composition.bindings', 'ambiguous_shared_set', 'strategy requires one explicitly shared set')
        if strategy == 'one-position' and any(b.baseline is None for b in self.bindings):
            raise ContractError('composition.baseline', 'missing_baseline', 'one-position requires every unmodified baseline')
        self._sets = {key: _SetRun(by_id[key], self) for key in self.dimension_order}
        if strategy == 'cartesian' and any(not run.spec.source.finite for run in self._sets.values()):
            raise ContractError('composition.cartesian', 'unbounded_pool',
                'finite indexed pools required; use explicit hybrid-cartesian for finite/unbounded advancement')
        if strategy == 'hybrid-cartesian' and self._sets and not any(run.spec.source.finite for run in self._sets.values()):
            raise ContractError('composition.hybrid', 'missing_finite_driver', 'at least one finite source required')
        self.exhaustion = {'single': 'ordered_sources', 'one-position': 'ordered_positions',
            'broadcast': 'shared_source', 'zip': 'shortest_source', 'cartesian': 'finite_product',
            'hybrid-cartesian': 'finite_driver_or_source'}[strategy]

    def _bounds(self, entries, **extra):
        return dict(strategy=self.strategy,
            source_pool_modes={key: run.spec.pool_mode for key, run in self._sets.items()},
            source_indices={key: entry.candidate.index for key, entry in entries.items() if entry is not None},
            accepted_indices={key: entry.accepted_index for key, entry in entries.items() if entry is not None},
            filter_boundaries={key: run.boundary for key, run in self._sets.items()}, **extra)

    def rows(self):
        if not self.bindings:
            return
        if self.strategy == 'single':
            yield from self._single()
        elif self.strategy == 'one-position':
            ordinal, run = 0, self._sets[self.dimension_order[0]]
            pool = None
            if run.spec.pool_mode == 'reuse' and run.spec.source.finite:
                values = run.accepted()
                try:
                    pool = list(values)
                except (MemoryError, OverflowError) as error:
                    raise ContractError(f'composition.{run.spec.set_id}.pool', 'allocation_failed', str(error)) from error
                finally:
                    values.close()
            for active in self.bindings:
                values = iter(pool) if pool is not None else run.accepted()
                try:
                    for entry in values:
                        ordinal += 1
                        yield ComposedRow(self, ordinal, [(b, entry if b == active else None,
                            'selected' if b == active else 'baseline') for b in self.bindings],
                            self._bounds({active.set_id: entry}, active_position=active.position_id))
                finally:
                    close = getattr(values, 'close', None)
                    if close is not None:
                        close()
                if self.cancelled():
                    return
        elif self.strategy == 'broadcast':
            values = self._sets[self.dimension_order[0]].accepted()
            try:
                for ordinal, entry in enumerate(values, 1):
                    yield ComposedRow(self, ordinal, [(b, entry, 'shared') for b in self.bindings],
                        self._bounds({self.dimension_order[0]: entry}))
            finally:
                values.close()
        elif self.strategy == 'zip':
            values = [run.accepted() for run in self._sets.values()]
            try:
                for ordinal, entries in enumerate(zip(*values), 1):
                    selected = dict(zip(self.dimension_order, entries))
                    yield ComposedRow(self, ordinal, [(b, selected[b.set_id], 'selected') for b in self.bindings], self._bounds(selected))
            finally:
                for value in values:
                    value.close()
        else:
            yield from self._product()

    def _single(self):
        values = {key: run.accepted() for key, run in self._sets.items()}
        initial = {}
        try:
            for key, value in values.items():
                initial[key] = next(value, None)
            for b in self.bindings:
                if initial[b.set_id] is None and b.baseline is None and any(e is not None for e in initial.values()):
                    raise ContractError(f'composition.{b.position_id}', 'missing_baseline', 'empty source needs its supplied baseline')
            ordinal = 0
            for active in self.bindings:
                first = initial[active.set_id]
                if first is None:
                    continue
                repeated = any(b.set_id == active.set_id for b in self.bindings[:self.bindings.index(active)])
                sequence = self._sets[active.set_id].accepted() if repeated else itertools.chain((first,), values[active.set_id])
                try:
                    for entry in sequence:
                        if self.cancelled():
                            return
                        ordinal += 1
                        chosen = dict(initial)
                        chosen[active.set_id] = entry
                        yield ComposedRow(self, ordinal, [(b, entry if b == active else initial[b.set_id],
                            'selected' if b == active else ('baseline' if initial[b.set_id] is None else 'held')) for b in self.bindings],
                            self._bounds(chosen, active_position=active.position_id))
                finally:
                    close = getattr(sequence, 'close', None)
                    if close is not None:
                        close()
        finally:
            for value in values.values():
                value.close()

    def _product(self):
        finite, dynamic, pools, iterators = [], [], [], []
        try:
            for key, run in self._sets.items():
                if run.spec.source.finite:
                    finite.append(key)
                    values = run.accepted()
                    try:
                        pool = []
                        for entry in values:
                            if run.spec.pool_mode != 'reuse' and any(c.scope == 'per_test' for c in
                                    entry.candidate.random_choices + entry.prefix.random_choices):
                                raise ContractError(f'composition.{key}', 'contradictory_scope',
                                    'random indexed source pools require explicit pool_mode=reuse')
                            pool.append(entry)
                        pools.append(pool)
                    finally:
                        values.close()
                    if not pool or self.cancelled():
                        return
                else:
                    dynamic.append(key)
                    iterators.append(run.accepted())
            sizes = {key: len(pool) for key, pool in zip(finite, pools)}
            for ordinal, combo in enumerate(itertools.product(*pools), 1):
                if self.cancelled():
                    return
                selected = dict(zip(finite, combo))
                for key, values in zip(dynamic, iterators):
                    try:
                        selected[key] = next(values)
                    except StopIteration:
                        return
                yield ComposedRow(self, ordinal, [(b, selected[b.set_id], 'selected') for b in self.bindings],
                    self._bounds(selected, pool_sizes=sizes, finite_dimensions=tuple(finite),
                        dynamic_dimensions=tuple(dynamic), indexed_source_reuse=True))
        except (MemoryError, OverflowError) as error:
            raise ContractError(f'composition.{key}.pool', 'allocation_failed',
                f'explicit indexed pool allocation failed: {error}') from error
        finally:
            for values in iterators:
                values.close()


@dataclass
class ComposerProgress:
    outer_index: int
    outer_total: int | None
    inner_index: int | None = None
    inner_total: int | None = None


class FuzzComposer:
    """Retained byte-dictionary facade over the same identified composition."""
    def compose(self, generators, base_values=None, strategy='single', *, pool_mode='fresh'):
        base, sets = base_values or {}, []
        for key, generator in generators.items():
            sets.append(CandidateSet(key, SourceStream.from_generator(generator, key), pool_mode=pool_mode))
        composer = CandidateComposer(sets, [CandidateBinding(key, key, base.get(key)) for key in generators], strategy)
        counts = [s.source.known_count for s in sets]
        if strategy == 'single':
            total = None if any(c is None for c in counts) else sum(counts)
        elif strategy == 'zip':
            finite = [c for c in counts if c is not None]
            total = min(finite) if finite else None
        else:
            total = None
        rows = composer.rows()
        try:
            for row in rows:
                prepared = row.resolve(f'facade:{row.ordinal}')
                by_id = {c.contribution_id: c.data for c in prepared.contributions}
                values = dict(base)
                values.update({b.placement_id: by_id[b.contribution_id] for b in prepared.selection.bindings})
                inner = inner_total = None
                outer, outer_total = row.ordinal - 1, total
                if strategy in ('cartesian', 'hybrid-cartesian'):
                    finite, sizes = row.bounds['finite_dimensions'], row.bounds['pool_sizes']
                    if finite:
                        outer, outer_total = row.bounds['accepted_indices'][finite[0]] - 1, sizes[finite[0]]
                        product = 1
                        for key in finite[1:]:
                            product *= sizes[key]
                        if product > 1:
                            inner, inner_total = (row.ordinal - 1) % product, product
                elif strategy == 'single':
                    active = row.bounds['active_position']
                    inner, inner_total = row.bounds['accepted_indices'][active] - 1, composer._sets[active].spec.source.known_count
                yield values, ComposerProgress(outer, outer_total, inner, inner_total)
        finally:
            rows.close()

    @staticmethod
    def estimate_count(generators, strategy='single'):
        counts = [gen.count() for gen in generators.values()]
        if not counts:
            return 0
        if strategy == 'single':
            return None if any(c is None for c in counts) else sum(counts)
        if strategy == 'zip':
            finite = [c for c in counts if c is not None]
            return min(finite) if finite else None
        if strategy in ('cartesian', 'hybrid-cartesian'):
            finite = [c for c in counts if c is not None]
            if not finite or (strategy == 'cartesian' and len(finite) != len(counts)):
                return None
            total = 1
            for count in finite:
                total *= count
            return total
        return None
