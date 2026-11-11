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

"""Pure, attributed candidate transformations, independent of packet placement."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import random

from bytefault.core.contracts import (ContractError, MutatorInvocation, MutatorResult,
    RandomChoice, SourceInvocation, SourceResult, freeze)
from bytefault.generators.mutator import Mutator, MUTATION_OPERATIONS
from bytefault.fuzzers.helpers import parse_hex_bytes


@dataclass(frozen=True)
class TransformSpec:
    mutator_id: str
    kind: str
    options: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'options', freeze(self.options))


@dataclass(frozen=True)
class TransformationOutcome:
    data: bytes
    mutators: tuple[MutatorInvocation, ...] = ()
    results: tuple[MutatorResult, ...] = ()
    random_choices: tuple[RandomChoice, ...] = ()
    disposition: str = 'accepted'


@dataclass(frozen=True)
class PreparationDisposition:
    set_id: str
    source: SourceInvocation
    source_result: SourceResult
    mutators: tuple[MutatorInvocation, ...]
    mutator_results: tuple[MutatorResult, ...]
    random_choices: tuple[RandomChoice, ...]
    reason: str


FILTERS = frozenset(('filter_comments', 'filter_empty'))
_OPTIONS = {
    'mutate': {'operation', 'operations', 'seed', 'rng_state', 'held_decisions', 'max_len', 'scope', 'scopes'},
    'text': {'from_encoding', 'to_encoding', 'errors'},
    'text_trim': {'encoding', 'chars', 'side', 'errors'},
    'hex_decode': {'encoding'}, 'hex_encode': {'uppercase'},
    'trim': {'chars', 'chars_hex', 'side'},
    'filter_comments': {'prefix', 'prefix_hex'}, 'filter_empty': set(),
    'reverse': set(), 'reorder': {'indices'},
    'word': {'index', 'delimiter', 'delimiter_hex'},
    'prepend': {'data', 'data_hex'}, 'append': {'data', 'data_hex'},
    'pad': {'length', 'value', 'side'},
    'field_encode': {'width', 'base', 'fill', 'mode', 'endian', 'pad_byte', 'contexts'},
}


def _bytes(options, name, default=None):
    if name in options and name + '_hex' in options:
        raise ValueError(f'choose {name} or {name}_hex')
    value = options.get(name, default)
    if name + '_hex' in options:
        value = bytes.fromhex(options[name + '_hex'])
    if value is not None and type(value) is not bytes:
        raise ValueError(f'{name} must be exact bytes')
    return value


class MutationPipeline:
    """One run's ordered transforms and independently advancing mutation RNGs.

    ``apply`` always returns exact bytes and disposition, including excluded
    records. No callback/storage/network is necessary for standalone use.
    """
    def __init__(self, transforms=()):
        self.specs = tuple(transforms)
        self._rngs, self._held = {}, {}
        ids = []
        for spec in self.specs:
            path = f'mutators.{getattr(spec, "mutator_id", "?")}'
            if not isinstance(spec, TransformSpec) or not spec.mutator_id or spec.kind not in _OPTIONS:
                raise ContractError(path, 'transform_configuration', 'known transform and nonempty identity required')
            if spec.mutator_id in ids:
                raise ContractError(path, 'duplicate_identity', spec.mutator_id)
            ids.append(spec.mutator_id)
            unknown = set(spec.options) - _OPTIONS[spec.kind]
            if unknown:
                raise ContractError(path, 'transform_configuration', f'unknown options: {sorted(unknown)}')
            if spec.kind == 'field_encode' and 'contexts' in spec.options:
                contexts = spec.options['contexts']
                if (not isinstance(contexts, Mapping) or not contexts or any(
                        not isinstance(key, str) or not key or not isinstance(value, Mapping) or
                        set(value) - {'width', 'base'} or 'width' not in value
                        for key, value in contexts.items())):
                    raise ContractError(path, 'transform_configuration', 'action IDs must map to width/base context')
                if any(later.kind in FILTERS for later in self.specs[self.specs.index(spec) + 1:]):
                    raise ContractError(path, 'contextual_filter_prefix',
                        'action-context encoding must follow source filters')
            if spec.kind == 'mutate':
                scope = spec.options.get('scope', 'per_test')
                scopes = spec.options.get('scopes', {})
                if scope not in ('per_test', 'sample_once') or not isinstance(scopes, Mapping) or any(
                        value not in ('per_test', 'sample_once') for value in scopes.values()):
                    raise ContractError(path, 'contradictory_scope', 'sample_once or per_test required')
                allowed = {'operation', 'index', 'bit', 'value', 'delta', 'slice_length', 'slice_start', 'insert_at'}
                if set(scopes) - allowed:
                    raise ContractError(path, 'transform_configuration', 'unknown mutation decision scope')
                self._rngs[spec.mutator_id] = random.Random(spec.options.get('seed'))
                if 'rng_state' in spec.options:
                    if spec.options.get('seed') is not None:
                        raise ContractError(path, 'transform_configuration', 'choose seed or rng_state')
                    try:
                        self._rngs[spec.mutator_id].setstate(tuple(spec.options['rng_state']))
                    except (TypeError, ValueError) as error:
                        raise ContractError(path, 'transform_configuration', str(error)) from error
                try:
                    for name, occurrence, unit in spec.options.get('held_decisions', ()):
                        key = (spec.mutator_id, name, occurrence)
                        if (name not in allowed or type(occurrence) is not int or occurrence < 0 or
                                type(unit) is not float or not 0 <= unit < 1 or key in self._held):
                            raise ValueError('valid unique normalized held decisions required')
                        self._held[key] = unit
                except (TypeError, ValueError) as error:
                    raise ContractError(path, 'transform_configuration', str(error)) from error

    @property
    def last_filter(self):
        return max((i for i, spec in enumerate(self.specs) if spec.kind in FILTERS), default=-1)

    @property
    def random_capable(self):
        return any(spec.kind == 'mutate' for spec in self.specs)

    def apply(self, data: bytes, iteration_id=None, *, start=0, stop=None, context=None):
        if type(data) is not bytes:
            raise ContractError('mutators.input', 'malformed', 'exact bytes required')
        invocations, results, choices = [], [], []
        disposition = 'accepted'
        for spec in self.specs[start:stop]:
            before = data
            options = spec.options
            invocation_options = dict(options, kind=spec.kind)
            if spec.kind == 'mutate':
                operation_choices = (options['operation'],) if 'operation' in options else options.get('operations', MUTATION_OPERATIONS)
                invocation_options['decision_mapping'] = {
                    'operation': operation_choices, 'delta': (-3, -2, -1, 1, 2, 3),
                    'bit': 'mask=1<<value', 'slice_length': 'length=value+1',
                    'index': 'zero_based_current_input_position',
                    'slice_start': 'zero_based_current_input_position',
                    'insert_at': 'zero_based_current_input_boundary', 'value': 'literal_byte'}
            invocation = MutatorInvocation(spec.mutator_id, 'bytefault.generators.transforms', invocation_options)
            try:
                if spec.kind == 'field_encode' and 'contexts' in options:
                    action = context.get('action_id') if isinstance(context, Mapping) else None
                    selected = options['contexts'].get(action)
                    if selected is None:
                        raise ContractError(f'mutators.{spec.mutator_id}', 'missing_context',
                                            'explicit configured action context required')
                    invocation_options['resolved_context'] = dict(selected, action_id=action)
                    invocation = MutatorInvocation(spec.mutator_id, 'bytefault.generators.transforms', invocation_options)
                if spec.kind == 'mutate':
                    seen = {}
                    def draw(name, lo, hi):
                        occurrence = seen.get(name, 0)
                        seen[name] = occurrence + 1
                        key = (spec.mutator_id, name, occurrence)
                        scope = options.get('scopes', {}).get(name, options.get('scope', 'per_test'))
                        if scope == 'sample_once':
                            if key not in self._held:
                                self._held[key] = self._rngs[spec.mutator_id].random()
                            unit = self._held[key]
                            # Exact rational mapping avoids rounding up to hi+1.
                            numerator, denominator = unit.as_integer_ratio()
                            value = lo + numerator * (hi - lo + 1) // denominator
                            resolved = {'unit': unit, 'value': value}
                        else:
                            value = self._rngs[spec.mutator_id].randrange(lo, hi + 1)
                            resolved = value
                        choices.append(RandomChoice(f'{spec.mutator_id}:{name}:{occurrence}', 'mutator',
                            f'{spec.mutator_id}.{name}.{occurrence}', (lo, hi), scope, resolved,
                            iteration_id if scope == 'per_test' else None))
                        return value
                    operations = options.get('operations')
                    if 'operation' in options:
                        if operations is not None:
                            raise ValueError('choose operation or operations')
                        operations = (options['operation'],)
                    if operations is not None and not operations:
                        raise ValueError('operations must be nonempty')
                    mutator = Mutator(max_len=options.get('max_len'), draw=draw, operations=operations)
                    data = mutator.mutate_once(data)
                    transformation = 'mutate:' + mutator.last_operation
                    if mutator.selected_operation != mutator.last_operation:
                        transformation += ':selected=' + mutator.selected_operation
                elif spec.kind == 'text':
                    errors = options.get('errors', 'strict')
                    data = data.decode(options.get('from_encoding', 'utf-8'), errors).encode(
                        options.get('to_encoding', 'utf-8'), errors)
                elif spec.kind == 'hex_decode':
                    data = parse_hex_bytes(data.decode(options.get('encoding', 'ascii')))
                elif spec.kind == 'text_trim':
                    encoding, errors = options.get('encoding', 'utf-8'), options.get('errors', 'strict')
                    text, side = data.decode(encoding, errors), options.get('side', 'both')
                    if side not in ('left', 'right', 'both'):
                        raise ValueError('trim side must be left, right or both')
                    text = {'left': str.lstrip, 'right': str.rstrip, 'both': str.strip}[side](text, options.get('chars'))
                    data = text.encode(encoding, errors)
                elif spec.kind == 'hex_encode':
                    text = data.hex()
                    data = (text.upper() if options.get('uppercase', False) else text).encode('ascii')
                elif spec.kind == 'trim':
                    chars = _bytes(options, 'chars')
                    side = options.get('side', 'both')
                    if side not in ('left', 'right', 'both'):
                        raise ValueError('trim side must be left, right or both')
                    data = {'left': bytes.lstrip, 'right': bytes.rstrip, 'both': bytes.strip}[side](data, chars)
                elif spec.kind == 'filter_comments':
                    prefix = _bytes(options, 'prefix', b'#')
                    if not prefix:
                        raise ValueError('comment prefix must be nonempty')
                    if data.startswith(prefix):
                        disposition = 'excluded:comment'
                elif spec.kind == 'filter_empty':
                    if not data:
                        disposition = 'excluded:empty'
                elif spec.kind == 'reverse':
                    data = data[::-1]
                elif spec.kind == 'reorder':
                    indices = tuple(options['indices'])
                    if any(type(i) is not int for i in indices) or sorted(indices) != list(range(len(data))):
                        raise ValueError('reorder indices must be an exact permutation of input positions')
                    data = bytes(data[i] for i in indices)
                elif spec.kind == 'word':
                    index = options.get('index', 0)
                    if type(index) is not int or index < 0:
                        raise ValueError('word index must be nonnegative')
                    data = data.split(_bytes(options, 'delimiter'))[index]
                elif spec.kind in ('prepend', 'append'):
                    extra = _bytes(options, 'data')
                    if extra is None:
                        raise ValueError('exact data required')
                    data = extra + data if spec.kind == 'prepend' else data + extra
                elif spec.kind == 'field_encode':
                    from bytefault.generators.field_encoding import encode_field
                    effective = {k: v for k, v in options.items() if k != 'contexts'}
                    if 'contexts' in options:
                        effective.update(selected)
                    data = encode_field(data, **effective)
                elif spec.kind == 'pad':
                    length, value = options['length'], options.get('value', 0)
                    side = options.get('side', 'left')
                    if type(length) is not int or length < 0 or type(value) is not int or not 0 <= value <= 255:
                        raise ValueError('nonnegative length and byte value required')
                    if side not in ('left', 'right'):
                        raise ValueError('pad side must be left or right')
                    padding = bytes([value]) * max(0, length - len(data))
                    data = padding + data if side == 'left' else data + padding
                if spec.kind != 'mutate':
                    transformation = spec.kind + (':' + disposition if disposition != 'accepted' else '')
            except ContractError as error:
                error.partial = TransformationOutcome(data, tuple(invocations), tuple(results), tuple(choices), 'error')
                error.failed_mutator = invocation
                raise
            except (ValueError, TypeError, LookupError, OverflowError, MemoryError) as error:
                attributed = ContractError(f'mutators.{spec.mutator_id}', 'transform_failed', str(error))
                attributed.partial = TransformationOutcome(data, tuple(invocations), tuple(results), tuple(choices), 'error')
                attributed.failed_mutator = invocation
                raise attributed from error
            invocations.append(invocation)
            results.append(MutatorResult(spec.mutator_id, before, data, transformation))
            if disposition != 'accepted':
                break
        return TransformationOutcome(data, tuple(invocations), tuple(results), tuple(choices), disposition)
