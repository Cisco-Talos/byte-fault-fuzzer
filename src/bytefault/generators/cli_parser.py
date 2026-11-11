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

"""Shared inline source grammar and lossless structured source equivalent.

Inline: TARGET:TYPE:PRIMARY[,modifier:value...]. Commas delimit tokens;
whitespace around tokens is syntax. Use SourceSpec for paths/values containing
reserved tokens or significant surrounding whitespace. Source and placement
modifiers are parsed independently; no modifier is a hexadecimal list entry.
"""
from __future__ import annotations

import random
from bytefault.core.contracts import ContractError
from bytefault.fuzzers.helpers import parse_hex_bytes
from bytefault.generators.sources import SourceSpec, open_source


class GenFieldParseError(ValueError):
    """Attributed invalid inline source configuration."""


_PLACEMENT = {'mode', 'offset_range', 'offset_scope', 'offset_seed'}
_KNOWN = {'exclude', 'width', 'start', 'fill', 'count', 'seed', 'max_len',
          'endian', 'step', 'source_mode', 'delimiter_hex', 'length_scope',
          'content_scope', 'range_scope', 'byte_range', 'range_choices',
          'mutation_scope', 'seed_encoding', *_PLACEMENT}
_ALLOWED = {
    'iter': {'exclude', 'width', 'start', 'fill', 'endian'},
    'random': {'count', 'seed', 'exclude', 'length_scope', 'content_scope',
               'range_scope', 'byte_range', 'range_choices'},
    'sweep': {'step', 'seed', 'content_scope', 'range_scope', 'byte_range', 'range_choices', 'exclude'},
    'mutate': {'count', 'seed', 'max_len', 'mutation_scope'},
    'list': set(), 'edge': {'width', 'endian'},
    'file': {'source_mode', 'delimiter_hex'}, 'dataset': set(),
}


def _split_params(raw):
    if not raw:
        return '', {}
    primary, modifiers = [], {}
    in_modifiers = False
    for token in raw.split(','):
        token = token.strip()
        if not token:
            raise GenFieldParseError('empty inline token; use structured payloads for empty bytes')
        key, separator, value = token.partition(':')
        if key in _KNOWN:
            if key in modifiers:
                raise GenFieldParseError(f'duplicate modifier {key!r}')
            if not separator and key != 'fill':
                raise GenFieldParseError(f'modifier {key!r} needs a value')
            modifiers[key] = value
            in_modifiers = True
        elif in_modifiers or separator:
            # A Windows drive colon belongs to a file primary, handled by its
            # type-aware parser before reaching this generic token scanner.
            raise GenFieldParseError(f'unknown modifier or ambiguous token {token!r}; use SourceSpec')
        else:
            primary.append(token)
    return ','.join(primary), modifiers


def _number(value):
    return int(value, 0)


def _range(value):
    parts = value.split('-', 1)
    pair = (_number(parts[0]), _number(parts[1])) if len(parts) == 2 else (_number(value), _number(value))
    if pair[0] > pair[1] or pair[0] < 0:
        raise GenFieldParseError('ordered nonnegative range required')
    return pair


def parse_source_field(spec, field_sizes=None, datasets=None):
    """Return (target, SourceSpec, placement_options), without reading content.

    Dataset admission is deferred to open_source; supplied datasets are passive
    mappings of name -> subset -> ordered exact byte values.
    """
    try:
        parts = spec.split(':', 2)
        if len(parts) < 2:
            raise GenFieldParseError('expected TARGET:TYPE[:PARAMS]')
        target, kind = parts[0].strip(), parts[1].strip().lower()
        raw = parts[2] if len(parts) == 3 else ''
        if not target:
            raise GenFieldParseError('nonempty target required')
        if kind not in _ALLOWED:
            raise GenFieldParseError(f'unknown source type {kind!r}')
        if kind == 'file':
            tokens = raw.split(',')
            primary = tokens[0].strip()
            tail_primary, mods = _split_params(','.join(tokens[1:])) if len(tokens) > 1 else ('', {})
            if not primary:
                raise GenFieldParseError('nonempty file path required')
            if tail_primary or any(not token.strip() for token in tokens):
                raise GenFieldParseError('inline file paths cannot contain commas; use SourceSpec')
        elif raw:
            primary, mods = _split_params(raw)
        else:
            primary, mods = '', {}
        unknown = set(mods) - _ALLOWED[kind] - _PLACEMENT
        if unknown:
            raise GenFieldParseError(f'unsupported {kind} modifiers {sorted(unknown)}')
        placement = {key: mods.pop(key) for key in tuple(mods) if key in _PLACEMENT}
        if target.startswith('@'):
            if target != '@append':
                lo, hi = _range(target[1:])
                if '-' in target[1:] and lo == hi:
                    # Zero-length ranges are still explicit replacement ranges.
                    pass
            mode = placement.get('mode', 'append' if target == '@append' else 'replace' if '-' in target[1:] else 'insert')
            if mode not in ('insert', 'overwrite', 'replace', 'append'):
                raise GenFieldParseError('mode must be insert, overwrite, replace or append')
            placement['mode'] = mode
        elif placement:
            raise GenFieldParseError('placement modifiers require an @offset, @start-end or @append target')
        if 'offset_range' in placement:
            placement['offset_range'] = _range(placement['offset_range'])
        if 'offset_scope' in placement and placement['offset_scope'] not in ('sample_once', 'per_test'):
            raise GenFieldParseError('offset_scope must be sample_once or per_test')
        if 'offset_seed' in placement:
            placement['offset_seed'] = _number(placement['offset_seed'])
        options = {}
        if kind == 'list':
            if not primary:
                raise GenFieldParseError('at least one hexadecimal list value required')
            options['payloads'] = tuple(parse_hex_bytes(value) for value in primary.split(','))
        elif kind == 'file':
            options = {'path': primary, 'source_mode': mods.get('source_mode', 'whole')}
            if 'delimiter_hex' in mods:
                if options['source_mode'] != 'lines':
                    raise GenFieldParseError('delimiter_hex requires source_mode:lines')
                options['delimiter'] = parse_hex_bytes(mods['delimiter_hex'])
                if not options['delimiter']:
                    raise GenFieldParseError('delimiter_hex must be nonempty')
        elif kind == 'dataset':
            if not primary:
                raise GenFieldParseError('dataset name required')
            name, _, subset = primary.partition('.')
            options = {'name': name, 'subset': subset or 'all'}
        elif kind in ('iter', 'edge'):
            width = _number(mods['width']) if 'width' in mods else (field_sizes or {}).get(target) or 1
            if kind == 'iter':
                if not primary:
                    raise GenFieldParseError('iterator range required')
                ranges = tuple(_range(value) for value in primary.split(','))
                if 'width' not in mods:
                    width = max(width, max(hi for _, hi in ranges).bit_length() // 8 + (max(hi for _, hi in ranges).bit_length() % 8 != 0))
                options['ranges'] = ranges
                options['excludes'] = tuple(n for lo, hi in (_range(item) for item in mods.get('exclude', '').split('|') if item) for n in range(lo, hi + 1))
                if 'start' in mods:
                    options['start_value'] = _number(mods['start'])
                options['fill'] = 'fill' in mods
            elif primary:
                raise GenFieldParseError('edge has only explicit modifiers, no primary value')
            options.update(width=width, endian=mods.get('endian', 'big'))
        elif kind in ('random', 'sweep'):
            if not primary:
                raise GenFieldParseError('length or length range required')
            lo, hi = _range(primary)
            options.update({'min_len': lo, 'max_len': hi} if kind == 'random' else {'start': lo, 'stop': hi})
            for key in ('count', 'seed', 'step'):
                if key in mods:
                    options[key] = _number(mods[key])
            for key in ('length_scope', 'content_scope', 'range_scope'):
                if key in mods:
                    options[key] = mods[key]
            if 'byte_range' in mods:
                options['byte_range'] = _range(mods['byte_range'])
            if 'range_choices' in mods:
                options['range_choices'] = tuple(_range(item) for item in mods['range_choices'].split('|'))
            if 'exclude' in mods:
                options['exclude_bytes'] = tuple(n for lo, hi in (_range(item) for item in mods['exclude'].split('|')) for n in range(lo, hi + 1))
        elif kind == 'mutate':
            if not primary:
                raise GenFieldParseError('hexadecimal mutation seed required')
            options['seeds'] = (parse_hex_bytes(primary),)
            options['count'] = _number(mods.get('count', '100'))
            for key in ('seed', 'max_len'):
                if key in mods:
                    options[key] = _number(mods[key])
            if 'mutation_scope' in mods:
                options['mutation_scope'] = mods['mutation_scope']
        return target, SourceSpec(target, kind, options, primary if kind in ('file', 'dataset') else None), placement
    except (ValueError, TypeError, OverflowError, MemoryError) as error:
        raise GenFieldParseError(f'--gen-field {spec!r}: {error}') from error


def parse_gen_field(spec, field_sizes=None, datasets=None):
    """Retained byte-generator facade using the same shared source parser."""
    target, source, placement = parse_source_field(spec, field_sizes, datasets)
    try:
        if source.kind == 'mutate':
            from bytefault.generators.mutator import MutatorGenerator
            options = source.options
            generator = MutatorGenerator(options['seeds'], options['count'],
                random.Random(options['seed']) if 'seed' in options else None,
                options.get('max_len'), mutation_scope=options.get('mutation_scope', 'per_test'))
            generator.source_spec = source
        else:
            generator = open_source(source, datasets=datasets).generator
        if target.startswith('@'):
            generator.injection_mode = placement['mode']
        generator.placement_options = placement
        return target, generator
    except (ContractError, ValueError, OSError) as error:
        raise GenFieldParseError(f'--gen-field {spec!r}: {error}') from error


def parse_gen_fields(specs, field_sizes=None, datasets=None):
    generators = {}
    for spec in specs:
        target, generator = parse_gen_field(spec, field_sizes, datasets)
        if target in generators:
            raise GenFieldParseError(f'duplicate --gen-field for {target!r}')
        generators[target] = generator
    return generators
