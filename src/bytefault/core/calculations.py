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

"""Generic byte computations, extracted from the retained packet builder.

No declaration discovery, protocol dispatch or execution belongs here. CRC integer
encoding and digest truncation preserve the retained generic algorithms.
"""
import hashlib
import zlib
from .contracts import ContractError

ALGORITHMS = {'crc32': 4, 'crc16': 2, 'md5': 16, 'sha1': 20, 'sha256': 32}
SUPPORTED_RULES = frozenset(('payload_length', 'sequence', 'length', 'checksum', *ALGORITHMS))


def algorithm(c):
    return (c.algorithm or 'crc32') if c.rule == 'checksum' else c.rule


def calculation_size(c, action):
    if c.size is not None:
        return c.size
    if c.rule in ALGORITHMS or c.rule == 'checksum':
        return ALGORITHMS.get(algorithm(c))
    if c.field_id is not None:
        field = next((f for f in action.fields if f.field_id == c.field_id and f.buffer_id == c.buffer_id), None)
        if field is not None and field.size:
            return field.size
    return None


def calculation_problem(c, action):
    if c.rule not in SUPPORTED_RULES:
        return 'unknown rule'
    if c.rule == 'checksum' and algorithm(c) not in ALGORITHMS:
        return 'unknown checksum algorithm'
    size = calculation_size(c, action)
    if size is None or size <= 0:
        return 'unknown destination size'
    if c.field_id is not None:
        field = next((f for f in action.fields if f.field_id == c.field_id and f.buffer_id == c.buffer_id), None)
        if field is None or field.offset is None or field.size is None:
            return 'unknown destination field/location'
        if field.offset + field.size > len(action.seed):
            return 'destination field exceeds current seed'
        if size > field.size:
            return 'calculation destination exceeds declared field; use an explicit fixed span'
    elif c.destination != 'append' and c.offset is None:
        return 'unknown destination location'
    if c.rule == 'payload_length':
        offset = (next(f.offset for f in action.fields if f.field_id == c.field_id and f.buffer_id == c.buffer_id)
                  if c.field_id is not None else c.offset)
        if c.destination == 'append' or c.payload_offset != offset + size:
            return 'payload length needs the seed offset following its destination'
        if offset + size > len(action.seed):
            return 'payload length needs a known seed destination'
    if c.rule == 'length':
        if c.counts not in ('body', 'tail', 'full', 'packet', 'range', 'field'):
            return 'unknown length count convention'
        if c.counts == 'field':
            field = next((f for f in action.fields if f.field_id == c.counts_field and f.buffer_id == c.buffer_id), None)
            if field is None or field.offset is None or field.size is None:
                return 'unknown counted field/location'
            if field.offset + field.size > len(action.seed):
                return 'counted field exceeds current seed'
    if algorithm(c) in ('md5', 'sha1', 'sha256') and size > ALGORITHMS[algorithm(c)]:
        return 'digest size exceeds algorithm output'
    return None


def digest(data, name, size):
    if name == 'crc32':
        return (zlib.crc32(data) & 0xffffffff).to_bytes(size, 'big')
    if name == 'crc16':
        crc = 0xffff
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                crc = ((crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1) & 0xffff
        return crc.to_bytes(size, 'big')
    return hashlib.new(name, data).digest()[:size]


def sequence_value(start, step, wrap, ordinal=1):
    if (type(start) is not int or type(step) is not int or type(ordinal) is not int or ordinal < 1 or
            (wrap is not None and (type(wrap) is not int or wrap < 1))):
        raise ContractError('calculations.sequence', 'malformed', 'integer sequence values and positive wrap/ordinal required')
    value = start + (ordinal - 1) * step
    return value % wrap if wrap is not None and ordinal > 1 else value


def calculation_bytes(c, data, size, start, end, *, field_spans=None, ordinal=1):
    """Compute bytes from supplied concrete locations, without choosing writes.

    Both ordinary materialization and pure schema construction use this arithmetic.
    The caller owns location resolution, explicit-edit precedence and optional versus
    required treatment. Unknown information raises an attributed error, never zero.
    """
    path = 'calculations.' + c.calculation_id
    if c.rule not in SUPPORTED_RULES:
        raise ContractError(path, 'unsupported_capability', 'unknown rule: ' + c.rule)
    if type(size) is not int or size <= 0:
        raise ContractError(path, 'malformed', 'positive output size required')
    if c.endian not in ('big', 'little'):
        raise ContractError(path, 'malformed', 'big or little endian required')
    if c.rule in ALGORITHMS or c.rule == 'checksum':
        name = algorithm(c)
        if name not in ALGORITHMS or (name in ('md5', 'sha1', 'sha256') and size > ALGORITHMS[name]):
            raise ContractError(path, 'unsupported_capability', 'unknown algorithm or unavailable digest size')
        return digest(bytes(data[c.range_start:c.range_end]), name, size)
    if c.override_value is not None:
        return c.override_value.to_bytes(size, c.endian)
    extent = max(len(data), end) if c.destination != 'append' else len(data) + size
    value = max(0, extent - (start + size))
    if c.rule == 'length':
        if c.counts in ('full', 'packet'):
            value = extent
        elif c.counts == 'range':
            bound = c.range_end
            bound = len(data) if bound is None else max(0, len(data) + bound) if bound < 0 else bound
            value = max(0, bound - c.range_start)
        elif c.counts == 'field':
            span = (field_spans or {}).get(c.counts_field)
            if span is None or span[1] is None:
                raise ContractError(path, 'unsupported_capability', 'counted field no longer has a known span')
            value = span[1] - span[0]
        elif c.counts not in ('body', 'tail'):
            raise ContractError(path, 'unsupported_capability', 'unknown length count convention')
    if c.rule == 'sequence':
        value = sequence_value(c.sequence_start, c.sequence_step, c.sequence_wrap,
                               c.sequence_ordinal or ordinal)
    return value.to_bytes(size, c.endian)
