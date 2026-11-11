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

"""Neutral checks for the retained pure construction adapter; no second sender."""
import binascii
import hashlib
import zlib

import pytest

from bytefault.core.contracts import ContractError
from bytefault.fuzzers.packet_builder import (PacketBuilder, _apply_computed_fields,
    _apply_offset_injections)
from bytefault.generators.field_encoding import field_width, padded_base, FieldByteGenerator
from bytefault.fuzzers.byte_mask import ByteMask


def test_schema_checksum_adapter_retains_algorithms_sizes_and_ranges():
    data = b'123456789'
    expected = {'crc16': binascii.crc_hqx(data, 0xffff).to_bytes(2, 'big'),
        'crc32': zlib.crc32(data).to_bytes(4, 'big'),
        **{name: hashlib.new(name, data).digest() for name in ('md5', 'sha1', 'sha256')}}
    for name, output in expected.items():
        packet = bytearray(data)
        schema = {'computed': [{'type': 'checksum', 'offset': 'append', 'algorithm': name}]}
        assert _apply_computed_fields(packet, schema) == (('checksum', 'repaired'),)
        assert packet == data + output
    packet = bytearray(data + b'\0' * 7)
    schema = {'computed': [{'type': 'checksum', 'offset': 9, 'size': 7,
        'range_end': -7, 'algorithm': 'sha256'}]}
    _apply_computed_fields(packet, schema)
    assert packet == data + hashlib.sha256(data).digest()[:7]
    # A new fixed destination includes real NUL padding, never textual escapes.
    packet = bytearray(data)
    schema = {'computed': [{'type': 'checksum', 'offset': 12, 'algorithm': 'crc16', 'range_end': 9}]}
    _apply_computed_fields(packet, schema)
    assert packet == data + b'\0' * 3 + b'\x29\xb1'


def test_schema_length_adapter_counts_unknowns_and_explicit_precedence():
    for options, expected in (({'counts': 'body'}, 5), ({'counts': 'full'}, 7),
            ({'counts': 'range', 'range_start': 2, 'range_end': -1}, 4),
            ({'counts': 'field', 'counts_field': 'body'}, 5)):
        packet = bytearray(b'\0\0ABCDE')
        schema = {'computed': [{'type': 'length', 'offset': 0, 'size': 2, 'endian': 'little', **options}]}
        _apply_computed_fields(packet, schema, field_bytes={'body': b'ABCDE'})
        assert packet == expected.to_bytes(2, 'little') + b'ABCDE'
    packet = bytearray(b'ABC')
    _apply_computed_fields(packet, {'computed': [{'type': 'length', 'offset': 5,
        'size': 2, 'counts': 'full'}]})
    assert packet == b'ABC\0\0\0\7'
    packet = bytearray(b'XXABC')
    schema = {'fields': [{'name': 'length', 'size': 2}, {'name': 'body', 'size': 'var'}],
        'computed': [{'type': 'length', 'field': 'length', 'counts': 'field', 'counts_field': 'absent'}]}
    assert _apply_computed_fields(packet, schema, field_bytes={'body': b'ABC'}) == (
        ('length', 'unavailable_rule_or_location'),)
    assert packet == b'XXABC'
    # Explicit override needs only its known output, not unavailable count inputs.
    _apply_computed_fields(packet, schema, length_override=4)
    assert packet == b'\0\4ABC'
    packet[:] = b'XXABC'
    assert _apply_computed_fields(packet, schema, skip_fields={'length'}, length_override=4) == (
        ('length', 'explicit_edit'),)
    assert packet == b'XXABC'
    schema['computed'][0]['required'] = True
    with pytest.raises(ContractError, match='counted field'):
        _apply_computed_fields(packet, schema)
    # An absent destination cannot silently fall back to offset zero.
    schema = {'computed': [{'type': 'length', 'size': 2}]}
    assert _apply_computed_fields(packet, schema) == (('length', 'unavailable_rule_or_location'),)
    assert packet == b'XXABC'
    schema = {'computed': [{'type': 'checksum', 'offset': 0, 'size': 2, 'algorithm': 'crc16'}]}
    assert _apply_computed_fields(packet, schema, skip_ranges=[(0, 1)]) == (('checksum', 'explicit_edit'),)
    assert packet == b'XXABC'
    schema['computed'][0]['size'] = -1
    with pytest.raises(ContractError, match='malformed'):
        _apply_computed_fields(packet, schema)


def test_pure_build_packet_sequence_state_and_oversized_fields(engine_factory):
    engine, trace, _, _ = engine_factory()
    engine.packet_schema = {'fields': [{'name': 'sequence', 'size': 1},
        {'name': 'length', 'size': 2}, {'name': 'body', 'size': 1}],
        'defaults': {'sequence': b'\0'},
        'computed': [{'type': 'sequence', 'field': 'sequence', 'size': 1, 'start': 6, 'step': 3, 'wrap': 8},
                     {'type': 'length', 'field': 'length', 'counts': 'body', 'endian': 'little'}]}
    engine._reset_sequence_state()
    assert engine.build_packet({'body': b'ABCDE'}) == b'\6\5\0ABCDE'
    assert engine.build_packet({'sequence': b'\xff', 'body': b'ABCDE'}) == b'\xff\5\0ABCDE'
    assert engine.build_packet({'body': b'ABCDE'}) == b'\1\5\0ABCDE'
    assert engine.build_packet({'body': b'ABCDE'}, skip_fields={'length'}) == b'\4\0\0ABCDE'
    engine.packet_schema['computed'][0]['step'] = 1.5
    with pytest.raises(ContractError, match='malformed'):
        engine.build_packet({'body': b'ABCDE'})
    assert not trace  # Pure construction never opens or offers traffic.


def test_offset_adapter_sorted_original_coordinates_and_raw_gap():
    packet = bytearray(b'ABC')
    assert _apply_offset_injections(packet, {'@2': b'z', '@1': b'xy'}, {}) is packet
    assert packet == b'AxyBzC'
    packet = bytearray(b'ABC')
    _apply_offset_injections(packet, {'@5': b'Z'}, {'@5': 'overwrite'})
    assert packet == b'ABC\0\0Z'
    packet = bytearray(b'ABC')
    with pytest.raises(ContractError, match='numeric offset'):
        _apply_offset_injections(packet, {'@unknown': b'Z'}, {})
    assert packet == b'ABC'


def test_pending_field_encoding_intent_remains_pure():
    assert field_width('body', {'body': 'var'}, {'body': 2}, {'body': b'ABCD'}) == 4
    baseline = padded_base('body', {'body': b'AB'}, {'body': 4}, 0xcc)
    assert baseline == b'\xcc\xccAB'
    mask = ByteMask([(1, 2)], [])
    assert list(FieldByteGenerator(mask, 4, baseline).generate()) == [b'\1\xccAB', b'\2\xccAB']
    assert list(FieldByteGenerator(mask, 4, baseline, fill=True, start_value=2).generate()) == [b'\2' * 4]
    assert PacketBuilder.build_from_schema({'fields': [{'name': 'body', 'size': 2}]},
                                          {'body': b'ABCDE'}) == b'ABCDE'
