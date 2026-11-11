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

"""
Unit tests for ProtocolFuzzer.build_packet().

Tests packet assembly, auto-length, field order, schema defaults.
Tests computed field modes including counts_field.
Uses 127.0.0.1 - no network traffic generated.
"""

import hashlib
import sys
import zlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pytest
from bytefault.fuzzers.fuzzer import (
    ProtocolFuzzer, _apply_computed_fields, _apply_offset_injections,
    _apply_checksum_field, _apply_length_field, PacketBuilder,
)

_NEUTRAL_SCHEMA = {
    "length": {"field": "length", "size": 2, "endian": "big", "counts": "body"},
    "fields": [
        {"name": "length", "size": 2},
        {"name": "kind", "size": 1},
        {"name": "ordinal", "size": 2},
        {"name": "marker", "size": 1},
        {"name": "mode", "size": 1},
        {"name": "payload", "size": "var"},
    ],
    "order": ["length", "kind", "ordinal", "marker", "mode", "payload"],
    "defaults": {"length": b"\x00\x00", "kind": b"\x5a", "ordinal": b"\x12\x34",
                 "marker": b"\x7e", "mode": b"\xc0", "payload": b""},
    "computed": [{"type": "sequence", "field": "ordinal", "size": 2,
                  "start": 0x1234, "step": 1, "wrap": 65536}],
}


@pytest.fixture
def fuzzer():
    """ProtocolFuzzer pointed at localhost. Never connects."""
    return ProtocolFuzzer(
        host="127.0.0.1",
        port=1234,
        protocol="neutral-fixture",
        packet_schema=_NEUTRAL_SCHEMA,
    )


def test_build_basic_packet(fuzzer):
    """Build packet with all fields specified."""
    pkt = fuzzer.build_packet({
        "kind": b"\x01",
        "marker": b"\x10",
        "mode": b"\x00",
        "payload": b"\x00\x00",
    })
    assert isinstance(pkt, bytes)
    assert len(pkt) == 9  # 2 (len) + 1 (kind) + 2 (ordinal) + 1 (marker) + 1 (mode) + 2 (payload)


def test_auto_length_field(fuzzer):
    """Auto-length header matches actual packet size."""
    pkt = fuzzer.build_packet({
        "kind": b"\x01",
        "marker": b"\x10",
        "mode": b"\x00",
        "payload": b"\xAA\xBB\xCC\xDD",
    })
    length_field = int.from_bytes(pkt[0:2], "big")
    # Length field should be total - 2 (length field itself)
    assert length_field == len(pkt) - 2


def test_auto_length_empty_payload(fuzzer):
    """Empty payload still gets correct length."""
    pkt = fuzzer.build_packet({
        "kind": b"\x01",
        "marker": b"\x10",
        "mode": b"\x00",
        "payload": b"",
    })
    length_field = int.from_bytes(pkt[0:2], "big")
    assert length_field == len(pkt) - 2


def test_auto_length_large_payload(fuzzer):
    """Large payload length computed correctly."""
    pkt = fuzzer.build_packet({
        "kind": b"\x01",
        "marker": b"\x10",
        "mode": b"\x00",
        "payload": b"\xAA" * 1024,
    })
    length_field = int.from_bytes(pkt[0:2], "big")
    assert length_field == len(pkt) - 2
    assert len(pkt) == 2 + 1 + 2 + 1 + 1 + 1024


def test_no_auto_length(fuzzer):
    """Manual length override preserved."""
    pkt = fuzzer.build_packet(
        {
            "length": b"\x00\xFF",
            "kind": b"\x01",
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"\x00\x00",
        },
        auto_length=False,
    )
    assert pkt[0:2] == b"\x00\xFF"


def test_field_order(fuzzer):
    """Fields assembled in schema order: length, kind, ordinal, marker, mode, payload."""
    pkt = fuzzer.build_packet({
        "kind": b"\x11",
        "marker": b"\x33",
        "mode": b"\x44",
        "payload": b"\x55\x66",
    })
    # pkt[0:2] = length, pkt[2] = kind, pkt[3:5] = ordinal (auto), pkt[5] = marker, pkt[6] = mode
    assert pkt[2] == 0x11  # kind
    assert pkt[5] == 0x33  # marker
    assert pkt[6] == 0x44  # mode
    assert pkt[7:9] == b"\x55\x66"  # payload


def test_length_override(fuzzer):
    """length_override forces a specific length value."""
    pkt = fuzzer.build_packet(
        {
            "kind": b"\x01",
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"\x00\x00",
        },
        length_override=0xBEEF,
    )
    assert int.from_bytes(pkt[0:2], "big") == 0xBEEF


def test_different_kind_values(fuzzer):
    """Kind byte appears at the declared offset for different values."""
    for kind_val in [0x00, 0x01, 0x08, 0x0F, 0xFF]:
        pkt = fuzzer.build_packet({
            "kind": bytes([kind_val]),
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"",
        })
        assert pkt[2] == kind_val


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ────────────────────────────────────────────────────────────────────────
# counts_field computed field mode
# ────────────────────────────────────────────────────────────────────────

# Minimal schema used by counts_field unit tests (not auth-specific)
_COUNTS_FIELD_SCHEMA = {
    "length": {"field": "pkt_length", "size": 2, "endian": "big", "counts": "body"},
    "fields": [
        {"name": "pkt_length", "size": 2},
        {"name": "name_len", "size": 1},
        {"name": "name", "size": "var"},
        {"name": "tail", "size": 1},
    ],
    "order": ["pkt_length", "name_len", "name", "tail"],
    "defaults": {
        "pkt_length": b"\x00\x00",
        "name_len": b"\x00",
        "name": b"",
        "tail": b"\xff",
    },
    "computed": [
        {
            "type": "length",
            "field": "name_len",
            "size": 1,
            "counts": "field",
            "counts_field": "name",
        },
    ],
}


class TestCountsField:

    def test_counts_field_basic(self):
        """counts_field computes length of a named field."""
        fb = {"name": b"admin", "tail": b"\xff"}
        raw = bytearray(PacketBuilder.build_from_schema(_COUNTS_FIELD_SCHEMA, fb))
        _apply_computed_fields(raw, _COUNTS_FIELD_SCHEMA, field_bytes=fb)
        # name_len is at offset 2 (after 2-byte pkt_length), size=1
        assert raw[2] == 5  # len(b"admin")

    def test_counts_field_empty(self):
        """Empty field yields name_len=0."""
        fb = {"name": b"", "tail": b"\xff"}
        raw = bytearray(PacketBuilder.build_from_schema(_COUNTS_FIELD_SCHEMA, fb))
        _apply_computed_fields(raw, _COUNTS_FIELD_SCHEMA, field_bytes=fb)
        assert raw[2] == 0

    def test_counts_field_long(self):
        """200-byte field yields name_len=0xC8."""
        fb = {"name": b"A" * 200, "tail": b"\xff"}
        raw = bytearray(PacketBuilder.build_from_schema(_COUNTS_FIELD_SCHEMA, fb))
        _apply_computed_fields(raw, _COUNTS_FIELD_SCHEMA, field_bytes=fb)
        assert raw[2] == 200

    def test_counts_field_missing_field_bytes(self):
        """Missing counts_field reference defaults to length 0 (no crash)."""
        fb = {"tail": b"\xff"}  # 'name' not provided
        raw = bytearray(PacketBuilder.build_from_schema(_COUNTS_FIELD_SCHEMA, fb))
        _apply_computed_fields(raw, _COUNTS_FIELD_SCHEMA, field_bytes=fb)
        assert raw[2] == 0

    def test_multiple_computed_lengths(self):
        """pkt_length (counts: body) and name_len (counts: field) both correct."""
        fb = {"name": b"admin", "tail": b"\xff"}
        raw = bytearray(PacketBuilder.build_from_schema(_COUNTS_FIELD_SCHEMA, fb))
        _apply_computed_fields(raw, _COUNTS_FIELD_SCHEMA, field_bytes=fb)
        # name_len
        assert raw[2] == 5
        # pkt_length: body = everything after pkt_length(2) = name_len(1)+name(5)+tail(1) = 7
        pkt_length = int.from_bytes(raw[0:2], "big")
        assert pkt_length == 7


class TestRandomPayloadWithAutoLength:
    """Prove the core use case: random payload of random length, auto-calculated
    length field, unique every iteration, runs forever.

    This is the most fundamental fuzz capability:
        [XX YY] [kind] [ordinal 2B] [marker] [mode] [random payload...]
         ^                                      ^
         auto-calculated body length             different every test
    """

    def test_random_payload_auto_length_unique_every_iteration(self, fuzzer):
        """Each iteration builds a packet with a unique random payload and
        a correctly calculated length header.  No network I/O."""
        import random as random_module
        from bytefault.fuzzers.composer import FuzzComposer
        from bytefault.generators.random_bytes import RandomBytesGenerator

        rng = random_module.Random(0xDEAD)
        gen = RandomBytesGenerator(min_len=10, max_len=200, rng=rng)
        assert gen.count() is None, "infinite generator"

        generators = {"payload": gen}
        base = dict(_NEUTRAL_SCHEMA["defaults"])
        composer = FuzzComposer()

        packets = []
        payloads = []
        for i, (field_bytes, _prog) in enumerate(composer.compose(generators, base, strategy="single")):
            if i >= 50:
                break
            pkt = fuzzer.build_packet(field_bytes, auto_length=True)
            packets.append(pkt)
            # Extract the payload (everything after the 7-byte header)
            payload = pkt[7:]
            payloads.append(payload)

            # Length field = body length (everything after 2-byte length prefix)
            length_field = int.from_bytes(pkt[0:2], "big")
            expected_body_len = len(pkt) - 2
            assert length_field == expected_body_len, (
                f"iter {i}: length field {length_field} != body {expected_body_len}"
            )

            # Payload length should be within the generator's range
            assert 10 <= len(payload) <= 200, (
                f"iter {i}: payload len {len(payload)} out of range 10-200"
            )

        # All 50 payloads should be unique
        assert len(set(payloads)) == 50, "every payload must be unique"

        # All 50 packets should be unique
        assert len(set(packets)) == 50, "every packet must be unique"

        # Payload lengths should vary (random length)
        payload_lens = {len(p) for p in payloads}
        assert len(payload_lens) > 1, "payload lengths should vary"

    def test_random_payload_cli_parse_to_packet(self, fuzzer):
        """Full stack: CLI ``payload:random:10-100`` spec -> generator ->
        composer -> build_packet with auto-length.  No network I/O."""
        from bytefault.generators.cli_parser import parse_gen_field
        from bytefault.fuzzers.composer import FuzzComposer

        field, gen = parse_gen_field("payload:random:10-100,seed:999")
        assert field == "payload"
        assert gen.count() is None  # infinite

        generators = {field: gen}
        base = dict(_NEUTRAL_SCHEMA["defaults"])
        composer = FuzzComposer()

        for i, (field_bytes, _prog) in enumerate(composer.compose(generators, base)):
            if i >= 20:
                break
            pkt = fuzzer.build_packet(field_bytes)
            length_field = int.from_bytes(pkt[0:2], "big")
            assert length_field == len(pkt) - 2
            payload = pkt[7:]
            assert 10 <= len(payload) <= 100


class TestSchemaFlexibility:
    """Schema sizes are defaults, not maximums.

    Approach C — user-provided values larger than schema field sizes
    expand the packet.  Length fields auto-compute over the actual layout.
    Downstream fields shift to accommodate.
    """

    def test_oversized_field_expands_packet(self, fuzzer):
        """A 100-byte value in a 1-byte schema field expands the packet."""
        big_ordinal = b"\xAA" * 100
        pkt = fuzzer.build_packet({
            "kind": b"\x08",
            "ordinal": big_ordinal,
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"",
        })
        # Schema: length(2) + kind(1) + ordinal(2) + marker(1) + mode(1) = 7 bytes
        # Actual: length(2) + kind(1) + ordinal(100) + marker(1) + mode(1) = 105 bytes
        assert len(pkt) == 105
        # ordinal starts at offset 3 (after length:2, kind:1)
        assert pkt[3:103] == big_ordinal
        # marker and mode shifted right
        assert pkt[103] == 0x10  # marker
        assert pkt[104] == 0x00  # mode

    def test_oversized_field_auto_length_correct(self, fuzzer):
        """Length field auto-computes over actual packet, not schema sizes."""
        big_ordinal = b"\xBB" * 50
        pkt = fuzzer.build_packet({
            "kind": b"\x01",
            "ordinal": big_ordinal,
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"\xCC" * 10,
        })
        # Actual: length(2) + kind(1) + ordinal(50) + marker(1) + mode(1) + payload(10) = 65
        assert len(pkt) == 65
        length_field = int.from_bytes(pkt[0:2], "big")
        # Length counts body (everything after the 2-byte length prefix)
        assert length_field == 63

    def test_multiple_oversized_fields(self, fuzzer):
        """Two oversized fields both expand; offsets and length are correct."""
        big_kind = b"\x01\x02\x03"  # 3 bytes in a 1-byte field
        big_marker = b"\xAA\xBB"         # 2 bytes in a 1-byte field
        pkt = fuzzer.build_packet({
            "kind": big_kind,
            "marker": big_marker,
            "mode": b"\x00",
            "payload": b"\xDD",
        })
        # length(2) + kind(3) + ordinal(2) + marker(2) + mode(1) + payload(1) = 11
        assert len(pkt) == 11
        length_field = int.from_bytes(pkt[0:2], "big")
        assert length_field == 9  # 11 - 2
        # kind at offset 2, 3 bytes
        assert pkt[2:5] == big_kind
        # ordinal at offset 5 (schema default, padded to 2 bytes)
        # marker at offset 7, 2 bytes
        assert pkt[7:9] == big_marker
        # mode at offset 9
        assert pkt[9] == 0x00
        # payload at offset 10
        assert pkt[10:11] == b"\xDD"

    def test_schema_defaults_still_padded(self, fuzzer):
        """Fields not provided by user still pad to schema size."""
        pkt = fuzzer.build_packet({
            "kind": b"\x01",
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"",
        })
        # Normal 7-byte packet — no oversized fields, existing behavior preserved
        assert len(pkt) == 7
        length_field = int.from_bytes(pkt[0:2], "big")
        assert length_field == 5  # body = kind(1) + ordinal(2) + marker(1) + mode(1)

    def test_oversized_with_random_generator(self, fuzzer):
        """Random generator targeting a fixed-size field expands the packet
        every iteration with correct length calculation."""
        import random as random_module
        from bytefault.fuzzers.composer import FuzzComposer
        from bytefault.generators.random_bytes import RandomBytesGenerator

        rng = random_module.Random(42)
        gen = RandomBytesGenerator(min_len=50, max_len=200, rng=rng)
        generators = {"ordinal": gen}  # ordinal is 2 bytes in the schema
        base = dict(_NEUTRAL_SCHEMA["defaults"])
        composer = FuzzComposer()

        for i, (field_bytes, _prog) in enumerate(composer.compose(generators, base)):
            if i >= 20:
                break
            pkt = fuzzer.build_packet(field_bytes)
            ordinal_len = len(field_bytes["ordinal"])
            # Packet = length(2) + kind(1) + ordinal(N) + marker(1) + mode(1)
            expected_total = 2 + 1 + ordinal_len + 1 + 1
            assert len(pkt) == expected_total, (
                f"iter {i}: expected {expected_total}, got {len(pkt)}"
            )
            length_field = int.from_bytes(pkt[0:2], "big")
            assert length_field == expected_total - 2

    def test_exact_size_value_unchanged(self, fuzzer):
        """Value exactly matching schema size is neither padded nor truncated."""
        pkt = fuzzer.build_packet({
            "kind": b"\x08",
            "marker": b"\x10",
            "mode": b"\x00",
            "payload": b"",
        })
        assert pkt[2] == 0x08  # kind = 1 byte, exact match
        assert len(pkt) == 7


# ────────────────────────────────────────────────────────────────────────
# _apply_offset_injections
# ────────────────────────────────────────────────────────────────────────


class TestOffsetInjections:
    """Direct tests for the _apply_offset_injections helper."""

    def test_insert_at_offset(self):
        """Insert mode splices payload at offset; packet grows."""
        pkt = bytearray(b"\x00\x01\x02\x03\x04")
        field_bytes = {"@2": b"\xAA\xBB"}
        _apply_offset_injections(pkt, field_bytes, {"@2": "insert"})
        assert pkt == bytearray(b"\x00\x01\xAA\xBB\x02\x03\x04")

    def test_overwrite_at_offset(self):
        """Overwrite mode replaces bytes in-place."""
        pkt = bytearray(b"\x00\x01\x02\x03\x04")
        field_bytes = {"@2": b"\xAA\xBB"}
        _apply_offset_injections(pkt, field_bytes, {"@2": "overwrite"})
        assert pkt == bytearray(b"\x00\x01\xAA\xBB\x04")

    def test_overwrite_extends_past_end(self):
        """Overwrite at offset that extends past packet end grows it."""
        pkt = bytearray(b"\x00\x01\x02")
        field_bytes = {"@2": b"\xAA\xBB\xCC"}
        _apply_offset_injections(pkt, field_bytes, {"@2": "overwrite"})
        assert pkt == bytearray(b"\x00\x01\xAA\xBB\xCC")

    def test_insert_at_zero(self):
        """Insert at offset 0 prepends."""
        pkt = bytearray(b"\x01\x02\x03")
        field_bytes = {"@0": b"\xFF\xFE"}
        _apply_offset_injections(pkt, field_bytes, {"@0": "insert"})
        assert pkt == bytearray(b"\xFF\xFE\x01\x02\x03")

    def test_insert_at_end(self):
        """Insert at offset == len(packet) appends."""
        pkt = bytearray(b"\x01\x02\x03")
        field_bytes = {"@3": b"\xDD\xEE"}
        _apply_offset_injections(pkt, field_bytes, {"@3": "insert"})
        assert pkt == bytearray(b"\x01\x02\x03\xDD\xEE")

    def test_multiple_inserts_ascending(self):
        """Two inserts applied in offset order with shift tracking."""
        pkt = bytearray(b"\x00\x01\x02\x03\x04")
        field_bytes = {"@1": b"\xAA", "@3": b"\xBB"}
        modes = {"@1": "insert", "@3": "insert"}
        _apply_offset_injections(pkt, field_bytes, modes)
        # @1 insert: 00 AA 01 02 03 04  (shift=1)
        # @3 insert: actual offset = 3+1 = 4 → 00 AA 01 02 BB 03 04
        assert pkt == bytearray(b"\x00\xAA\x01\x02\xBB\x03\x04")

    def test_default_mode_is_insert(self):
        """Missing mode in offset_modes dict defaults to insert."""
        pkt = bytearray(b"\x00\x01\x02")
        field_bytes = {"@1": b"\xAA"}
        _apply_offset_injections(pkt, field_bytes, {})  # empty modes
        assert pkt == bytearray(b"\x00\xAA\x01\x02")

    def test_non_offset_keys_ignored(self):
        """Schema field names (no @) are skipped."""
        pkt = bytearray(b"\x00\x01\x02")
        field_bytes = {"kind": b"\xFF", "@1": b"\xAA"}
        _apply_offset_injections(pkt, field_bytes, {"@1": "insert"})
        assert pkt == bytearray(b"\x00\xAA\x01\x02")

    def test_no_offsets_returns_unchanged(self):
        """No @N keys → packet unchanged."""
        pkt = bytearray(b"\x00\x01\x02")
        field_bytes = {"kind": b"\x08"}
        _apply_offset_injections(pkt, field_bytes, {})
        assert pkt == bytearray(b"\x00\x01\x02")


# ────────────────────────────────────────────────────────────────────────
# Checksum computed type
# ────────────────────────────────────────────────────────────────────────


class TestChecksumComputed:
    """Tests for type: 'checksum' in _apply_computed_fields."""

    def test_crc32_mid_packet(self):
        """CRC32 written at a fixed offset inside the packet."""
        # Schema: 4 bytes data + 4 bytes CRC placeholder
        pkt = bytearray(b"\x01\x02\x03\x04" + b"\x00\x00\x00\x00")
        schema = {
            "fields": [],
            "computed": [
                {"type": "checksum", "field": "crc", "offset": 4,
                 "size": 4, "algorithm": "crc32",
                 "range_start": 0, "range_end": 4},
            ],
        }
        _apply_computed_fields(pkt, schema)
        expected_crc = zlib.crc32(b"\x01\x02\x03\x04") & 0xFFFFFFFF
        actual_crc = int.from_bytes(pkt[4:8], "big")
        assert actual_crc == expected_crc

    def test_crc32_append(self):
        """CRC32 appended to the end of the packet."""
        pkt = bytearray(b"\xAA\xBB\xCC\xDD")
        schema = {
            "fields": [],
            "computed": [
                {"type": "checksum", "offset": "append",
                 "size": 4, "algorithm": "crc32"},
            ],
        }
        _apply_computed_fields(pkt, schema)
        assert len(pkt) == 8
        expected_crc = zlib.crc32(b"\xAA\xBB\xCC\xDD") & 0xFFFFFFFF
        actual_crc = int.from_bytes(pkt[4:8], "big")
        assert actual_crc == expected_crc

    def test_crc16_ccitt(self):
        """CRC-16/CCITT-FALSE computed correctly."""
        data = b"\x31\x32\x33\x34\x35\x36\x37\x38\x39"  # "123456789"
        pkt = bytearray(data + b"\x00\x00")
        schema = {
            "fields": [],
            "computed": [
                {"type": "checksum", "offset": len(data),
                 "size": 2, "algorithm": "crc16",
                 "range_start": 0, "range_end": len(data)},
            ],
        }
        _apply_computed_fields(pkt, schema)
        # Known CRC-16/CCITT-FALSE of "123456789" = 0x29B1
        actual_crc = int.from_bytes(pkt[len(data):len(data) + 2], "big")
        assert actual_crc == 0x29B1

    def test_md5_truncated(self):
        """MD5 digest truncated to specified size."""
        data = b"test data for md5"
        pkt = bytearray(data + b"\x00" * 8)
        schema = {
            "fields": [],
            "computed": [
                {"type": "checksum", "offset": len(data),
                 "size": 8, "algorithm": "md5",
                 "range_start": 0, "range_end": len(data)},
            ],
        }
        _apply_computed_fields(pkt, schema)
        expected = hashlib.md5(data).digest()[:8]
        assert pkt[len(data):len(data) + 8] == expected

    def test_sha256_full(self):
        """SHA-256 at full 32-byte digest length."""
        data = b"\x01\x02\x03"
        pkt = bytearray(data + b"\x00" * 32)
        schema = {
            "fields": [],
            "computed": [
                {"type": "checksum", "offset": len(data),
                 "size": 32, "algorithm": "sha256",
                 "range_start": 0, "range_end": len(data)},
            ],
        }
        _apply_computed_fields(pkt, schema)
        expected = hashlib.sha256(data).digest()
        assert pkt[len(data):len(data) + 32] == expected

    def test_negative_range_end(self):
        """Negative range_end counts from packet end."""
        # 6 bytes data + 2 bytes CRC placeholder → range_end=-2 excludes CRC
        pkt = bytearray(b"\x10\x20\x30\x40\x50\x60" + b"\x00\x00")
        schema = {
            "fields": [],
            "computed": [
                {"type": "checksum", "offset": 6,
                 "size": 2, "algorithm": "crc16",
                 "range_start": 0, "range_end": -2},
            ],
        }
        _apply_computed_fields(pkt, schema)
        # CRC computed over bytes 0..5 (6 bytes, excludes the CRC field)
        data = b"\x10\x20\x30\x40\x50\x60"
        crc = 0xFFFF
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        actual = int.from_bytes(pkt[6:8], "big")
        assert actual == crc

    def test_checksum_skip_field(self):
        """Checksum field in skip_fields is not written."""
        pkt = bytearray(b"\x01\x02\x00\x00")
        schema = {
            "fields": [],
            "computed": [
                {"type": "checksum", "field": "crc", "offset": 2,
                 "size": 2, "algorithm": "crc32"},
            ],
        }
        _apply_computed_fields(pkt, schema, skip_fields={"crc"})
        assert pkt[2:4] == b"\x00\x00"  # unchanged


# ────────────────────────────────────────────────────────────────────────
# Range-length mode
# ────────────────────────────────────────────────────────────────────────


class TestRangeLength:
    """Tests for counts: 'range' in length computed specs."""

    def test_range_counts_subset(self):
        """Length field at offset 0 counts only bytes 4 through 8."""
        # [length:2][header:2][data:4][trailer:2] = 10 bytes
        pkt = bytearray(b"\x00\x00\xAA\xBB\x01\x02\x03\x04\xCC\xDD")
        schema = {
            "fields": [],
            "computed": [
                {"type": "length", "offset": 0, "size": 2,
                 "counts": "range", "range_start": 4, "range_end": 8},
            ],
        }
        _apply_computed_fields(pkt, schema)
        length_val = int.from_bytes(pkt[0:2], "big")
        assert length_val == 4  # bytes 4-7

    def test_range_to_end(self):
        """range_end: null counts from range_start to end of packet."""
        pkt = bytearray(b"\x00\x00\xFF\xFF\x01\x02\x03")
        schema = {
            "fields": [],
            "computed": [
                {"type": "length", "offset": 0, "size": 2,
                 "counts": "range", "range_start": 4},
            ],
        }
        _apply_computed_fields(pkt, schema)
        assert int.from_bytes(pkt[0:2], "big") == 3  # bytes 4, 5, 6

    def test_range_negative_end(self):
        """Negative range_end counts from packet end."""
        pkt = bytearray(b"\x00\x00\x01\x02\x03\x04\x05\x06")
        schema = {
            "fields": [],
            "computed": [
                {"type": "length", "offset": 0, "size": 2,
                 "counts": "range", "range_start": 2, "range_end": -2},
            ],
        }
        _apply_computed_fields(pkt, schema)
        # range_end = 8 + (-2) = 6 → bytes 2..5 = 4 bytes
        assert int.from_bytes(pkt[0:2], "big") == 4


# ────────────────────────────────────────────────────────────────────────
# Multiple computed fields (length + checksum together)
# ────────────────────────────────────────────────────────────────────────


class TestMultipleComputed:
    """Length and checksum coexist in the same schema."""

    def test_length_then_checksum(self):
        """Length computed first, then CRC32 appended — both correct."""
        # [length:2][data:4] → length counts body, then CRC32 appended
        pkt = bytearray(b"\x00\x00\xAA\xBB\xCC\xDD")
        schema = {
            "fields": [],
            "computed": [
                {"type": "length", "offset": 0, "size": 2,
                 "counts": "body"},
                {"type": "checksum", "offset": "append",
                 "size": 4, "algorithm": "crc32"},
            ],
        }
        _apply_computed_fields(pkt, schema)
        # Length = body (everything after 2+2=4)... actually "body" = len - (offset+size) = 6-(0+2)=4
        length_val = int.from_bytes(pkt[0:2], "big")
        assert length_val == 4
        # CRC32 of the packet as it was at checksum time (length already written)
        crc_data = bytes(pkt[:6])  # the 6-byte packet before CRC append
        expected_crc = zlib.crc32(crc_data) & 0xFFFFFFFF
        actual_crc = int.from_bytes(pkt[6:10], "big")
        assert actual_crc == expected_crc
        assert len(pkt) == 10
