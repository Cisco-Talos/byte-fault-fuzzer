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

"""Packet building and schema utilities.

Contains:
- ``PacketBuilder`` — assemble packets from schema + field values
- Schema introspection helpers (``_length_spec_from_schema``, etc.)
- Computed-field application (``_apply_computed_fields``, etc.)
- Offset injection (``_apply_offset_injections``)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

from bytefault.fuzzers.helpers import _field_sizes_from_schema
from bytefault.core.contracts import Calculation, ContractError
from bytefault.core.calculations import ALGORITHMS, calculation_bytes
from bytefault.core.validation import passive

logger = logging.getLogger(__name__)

# Retained schema-construction API for protocol and callable integrations.
# The bundled Raw declaration is intentionally not its full capability test.

# ── Schema introspection ────────────────────────────────────────────


def _length_spec_from_schema(schema: Optional[dict]) -> dict | None:
    if not schema:
        return None
    length_spec = schema.get("length")
    if length_spec:
        spec = dict(length_spec)
        spec.setdefault("type", "length")
    else:
        spec = None
        for entry in schema.get("computed", []):
            if entry.get("type", "length") == "length":
                spec = dict(entry)
                break
    if not spec:
        return None
    if "field" not in spec:
        if any(f.get("name") == "length" for f in schema.get("fields", [])):
            spec["field"] = "length"
    return spec


def _computed_specs_from_schema(schema: Optional[dict]) -> List[dict]:
    if not schema:
        return []
    computed = list(schema.get("computed", []))
    length_spec = schema.get("length")
    if length_spec:
        spec = dict(length_spec)
        spec.setdefault("type", "length")
        if "field" not in spec:
            if any(f.get("name") == "length" for f in schema.get("fields", [])):
                spec["field"] = "length"
        if not any(
            c.get("type", "length") == "length" and c.get("field") == spec.get("field")
            for c in computed
        ):
            computed.append(spec)
    return computed


def _sequence_specs_from_schema(schema: Optional[dict]) -> List[dict]:
    if not schema:
        return []
    return [
        spec
        for spec in schema.get("computed", [])
        if spec.get("type") == "sequence" and spec.get("field")
    ]


def _field_offsets_from_schema(schema: Optional[dict], field_bytes: Dict[str, bytes]) -> Dict[str, Tuple[int, int]]:
    offsets: Dict[str, Tuple[int, int]] = {}
    if not schema:
        return offsets
    field_sizes = _field_sizes_from_schema(schema)
    order = schema.get("order", [f.get("name") for f in schema.get("fields", [])])
    cursor = 0
    for name in order:
        if not name:
            continue
        size = field_sizes.get(name, "var")
        if size == "var":
            value = field_bytes.get(name, b"")
            field_len = len(value)
        else:
            # Use actual value length when larger than schema size.
            # This ensures computed fields (length, etc.) see the real
            # packet layout, not the schema's ideal layout.
            actual = field_bytes.get(name, b"")
            field_len = max(int(size), len(actual)) if actual else int(size)
        offsets[name] = (cursor, field_len)
        cursor += field_len
    return offsets


# ── Computed field application ───────────────────────────────────────


def _apply_computed_fields(
    packet: bytearray,
    schema: Optional[dict],
    field_bytes: Optional[Dict[str, bytes]] = None,
    pad_byte: int = 0x00,
    skip_fields: Optional[Set[str]] = None,
    skip_ranges: Optional[List[Tuple[int, int]]] = None,
    length_override: Optional[int] = None,
) -> tuple[tuple[str, str], ...]:
    """Apply known calculations and return per-spec repair/skip/unavailable facts.

    Sequence values are bound separately by the pure build_packet adapter.
    Missing schema/computations returns an empty tuple. Required unavailable
    calculations and malformed inputs raise an attributed ContractError.
    """
    if not schema:
        return ()
    computed = _computed_specs_from_schema(schema)
    if not computed:
        return ()
    skip_fields = skip_fields or set()
    field_bytes = field_bytes or {}
    offsets = _field_offsets_from_schema(schema, field_bytes)
    field_sizes_map = _field_sizes_from_schema(schema)

    outcomes = []
    for spec in computed:
        spec_type = spec.get("type", "length")
        if spec_type == "length":
            outcome = _apply_length_field(spec, packet, offsets, field_sizes_map,
                                          field_bytes, skip_fields, skip_ranges, length_override)
            outcomes.append((spec.get("field") or "length", outcome))
        elif spec_type == "checksum":
            outcome = _apply_checksum_field(spec, packet, offsets, field_sizes_map,
                                            skip_fields, skip_ranges)
            outcomes.append((spec.get("field") or "checksum", outcome))
        elif spec_type == "sequence":
            continue  # handled by _apply_sequence_fields
        else:
            if spec.get("required", False):
                raise ContractError("schema.computed", "unsupported_capability", str(spec_type))
            outcomes.append((str(spec_type), "unavailable_rule_or_location"))
    return tuple(outcomes)


def _destination(spec, offsets, field_sizes, *, checksum=False):
    field = spec.get("field")
    offset = ("append" if spec.get("offset") == "append" else
              offsets[field][0] if field in offsets else spec.get("offset"))
    size = spec.get("size")
    if size is None:
        size = (ALGORITHMS.get(spec.get("algorithm", "crc32")) if checksum else
                offsets[field][1] if field in offsets else field_sizes.get(field))
    if offset is not None and offset != "append" and (type(offset) is not int or offset < 0):
        raise ContractError("schema.computed.offset", "malformed", "nonnegative integer or append required")
    if size is not None and (type(size) is not int or size <= 0):
        raise ContractError("schema.computed.size", "malformed", "positive integer required")
    return offset, size


def _apply_calculation(packet, calculation, offset, size, *, field_bytes=None, skip_ranges=None):
    passive(calculation, "schema.computed")
    if size is None or offset is None:
        if calculation.required:
            raise ContractError("schema.computed", "unsupported_capability", "known output location/size required")
        return "unavailable_rule_or_location"
    start = len(packet) if offset == "append" else offset
    if skip_ranges and any(lo < start + size and hi > start for lo, hi in skip_ranges):
        return "explicit_edit"
    spans = {name: (0, len(value)) for name, value in (field_bytes or {}).items()}
    try:
        output = calculation_bytes(calculation, packet, size, start, start + size,
                                   field_spans=spans)
    except OverflowError as exc:
        if calculation.required:
            raise ContractError("schema.computed", "calculation_overflow", str(exc)) from exc
        return "unavailable_overflow"
    except ContractError as exc:
        if calculation.required or exc.code != "unsupported_capability":
            raise
        return "unavailable_rule_or_location"
    if start > len(packet):
        packet.extend(b"\0" * (start - len(packet)))
    packet[start:start + size] = output
    return "repaired"


def _apply_length_field(
    spec: dict,
    packet: bytearray,
    offsets: Dict[str, Tuple[int, int]],
    field_sizes: Dict[str, object],
    field_bytes: Dict[str, bytes],
    skip_fields: Optional[Set[str]],
    skip_ranges: Optional[List[Tuple[int, int]]],
    length_override: Optional[int],
):
    """Translate a pure schema length request to the authoritative core arithmetic."""
    if spec.get("field") in (skip_fields or set()):
        return "explicit_edit"
    offset, size = _destination(spec, offsets, field_sizes)
    calculation = Calculation(str(spec.get("field") or "length"), "schema", "length",
        offset=None if offset == "append" else offset, size=size,
        endian=spec.get("endian", "big"), destination="append" if offset == "append" else "fixed",
        counts=spec.get("counts", "body"), counts_field=spec.get("counts_field"),
        range_start=spec.get("range_start", 0), range_end=spec.get("range_end"),
        required=spec.get("required", False), override_value=length_override)
    return _apply_calculation(packet, calculation, offset, size,
                              field_bytes=field_bytes, skip_ranges=skip_ranges)


def _apply_checksum_field(
    spec: dict,
    packet: bytearray,
    offsets: Dict[str, Tuple[int, int]],
    field_sizes: Dict[str, object],
    skip_fields: Optional[Set[str]],
    skip_ranges: Optional[List[Tuple[int, int]]] = None,
):
    """Translate a schema checksum/digest; core owns algorithms, sizing and encoding."""
    if spec.get("field") in (skip_fields or set()):
        return "explicit_edit"
    offset, size = _destination(spec, offsets, field_sizes, checksum=True)
    calculation = Calculation(str(spec.get("field") or "checksum"), "schema", "checksum",
        offset=None if offset == "append" else offset, size=size,
        destination="append" if offset == "append" else "fixed",
        algorithm=spec.get("algorithm", "crc32"), range_start=spec.get("range_start", 0),
        range_end=spec.get("range_end"), required=spec.get("required", False))
    return _apply_calculation(packet, calculation, offset, size, skip_ranges=skip_ranges)


# ── Offset injections ────────────────────────────────────────────────


def _apply_offset_injections(
    packet: bytearray,
    field_bytes: Dict[str, bytes],
    offset_modes: Dict[str, str],
) -> bytearray:
    """Apply ``@N`` offset injections to *packet* in-place.

    Injections are applied in ascending offset order.  For *insert* mode
    an accumulated shift is tracked so later offsets remain valid relative
    to the original (pre-injection) packet layout.

    Modes:
        ``insert`` (default) — splice payload at offset; downstream bytes
            shift right.  ``packet[off:off] = value``
        ``overwrite`` — write payload starting at offset; packet grows if
            the payload extends past the end.

    This adapter translates sorted original coordinates into explicit working
    placements, then uses the current materializer. It performs no calculation;
    combined edits/relocated repair use the ordinary FieldLocation request.
    """
    from bytefault.core.contracts import (ConversationAction, PreparedRow,
        PreparedContribution, SourceInvocation, Placement)
    from bytefault.core.byte_edits import materialize

    injections = []
    for name, value in field_bytes.items():
        if name.startswith("@"):
            try:
                offset = int(name[1:])
            except ValueError as exc:
                raise ContractError("schema.injections." + name, "malformed", "numeric offset required") from exc
            mode = offset_modes.get(name, "insert")
            if offset < 0 or mode not in ("insert", "overwrite") or type(value) is not bytes:
                raise ContractError("schema.injections." + name, "malformed",
                                    "nonnegative offset, exact bytes and insert/overwrite required")
            injections.append((offset, value, mode))
    contributions, placements, shift = [], [], 0
    for index, (offset, value, mode) in enumerate(sorted(injections, key=lambda item: item[0])):
        identity = str(index)
        contributions.append(PreparedContribution(identity, value, SourceInvocation(identity, "literal")))
        placements.append(Placement(identity, identity, "schema", mode, offset + shift))
        if mode == "insert":
            shift += len(value)
    action = ConversationAction("schema", bytes(packet))
    row = PreparedRow("schema", 1, tuple(contributions), tuple(placements))
    packet[:] = materialize(action, row).final_bytes
    return packet


# ── PacketBuilder ────────────────────────────────────────────────────


class PacketBuilder:
    """Build protocol packets with configurable fields."""

    @staticmethod
    def build_from_schema(
        schema: dict,
        field_bytes: dict,
        pad_byte: int = 0x00,
    ) -> bytes:
        fields = schema.get("fields", [])
        field_sizes = {}
        for entry in fields:
            name = entry.get("name")
            if name:
                field_sizes[name] = entry.get("size")

        order = schema.get("order", [f.get("name") for f in fields])
        body = b""
        for name in order:
            if not name:
                continue
            value = field_bytes.get(name, b"")
            size = field_sizes.get(name, "var")
            if size == "var":
                body += value
            else:
                if len(value) < size:
                    # Pad short values up to schema size (schema helps)
                    value = bytes([pad_byte]) * (size - len(value)) + value
                # No truncation — user-provided values larger than schema
                # size expand the packet.  Schema is a default, not a limit.
                body += value
        return body
