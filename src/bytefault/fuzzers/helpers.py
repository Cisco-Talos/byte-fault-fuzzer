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

"""Standalone fuzzer helpers with no dependencies beyond the standard library."""

from __future__ import annotations

import logging
import random
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Retain schema/byte helpers for protocol authors and callable integrations.
# Raw-only packaging does not exercise every supported helper or schema shape.

def parse_hex_bytes(value: str) -> bytes:
    """Parse a hex string into bytes (accepts spaces, 0x, \\x)."""
    cleaned = value.replace(" ", "").replace("0x", "").replace("\\x", "")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"Invalid hex string length: {value}")
    return bytes.fromhex(cleaned)


def parse_hex_byte(value: str) -> int:
    """Parse a single hex byte (accepts 0x prefix)."""
    raw = parse_hex_bytes(value)
    if len(raw) != 1:
        raise ValueError(f"Expected single byte, got {len(raw)} bytes")
    return raw[0]


def _randbytes(rng: Optional[random.Random], length: int) -> bytes:
    if length <= 0:
        return b""
    if rng is None:
        return secrets.token_bytes(length)
    try:
        return rng.randbytes(length)  # type: ignore[attr-defined]
    except AttributeError:
        return rng.getrandbits(length * 8).to_bytes(length, "big")


def _randlength(rng: Optional[random.Random], min_len: int, max_len: int) -> int:
    if min_len >= max_len:
        return min_len
    if rng is None:
        return min_len + secrets.randbelow(max_len - min_len + 1)
    return rng.randint(min_len, max_len)


def _parse_length_range(spec: str) -> Tuple[int, int]:
    raw = spec.strip()
    if "-" in raw:
        left, right = raw.split("-", 1)
        if not left or not right:
            raise ValueError(f"Invalid length range {spec!r}")
        min_len = int(left.strip(), 0)
        max_len = int(right.strip(), 0)
    else:
        min_len = max_len = int(raw, 0)
    if min_len <= 0 or max_len <= 0:
        raise ValueError("Length values must be >= 1")
    if min_len > max_len:
        raise ValueError("Min length cannot exceed max length")
    return min_len, max_len


def _parse_recovery_delays(spec: Optional[str]) -> List[float]:
    if not spec:
        return []
    parts = [item.strip() for item in spec.split(",") if item.strip()]
    if not parts:
        return []
    delays: List[float] = []
    for part in parts:
        delays.append(float(part))
    return delays


def _load_seed_file(path: str, *, encoding: str = 'binary') -> bytes:
    """Load exact binary seed bytes, or explicitly selected ASCII hex input."""
    data = Path(path).read_bytes()
    if encoding == 'binary':
        return data
    if encoding != 'hex':
        raise ValueError("seed encoding must be 'binary' or 'hex'")
    text = ''.join(data.decode('ascii').split())
    return parse_hex_bytes(text)


def _field_sizes_from_schema(schema: Optional[dict]) -> Dict[str, Optional[int]]:
    sizes: Dict[str, Optional[int]] = {}
    for entry in (schema or {}).get("fields", []):
        name = entry.get("name")
        if name:
            sizes[name] = entry.get("size")
    return sizes


def _int_to_bytes(value: int, size: Optional[int]) -> bytes:
    if size is None or size == "var":
        # Minimal length for the integer.
        length = max(1, (value.bit_length() + 7) // 8)
    else:
        length = size
    return value.to_bytes(length, "big")


def _field_default_lens_from_schema(schema: Optional[dict]) -> Dict[str, Optional[int]]:
    defaults: Dict[str, Optional[int]] = {}
    for entry in (schema or {}).get("fields", []):
        name = entry.get("name")
        if name:
            defaults[name] = entry.get("default_len")
    return defaults
