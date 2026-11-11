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

from __future__ import annotations

import os
from pathlib import Path


def resolve_log_path(log_path: str | None, artifacts_dir: Path) -> str | None:
    if not log_path:
        return None
    if os.path.isabs(log_path) or os.path.splitdrive(log_path)[0] or '/' in log_path or '\\' in log_path:
        return log_path
    return str(artifacts_dir / "logs" / log_path)


import logging
from typing import Optional


LOG_FORMAT = "%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Retained callable formatting/setup utilities, also exposed by fuzzers.fuzzer.
# Normal execution uses ActionLog; setup_logging is an explicit caller opt-in
# that configures Python logging, not the application's required record writer.

def fmt_bytes(data: bytes, max_ascii: int = 200) -> str:
    """Format bytes as ``hex [ascii]`` when content is mostly printable.

    Always returns the hex representation.  When >=60 % of the bytes fall in
    the printable ASCII range (0x20–0x7E) or are common control chars (CR, LF,
    TAB), an ASCII decode is appended in brackets.

    Examples::

        fmt_bytes(b"USER anonymous\\r\\n")
        # '5553455220616e6f6e796d6f75730d0a [USER anonymous\\r\\n]'

        fmt_bytes(b"\\x00\\x04\\x08\\x2a")
        # '0004082a'
    """
    hex_str = data.hex()
    if not data:
        return hex_str

    printable = sum(
        1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    if printable / len(data) < 0.60:
        return hex_str

    # Build a readable ASCII rendition (replace control chars with escape sequences)
    _esc = {0x09: "\\t", 0x0A: "\\n", 0x0D: "\\r"}
    parts: list[str] = []
    for b in data[:max_ascii]:
        if b in _esc:
            parts.append(_esc[b])
        elif 0x20 <= b <= 0x7E:
            parts.append(chr(b))
        else:
            parts.append(f"\\x{b:02x}")
    ascii_str = "".join(parts)
    if len(data) > max_ascii:
        ascii_str += "..."
    return f"{hex_str} [{ascii_str}]"


def setup_logging(debug: bool, log_file: Optional[str] = None) -> None:
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)

    if not root.handlers:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT))
        root.addHandler(stream_handler)

    if log_file:
        abs_log = os.path.abspath(log_file)
        for handler in root.handlers:
            if isinstance(handler, logging.FileHandler) and handler.baseFilename == abs_log:
                return  # already attached
        file_handler = logging.FileHandler(abs_log, mode="a")  # always append
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT))
        root.addHandler(file_handler)
