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

"""Rich renderable components for the fuzzer Live UI.

Each ``build_*`` function takes a ``FuzzSessionState`` and returns a
Rich renderable (``Text``, ``Table``, ``Group``, etc.) suitable for
``Live.update()``.

Rendering is stateless — every frame is built from scratch, matching
Rich Live's redraw-from-scratch model.

All components recalculate widths and row counts from current terminal
dimensions each frame, supporting terminal resize.
"""

from __future__ import annotations

import os
import random
import shutil
import time
from pathlib import Path
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Deque, Dict, List, Optional, Sequence, Tuple
from bytefault.ui.state import RingBufferEntry

try:
    from rich import box as rich_box
    from rich.align import Align
    from rich.console import Group
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskID,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.rule import Rule
    from rich.style import Style
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

if TYPE_CHECKING:
    from bytefault.ui.state import ViewState as FuzzSessionState

# ── Constants ────────────────────────────────────────────────────────

SPARKLINE_CHARS = "_▁▂▃▄▅▆▇█"

# Styles -- loaded from the centralized theme module.
# All Style constants (LABEL_STYLE, VALUE_STYLE, etc.) are populated
# at import time by ``theme.apply_theme()`` and re-exported here so
# existing ``from rich_renderables import LABEL_STYLE`` still works.
from bytefault.ui.theme import (  # noqa: E402  (after try/except)
    ACTIVE_SCREEN_STYLE,
    BORDER_COLOR,
    BYTE_STYLE_CONTROL,
    BYTE_STYLE_FF,
    BYTE_STYLE_HIGH,
    BYTE_STYLE_NEWLINE,
    BYTE_STYLE_NULL,
    BYTE_STYLE_TEXT,
    CRITICAL_STYLE,
    FIELD_COLORS,
    HB_GREEN_BRIGHT,
    HB_GREEN_DIM,
    HB_PULSE_PERIOD,
    HEADER_BG,
    HELP_TITLE_STYLE,
    INACTIVE_SCREEN_STYLE,
    LABEL_STYLE,
    LOG_BRACKET_STYLE,
    LOG_FOLLOW_STYLE,
    LOG_HEX_STYLE,
    LOG_LEVEL_CRITICAL,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LINE_NUM_STYLE,
    LOG_MESSAGE_STYLE,
    LOG_SCROLL_STYLE,
    LOG_SEARCH_CURSOR_STYLE,
    LOG_SEARCH_INPUT_STYLE,
    LOG_SEARCH_SLASH_STYLE,
    LOG_SEARCH_STYLE,
    LOG_TIMESTAMP_STYLE,
    MENU_BG,
    MUTED_STYLE,
    PROGRESS_INNER_STYLE,
    RAIN_CHARS as _RAIN_CHARS,
    RECOVERY_STYLE,
    RULE_STYLE,
    SEPARATOR_STYLE,
    SPARKLINE_RX_STYLE,
    SPARKLINE_TX_STYLE,
    STATUS_PAUSED_STYLE,
    STATUS_RUNNING_STYLE,
    STATUS_STOPPING_STYLE,
    TX_STYLE,
    RX_STYLE,
    VALUE_STYLE,
    WARNING_STYLE,
    _HB_GREEN_MID,
    _HB_RED,
    _HB_UNKNOWN,
    _RAIN_STYLES,
    get_theme_name,
)

# Heartbeat (ICMP monitor) non-style constants
_HB_SYMBOL = "\u25cf"  # BLACK CIRCLE
_HB_GREEN_DIM = HB_GREEN_DIM     # RGB tuple, interpolated at render time
_HB_GREEN_BRIGHT = HB_GREEN_BRIGHT
_HB_PULSE_PERIOD = HB_PULSE_PERIOD


# ── Matrix rain ──────────────────────────────────────────────────────

# _RAIN_CHARS imported from theme (changes per-theme, e.g. katakana vs hex)
# _RAIN_STYLES imported from theme (6-level brightness palette)


def build_matrix_rain(
    width: Optional[int] = None,
    height: int = 2,
    orientation: str = "horizontal",
    density: float = 0.12,
    seed: int = 42,
) -> Text:
    """Build an animated matrix digital rain effect.

    Animation state is derived from ``time.time()`` so each call
    advances the animation without an external clock.

    Parameters
    ----------
    width : int, optional
        Terminal width (auto-detected if omitted).
    height : int
        Number of rows (default 2).
    orientation : str
        ``'horizontal'`` — streams move left-to-right (default).
        ``'vertical'`` — drops fall top-to-bottom.
    density : float
        Approximate fraction of cells occupied (0.0-1.0).
    seed : int
        RNG seed for reproducible stream layouts.
    """
    w = width or shutil.get_terminal_size((80, 24)).columns
    rng = random.Random(seed)

    if orientation == "horizontal":
        return _rain_horizontal(w, height, density, rng)
    return _rain_vertical(w, height, rng)


def _rain_horizontal(
    width: int, height: int, density: float, rng: random.Random,
) -> Text:
    """Streams move left-to-right across each row."""
    now = time.time()
    n_styles = len(_RAIN_STYLES)
    n_chars = len(_RAIN_CHARS)
    # More streams on wider terminals for better coverage.
    n_per_row = max(4, int(width * density / 2))

    text = Text()
    for row_idx in range(height):
        # Generate stream parameters (deterministic per row).
        streams: list = []
        row_rng = random.Random(rng.random())
        for _ in range(n_per_row):
            speed = row_rng.uniform(10, 30)
            trail = row_rng.randint(4, 8)
            # Large, widely varied gap so each stream has a different
            # cycle length (1.5x-3x the visible width).  This prevents
            # all streams from wrapping simultaneously.
            gap = row_rng.randint(width // 2, width * 2)
            phase = row_rng.uniform(0, width + trail + gap)
            streams.append((speed, trail, gap, phase))

        # Compute brightness level for each cell.
        cells: List[int] = [-1] * width
        for speed, trail, gap, phase in streams:
            cycle = width + trail + gap
            head = int((now * speed + phase) % cycle)
            for t in range(trail + 1):
                col = head - t
                if 0 <= col < width:
                    lvl = max(0, n_styles - 1 - t)
                    if lvl > cells[col]:
                        cells[col] = lvl

        # Render row — pick characters that flicker ~3x/sec.
        time_slot = int(now * 3)
        for col, lvl in enumerate(cells):
            if lvl < 0:
                text.append(" ")
            else:
                ci = (row_idx * 997 + col * 31 + time_slot * 7) % n_chars
                text.append(_RAIN_CHARS[ci], style=_RAIN_STYLES[lvl])
        if row_idx < height - 1:
            text.append("\n")

    return text


def _rain_vertical(
    width: int, height: int, rng: random.Random,
) -> Text:
    """Drops fall top-to-bottom down each column."""
    now = time.time()
    n_styles = len(_RAIN_STYLES)
    n_chars = len(_RAIN_CHARS)

    grid = [[-1] * width for _ in range(height)]
    for col_idx in range(width):
        speed = rng.uniform(1.5, 4.0)
        gap = rng.randint(2, 6)
        phase = rng.uniform(0, height + 1 + gap)
        cycle = height + 1 + gap
        head = int((now * speed + phase) % cycle)
        for t in range(min(height, n_styles)):
            row = head - t
            if 0 <= row < height:
                lvl = max(0, n_styles - 1 - t)
                if lvl > grid[row][col_idx]:
                    grid[row][col_idx] = lvl

    text = Text()
    time_slot = int(now * 3)
    for row_idx in range(height):
        for col_idx in range(width):
            lvl = grid[row_idx][col_idx]
            if lvl < 0:
                text.append(" ")
            else:
                ci = (row_idx * 997 + col_idx * 31 + time_slot * 7) % n_chars
                text.append(_RAIN_CHARS[ci], style=_RAIN_STYLES[lvl])
        if row_idx < height - 1:
            text.append("\n")

    return text


# ── Byte coloring ────────────────────────────────────────────────────


def style_hex_byte(byte_val: int) -> Style:
    """Return the Rich ``Style`` for a given byte value.

    Categories:
    - 0x09, 0x20-0x7E → readable ASCII text (tab + printable)
    - 0x00 → null
    - 0x0A, 0x0D → line endings
    - 0x01-0x08, 0x0B-0x0C, 0x0E-0x1F → control (unusual in protocols)
    - 0xFF → all-ones (broadcast, padding, uninit)
    - 0x80-0xFE → high/binary/extended
    """
    if byte_val == 0x00:
        return BYTE_STYLE_NULL
    if byte_val in (0x0A, 0x0D):
        return BYTE_STYLE_NEWLINE
    if byte_val == 0x09 or 0x20 <= byte_val <= 0x7E:
        return BYTE_STYLE_TEXT
    if 0x01 <= byte_val <= 0x1F:
        return BYTE_STYLE_CONTROL
    if byte_val == 0xFF:
        return BYTE_STYLE_FF
    # 0x80-0xFE
    return BYTE_STYLE_HIGH


# ── Menu row ─────────────────────────────────────────────────────────


def build_menu_row(state: "FuzzSessionState") -> Text:
    """Build the top menu row showing screens and controls.

    Left: screen selector with active indicator.
    Right: state indicators and controls.
    Full terminal width.
    """
    term_width = shutil.get_terminal_size((80, 24)).columns
    text = Text()

    # Left side: screen selector
    active = state.active_screen

    # F2 Dashboard
    if active == "dashboard":
        text.append(" F2 Dashboard", style=ACTIVE_SCREEN_STYLE)
        text.append("*", style=ACTIVE_SCREEN_STYLE)
    else:
        text.append(" F2 Dashboard", style=INACTIVE_SCREEN_STYLE)

    text.append(" | ", style=SEPARATOR_STYLE)

    # F3 Crashes (count)
    crash_label = f"F3 Findings ({len(state.crash_records)})"
    if active == "crashes":
        text.append(crash_label, style=ACTIVE_SCREEN_STYLE)
        text.append("*", style=ACTIVE_SCREEN_STYLE)
    else:
        text.append(crash_label, style=INACTIVE_SCREEN_STYLE)

    text.append(" | ", style=SEPARATOR_STYLE)

    # F4 Log
    if active == "log":
        text.append("F4 Log", style=ACTIVE_SCREEN_STYLE)
        text.append("*", style=ACTIVE_SCREEN_STYLE)
    else:
        text.append("F4 Log", style=INACTIVE_SCREEN_STYLE)

    text.append(" | ", style=SEPARATOR_STYLE)

    text.append("</> Cycle", style=MUTED_STYLE)

    # Right side: state + controls
    right_parts = Text()

    # Status
    if getattr(state, "_stopping", False):
        right_parts.append("STOPPING", style=STATUS_STOPPING_STYLE)
    elif state.paused:
        right_parts.append("PAUSED", style=STATUS_PAUSED_STYLE)
    elif state.execution_state not in ('initializing','running'):
        right_parts.append(state.execution_state.upper(),style=STATUS_RUNNING_STYLE)
    else:
        right_parts.append("RUNNING", style=STATUS_RUNNING_STYLE)

    right_parts.append(" | ", style=SEPARATOR_STYLE)
    right_parts.append(f"V:{state.verbosity_level}", style=VALUE_STYLE)
    right_parts.append(" | ", style=SEPARATOR_STYLE)
    right_parts.append("SPACE Pause", style=MUTED_STYLE)
    right_parts.append(" | ", style=SEPARATOR_STYLE)
    right_parts.append("V+/V-", style=MUTED_STYLE)
    right_parts.append(" | ", style=SEPARATOR_STYLE)
    right_parts.append("Q Quit", style=MUTED_STYLE)
    right_parts.append(" | ", style=SEPARATOR_STYLE)
    right_parts.append("? Help", style=MUTED_STYLE)

    # Pad between left and right
    left_len = len(text.plain)
    right_len = len(right_parts.plain)
    padding = max(1, term_width - left_len - right_len)
    text.append(" " * padding)
    text.append_text(right_parts)

    # Apply background style across the full row
    text.stylize(MENU_BG)

    if term_width < 100:
        text = Text(style=MENU_BG)
        for screen,label in (('dashboard','F2 Dashboard'),('crashes',f'F3 Findings({len(state.crash_records)})'),('log','F4 Log')):
            if text.plain:
                text.append(' | ',style=SEPARATOR_STYLE)
            text.append(label+('*' if active==screen else ''),
                        style=ACTIVE_SCREEN_STYLE if active==screen else INACTIVE_SCREEN_STYLE)
        text.append(' | '+right_parts.plain.split(' | ',1)[0]+f' V:{state.verbosity_level} | ? Help',style=MUTED_STYLE)

    return text


# ── Heartbeat cell ────────────────────────────────────────────────────


def _heartbeat_green_style(phase: float) -> Style:
    """Interpolate between dim and bright green.

    *phase* is 0.0 (dimmest) to 1.0 (brightest).  The result matches
    ``VALUE_STYLE`` at peak brightness so the pulse never outshines
    the surrounding header text.
    """
    r = int(_HB_GREEN_DIM[0] + (_HB_GREEN_BRIGHT[0] - _HB_GREEN_DIM[0]) * phase)
    g = int(_HB_GREEN_DIM[1] + (_HB_GREEN_BRIGHT[1] - _HB_GREEN_DIM[1]) * phase)
    b = int(_HB_GREEN_DIM[2] + (_HB_GREEN_BRIGHT[2] - _HB_GREEN_DIM[2]) * phase)
    return Style(color=f"#{r:02x}{g:02x}{b:02x}")


def build_heartbeat_cell(state: "FuzzSessionState") -> Text:
    """Build a 3-character heartbeat indicator (aesthetic sliding block).

    A bright block sweeps across 3 positions with a gradient trail,
    wrapping around every ``_HB_PULSE_PERIOD`` seconds.  When ICMP is
    unresponsive all blocks turn muted red.

    Returns a ``Text`` with a leading space + 3 block characters.
    """
    # This slider owns heartbeat styling at every verbosity; the old dot path is retired.
    cell = Text(no_wrap=True)

    if state.heartbeat_alive is None:
        cell.append(" \u25b1\u25b1\u25b1", style=_HB_UNKNOWN)
        return cell

    if not state.heartbeat_alive:
        cell.append(" \u25b1\u25b1\u25b1", style=_HB_RED)
        return cell

    # Alive — wrap-around with gradient trail
    t = time.monotonic()
    head = int(t / (_HB_PULSE_PERIOD / 3)) % 3
    trail = (head - 1) % 3

    bright = _heartbeat_green_style(1.0)
    medium = _heartbeat_green_style(0.40)
    dim_bg = _heartbeat_green_style(0.08)

    cell.append(" ")  # left pad
    for i in range(3):
        if i == head:
            cell.append("\u25b0", style=bright)
        elif i == trail:
            cell.append("\u25b0", style=medium)
        else:
            cell.append("\u25b1", style=dim_bg)
    return cell


# ── Header section ───────────────────────────────────────────────────


def _header_cell(label: str, value: str) -> Text:
    """Build a single header cell with styled label and value.

    If *label* is empty the cell shows only the value.
    Otherwise the cell renders ``LABEL value`` on one line.
    """
    cell = Text(justify="center", no_wrap=True)
    if label:
        cell.append(label + " ", style=LABEL_STYLE)
    cell.append(value, style=VALUE_STYLE)
    return cell


def _build_header_row(
    items: List[tuple],
    term_width: int,
    *,
    show_edge: bool = False,
) -> Table:
    """Build a single header row as a Table with one column per item.

    Each *item* is a ``(label, value)`` pair.  Column widths are
    proportional to content length so short values get narrow columns
    and long values get wider ones.

    When *show_edge* is False the outer border is omitted so rows can
    be composed inside a container that draws boundaries itself.
    """
    row = Table(
        show_header=False,
        show_edge=show_edge,
        border_style=BORDER_COLOR,
        width=term_width,
        pad_edge=False,
        padding=(0, 1),
    )
    cells = []
    for item in items:
        if isinstance(item, Text):
            # Pre-rendered Text (e.g. heartbeat indicator).
            # ratio=3 keeps the column compact — comparable to a
            # short protocol name — while leaving room for content.
            row.add_column(justify="center", ratio=3, no_wrap=True)
            cells.append(item)
        else:
            label, value = item
            content_w = len(label) + (1 if label else 0) + len(value)
            row.add_column(justify="center", ratio=max(1, content_w), no_wrap=True)
            cells.append(_header_cell(label, value))
    row.add_row(*cells)
    return row


def build_header(state: "FuzzSessionState") -> Group:
    """Build the header section.

    Row 1 (boxed): PROTOCOL | HOST | TEST | ELAPSED | CRASHES
    Row 2 (text):  field=value pairs (variable per-protocol fields)
    """
    term_width = shutil.get_terminal_size((80, 24)).columns

    # ── TEST value ──────────────────────────────────────────────────
    if state.total_iterations:
        pct = (state.current_iteration / state.total_iterations) * 100 if state.total_iterations > 0 else 0
        test_str = f"{state.current_iteration}/{state.total_iterations} ({pct:.1f}%)"
    else:
        test_str = str(state.current_iteration)

    # ── ELAPSED ─────────────────────────────────────────────────────
    elapsed_s = state.elapsed_seconds
    hours, remainder = divmod(int(elapsed_s), 3600)
    minutes, seconds = divmod(remainder, 60)
    elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    # ── Single boxed row ────────────────────────────────────────────
    host_val = f"{state.host}:{state.port}" if state.port else state.host
    row1_items: list = [
        ("", state.protocol or "\u2014"),
        ("", host_val),
        ("CASE", test_str),
        ("", elapsed_str),
        ("POTENTIAL", str(state.crash_count)),
    ]
    if term_width<100:
        row1_items=[('',state.protocol or '—'),('',host_val),('CASE',test_str),('POTENTIAL',str(state.crash_count))]

    # Prepend heartbeat indicator as its own column when enabled
    if state.heartbeat_enabled:
        row1_items.insert(0, build_heartbeat_cell(state))
    row1 = _build_header_row(row1_items, term_width)

    container = Table(
        show_header=False,
        show_edge=True,
        show_lines=False,
        border_style=BORDER_COLOR,
        style=HEADER_BG,
        padding=0,
        pad_edge=False,
        width=term_width,
    )
    container.add_column(width=term_width - 2)
    container.add_row(row1)
    if term_width < 100:
        # A short terminal needs bytes as well as status. Keep every value,
        # without spending three rows on a border or squeezing away its count.
        compact = Text()
        if state.heartbeat_enabled:
            compact.append_text(build_heartbeat_cell(state))
            compact.append(' | ',style=SEPARATOR_STYLE)
        compact.append(f'{state.protocol or "—"} | {host_val} | POTENTIAL {state.crash_count}',style=VALUE_STYLE)
        container = compact

    # ── Protocol field diagram (replaces flat text row) ─────────────
    fuzz_target = state.current_fuzz_target or None
    diagram = build_protocol_diagram(
        schema=state.packet_schema,
        field_bytes=state.current_field_bytes,
        fuzz_target=fuzz_target,
        term_width=term_width,
        verbosity=state.verbosity_level,
    )
    if term_width < 100 and not state.current_fields:
        data=state.intended
        diagram=Text('RAW '+(data.hex(' ') if data is not None else '(unavailable)'),style=VALUE_STYLE)

    summaries = Text('FIELDS ', style=LABEL_STYLE)
    count = 0
    for field in state.current_fields:
        if field['field_id'] in state.hidden_fields:
            continue
        if count:
            summaries.append(' | ',style=MUTED_STYLE)
        data = field['value']
        label='/'.join((field['action_id'],field['buffer_id'],field['field_id']))
        summaries.append(label+'='+(data.hex() if data is not None else 'unavailable'),style=VALUE_STYLE)
        count += 1
    identity = Text(f'CASE {state.current_iteration} VARIANT {state.variant_id or "—"} '
        f'ACTION {state.action_id or "—"} ATTEMPT {state.attempt_id or "—"}',style=VALUE_STYLE)
    if term_width<100 and not state.attempt_id:
        identity.append(' elapsed='+elapsed_str)
    facts = Text(f'{state.execution_state} | {state.acceptance} accepted={state.accepted_count} '
        f'RX={state.receive_outcome} meaning={state.response_meaning} | follow-up={state.followup_pending}',style=MUTED_STYLE)
    if state.monitoring_hold:
        facts.append(' HOLD '+state.monitoring_hold,style=WARNING_STYLE)
    if state.degraded:
        facts.append('\nDISPLAY DEGRADED: '+state.degraded,style=WARNING_STYLE)
    if state.intended is not None and not state.final_fields_available:
        facts.append('\nFinal field locations unavailable in this record',style=MUTED_STYLE)
    return Group(container,identity,facts,*([summaries] if count else []),diagram)


# ── Line graph (braille) ─────────────────────────────────────────────

# Braille dot grid layout per character (2 cols x 4 rows):
#   Row 0 (top):    dot1=0x01  dot4=0x08
#   Row 1:          dot2=0x02  dot5=0x10
#   Row 2:          dot3=0x04  dot6=0x20
#   Row 3 (bottom): dot7=0x40  dot8=0x80
_BRAILLE_BASE = 0x2800
_BRAILLE_LEFT = [0x40, 0x04, 0x02, 0x01]   # row 3,2,1,0 (bottom→top)
_BRAILLE_RIGHT = [0x80, 0x20, 0x10, 0x08]  # row 3,2,1,0 (bottom→top)
_BRAILLE_BLANK = "\u2800"


def _make_line_graph(
    history: Sequence[float],
    width: int,
    style: Style,
) -> Text:
    """Build a braille-dot line graph from a numeric history sequence.

    Packs 2 data points per character (left + right columns).
    4 vertical levels per row for smooth stock-ticker appearance.
    Adjacent points are connected by filling intermediate dots.
    """
    text = Text()
    if not history:
        text.append(_BRAILLE_BLANK * width, style=MUTED_STYLE)
        return text

    # Each char holds 2 data points
    data_points = width * 2
    data = list(history)[-data_points:]
    if not data:
        text.append(_BRAILLE_BLANK * width, style=MUTED_STYLE)
        return text

    max_val = max(data)
    min_val = min(data)
    val_range = max_val - min_val

    # Quantize to 0-3 (4 vertical levels)
    levels: List[int] = []
    for val in data:
        if val_range == 0 and max_val > 0:
            lvl = 2  # mid
        elif val_range > 0:
            lvl = int(((val - min_val) / val_range) * 3)
        else:
            lvl = 0
        levels.append(max(0, min(3, lvl)))

    # Pad to even count
    if len(levels) % 2:
        levels.append(levels[-1])

    # Build braille characters — set dots for each data point and
    # fill intermediate rows between adjacent points for continuity.
    for i in range(0, len(levels), 2):
        bits = 0
        l_lvl = levels[i]
        r_lvl = levels[i + 1]

        # Primary dots
        bits |= _BRAILLE_LEFT[l_lvl]
        bits |= _BRAILLE_RIGHT[r_lvl]

        # Fill between left and right within this char for continuity
        lo = min(l_lvl, r_lvl)
        hi = max(l_lvl, r_lvl)
        for fill in range(lo, hi + 1):
            # Determine which column gets the fill dot based on position
            if fill <= l_lvl:
                bits |= _BRAILLE_LEFT[fill]
            if fill <= r_lvl:
                bits |= _BRAILLE_RIGHT[fill]

        text.append(chr(_BRAILLE_BASE | bits), style=style)

    # Pad remaining chars if history is short
    rendered = len(levels) // 2
    if rendered < width:
        text.append(_BRAILLE_BLANK * (width - rendered), style=MUTED_STYLE)

    return text


def _format_rate(bytes_per_sec: float) -> str:
    """Format a byte rate with auto-scaled units."""
    if bytes_per_sec >= 1_048_576:
        return f"{bytes_per_sec / 1_048_576:6.1f} MB/s"
    if bytes_per_sec >= 1024:
        return f"{bytes_per_sec / 1024:6.1f} KB/s"
    return f"{bytes_per_sec:6.0f}  B/s"


def build_sparkline(
    tx_history: Deque[float],
    rx_history: Deque[float],
    width: Optional[int] = None,
    tests_per_second: float = 0.0,
    rates: Optional[Tuple[float,float]] = None,
) -> Text:
    """Build TX/RX line graph indicator.

    Two rows:
    - TX row with braille line graph, prefixed with ``TX: X.X KB/s``
    - RX row with braille line graph, prefixed with ``RX: X.X KB/s``

    Rate is computed as average bytes-per-iteration over the last
    10 entries, multiplied by tests_per_second to get bytes/sec.
    """
    if width is None:
        width = shutil.get_terminal_size((80, 24)).columns

    # Compute actual throughput rates (bytes/sec)
    def _avg_rate(hist: Deque[float]) -> float:
        if not hist:
            return 0.0
        window = list(hist)[-10:]
        avg_bytes = sum(window) / len(window)
        return avg_bytes * tests_per_second if tests_per_second > 0 else 0.0

    tx_rate,rx_rate = rates if rates is not None else (_avg_rate(tx_history),_avg_rate(rx_history))

    tx_prefix = f" TX: {_format_rate(tx_rate)} "
    rx_prefix = f" RX: {_format_rate(rx_rate)} "
    graph_width = max(10, width - len(tx_prefix) - 1)

    text = Text()
    text.append(tx_prefix, style=TX_STYLE)
    text.append_text(_make_line_graph(tx_history, graph_width, SPARKLINE_TX_STYLE))
    text.append("\n")
    text.append(rx_prefix, style=RX_STYLE)
    text.append_text(_make_line_graph(rx_history, graph_width, SPARKLINE_RX_STYLE))

    return text


# ── HexDump renderable ──────────────────────────────────────────────


def _hex_section_width(n: int) -> int:
    """Return rendered char width of the hex-bytes column for *n* bytes.

    Each byte is 2 hex chars.  All bytes except the last get a trailing
    space.  An extra space (group separator) appears after every 8th
    byte except the very last byte.
    """
    if n <= 0:
        return 0
    return 2 * n + max(0, n - 1) + (n - 1) // 8


def _hexdump_bytes_per_line(term_width: int) -> int:
    """Calculate adaptive bytes-per-line (multiple of 8) for hexdump.

    Full-line width for G groups of 8 bytes = ``33*G + 12``:
      offset(10) + hex(25G-2) + gap(2) + ascii(8G+2).
    """
    groups = max(1, (term_width - 12) // 33)
    return groups * 8


def _hexdump_line_width(bytes_per_line: int) -> int:
    """Calculate the rendered char width of a hexdump line."""
    groups = bytes_per_line // 8
    return 33 * groups + 12


class HexDumpRenderable:
    """Wireshark TCP stream style hexdump.

    - Adaptive column count: expands in 8-byte groups to fill terminal.
    - Sent data: content starts at left edge of terminal.
    - Received data: content pushed to right edge of terminal.
    - Includes offset column, hex bytes, and ASCII decode.
    - Per-byte coloring by category.
    """

    def __init__(
        self,
        data: bytes,
        direction: str = "sent",
        term_width: Optional[int] = None,
        byte_styles: Optional[Dict[int, Style]] = None,
    ) -> None:
        self.data = data
        self.direction = direction
        self.term_width = term_width or shutil.get_terminal_size((80, 24)).columns
        self.bytes_per_line = _hexdump_bytes_per_line(self.term_width)
        # Per-byte-position style overrides (for V:3 field coloring).
        self._byte_styles: Dict[int, Style] = byte_styles or {}

    def build(self) -> Text:
        """Build the hexdump as a Rich ``Text`` object."""
        text = Text()
        is_recv = self.direction == "recv"
        group_size = 8

        if is_recv:
            # Keep receive rows right-aligned without exceeding a narrow viewport.
            bpl = min(16,self.bytes_per_line)
            line_w = _hexdump_line_width(bpl)
            indent = max(0, self.term_width - line_w)
            extra_gap = 0
        else:
            # Sent: adaptive, ASCII pushed to right terminal edge
            bpl = self.bytes_per_line
            line_w = _hexdump_line_width(bpl)
            indent = 0
            extra_gap = max(0, self.term_width - line_w)

        for offset in range(0, len(self.data), bpl):
            chunk = self.data[offset:offset + bpl]
            is_short = len(chunk) < bpl

            # Indent (recv only)
            if indent > 0:
                text.append(" " * indent)

            # Offset column
            text.append(f"{offset:08x}  ", style=MUTED_STYLE)

            # Hex bytes — always left-aligned within hex section
            for i, b in enumerate(chunk):
                abs_pos = offset + i
                style = self._byte_styles.get(abs_pos) or style_hex_byte(b)
                text.append(f"{b:02x}", style=style)
                if i < len(chunk) - 1:
                    text.append(" ")
                if (i + 1) % group_size == 0 and i < len(chunk) - 1:
                    text.append(" ")

            # Pad hex section for short lines
            if is_short:
                pad = _hex_section_width(bpl) - _hex_section_width(len(chunk))
                text.append(" " * pad)

            # Gap between hex and ASCII
            text.append("  ", style=MUTED_STYLE)
            if extra_gap > 0:
                text.append(" " * extra_gap)

            # ASCII decode
            text.append("|", style=MUTED_STYLE)
            for i, b in enumerate(chunk):
                abs_pos = offset + i
                override = self._byte_styles.get(abs_pos)
                if override:
                    if 0x20 <= b <= 0x7E:
                        text.append(chr(b), style=override)
                    else:
                        text.append(".", style=override)
                else:
                    style = style_hex_byte(b)
                    if 0x20 <= b <= 0x7E:
                        text.append(chr(b), style=style)
                    else:
                        text.append(".", style=MUTED_STYLE)
            if is_short:
                text.append(" " * (bpl - len(chunk)))
            text.append("|", style=MUTED_STYLE)
            text.append("\n")

        return text


# ── Rain fill (inline) ───────────────────────────────────────────────


def _append_rain_fill(
    text: Text, width: int, used_cols: int, row_id: int, enabled: bool = True,
) -> None:
    """Append matrix rain characters to fill unused columns on a row.

    Generates a partial-row horizontal rain effect using ``time.time()``
    as the animation clock.  *row_id* seeds each row differently so
    adjacent rows don't mirror each other.
    """
    remaining = width - used_cols
    if remaining <= 0:
        return
    if not enabled:
        text.append(" " * remaining)
        return

    now = time.time()
    n_styles = len(_RAIN_STYLES)
    n_chars = len(_RAIN_CHARS)
    rng = random.Random(row_id)
    n_streams = max(2, int(remaining * 0.12 / 2))

    # Generate stream parameters (deterministic per row_id).
    streams: list = []
    for _ in range(n_streams):
        speed = rng.uniform(10, 30)
        trail = rng.randint(4, 8)
        # Widely varied gap so streams wrap at different times.
        gap = rng.randint(remaining // 2, remaining * 2)
        phase = rng.uniform(0, remaining + trail + gap)
        streams.append((speed, trail, gap, phase))

    # Compute brightness for each cell.
    cells = [-1] * remaining
    for speed, trail, gap, phase in streams:
        cycle = remaining + trail + gap
        head = int((now * speed + phase) % cycle)
        for t in range(trail + 1):
            col = head - t
            if 0 <= col < remaining:
                lvl = max(0, n_styles - 1 - t)
                if lvl > cells[col]:
                    cells[col] = lvl

    # Render characters.
    time_slot = int(now * 3)
    for col, lvl in enumerate(cells):
        if lvl < 0:
            text.append(" ")
        else:
            ci = (row_id * 997 + (used_cols + col) * 31 + time_slot * 7) % n_chars
            text.append(_RAIN_CHARS[ci], style=_RAIN_STYLES[lvl])


# ── Test section ─────────────────────────────────────────────────────


def _format_entry_v0(entry: RingBufferEntry, width: int) -> Text:
    """Level 0: One-line summary per test."""
    text = Text()
    ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))

    if entry.entry_type in ("test","setup"):
        text.append(f" {ts} ", style=MUTED_STYLE)
        text.append(f"Test {entry.iteration}" if entry.entry_type=='test' else 'Setup', style=VALUE_STYLE)
        text.append(f" | offered {entry.sent_len}B", style=TX_STYLE)
        text.append(f" | recv {entry.recv_len}B", style=RX_STYLE)
        facts = entry.result or {}
        text.append(f" | {facts.get('acceptance','unknown')} / {facts.get('receive_outcome','unknown')}", style=VALUE_STYLE)
    elif entry.entry_type == "crash":
        text.append(f" {ts} ", style=MUTED_STYLE)
        text.append("[FINDING] ", style=WARNING_STYLE)
        text.append(entry.message or f"Crash at iteration {entry.iteration}", style=CRITICAL_STYLE)
    elif entry.entry_type == "recovery":
        text.append(f" {ts} ", style=MUTED_STYLE)
        text.append("[INFO] ", style=RECOVERY_STYLE)
        text.append(entry.message or "Device recovered", style=RECOVERY_STYLE)
    elif entry.entry_type == "health":
        text.append(f" {ts} ", style=MUTED_STYLE)
        text.append("[WARNING] ", style=WARNING_STYLE)
        text.append(entry.message, style=WARNING_STYLE)
    elif entry.entry_type == "error":
        text.append(f" {ts} ", style=MUTED_STYLE)
        text.append("[WARNING] ", style=WARNING_STYLE)
        text.append(entry.message, style=WARNING_STYLE)

    return text


def _styled_hex_snippet(data: bytes, max_hex_len: int) -> Text:
    """Build a styled, truncated hex string from raw bytes."""
    text = Text()
    hex_str = data.hex()
    if len(hex_str) > max_hex_len:
        hex_str = hex_str[:max_hex_len - 3] + "..."
    for i in range(0, len(hex_str), 2):
        pair = hex_str[i:i+2]
        if pair == "..":
            text.append(pair, style=MUTED_STYLE)
            if i + 2 < len(hex_str):
                text.append(hex_str[i+2:], style=MUTED_STYLE)
            break
        try:
            byte_val = int(pair, 16)
            text.append(pair, style=style_hex_byte(byte_val))
        except ValueError:
            text.append(pair, style=MUTED_STYLE)
    return text


def _format_entry_v1(entry: RingBufferEntry, width: int) -> Text:
    """Level 1: Truncated hex payloads, one line per send/recv."""
    text = Text()
    ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))

    if entry.entry_type not in ("test","setup"):
        return _format_entry_v0(entry, width)

    # Fixed-width prefix: " HH:MM:SS Test NNNNN "
    prefix = f" {ts} Test {entry.iteration} " if entry.entry_type=="test" else f" {ts} Setup "
    prefix_len = len(prefix)
    # Direction arrow + size suffix
    arrow = "-> "
    size_suffix = f" ({entry.sent_len}B)"
    # Available hex chars = width - prefix - arrow - size_suffix
    max_hex = max(20, width - prefix_len - len(arrow) - len(size_suffix))

    text.append(prefix[:len(ts) + 2], style=MUTED_STYLE)
    text.append(prefix[len(ts) + 2:], style=VALUE_STYLE)
    text.append(arrow, style=TX_STYLE)
    if entry.sent_bytes:
        text.append_text(_styled_hex_snippet(entry.sent_bytes, max_hex))
    else:
        text.append("(none)", style=MUTED_STYLE)
    text.append(size_suffix, style=TX_STYLE)

    if entry.recv_bytes is not None:
        text.append("\n")
        # Align recv arrow with sent arrow
        recv_arrow = "<- "
        recv_suffix = f" ({entry.recv_len}B)"
        recv_max_hex = max(20, width - prefix_len - len(recv_arrow) - len(recv_suffix))
        text.append(" " * prefix_len, style=MUTED_STYLE)
        text.append(recv_arrow, style=RX_STYLE)
        text.append_text(_styled_hex_snippet(entry.recv_bytes, recv_max_hex))
        text.append(recv_suffix, style=RX_STYLE)

    return text


def _format_entry_v2(entry: RingBufferEntry, width: int, rain_row_base: int = 0,
                     rain_enabled: bool = False) -> Text:
    """Level 2: Wireshark TCP stream style hexdump."""
    if entry.entry_type not in ("test","setup"):
        return _format_entry_v0(entry, width)

    text = Text()
    ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
    ts_label = f" {ts} "
    iter_label = f"Test {entry.iteration}" if entry.entry_type=="test" else "Setup"
    text.append(ts_label, style=MUTED_STYLE)
    text.append(iter_label, style=VALUE_STYLE)
    _append_rain_fill(text, width, len(ts_label) + len(iter_label), rain_row_base, rain_enabled)
    text.append("\n")

    if entry.sent_bytes:
        sent_label = f" -> Offered ({entry.sent_len} bytes)"
        text.append(sent_label, style=TX_STYLE)
        _append_rain_fill(text, width, len(sent_label), rain_row_base + 1, rain_enabled)
        text.append("\n")
        hexdump = HexDumpRenderable(
            entry.sent_bytes, direction="sent", term_width=width,
        )
        text.append_text(hexdump.build())

    if entry.recv_bytes is not None:
        # Right-align the recv label to terminal width
        recv_label = f"<- Recv ({entry.recv_len} bytes)"
        label_pad = max(0, width - len(recv_label))
        text.append(" " * label_pad)
        text.append(recv_label, style=RX_STYLE)
        text.append("\n")
        hexdump = HexDumpRenderable(entry.recv_bytes, direction="recv", term_width=width)
        text.append_text(hexdump.build())

    return text


def _format_entry_v3(
    entry: RingBufferEntry,
    width: int,
    schema: Optional[Dict] = None,
    rain_row_base: int = 0,
    rain_enabled: bool = False,
) -> Text:
    """Level 3: Field-colored hexdump.

    Each protocol field's bytes are rendered in a distinct color from
    ``FIELD_COLORS``, coordinated with the header diagram.  Bytes
    outside any known field range fall back to the standard byte-
    category coloring used in V:2.
    """
    if entry.entry_type not in ("test","setup"):
        return _format_entry_v0(entry, width)

    text = Text()
    ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
    ts_label = f" {ts} "
    iter_label = f"Test {entry.iteration}" if entry.entry_type=="test" else "Setup"
    text.append(ts_label, style=MUTED_STYLE)
    text.append(iter_label, style=VALUE_STYLE)
    _append_rain_fill(text, width, len(ts_label) + len(iter_label), rain_row_base, rain_enabled)
    text.append("\n")

    # Build per-byte style map from schema + field_bytes
    byte_styles: Optional[Dict[int, Style]] = None
    if schema and entry.field_bytes and entry.sent_bytes:
        byte_styles = build_field_byte_styles(
            schema, entry.field_bytes, len(entry.sent_bytes),
        )
        if not byte_styles:
            byte_styles = None

    if entry.sent_bytes:
        sent_label = f" -> Offered ({entry.sent_len} bytes)"
        text.append(sent_label, style=TX_STYLE)
        _append_rain_fill(text, width, len(sent_label), rain_row_base + 1, rain_enabled)
        text.append("\n")
        hexdump = HexDumpRenderable(
            entry.sent_bytes, direction="sent", term_width=width,
            byte_styles=byte_styles or {},
        )
        text.append_text(hexdump.build())

    if entry.recv_bytes is not None:
        recv_label = f"<- Recv ({entry.recv_len} bytes)"
        label_pad = max(0, width - len(recv_label))
        text.append(" " * label_pad)
        text.append(recv_label, style=RX_STYLE)
        text.append("\n")
        hexdump = HexDumpRenderable(entry.recv_bytes, direction="recv", term_width=width)
        text.append_text(hexdump.build())

    return text


def _format_entry_v4(
    entry: RingBufferEntry,
    width: int,
    schema: Optional[Dict] = None,
    rain_row_base: int = 0,
    rain_enabled: bool = False,
) -> Text:
    """Level 4: Earlier exchanges followed once by this action's exchange.

    The entry's conversation log contains only preceding exchanges. The
    current action is rendered below with its own direction and identity.
    """
    if entry.entry_type not in ("test","setup"):
        return _format_entry_v0(entry, width)

    text = Text()
    ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
    ts_label = f" {ts} "
    iter_label = f"Test {entry.iteration}" if entry.entry_type=="test" else "Setup"
    text.append(ts_label, style=MUTED_STYLE)
    text.append(iter_label, style=VALUE_STYLE)
    _append_rain_fill(text, width, len(ts_label) + len(iter_label), rain_row_base, rain_enabled)
    text.append("\n")

    rain_row = rain_row_base + 1

    # -- Conversation log (pre-test exchanges) --
    conv = entry.conversation_log
    if conv:
        for direction, stage, data in conv:
            if not isinstance(data, (bytes, bytearray)):
                continue
            if direction == "->":
                label = f" -> Offer {stage} ({len(data)} bytes)"
                text.append(label, style=MUTED_STYLE)
                _append_rain_fill(text, width, len(label), rain_row, rain_enabled)
                text.append("\n")
                rain_row += 1
                hexdump = HexDumpRenderable(
                    data, direction="sent", term_width=width,
                )
                text.append_text(hexdump.build())
            else:
                label = f"<- Receive {stage} ({len(data)} bytes)"
                label_pad = max(0, width - len(label))
                text.append(" " * label_pad)
                text.append(label, style=MUTED_STYLE)
                text.append("\n")
                rain_row += 1
                hexdump = HexDumpRenderable(
                    data, direction="recv", term_width=width,
                )
                text.append_text(hexdump.build())
            rain_row += 1

    # -- Test packet (V:3 field-colored hexdump) --
    byte_styles: Optional[Dict[int, Style]] = None
    if schema and entry.field_bytes and entry.sent_bytes:
        byte_styles = build_field_byte_styles(
            schema, entry.field_bytes, len(entry.sent_bytes),
        )
        if not byte_styles:
            byte_styles = None

    action = (entry.result or {}).get('action_id') or 'selected action'
    if entry.sent_bytes:
        sent_label = f" -> Offered {action} ({entry.sent_len} bytes)"
        text.append(sent_label, style=TX_STYLE)
        _append_rain_fill(text, width, len(sent_label), rain_row, rain_enabled)
        text.append("\n")
        hexdump = HexDumpRenderable(
            entry.sent_bytes, direction="sent", term_width=width,
            byte_styles=byte_styles or {},
        )
        text.append_text(hexdump.build())

    if entry.recv_bytes is not None:
        recv_label = f"<- Received {action} ({entry.recv_len} bytes)"
        label_pad = max(0, width - len(recv_label))
        text.append(" " * label_pad)
        text.append(recv_label, style=RX_STYLE)
        text.append("\n")
        hexdump = HexDumpRenderable(entry.recv_bytes, direction="recv", term_width=width)
        text.append_text(hexdump.build())

    return text


# Verbosity level -> formatter
_ENTRY_FORMATTERS = {
    0: _format_entry_v0,
    1: _format_entry_v1,
    2: _format_entry_v2,
    3: _format_entry_v3,
    4: _format_entry_v4,
}


def _result_deviations(entry: RingBufferEntry) -> list[str]:
    """Only unusual per-attempt facts need space below a live history entry."""
    if entry.entry_type not in ('test','setup') or not entry.result:
        return []
    facts=entry.result
    deviations=[]
    if facts.get('acceptance')!='accepted' or facts.get('accepted_count')!=entry.sent_len:
        deviations.append(f"acceptance={facts.get('acceptance')} accepted={facts.get('accepted_count')}/{entry.sent_len}")
    if facts.get('intended')!=entry.sent_bytes:
        deviations.append('intended differs from offer')
    if facts.get('receive_outcome') not in ('unrequested','bounded_chunk','read_cap','complete'):
        deviations.append('RX='+str(facts.get('receive_outcome')))
    if facts.get('meaning') not in (None,'uninterpreted'):
        deviations.append('meaning='+str(facts['meaning']))
    attempt=facts.get('attempt_id')
    if attempt and not str(attempt).endswith('attempt-1'):
        deviations.append('attempt='+str(attempt))
    return deviations


def _estimate_entry_rows(verbosity: int, entry: RingBufferEntry) -> int:
    """Estimate how many terminal rows an entry will occupy."""
    if entry.entry_type not in ("test","setup"):
        return 1
    extra=int(bool(_result_deviations(entry)))
    if verbosity == 0:
        return 1+extra
    if verbosity == 1:
        return (2 if entry.recv_bytes is not None else 1)+extra
    # v2/v3/v4: hexdump with adaptive line width
    sent_bpl = _hexdump_bytes_per_line(shutil.get_terminal_size((80, 24)).columns)
    recv_bpl = min(16,sent_bpl)
    rows = 1  # timestamp line
    if entry.sent_bytes:
        rows += 1 + max(1, (len(entry.sent_bytes) + sent_bpl - 1) // sent_bpl)
    if entry.recv_bytes is not None:
        rows += 1 + max(1, (len(entry.recv_bytes) + recv_bpl - 1) // recv_bpl)
    # v4: add conversation log exchanges
    if verbosity >= 4 and entry.conversation_log:
        for _dir, _stage, data in entry.conversation_log:
            if isinstance(data, (bytes, bytearray)):
                bpl = sent_bpl if _dir == "->" else recv_bpl
                rows += 1 + max(1, (len(data) + bpl - 1) // bpl)
    return rows+extra


def build_test_section(
    state: "FuzzSessionState",
    available_rows: int,
) -> Text:
    """Build the scrolling test output section from the ring buffer.

    Returns EXACTLY *available_rows* lines of content — clipped if
    entries overflow, padded with blank lines if entries underflow.
    This guarantees a fixed-height middle panel so the footer (progress
    bar) stays pinned at the bottom of the terminal.
    """
    text = Text()
    if not state.recent_tests:
        text.append(" Waiting for tests...", style=MUTED_STYLE)
        # Pad to exact height
        text.append("\n" * (available_rows - 1))
        return text

    verbosity = state.verbosity_level
    rain_enabled = getattr(state, 'rain_enabled', False)
    formatter = _ENTRY_FORMATTERS.get(verbosity, _format_entry_v0)
    term_width = shutil.get_terminal_size((80, 24)).columns

    # Walk the buffer backwards, collecting entries that fit.
    # Always include at least one entry (the most recent).
    entries_to_render: List[TestEntry] = []
    rows_used = 0
    for entry in reversed(state.recent_tests):
        est_rows = _estimate_entry_rows(verbosity, entry)
        if rows_used + est_rows > available_rows and entries_to_render:
            break
        entries_to_render.append(entry)
        rows_used += est_rows
        if rows_used >= available_rows:
            break

    # Render newest-first (stack order: most recent on top).
    import io
    from rich.console import Console
    wrapping_console=Console(file=io.StringIO(),width=term_width)
    lines_emitted = 0
    for entry_idx, entry in enumerate(entries_to_render):
        # Rain seed based on screen position, not iteration, so
        # streams don't reset when entries scroll.
        rain_row_base = entry_idx * 2
        if verbosity == 4:
            rendered = _format_entry_v4(
                entry, term_width, schema=entry.schema or state.packet_schema,
                rain_row_base=rain_row_base, rain_enabled=rain_enabled,
            )
        elif verbosity == 3:
            rendered = _format_entry_v3(
                entry, term_width, schema=entry.schema or state.packet_schema,
                rain_row_base=rain_row_base, rain_enabled=rain_enabled,
            )
        elif verbosity == 2:
            rendered = _format_entry_v2(
                entry, term_width, rain_row_base=rain_row_base,
                rain_enabled=rain_enabled,
            )
        else:
            rendered = formatter(entry, term_width)
        deviations=_result_deviations(entry)
        if deviations:
            rendered=Text('  '+', '.join(deviations)+'\n',style=WARNING_STYLE)+rendered
        if state.test_banner and entry.entry_type=='test':
            rendered=Text('─'*term_width+'\n',style=RULE_STYLE)+rendered
        rendered=Text('\n').join(rendered.wrap(wrapping_console,term_width,overflow='fold'))
        rendered_plain = rendered.plain
        if not rendered_plain.endswith("\n"):
            rendered_plain += "\n"
        entry_lines = rendered_plain.count("\n")

        if lines_emitted + entry_lines <= available_rows:
            # Entire entry fits
            text.append_text(rendered)
            if not rendered.plain.endswith("\n"):
                text.append("\n")
            lines_emitted += entry_lines
        else:
            # Partial fit — clip by lines, preserving original styling
            styled_lines = rendered.split("\n")
            for styled_line in styled_lines:
                if lines_emitted >= available_rows:
                    break
                # Skip empty trailing fragments unless we need padding
                if not styled_line.plain and lines_emitted >= available_rows - 1:
                    continue
                text.append_text(styled_line)
                text.append("\n")
                lines_emitted += 1
            break

    # Pad with blank lines to fill remaining space
    if lines_emitted < available_rows:
        text.append("\n" * (available_rows - lines_emitted))

    return text[:-1] if text.plain.endswith('\n') else text


# ── Progress bars ────────────────────────────────────────────────────


def build_progress_bars(state: "FuzzSessionState") -> Table:
    """Build outer/inner progress bars.

    Uses Rich ``Progress`` for rendering, but wraps in a ``Table``
    to get consistent full-width layout.

    The outer bar shows overall progress; the inner bar shows
    current target-group progress (from ``ComposerProgress``).
    """
    term_width = shutil.get_terminal_size((80, 24)).columns
    # Build a simple text-based progress representation
    # (Rich Progress objects need a live context; we build manually)
    text = Text()

    # Outer progress
    total = state.total_iterations
    current = state.current_iteration
    bounded = False
    if not total and state.progress:
        limit = state.progress.get('case_limit')
        if type(limit) is int and limit > 0:
            # A case limit bounds preparation, not the number of selected
            # tests. Label the bar as a limit instead of claiming completion.
            total, current, bounded = limit, state.progress.get('prepared_cases',0), True

    if total and total > 0:
        pct = min(100.0, (current / total) * 100)

        # Elapsed time
        elapsed_s = state.elapsed_seconds
        hours, remainder = divmod(int(elapsed_s), 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        # ETA
        if state.tests_per_second > 0 and total > current:
            eta_s = (total - current) / state.tests_per_second
            eta_h, eta_rem = divmod(int(eta_s), 3600)
            eta_m, eta_sec = divmod(eta_rem, 60)
            eta_str = f"{eta_h:02d}:{eta_m:02d}:{eta_sec:02d}"
        else:
            eta_str = "--:--:--"

        # Build suffix first to calculate remaining bar width
        suffix = (f" Case limit {current}/{total}" if bounded else f" Test {current}/{total}")
        suffix += f" | {time_str} | ETA {eta_str if not bounded else '--:--:--'}"
        pct_prefix = f" {pct:5.1f}% "
        bar_width = max(10, term_width - len(pct_prefix) - len(suffix) - 2)
        filled = int((pct / 100) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        text.append(pct_prefix, style=LABEL_STYLE)
        text.append(bar, style=TX_STYLE)
        text.append(suffix, style=VALUE_STYLE)
    else:
        # An unknown total has a visible indeterminate bar, never a percent
        # or an invented ETA. Its pulse advances with prepared cases.
        width = max(10, term_width - 31)
        position = ((state.progress.get('prepared_cases',0) if state.progress else current) % max(1,width-3))
        text.append(' ',style=LABEL_STYLE)
        text.append('░'*position+'███'+'░'*max(0,width-position-3),style=TX_STYLE)
        text.append(f' Test {current} | total unknown',style=VALUE_STYLE)
        if state.tests_per_second > 0:
            text.append(f" | {state.tests_per_second:.1f} tests/sec", style=MUTED_STYLE)

    # Inner progress (if available via ComposerProgress data on state)
    # Rendered ABOVE the outer bar so the test/time/ETA line stays
    # pinned at the very bottom of the terminal.
    outer_pos = getattr(state, "_outer_pos", None)
    inner_pos = getattr(state, "_inner_pos", None)
    inner_text: Optional[Text] = None
    if inner_pos and inner_pos[1] and inner_pos[1] > 0:
        inner_text = Text()
        inner_current, inner_total = inner_pos
        inner_pct = min(100.0, (inner_current / inner_total) * 100)
        inner_suffix = f" {inner_current}/{inner_total}"
        inner_prefix = f"   {inner_pct:5.1f}% "
        inner_bar_width = max(10, term_width - len(inner_prefix) - len(inner_suffix) - 2)
        inner_filled = int((inner_pct / 100) * inner_bar_width)
        inner_bar = "█" * inner_filled + "░" * (inner_bar_width - inner_filled)
        inner_text.append(inner_prefix, style=LABEL_STYLE)
        inner_text.append(inner_bar, style=PROGRESS_INNER_STYLE)
        inner_text.append(inner_suffix, style=VALUE_STYLE)

    # Compose: inner bar (if any) on top, outer bar on bottom
    final_text = Text()
    if state.progress:
        p=state.progress
        final_text.append(f"{'SELECTED' if state.current_selected else 'SETUP'} | "
            f"prepared={p.get('prepared_cases',0)} selected={p.get('selected_cases',0)} "
            f"omitted={p.get('omitted_cases',0)} tests={p.get('fuzz_tests',0)} "
            f"attempts={p.get('attempts',0)} setup={p.get('setup_attempts',0)}\n",style=VALUE_STYLE)
        final_text.append(f"case limit={p.get('case_limit') if p.get('case_limit') is not None else 'none'} | "
            f"{'final accounted' if p.get('final') else 'total unknown'} | "
            f"view rate={state.tests_per_second:.1f} attempts/s\n",style=MUTED_STYLE)
    if inner_text is not None:
        final_text.append_text(inner_text)
        final_text.append("\n")
    final_text.append_text(text)

    # Wrap in table for consistent full-width
    table = Table(
        show_header=False,
        show_edge=False,
        show_lines=False,
        padding=0,
        pad_edge=False,
        width=term_width,
    )
    table.add_column(width=term_width)
    table.add_row(final_text)
    return table


# ── Crash table ──────────────────────────────────────────────────────


def build_crash_table(crash_records: List[Dict]) -> Table:
    """Build a full-width crash detail table.

    Columns: #, TEST, TIMESTAMP, PAYLOAD, CORE, SIG.
    """
    term_width = shutil.get_terminal_size((80, 24)).columns

    if crash_records and 'observation_id' in crash_records[0]:
        table=Table(title=f'Findings / results ({len(crash_records)} retained; full history in Log)',
            width=term_width,show_lines=True)
        table.add_column('CASE / ACTION',ratio=1)
        table.add_column('CLASSIFICATION / STATUS',ratio=2)
        table.add_column('REPORT / EVENT',ratio=3,overflow='fold')
        # The retained summary is bounded; complete older occurrences remain in
        # the bound log/result owner instead of being guessed equivalent.
        for record in crash_records[-4:]:
            assessments=record.get('assessments',())
            classification='; '.join(a['classification']+' ('+a['uncertainty']+')' for a in assessments) or 'unclassified'
            status=record.get('report_status',record.get('followup',''))
            links='\n'.join(record.get('reports',())) or record.get('event_id',record['observation_id'])
            cores=record.get('acquired_cores',())
            if len(cores)>1:
                report_dir=(Path(record['reports'][-1]).parent if record.get('reports') else None)
                def copied_path(core):
                    path=Path(core['path'])
                    if report_dir is not None:
                        try: return path.relative_to(report_dir).as_posix()
                        except ValueError: pass
                    return str(path)
                links=('MULTIPLE CORES ACQUIRED '+str(len(cores))+'\n'+
                    '\n'.join(repr(core.get('name') or 'exact remote name unavailable')+
                        ': '+copied_path(core) for core in cores)+'\n'+links)
            table.add_row(str(record.get('iteration','?'))+' / '+record.get('action_id',''),
                classification+'\n'+status,Text(links))
        return table
    if not crash_records:
        table = Table(
            show_header=False,
            show_edge=True,
            border_style=BORDER_COLOR,
            width=term_width,
        )
        table.add_column(justify="center", width=term_width - 4)
        table.add_row(Text("No crashes detected.", style=MUTED_STYLE))
        return table

    table = Table(
        show_header=True,
        header_style=LABEL_STYLE,
        show_edge=True,
        border_style=BORDER_COLOR,
        width=term_width,
    )
    table.add_column("#", justify="right", width=2)
    table.add_column("TEST", justify="right", width=6)
    table.add_column("TIMESTAMP", justify="center", width=20)
    table.add_column("PAYLOAD", justify="left", ratio=1)
    table.add_column("CORE", justify="center", width=4)
    table.add_column("SIG", justify="left", width=44)

    for i, record in enumerate(crash_records, 1):
        iteration = str(record.get("iteration", "?"))
        timestamp = record.get("timestamp", "")
        if isinstance(timestamp, (int, float)):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        payload = record.get("payload_hex", "")
        if len(payload) > 40:
            payload = payload[:37] + "..."

        has_core = record.get("has_core", False)
        core = "Y" if has_core else "N"

        # Extract crash bucket directory name for the SIG column
        crash_dir = record.get("crash_dir", "")
        if crash_dir:
            sig = os.path.basename(crash_dir)
            if len(sig) > 42:
                sig = sig[:39] + "..."
        else:
            sig = ""

        table.add_row(str(i), iteration, timestamp, payload, core, sig)

    return table


# ── Protocol diagram ─────────────────────────────────────────────────


def compute_field_byte_ranges(
    schema: Optional[Dict],
    field_bytes: Dict[str, bytes],
    packet_len: int,
) -> List[Tuple[str, int, int]]:
    """Compute byte offset ranges for all schema fields in a packet.

    Returns a list of ``(field_name, offset, length)`` tuples ordered
    by position in the packet.  Used by V:3 field-coordinated coloring
    to map hexdump bytes to their protocol fields.
    """
    if not schema:
        return []

    if 'final_fields' in schema:
        return [(f['field_id'],f['offset'],f['size']) for f in schema['final_fields']
                if f['offset'] is not None and f['size'] is not None]
    fields = schema.get("fields", [])
    order = schema.get("order", [f.get("name") for f in fields])
    sizes: Dict[str, object] = {}
    for entry in fields:
        name = entry.get("name")
        if name:
            sizes[name] = entry.get("size")

    cursor = 0
    offsets: Dict[str, Tuple[int, int]] = {}
    ordered_names: List[str] = []
    for name in order:
        if not name:
            continue
        sz = sizes.get(name)
        if sz == "var" or sz is None:
            val = field_bytes.get(name, b"")
            flen = len(val)
        else:
            actual = field_bytes.get(name, b"")
            flen = max(int(sz), len(actual)) if actual else int(sz)
        offsets[name] = (cursor, flen)
        ordered_names.append(name)
        cursor += flen

    # Adjust for expanded packet (offset injections).
    if cursor < packet_len:
        excess = packet_len - cursor
        for name in ordered_names:
            sz = sizes.get(name)
            if sz == "var" or sz is None:
                old_off, old_len = offsets[name]
                offsets[name] = (old_off, old_len + excess)
                found = False
                for n2 in ordered_names:
                    if n2 == name:
                        found = True
                        continue
                    if found and n2 in offsets:
                        o2, l2 = offsets[n2]
                        offsets[n2] = (o2 + excess, l2)
                break

    result: List[Tuple[str, int, int]] = []
    for name in ordered_names:
        off, flen = offsets[name]
        if flen > 0:
            result.append((name, off, flen))
    return result


def build_field_byte_styles(
    schema: Optional[Dict],
    field_bytes: Dict[str, bytes],
    packet_len: int,
) -> Dict[int, Style]:
    """Build a byte-position → Style mapping for V:3 field coloring.

    Each field in the schema receives a distinct color from
    ``FIELD_COLORS``.  Every byte position in the packet that falls
    within a known field range is mapped to that field's color.

    The color assignment order matches ``build_protocol_diagram`` at
    V:3, so the hexdump and header diagram use coordinated colors.
    """
    ranges = compute_field_byte_ranges(schema, field_bytes, packet_len)
    if not ranges:
        return {}

    # Build a mapping from field name to its ordinal index in the schema.
    fields = schema.get("fields", []) if schema else []
    order = schema.get("order", [f.get("name") for f in fields]) if schema else []
    name_to_idx: Dict[str, int] = {}
    idx = 0
    for name in order:
        if name:
            name_to_idx[name] = idx
            idx += 1

    styles: Dict[int, Style] = {}
    for field_name, offset, length in ranges:
        fidx = name_to_idx.get(field_name, 0)
        color = FIELD_COLORS[fidx % len(FIELD_COLORS)]
        for pos in range(offset, offset + length):
            styles[pos] = color
    return styles


def _field_display_width(name: str, size: object, actual_len: int) -> int:
    """Minimum character width for a fixed-size protocol field.

    Width must hold whichever is wider: the field name or the hex
    representation (``size * 3 - 1`` for space-separated pairs).
    An extra 2 chars of padding keeps columns from cramming together.
    """
    if size == "var" or size is None:
        hex_w = max(1, actual_len * 3 - 1) if actual_len else 3
    else:
        hex_w = max(1, int(size) * 3 - 1)
    return max(len(name), hex_w) + 2


def _hex_spaced(data: bytes, max_width: int = 0) -> str:
    """Format bytes as space-separated hex pairs, optionally truncated."""
    spaced = " ".join(f"{b:02x}" for b in data)
    if max_width and len(spaced) > max_width:
        # Truncate to whole hex pairs: each pair is 3 chars (XX + space)
        # except the last which is 2 chars.
        trunc = max(2, max_width - 3)
        # Back up to the last full pair boundary
        cut = (trunc // 3) * 3
        if cut < 2:
            cut = 2
        spaced = spaced[:cut].rstrip() + " .."
    return spaced


def build_protocol_diagram(
    schema: Optional[Dict],
    field_bytes: Dict[str, bytes],
    fuzz_target: Optional[str] = None,
    term_width: Optional[int] = None,
    verbosity: int = 0,
) -> Group:
    """Build an RFC-style protocol field diagram.

    Returns a Rich ``Group`` containing one or more wrapped table rows.
    Fixed-size fields get exact-width columns.  The last ``var``-size
    field fills remaining space.  When the terminal is too narrow for
    all fields, the diagram wraps to multiple rows (each row is a
    separate ``Table``).

    At *verbosity* >= 3, each field receives a distinct color from
    ``FIELD_COLORS``, coordinated with the V:3 hexdump coloring.

    If *schema* is ``None``, falls back to a raw hex display grouped by
    field_bytes keys.
    """
    tw = term_width or shutil.get_terminal_size((80, 24)).columns

    if schema and 'final_fields' in schema:
        output=[]
        for field in schema['final_fields']:
            offset,size=field['offset'],field['size']
            label='/'.join((field['action_id'],field['buffer_id'],field['field_id']))+f' [{offset if offset is not None else "?"}:'+(str(offset+size) if offset is not None and size is not None else '?')+']'
            data=field.get('value')
            output.append(Text(label+' '+(data.hex(' ') if data is not None else '(location/extent unavailable)'),style=VALUE_STYLE))
        if not output:
            return _build_raw_field_diagram(field_bytes,fuzz_target,tw,verbosity)
        return Group(*output)

    if not schema:
        return _build_raw_field_diagram(field_bytes, fuzz_target, tw, verbosity)

    # Parse comma-separated fuzz targets into a set for O(1) lookup.
    fuzz_targets: set = set()
    if fuzz_target:
        fuzz_targets = {t.strip() for t in fuzz_target.split(",")}

    fields = schema.get("fields", [])
    order = schema.get("order", [f.get("name") for f in fields])
    sizes: Dict[str, object] = {}
    for entry in fields:
        name = entry.get("name")
        if name:
            sizes[name] = entry.get("size")

    # Build (name, size, data, is_var, display_width) tuples.
    # Skip fields with no data unless they are fuzz targets.
    entries: List[tuple] = []
    for name in order:
        if not name:
            continue
        size = sizes.get(name, "var")
        data = field_bytes.get(name, b"")
        # Hide empty fields that aren't being fuzzed.
        if not data and name not in fuzz_targets:
            continue
        is_var = (size == "var" or size is None)
        if is_var:
            dw = _field_display_width(name, "var", len(data))
        else:
            dw = _field_display_width(name, size, len(data))
        entries.append((name, size, data, is_var, dw))

    if not entries:
        t = Text("No protocol fields defined.", style=MUTED_STYLE)
        return Group(t)

    # Partition entries into rows that fit within term_width.
    # Table border overhead: 1 left edge + 1 right edge + 1 separator
    # per column boundary = 2 + (n-1) = n+1 chars for n columns.
    rows = _partition_fields_into_rows(entries, tw)

    tables: list = []
    for row_entries in rows:
        table = Table(
            show_header=True,
            header_style=LABEL_STYLE,
            show_edge=False,
            box=rich_box.SIMPLE_HEAD,
            border_style=BORDER_COLOR,
            width=tw,
            padding=(0, 1),
        )

        # Determine if the last entry in this row is var-size
        last_is_var = row_entries[-1][3]

        for i, (name, size, data, is_var, dw) in enumerate(row_entries):
            is_last = (i == len(row_entries) - 1)
            header = name.upper()
            if verbosity >= 3:
                hdr_style = FIELD_COLORS[i % len(FIELD_COLORS)] + Style(bold=True)
            else:
                hdr_style = LABEL_STYLE

            if is_var:
                # Var field fills remaining width via ratio
                table.add_column(
                    header, justify="left", ratio=1,
                    header_style=hdr_style,
                )
            else:
                table.add_column(
                    header, justify="left", width=dw,
                    header_style=hdr_style,
                )

        # Data row
        cells: list = []
        for i, (name, size, data, is_var, dw) in enumerate(row_entries):
            is_last = (i == len(row_entries) - 1)
            if verbosity >= 3:
                style = FIELD_COLORS[i % len(FIELD_COLORS)]
            else:
                style = VALUE_STYLE

            if not data:
                cells.append(Text("--", style=MUTED_STYLE))
            elif is_var:
                # Fill available width, truncate if needed
                fixed_cost = sum(
                    e[4] + 3 for e in row_entries if not e[3]
                )
                avail = tw - fixed_cost - 4
                hex_str = _hex_spaced(data, max_width=max(6, avail))
                cells.append(Text(hex_str, style=style))
            else:
                hex_str = _hex_spaced(data)
                cells.append(Text(hex_str, style=style))

        table.add_row(*cells)
        tables.append(table)

    return Group(*tables)


def _partition_fields_into_rows(
    entries: List[tuple],
    term_width: int,
) -> List[List[tuple]]:
    """Split field entries into rows that fit within *term_width*.

    Each row is a list of ``(name, size, data, is_var, display_width)``
    tuples.  Border overhead per table: ``N + 1`` chars for N columns
    (edge + separators).  Minimum 1 field per row.

    A var-size field uses ``ratio=1`` to fill remaining space, but
    small fixed-size fields after it can still share the row as long
    as there's room.  Only start a new row when adding a field would
    exceed *term_width*.
    """
    rows: List[List[tuple]] = []
    current_row: List[tuple] = []
    used = 2  # left + right table edges
    has_var = False  # track if current row already has a var field

    for entry in entries:
        name, size, data, is_var, dw = entry
        # Var fields use ratio=1 and truncate, so their cost for
        # row-fitting purposes is just the header label + padding,
        # not the full hex representation of their data.
        if is_var:
            cost = 1 + len(name) + 2  # separator + name + padding
        else:
            cost = 1 + dw  # separator + column content width

        if current_row and (used + cost) > term_width:
            rows.append(current_row)
            current_row = []
            used = 2
            has_var = False

        current_row.append(entry)
        if is_var:
            has_var = True
        used += cost

    if current_row:
        rows.append(current_row)

    return rows


def _build_raw_field_diagram(
    field_bytes: Dict[str, bytes],
    fuzz_target: Optional[str],
    term_width: int,
    verbosity: int = 0,
) -> Group:
    """Fallback diagram when no schema is available.

    Shows each key in ``field_bytes`` as a labeled hex column in a
    single-row table.
    """
    if not field_bytes:
        t = Text("No field data available.", style=MUTED_STYLE)
        return Group(t)

    table = Table(
        show_header=True,
        header_style=LABEL_STYLE,
        show_edge=False,
        box=rich_box.SIMPLE_HEAD,
        border_style=BORDER_COLOR,
        width=term_width,
        padding=(0, 1),
    )

    fuzz_targets: set = set()
    if fuzz_target:
        fuzz_targets = {t.strip() for t in fuzz_target.split(",")}

    items = list(field_bytes.items())
    for i, (name, data) in enumerate(items):
        is_last = (i == len(items) - 1)
        if verbosity >= 3:
            hdr_style = FIELD_COLORS[i % len(FIELD_COLORS)] + Style(bold=True)
        else:
            hdr_style = LABEL_STYLE
        header = name.upper()

        if is_last:
            table.add_column(header, justify="left", ratio=1, header_style=hdr_style)
        else:
            w = _field_display_width(name, "var", len(data))
            table.add_column(header, justify="left", width=w, header_style=hdr_style)

    cells: list = []
    for i, (name, data) in enumerate(items):
        is_last = (i == len(items) - 1)
        if verbosity >= 3:
            style = FIELD_COLORS[i % len(FIELD_COLORS)]
        else:
            style = VALUE_STYLE
        if not data:
            cells.append(Text("--", style=MUTED_STYLE))
        elif is_last:
            hex_str = _hex_spaced(data, max_width=max(6, term_width - 20))
            cells.append(Text(hex_str, style=style))
        else:
            hex_str = _hex_spaced(data)
            cells.append(Text(hex_str, style=style))

    table.add_row(*cells)
    return Group(table)


# ── Help overlay ─────────────────────────────────────────────────────

# Key binding definitions — single source of truth for the help panel.
# Each tuple: (key_label, description, section).
_HELP_BINDINGS = (
    # Navigation
    ("< >", "Cycle screens", "Navigation"),
    ("F2", "Dashboard", "Navigation"),
    ("F3", "Findings/results", "Navigation"),
    ("F4", "Log viewer", "Navigation"),
    ("? / Esc", "Toggle help", "Navigation"),
    # Display
    ("v / V", "Verbosity +/- (0-4)", "Display"),
    ("t", "Cycle color theme", "Display"),
    ("m", "Toggle digital rain", "Display"),
    # Fuzzing
    ("Space", "Pause / Resume", "Fuzzing"),
    ("Q", "Quit", "Fuzzing"),
    # Log viewer
    ("Up / Down", "Scroll log 1 line", "Log Viewer"),
    ("PgUp/PgDn", "Scroll log page", "Log Viewer"),
    ("Home / End", "Log top / bottom", "Log Viewer"),
    ("/", "Search log", "Log Viewer"),
    ("n / p", "Next / previous match", "Log Viewer"),
    ("d", "Exact record detail / back", "Log Viewer"),
    ("Esc", "Cancel search", "Log Viewer"),
)


def build_help_panel(available_rows: int = 20) -> Group:
    """Build a help overlay showing all key bindings.

    Uses a two-column layout (Navigation + Fuzzing side by side) when
    the terminal is wide enough (>= 60 cols), and collapses to a single
    stacked column on narrow terminals.

    Parameters
    ----------
    available_rows:
        Maximum number of rows the panel may occupy.  The panel will
        fill remaining space with blank lines to prevent content from
        "leaking" underneath.
    """
    term_width = shutil.get_terminal_size((80, 24)).columns

    # Group bindings by section
    sections: Dict[str, list] = {}
    for key, desc, section in _HELP_BINDINGS:
        sections.setdefault(section, []).append((key, desc))

    # Build section blocks as Rich Text objects
    def _render_section(title: str, bindings: list) -> Text:
        block = Text()
        block.append(f"  {title}\n", style=LABEL_STYLE)
        for key, desc in bindings:
            block.append(f" {key:<10} ", style=VALUE_STYLE)
            block.append(f"{desc}\n", style=MUTED_STYLE)
        return block

    section_order = ["Navigation", "Display", "Fuzzing", "Log Viewer"]
    blocks = []
    for name in section_order:
        if name in sections:
            blocks.append(_render_section(name, sections[name]))

    # Header -- show current theme name
    _tname = get_theme_name() or "default"
    header = Text()
    header.append("\n")
    header.append("  BYTEFAULT HELP", style=HELP_TITLE_STYLE)
    header.append(f"  [{_tname}]\n", style=MUTED_STYLE)
    header.append("\n")

    # Wide layout (>= 60): two columns side by side via a Table
    # Narrow layout (< 60): single stacked column
    wide = term_width >= 60

    if wide:
        table = Table(
            show_header=False,
            show_edge=False,
            show_lines=False,
            padding=(0, 1),
            expand=True,
            border_style=BORDER_COLOR,
        )
        table.add_column(ratio=1)
        table.add_column(ratio=1)

        # Left column: Navigation + Display, Right column: Fuzzing
        left = Text()
        for b in blocks[:2]:
            left.append_text(b)
        right = Text()
        for b in blocks[2:]:
            right.append_text(b)

        table.add_row(left, right)

        # Footer
        footer = Text()
        footer.append("\n")
        footer.append("  Press ", style=MUTED_STYLE)
        footer.append("?", style=VALUE_STYLE)
        footer.append(" to close", style=MUTED_STYLE)

        return Group(header, table, footer)
    else:
        # Stacked single column
        combined = Text()
        combined.append_text(header)
        for b in blocks:
            combined.append_text(b)
        combined.append("\n")
        combined.append("  Press ", style=MUTED_STYLE)
        combined.append("?", style=VALUE_STYLE)
        combined.append(" to close", style=MUTED_STYLE)
        return Group(combined)


# ── Screen composers ─────────────────────────────────────────────────

def build_resume_panel(state,max_rows):
    """Bound visible resume facts; full identities/history stay in Log/inspect."""
    from bytefault.ui.resume import get
    resume=state.resume; counts=resume['inherited_counts']; progress=state.progress
    lines=['RESUME inherited '+ ' '.join(f'{key}={counts.get(key,0)}' for key in ('completed','finished','uncertain')),
        ' '.join(f'{key}={counts.get(key,0)}' for key in ('not_started','skipped'))+
        f" | NEW tests={progress.get('fuzz_tests',0)} attempts={progress.get('attempts',0)} bytes={state.total_bytes_sent}"]
    gate=resume['continuation']; hold=gate['hold']
    inherited=lines
    lines=[]
    if gate['stopped']: lines.append('RESUME STOPPED '+str(gate['stop_cause'])+': '+str(gate['stop_reason']))
    for name in ('recovery_issue','preparation_issue'):
        if resume[name]: lines.append('READER '+str(resume[name]))
    if resume['barrier']: lines.append('UNRESOLVED case='+str(resume['barrier']['case_number'])+' choose rerun/skip')
    if hold:
        lines.append('HOLD '+get(hold,'decision_id')+' deadline='+gate['deadline_state']+' '+str(gate['deadline']))
        success=set(gate['satisfied']); groups={}
        for item in get(hold,'obligations',()):
            condition,action=get(item,'condition'),get(item,'followup_action_id')
            groups.setdefault(condition,[]).append(str(action)+'='+('succeeded' if (condition,action) in success else 'pending'))
        lines.append(f'WAIT succeeded={len(success)} pending={sum(len(items) for items in groups.values())-len(success)}; full facts: Log / inspect-resume')
        # Critical causal truth precedes the bounded catalog and identities.
        lines.extend(inherited)
        lines.extend('WAIT '+condition+' '+' '.join(values) for condition,values in groups.items())
    else:
        lines.extend(inherited)
    if resume['choices']:
        ack=resume['acknowledged_choices']
        lines.append('CHOICE '+', '.join(choice['disposition']+(' acknowledged' if any(dict(a)==dict(choice) for a in ack) else ' selected/unacknowledged')
            for choice in resume['choices'][:2])+(' | more in Log' if len(resume['choices'])>2 else ''))
    lines.append('CASES '+ ' | '.join(f"{item['case_number']}/{item['variant_id']} {item['state']}" for item in resume['cases'][-3:]))
    if hold:
        corr=get(hold,'correlation')
        lines.append('ORIGINAL '+get(corr,'run_id')+' attempt='+get(corr,'attempt_id'))
    lines.append('ORIGINAL '+resume['logical_run_id']+' | NEW execution='+resume['run_id'])
    lines.append(f"CASE window {len(resume['cases'])}/{resume['case_window']}; full facts in Log / inspect-resume")
    if len(lines)>max_rows:
        lines=lines[:max_rows]
    return Text('\n'.join(lines),style=VALUE_STYLE,no_wrap=True,overflow='ellipsis')


def build_dashboard(
    state: "FuzzSessionState",
    tx_history: Optional[Deque[float]] = None,
    rx_history: Optional[Deque[float]] = None,
) -> Group:
    """Compose the full Dashboard screen.

    Menu + Header + Sparkline + Test Section + Progress Bars.
    """
    term_size = shutil.get_terminal_size((80, 24))
    term_width = term_size.columns
    term_height = term_size.lines

    parts: list = []

    # Menu row (1 row)
    parts.append(build_menu_row(state))
    if state.show_help:
        return Group(parts[0],build_help_panel(term_height-2))

    # Header section (estimate ~4-6 rows)
    header = build_header(state)
    parts.append(header)
    formatted=Text(state.formatted_output,style=VALUE_STYLE) if state.formatted_output else None
    if formatted is not None:
        parts.append(formatted)

    # Sparkline (4 rows: rule + 2 sparkline rows + rule)
    tx_hist = tx_history or deque(maxlen=100)
    rx_hist = rx_history or deque(maxlen=100)
    chart_rows=4 if not state.resume or term_height>=30 else 0
    if chart_rows:
        parts.append(Rule(style=RULE_STYLE))
        parts.append(build_sparkline(
            tx_hist, rx_hist,
            tests_per_second=state.tests_per_second,
            rates=(state.tx_bytes_per_second,state.rx_bytes_per_second),
        ))
        parts.append(Rule(style=RULE_STYLE))

    # The footer boundary belongs in the measured vertical budget.
    progress = build_progress_bars(state)
    progress_boundary = Rule(style=RULE_STYLE)

    # Test section gets remaining rows
    # Header box: 1 boxed row (4 lines) + protocol diagram (2 lines
    # with SIMPLE_HEAD box: header + data, no top/bottom borders)
    # Measure actual wrapped components at the current terminal width. Identity,
    # scope and status rows cannot consume the test/footer budget invisibly.
    import io
    from rich.console import Console
    measuring=Console(file=io.StringIO(),width=term_width,height=term_height)
    def rows(component):
        return len(measuring.render_lines(component,measuring.options,pad=False))
    overhead = (rows(parts[0]) + rows(header) + chart_rows + rows(progress_boundary)
        + rows(progress) + (rows(formatted) if formatted is not None else 0))
    if state.resume:
        panel=build_resume_panel(state,max(3,min(12,term_height-overhead-1)))
        parts.insert(2,panel)
        overhead+=rows(panel)
    available_rows = max(1, term_height - overhead)

    parts.append(build_test_section(state, available_rows))
    parts.append(progress_boundary)
    parts.append(progress)

    return Group(*parts)


def build_crash_screen(state: "FuzzSessionState") -> Group:
    """Compose the Crash Detail screen (F3).

    Menu + Crash Table (or Help overlay).
    """
    parts: list = []
    parts.append(build_menu_row(state))
    if state.show_help:
        parts.append(build_help_panel())
    else:
        if getattr(state,'resume',None):
            size=shutil.get_terminal_size((80,24))
            parts.append(build_resume_panel(state,min(12,max(3,size.lines//2))))
        parts.append(build_crash_table(state.crash_records))
    return Group(*parts)


# ── Log viewer helpers ──────────────────────────────────────────────

# Log styles imported from theme (LOG_SEARCH_STYLE, LOG_LINE_NUM_STYLE, etc.)

def _style_log_line(line: str, search_q: str = "") -> Text:
    """Apply syntax coloring to a single log line.

    Expected format: ``YYYY-MM-DD HH:MM:SS.mmm [LEVEL] message``
    Falls back to plain VALUE_STYLE if the line doesn't match.
    """
    text = Text()

    # Try to parse standard log format
    # Timestamp: 23 chars  "2025-02-28 12:34:56.789"
    # Then " [LEVEL] " then message
    level_style = None
    timestamp_end = 0
    level_start = 0
    level_end = 0
    msg_start = 0

    bracket_open = line.find("[")
    bracket_close = line.find("]", bracket_open + 1) if bracket_open >= 0 else -1

    if bracket_open >= 0 and bracket_close > bracket_open:
        tag = line[bracket_open + 1:bracket_close].strip()
        level_style = {
            "DEBUG": LOG_LEVEL_DEBUG,
            "INFO": LOG_LEVEL_INFO,
            "WARNING": LOG_LEVEL_WARNING,
            "WARN": LOG_LEVEL_WARNING,
            "ERROR": LOG_LEVEL_ERROR,
            "CRITICAL": LOG_LEVEL_CRITICAL,
            "FATAL": LOG_LEVEL_CRITICAL,
        }.get(tag)

    if level_style and bracket_open > 0:
        timestamp_end = bracket_open
        level_start = bracket_open
        level_end = bracket_close + 1
        msg_start = level_end
    else:
        # No recognized format -- render as plain message
        if search_q:
            _append_with_highlight(text, line, search_q)
        else:
            text.append(line, style=LOG_MESSAGE_STYLE)
        return text

    # Timestamp portion
    ts = line[:timestamp_end]
    if search_q:
        _append_with_highlight(text, ts, search_q, default_style=LOG_TIMESTAMP_STYLE)
    else:
        text.append(ts, style=LOG_TIMESTAMP_STYLE)

    # Level tag with brackets
    text.append("[", style=LOG_BRACKET_STYLE)
    text.append(line[bracket_open + 1:bracket_close], style=level_style)
    text.append("]", style=LOG_BRACKET_STYLE)

    # Message body
    msg = line[msg_start:]
    msg_style = level_style if level_style in (LOG_LEVEL_WARNING, LOG_LEVEL_ERROR, LOG_LEVEL_CRITICAL) else LOG_MESSAGE_STYLE
    if search_q:
        _append_with_highlight(text, msg, search_q, default_style=msg_style)
    else:
        text.append(msg, style=msg_style)

    return text


def _append_with_highlight(
    text: Text,
    content: str,
    search_q: str,
    default_style: Optional[Style] = None,
) -> None:
    """Append *content* to *text*, highlighting all occurrences of *search_q*."""
    if default_style is None:
        default_style = LOG_MESSAGE_STYLE
    if not search_q:
        text.append(content, style=default_style)
        return
    lower = content.lower()
    pos = 0
    while pos < len(content):
        match_pos = lower.find(search_q, pos)
        if match_pos < 0:
            text.append(content[pos:], style=default_style)
            break
        if match_pos > pos:
            text.append(content[pos:match_pos], style=default_style)
        text.append(
            content[match_pos:match_pos + len(search_q)],
            style=LOG_SEARCH_STYLE,
        )
        pos = match_pos + len(search_q)


def build_log_screen(state: "FuzzSessionState") -> Group:
    """Compose the Log Viewer screen (F4).

    Layout (exact line budget):
      Row 1      : Menu bar
      Rows 2-3   : CMD + LOG labels (no box chrome -- raw Text rows)
      Rows 4..N-1: Log content lines (plain Text, no Table wrapper)
      Row N      : Status bar (search prompt / position)
    """
    term_size = shutil.get_terminal_size((80, 24))
    term_width = term_size.columns
    term_height = term_size.lines

    parts: list = []

    # Row 1 -- menu bar (may wrap on narrow terminals)
    menu = build_menu_row(state)
    parts.append(menu)
    if state.show_help:
        return Group(menu,build_help_panel(term_height-2))
    menu_lines = max(1, -(-len(menu.plain) // term_width))  # ceil division

    # Row 2 -- log file path
    log_row = Text()
    detail = state.log_detail_rows is not None
    log_row.append(" DETAIL " if detail else " LOG ", style=LABEL_STYLE)
    log_row.append(state.log_file or "(none)", style=VALUE_STYLE)
    parts.append(log_row)

    # Row N -- status bar (built later, but account for it now)
    # Budget: menu_lines + 1(log) + view_rows + 1(status) = term_height
    import io
    from rich.console import Console
    measuring=Console(file=io.StringIO(),width=term_width,height=term_height)
    menu_lines=len(measuring.render_lines(menu,measuring.options,pad=False))
    path_rows=len(measuring.render_lines(log_row,measuring.options,pad=False))
    view_rows = max(3, term_height - menu_lines - path_rows - 1)

    # ApplicationView/LogRows own file decoding; render their projected rows only.
    lines = state.log_detail_rows if detail else state.log_lines
    if not lines and not getattr(state,'log_index_ready',False):
        lines=['('+state.log_issue+')' if state.log_issue else '(indexing configured log...)']
    total_lines = len(lines)

    # Determine scroll position
    follow = not detail and state.log_scroll_offset < 0
    if follow:
        start = max(0, total_lines - view_rows)
    else:
        position=state.log_detail_scroll_offset if detail else state.log_scroll_offset
        start = max(0, min(position, max(0, total_lines - view_rows)))

    end = min(total_lines, start + view_rows)
    visible = lines[start:end]

    # Search query (lowercased for matching)
    search_q = state.log_search_query.lower() if state.log_search_query else ""
    line_num_width = max(1, len(str(total_lines)))
    prefix_len = line_num_width + 1  # "NNN "
    max_line_len = max(10, term_width - prefix_len)

    # Build log content -- one Text object with exactly view_rows newline-
    # separated lines so the vertical budget is deterministic.
    log_content = Text()
    for i in range(view_rows):
        if i > 0:
            log_content.append("\n")

        if i < len(visible):
            line_idx = start + i
            raw = visible[i].rstrip("\n").rstrip("\r")
            display_line = raw[:max_line_len]

            # Line number
            num_str = str(line_idx + 1).rjust(line_num_width)
            log_content.append(num_str, style=LOG_LINE_NUM_STYLE)
            log_content.append(" ", style=LOG_LINE_NUM_STYLE)

            # Colorized log line
            styled = _style_log_line(display_line, search_q)
            log_content.append_text(styled)
        else:
            # Empty filler line (tilde like less/vim)
            log_content.append("~", style=MUTED_STYLE)

    parts.append(log_content)

    # Status bar -- always the last row
    status = Text()
    if detail:
        status.append(f" DETAIL {start+1}-{end}/{total_lines}  d Back",style=VALUE_STYLE)
        status.append("  Up/Dn PgUp/PgDn Home/End  ? Help",style=MUTED_STYLE)
    elif state.log_search_active:
        status.append("/", style=LOG_SEARCH_SLASH_STYLE)
        status.append(state.log_search_input, style=LOG_SEARCH_INPUT_STYLE)
        status.append("_", style=LOG_SEARCH_CURSOR_STYLE)
    else:
        if follow:
            status.append(" FOLLOW", style=LOG_FOLLOW_STYLE)
        else:
            pct = int(100 * end / total_lines) if total_lines > 0 else 0
            status.append(
                f" LINE {start + 1}-{end}/{total_lines} ({pct}%)",
                style=LOG_SCROLL_STYLE,
            )
        status.append("  ", style=MUTED_STYLE)
        if getattr(state,'log_index_pending',False):
            status.append('refreshing  ',style=MUTED_STYLE)
        if state.log_search_query:
            matches = len(state.log_search_matches)
            idx = state.log_search_index + 1 if matches else 0
            status.append(f"/{state.log_search_query}", style=LABEL_STYLE)
            if state.log_search_pending:
                status.append(' [searching]',style=VALUE_STYLE)
            elif state.log_search_issue:
                status.append(' ['+state.log_search_issue+']',style=VALUE_STYLE)
            else:
                status.append(f" [{idx}/{matches}]", style=VALUE_STYLE)
                if state.log_match_in_record:
                    status.append(" [full record; d detail]",style=VALUE_STYLE)
            status.append("  ", style=MUTED_STYLE)
        status.append(
            "Up/Dn PgUp/PgDn Home/End  / Search  n/p Next/Prev  d Detail  ? Help",
            style=MUTED_STYLE,
        )
    pad = max(0, term_width - len(status.plain))
    status.append(" " * pad)
    status.stylize(MENU_BG)
    status.truncate(term_width,overflow='ellipsis')
    parts.append(status)

    return Group(*parts)



