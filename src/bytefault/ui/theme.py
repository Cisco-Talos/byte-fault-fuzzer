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

"""Centralized color theme for the bytefault Rich TUI.

Themes are registered in the ``_REGISTRY`` ordered dict.  Call
``cycle_theme()`` (bound to the ``t`` key) to rotate through them at
runtime.  ``apply_theme()`` resolves the active palette into ``Style``
objects and populates this module's namespace so other modules can do::

    from bytefault.ui.theme import LABEL_STYLE, VALUE_STYLE

Live switching is handled by ``_propagate()`` which pushes updated
constants into already-imported consumer modules (``rich_renderables``).

Rich ``Theme`` objects (for use with ``Console(theme=...)``) are also
available via ``build_theme()``.
"""

from __future__ import annotations

import sys
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple, Union

try:
    from rich.style import Style
    from rich.theme import Theme

    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False

# ── Rain character sets ──────────────────────────────────────────────

# Half-width katakana (single-cell-width) + digits   -- "The Matrix"
KATAKANA_RAIN = (
    "\uff66\uff67\uff68\uff69\uff6a\uff6b\uff6c\uff6d\uff6e\uff6f"
    "\uff70\uff71\uff72\uff73\uff74\uff75\uff76\uff77\uff78\uff79"
    "\uff7a\uff7b\uff7c\uff7d\uff7e\uff7f\uff80\uff81\uff82\uff83"
    "\uff84\uff85\uff86\uff87\uff88\uff89\uff8a\uff8b\uff8c\uff8d"
    "\uff8e\uff8f\uff90\uff91\uff92\uff93\uff94\uff95\uff96\uff97"
    "\uff98\uff99\uff9a\uff9b\uff9c\uff9d"
    "0123456789"
)

# Hex + punctuation  -- data-stream / water aesthetic
HEX_STREAM_RAIN = "0123456789abcdef.:;~-=+*|/\\@#"

# Ash/ember glyphs -- falling cinders aesthetic
EMBER_RAIN = ".:;'`~*+^oO0@#$%&!?/|\\=-_"


# ── Matrix-Solarized Dark ───────────────────────────────────────────
# Green-tinted hierarchy: important data pops, structure recedes.

MATRIX_SOLARIZED: Dict[str, str] = {
    # Layout chrome
    "border_color":          "#3a5a35",
    "rule":                  "#3a5a35",
    "header_bg":             "on #0a1a0a",
    "menu_bg":               "on #0a1a0a",
    "separator":             "#2a4a2a",

    # General purpose
    "label":                 "bold #5a9a5a",
    "value":                 "#b0d0b0",
    "muted":                 "#4e6e4e",
    "warning":               "#d7af5f",
    "critical":              "bold #d75f5f",
    "recovery":              "#5faf5f",

    # Traffic
    "tx":                    "#a08050",
    "rx":                    "#5faf5f",
    "sparkline_tx":          "#6a5838",
    "sparkline_rx":          "#3a6a3a",

    # Menu / screen tabs
    "active_screen":         "bold #c0e0c0",
    "inactive_screen":       "#4e6e4e",
    "status_running":        "bold #5fdf5f",
    "status_paused":         "bold #d7af5f",
    "status_stopping":       "bold #d75f5f",

    # Hex byte categories
    "byte_text":             "#b0d0b0",
    "byte_null":             "#5a6a8a",
    "byte_newline":          "#8fa8d4",
    "byte_control":          "#9aaa5a",
    "byte_high":             "#708070",
    "byte_ff":               "#a0845a",

    # Per-field color palette (V:3 coordinated coloring)
    "field_0":               "#5fafaf",       # teal
    "field_1":               "#af87d7",       # lavender
    "field_2":               "#d7af5f",       # amber
    "field_3":               "#87af5f",       # olive
    "field_4":               "#d78787",       # salmon
    "field_5":               "#5f87d7",       # steel blue
    "field_6":               "#afaf5f",       # khaki
    "field_7":               "#d787af",       # rose

    # Heartbeat indicator
    "hb_red":                "#8a4a4a",
    "hb_green_mid":          "#5a8a5a",

    # Matrix rain (6-level brightness)
    "rain_0":                "#1a2a1a",
    "rain_1":                "#2a3a2a",
    "rain_2":                "#3a5a3a",
    "rain_3":                "#508050",
    "rain_4":                "#70a870",
    "rain_5":                "#90d090",

    # Progress bars
    "progress_inner":        "#8a7050",

    # Help panel
    "help_title":            "bold #c0e0c0",

    # Log viewer
    "log_search":            "#1a1a1a on #d7af5f",
    "log_line_num":          "#4e6e4e",
    "log_follow":            "bold #5faf5f",
    "log_scroll":            "bold #d7af5f",
    "log_timestamp":         "#5a7a5a",
    "log_level_debug":       "#5a8a5a",
    "log_level_info":        "#5faf5f",
    "log_level_warning":     "bold #d7af5f",
    "log_level_error":       "bold #d75f5f",
    "log_level_critical":    "bold #ff5f5f",
    "log_message":           "#b0d0b0",
    "log_hex":               "#708070",
    "log_bracket":           "#5a7a5a",

    # Log search prompt
    "log_search_slash":      "bold #5faf5f",
    "log_search_input":      "#b0d0b0",
    "log_search_cursor":     "blink #b0d0b0",
}


# ── Tangled Up in Blue ──────────────────────────────────────────────
# Deep navy and warm cream derived from a 5-swatch palette:
#   #92C2D6  light blue (accent)
#   #325270  medium blue (structure)
#   #10263B  dark navy (background)
#   #2B1B07  dark brown (warm contrast)
#   #DBCDAC  warm cream (text)

TANGLED_IN_BLUE: Dict[str, str] = {
    # Layout chrome
    "border_color":          "#325270",
    "rule":                  "#325270",
    "header_bg":             "on #0a1a2a",
    "menu_bg":               "on #0a1a2a",
    "separator":             "#1a3a50",

    # General purpose
    "label":                 "bold #92c2d6",
    "value":                 "#dbcdac",
    "muted":                 "#4a6a80",
    "warning":               "#d7a85f",
    "critical":              "bold #d75f5f",
    "recovery":              "#92c2d6",

    # Traffic
    "tx":                    "#a08050",
    "rx":                    "#92c2d6",
    "sparkline_tx":          "#6a5838",
    "sparkline_rx":          "#3a5a70",

    # Menu / screen tabs
    "active_screen":         "bold #dbcdac",
    "inactive_screen":       "#4a6a80",
    "status_running":        "bold #92c2d6",
    "status_paused":         "bold #d7a85f",
    "status_stopping":       "bold #d75f5f",

    # Hex byte categories
    "byte_text":             "#dbcdac",
    "byte_null":             "#4a6a80",
    "byte_newline":          "#7aaac6",
    "byte_control":          "#8a9a6a",
    "byte_high":             "#607080",
    "byte_ff":               "#a0845a",

    # Per-field color palette
    "field_0":               "#5fafaf",       # teal
    "field_1":               "#af87d7",       # lavender
    "field_2":               "#d7af5f",       # amber
    "field_3":               "#87af5f",       # olive
    "field_4":               "#d78787",       # salmon
    "field_5":               "#5f87d7",       # steel blue
    "field_6":               "#afaf5f",       # khaki
    "field_7":               "#d787af",       # rose

    # Heartbeat indicator
    "hb_red":                "#8a4a4a",
    "hb_green_mid":          "#5a7a8a",

    # Rain (6-level blue gradient -- dark navy to light blue)
    "rain_0":                "#0a1520",
    "rain_1":                "#152535",
    "rain_2":                "#25405a",
    "rain_3":                "#3a6080",
    "rain_4":                "#5a90b0",
    "rain_5":                "#92c2d6",

    # Progress bars
    "progress_inner":        "#5a7a8a",

    # Help panel
    "help_title":            "bold #dbcdac",

    # Log viewer
    "log_search":            "#10263b on #d7a85f",
    "log_line_num":          "#4a6a80",
    "log_follow":            "bold #92c2d6",
    "log_scroll":            "bold #d7a85f",
    "log_timestamp":         "#4a7090",
    "log_level_debug":       "#4a7a90",
    "log_level_info":        "#92c2d6",
    "log_level_warning":     "bold #d7a85f",
    "log_level_error":       "bold #d75f5f",
    "log_level_critical":    "bold #ff5f5f",
    "log_message":           "#dbcdac",
    "log_hex":               "#607080",
    "log_bracket":           "#4a7090",

    # Log search prompt
    "log_search_slash":      "bold #92c2d6",
    "log_search_input":      "#dbcdac",
    "log_search_cursor":     "blink #dbcdac",
}


# ── Mordor ──────────────────────────────────────────────────────────
# Volcanic reds and embers on charcoal/black.  Inspired by the dark
# land itself -- smoldering, oppressive, with flickers of firelight.

MORDOR: Dict[str, str] = {
    # Layout chrome
    "border_color":          "#4a2020",
    "rule":                  "#4a2020",
    "header_bg":             "on #0a0808",
    "menu_bg":               "on #0a0808",
    "separator":             "#2a1515",

    # General purpose
    "label":                 "bold #c05040",
    "value":                 "#c0a898",
    "muted":                 "#5a4a4a",
    "warning":               "#d7a040",
    "critical":              "bold #ff4030",
    "recovery":              "#a08060",

    # Traffic
    "tx":                    "#d08030",
    "rx":                    "#b05040",
    "sparkline_tx":          "#7a5020",
    "sparkline_rx":          "#5a2a2a",

    # Menu / screen tabs
    "active_screen":         "bold #e0c0a0",
    "inactive_screen":       "#5a4a4a",
    "status_running":        "bold #d06040",
    "status_paused":         "bold #d7a040",
    "status_stopping":       "bold #ff4030",

    # Hex byte categories
    "byte_text":             "#c0a898",
    "byte_null":             "#4a4050",
    "byte_newline":          "#8a7080",
    "byte_control":          "#8a8050",
    "byte_high":             "#605858",
    "byte_ff":               "#a07040",

    # Per-field color palette
    "field_0":               "#c07060",       # ember
    "field_1":               "#a08060",       # ash
    "field_2":               "#d7a040",       # flame
    "field_3":               "#8a7a50",       # sulphur
    "field_4":               "#d07070",       # lava
    "field_5":               "#7a6a90",       # shadow
    "field_6":               "#b09050",       # bronze
    "field_7":               "#c08070",       # smolder

    # Heartbeat indicator
    "hb_red":                "#8a3030",
    "hb_green_mid":          "#8a6040",

    # Rain (6-level ember gradient -- dark ash to bright flame)
    "rain_0":                "#1a0a0a",
    "rain_1":                "#2a1510",
    "rain_2":                "#4a2018",
    "rain_3":                "#7a3020",
    "rain_4":                "#b04828",
    "rain_5":                "#e06830",

    # Progress bars
    "progress_inner":        "#6a4030",

    # Help panel
    "help_title":            "bold #e0c0a0",

    # Log viewer
    "log_search":            "#0a0808 on #d7a040",
    "log_line_num":          "#5a4a4a",
    "log_follow":            "bold #d06040",
    "log_scroll":            "bold #d7a040",
    "log_timestamp":         "#6a5040",
    "log_level_debug":       "#6a5a50",
    "log_level_info":        "#b08060",
    "log_level_warning":     "bold #d7a040",
    "log_level_error":       "bold #d04030",
    "log_level_critical":    "bold #ff4030",
    "log_message":           "#c0a898",
    "log_hex":               "#605858",
    "log_bracket":           "#6a5040",

    # Log search prompt
    "log_search_slash":      "bold #d06040",
    "log_search_input":      "#c0a898",
    "log_search_cursor":     "blink #c0a898",
}


# -- Light -----------------------------------------------------------------
# Number of field colors in the palette
_FIELD_COLOR_COUNT = 8

# Heartbeat pulse gradient endpoints -- set per-theme by apply_theme().
# Tuples are interpolated at render time, not Rich Style objects.
HB_GREEN_DIM: Tuple[int, int, int] = (0x3a, 0x5a, 0x3a)
HB_GREEN_BRIGHT: Tuple[int, int, int] = (0x7a, 0xaa, 0x7a)
HB_PULSE_PERIOD: float = 3.0

# Rain character string -- set per-theme by apply_theme().
RAIN_CHARS: str = KATAKANA_RAIN


# ── Theme registry ──────────────────────────────────────────────────

# { name -> {palette, rain_chars, hb_dim, hb_bright, hb_period} }
_REGISTRY: "OrderedDict[str, dict]" = OrderedDict()
_current_theme: str = ""


def register_theme(
    name: str,
    palette: Dict[str, str],
    *,
    rain_chars: str = "",
    hb_dim: Tuple[int, int, int] = (0x3a, 0x5a, 0x3a),
    hb_bright: Tuple[int, int, int] = (0x7a, 0xaa, 0x7a),
    hb_period: float = 3.0,
) -> None:
    """Register a named theme in the global registry."""
    _REGISTRY[name] = {
        "palette": palette,
        "rain_chars": rain_chars or KATAKANA_RAIN,
        "hb_dim": hb_dim,
        "hb_bright": hb_bright,
        "hb_period": hb_period,
    }


def get_theme_name() -> str:
    """Return the name of the currently active theme."""
    return _current_theme


def get_theme_names() -> List[str]:
    """Return ordered list of all registered theme names."""
    return list(_REGISTRY.keys())


def cycle_theme(direction: int = 1) -> str:
    """Activate the next (*direction* = +1) or previous (-1) theme.

    Returns the newly active theme name.
    """
    names = list(_REGISTRY.keys())
    if not names:
        return _current_theme
    try:
        idx = names.index(_current_theme)
    except ValueError:
        idx = 0
    idx = (idx + direction) % len(names)
    apply_theme(names[idx])
    return names[idx]


# ── Theme API ───────────────────────────────────────────────────────

def build_theme(palette: Optional[Dict[str, str]] = None) -> "Theme":
    """Return a Rich ``Theme`` from the given palette dict.

    If *palette* is ``None``, uses ``MATRIX_SOLARIZED``.
    """
    if not HAS_RICH:  # pragma: no cover
        raise RuntimeError("rich is not installed")
    return Theme(palette or MATRIX_SOLARIZED)


def _parse_style(style_str: str) -> "Style":
    """Convert a Rich style string to a ``Style`` object."""
    return Style.parse(style_str)


# ── Module-level Style constants ────────────────────────────────────
# Populated by apply_theme() at module load time.  Every name that
# rich_renderables.py historically imported is present here.

# Sentinel so we can detect "not yet loaded" if needed.
_loaded = False

# Layout chrome
BORDER_COLOR: str = ""
RULE_STYLE: str = ""
HEADER_BG: "Style" = None  # type: ignore[assignment]
MENU_BG: "Style" = None  # type: ignore[assignment]
SEPARATOR_STYLE: "Style" = None  # type: ignore[assignment]

# General purpose
LABEL_STYLE: "Style" = None  # type: ignore[assignment]
VALUE_STYLE: "Style" = None  # type: ignore[assignment]
MUTED_STYLE: "Style" = None  # type: ignore[assignment]
WARNING_STYLE: "Style" = None  # type: ignore[assignment]
CRITICAL_STYLE: "Style" = None  # type: ignore[assignment]
RECOVERY_STYLE: "Style" = None  # type: ignore[assignment]

# Traffic
TX_STYLE: "Style" = None  # type: ignore[assignment]
RX_STYLE: "Style" = None  # type: ignore[assignment]
SPARKLINE_TX_STYLE: "Style" = None  # type: ignore[assignment]
SPARKLINE_RX_STYLE: "Style" = None  # type: ignore[assignment]

# Menu / screen tabs
ACTIVE_SCREEN_STYLE: "Style" = None  # type: ignore[assignment]
INACTIVE_SCREEN_STYLE: "Style" = None  # type: ignore[assignment]
STATUS_RUNNING_STYLE: "Style" = None  # type: ignore[assignment]
STATUS_PAUSED_STYLE: "Style" = None  # type: ignore[assignment]
STATUS_STOPPING_STYLE: "Style" = None  # type: ignore[assignment]

# Hex byte categories
BYTE_STYLE_TEXT: "Style" = None  # type: ignore[assignment]
BYTE_STYLE_NULL: "Style" = None  # type: ignore[assignment]
BYTE_STYLE_NEWLINE: "Style" = None  # type: ignore[assignment]
BYTE_STYLE_CONTROL: "Style" = None  # type: ignore[assignment]
BYTE_STYLE_HIGH: "Style" = None  # type: ignore[assignment]
BYTE_STYLE_FF: "Style" = None  # type: ignore[assignment]

# Per-field colors
FIELD_COLORS: List["Style"] = []

# Heartbeat
_HB_RED: "Style" = None  # type: ignore[assignment]
_HB_UNKNOWN: "Style" = None  # type: ignore[assignment]
_HB_GREEN_MID: "Style" = None  # type: ignore[assignment]

# Rain
_RAIN_STYLES: tuple = ()

# Progress
PROGRESS_INNER_STYLE: "Style" = None  # type: ignore[assignment]

# Help
HELP_TITLE_STYLE: "Style" = None  # type: ignore[assignment]

# Log viewer
LOG_SEARCH_STYLE: "Style" = None  # type: ignore[assignment]
LOG_LINE_NUM_STYLE: "Style" = None  # type: ignore[assignment]
LOG_FOLLOW_STYLE: "Style" = None  # type: ignore[assignment]
LOG_SCROLL_STYLE: "Style" = None  # type: ignore[assignment]
LOG_TIMESTAMP_STYLE: "Style" = None  # type: ignore[assignment]
LOG_LEVEL_DEBUG: "Style" = None  # type: ignore[assignment]
LOG_LEVEL_INFO: "Style" = None  # type: ignore[assignment]
LOG_LEVEL_WARNING: "Style" = None  # type: ignore[assignment]
LOG_LEVEL_ERROR: "Style" = None  # type: ignore[assignment]
LOG_LEVEL_CRITICAL: "Style" = None  # type: ignore[assignment]
LOG_MESSAGE_STYLE: "Style" = None  # type: ignore[assignment]
LOG_HEX_STYLE: "Style" = None  # type: ignore[assignment]
LOG_BRACKET_STYLE: "Style" = None  # type: ignore[assignment]
LOG_SEARCH_SLASH_STYLE: "Style" = None  # type: ignore[assignment]
LOG_SEARCH_INPUT_STYLE: "Style" = None  # type: ignore[assignment]
LOG_SEARCH_CURSOR_STYLE: "Style" = None  # type: ignore[assignment]


def apply_theme(
    name_or_palette: Union[str, Dict[str, str], None] = None,
) -> None:
    """Populate module-level Style constants from a theme or palette.

    *name_or_palette* may be:
    - A ``str``  -- looked up in the registry.
    - A ``dict`` -- used directly as the palette.
    - ``None``   -- uses the first registered theme (or MATRIX_SOLARIZED).

    This is called automatically at module load time.  Call it again
    (e.g. via ``cycle_theme()``) to switch themes at runtime.
    """
    global _current_theme

    if not HAS_RICH:  # pragma: no cover
        return

    if isinstance(name_or_palette, str):
        config = _REGISTRY.get(name_or_palette)
        if config is None:
            raise KeyError(f"Unknown theme: {name_or_palette!r}")
        p = config["palette"]
        _current_theme = name_or_palette
    elif isinstance(name_or_palette, dict):
        p = name_or_palette
        # Raw palette -- no registry entry; keep current name blank.
        _current_theme = ""
    else:
        # None -- pick first registered theme, or fall back to built-in.
        if _REGISTRY:
            name = next(iter(_REGISTRY))
            config = _REGISTRY[name]
            p = config["palette"]
            _current_theme = name
        else:
            p = MATRIX_SOLARIZED
            _current_theme = ""

    g = globals()

    # Layout chrome -- these two are raw color strings, not Style objects
    g["BORDER_COLOR"] = p["border_color"]
    g["RULE_STYLE"] = p["rule"]
    g["HEADER_BG"] = _parse_style(p["header_bg"])
    g["MENU_BG"] = _parse_style(p["menu_bg"])
    g["SEPARATOR_STYLE"] = _parse_style(p["separator"])

    # General purpose
    g["LABEL_STYLE"] = _parse_style(p["label"])
    g["VALUE_STYLE"] = _parse_style(p["value"])
    g["MUTED_STYLE"] = _parse_style(p["muted"])
    g["WARNING_STYLE"] = _parse_style(p["warning"])
    g["CRITICAL_STYLE"] = _parse_style(p["critical"])
    g["RECOVERY_STYLE"] = _parse_style(p["recovery"])

    # Traffic
    g["TX_STYLE"] = _parse_style(p["tx"])
    g["RX_STYLE"] = _parse_style(p["rx"])
    g["SPARKLINE_TX_STYLE"] = _parse_style(p["sparkline_tx"])
    g["SPARKLINE_RX_STYLE"] = _parse_style(p["sparkline_rx"])

    # Menu / screen tabs
    g["ACTIVE_SCREEN_STYLE"] = _parse_style(p["active_screen"])
    g["INACTIVE_SCREEN_STYLE"] = _parse_style(p["inactive_screen"])
    g["STATUS_RUNNING_STYLE"] = _parse_style(p["status_running"])
    g["STATUS_PAUSED_STYLE"] = _parse_style(p["status_paused"])
    g["STATUS_STOPPING_STYLE"] = _parse_style(p["status_stopping"])

    # Hex byte categories
    g["BYTE_STYLE_TEXT"] = _parse_style(p["byte_text"])
    g["BYTE_STYLE_NULL"] = _parse_style(p["byte_null"])
    g["BYTE_STYLE_NEWLINE"] = _parse_style(p["byte_newline"])
    g["BYTE_STYLE_CONTROL"] = _parse_style(p["byte_control"])
    g["BYTE_STYLE_HIGH"] = _parse_style(p["byte_high"])
    g["BYTE_STYLE_FF"] = _parse_style(p["byte_ff"])

    # Per-field colors
    g["FIELD_COLORS"] = [
        _parse_style(p[f"field_{i}"]) for i in range(_FIELD_COLOR_COUNT)
    ]

    # Heartbeat
    g["_HB_RED"] = _parse_style(p["hb_red"])
    g["_HB_UNKNOWN"] = g["MUTED_STYLE"]  # alias
    g["_HB_GREEN_MID"] = _parse_style(p["hb_green_mid"])

    # Rain
    g["_RAIN_STYLES"] = tuple(
        _parse_style(p[f"rain_{i}"]) for i in range(6)
    )

    # Progress
    g["PROGRESS_INNER_STYLE"] = _parse_style(p["progress_inner"])

    # Help
    g["HELP_TITLE_STYLE"] = _parse_style(p["help_title"])

    # Log viewer
    g["LOG_SEARCH_STYLE"] = _parse_style(p["log_search"])
    g["LOG_LINE_NUM_STYLE"] = _parse_style(p["log_line_num"])
    g["LOG_FOLLOW_STYLE"] = _parse_style(p["log_follow"])
    g["LOG_SCROLL_STYLE"] = _parse_style(p["log_scroll"])
    g["LOG_TIMESTAMP_STYLE"] = _parse_style(p["log_timestamp"])
    g["LOG_LEVEL_DEBUG"] = _parse_style(p["log_level_debug"])
    g["LOG_LEVEL_INFO"] = _parse_style(p["log_level_info"])
    g["LOG_LEVEL_WARNING"] = _parse_style(p["log_level_warning"])
    g["LOG_LEVEL_ERROR"] = _parse_style(p["log_level_error"])
    g["LOG_LEVEL_CRITICAL"] = _parse_style(p["log_level_critical"])
    g["LOG_MESSAGE_STYLE"] = _parse_style(p["log_message"])
    g["LOG_HEX_STYLE"] = _parse_style(p["log_hex"])
    g["LOG_BRACKET_STYLE"] = _parse_style(p["log_bracket"])
    g["LOG_SEARCH_SLASH_STYLE"] = _parse_style(p["log_search_slash"])
    g["LOG_SEARCH_INPUT_STYLE"] = _parse_style(p["log_search_input"])
    g["LOG_SEARCH_CURSOR_STYLE"] = _parse_style(p["log_search_cursor"])

    # Per-theme extra properties (rain chars + heartbeat gradient)
    if _current_theme and _current_theme in _REGISTRY:
        cfg = _REGISTRY[_current_theme]
        g["RAIN_CHARS"] = cfg["rain_chars"]
        g["HB_GREEN_DIM"] = cfg["hb_dim"]
        g["HB_GREEN_BRIGHT"] = cfg["hb_bright"]
        g["HB_PULSE_PERIOD"] = cfg["hb_period"]
    else:
        g["RAIN_CHARS"] = KATAKANA_RAIN

    g["_loaded"] = True
    _propagate()


# ── Propagation to consumer modules ────────────────────────────────

# Style names that exist identically in both theme and rich_renderables.
_PROP_SAME: Tuple[str, ...] = (
    "BORDER_COLOR", "RULE_STYLE", "HEADER_BG", "MENU_BG", "SEPARATOR_STYLE",
    "LABEL_STYLE", "VALUE_STYLE", "MUTED_STYLE", "WARNING_STYLE",
    "CRITICAL_STYLE", "RECOVERY_STYLE",
    "TX_STYLE", "RX_STYLE", "SPARKLINE_TX_STYLE", "SPARKLINE_RX_STYLE",
    "ACTIVE_SCREEN_STYLE", "INACTIVE_SCREEN_STYLE",
    "STATUS_RUNNING_STYLE", "STATUS_PAUSED_STYLE", "STATUS_STOPPING_STYLE",
    "BYTE_STYLE_TEXT", "BYTE_STYLE_NULL", "BYTE_STYLE_NEWLINE",
    "BYTE_STYLE_CONTROL", "BYTE_STYLE_HIGH", "BYTE_STYLE_FF",
    "FIELD_COLORS",
    "_HB_RED", "_HB_UNKNOWN", "_HB_GREEN_MID",
    "_RAIN_STYLES",
    "PROGRESS_INNER_STYLE", "HELP_TITLE_STYLE",
    "LOG_SEARCH_STYLE", "LOG_LINE_NUM_STYLE", "LOG_FOLLOW_STYLE",
    "LOG_SCROLL_STYLE", "LOG_TIMESTAMP_STYLE",
    "LOG_LEVEL_DEBUG", "LOG_LEVEL_INFO", "LOG_LEVEL_WARNING",
    "LOG_LEVEL_ERROR", "LOG_LEVEL_CRITICAL",
    "LOG_MESSAGE_STYLE", "LOG_HEX_STYLE", "LOG_BRACKET_STYLE",
    "LOG_SEARCH_SLASH_STYLE", "LOG_SEARCH_INPUT_STYLE",
    "LOG_SEARCH_CURSOR_STYLE",
)

# Names that have a different target name in rich_renderables.
_PROP_RENAMES: Dict[str, str] = {
    "RAIN_CHARS": "_RAIN_CHARS",
    "HB_GREEN_DIM": "_HB_GREEN_DIM",
    "HB_GREEN_BRIGHT": "_HB_GREEN_BRIGHT",
    "HB_PULSE_PERIOD": "_HB_PULSE_PERIOD",
}


def _propagate() -> None:
    """Push current style values to already-imported consumer modules.

    ``from theme import X`` creates a local binding that does not
    update when ``theme.X`` changes.  This function manually copies
    the new values into those modules' namespaces.
    """
    rr = sys.modules.get("bytefault.ui.rich_renderables")
    if rr is None:
        return
    g = globals()
    for name in _PROP_SAME:
        if name in g:
            setattr(rr, name, g[name])
    for src, dst in _PROP_RENAMES.items():
        if src in g:
            setattr(rr, dst, g[src])


# ── Register built-in themes ───────────────────────────────────────

register_theme(
    "matrix-solarized",
    MATRIX_SOLARIZED,
    rain_chars=KATAKANA_RAIN,
    hb_dim=(0x3a, 0x5a, 0x3a),
    hb_bright=(0x7a, 0xaa, 0x7a),
    hb_period=3.0,
)
register_theme(
    "tangled-in-blue",
    TANGLED_IN_BLUE,
    rain_chars=HEX_STREAM_RAIN,
    hb_dim=(0x10, 0x30, 0x4a),
    hb_bright=(0x92, 0xc2, 0xd6),
    hb_period=3.5,
)
register_theme(
    "mordor",
    MORDOR,
    rain_chars=EMBER_RAIN,
    hb_dim=(0x3a, 0x18, 0x18),
    hb_bright=(0xc0, 0x50, 0x30),
    hb_period=2.5,
)

# Auto-load default theme on import
apply_theme("matrix-solarized")
