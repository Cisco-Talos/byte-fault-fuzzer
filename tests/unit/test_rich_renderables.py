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

"""Tests for Rich UI renderable components.

Verifies each builder function with mock ``FuzzSessionState``, ensures
no Rich exceptions are raised, and checks basic structural correctness.
"""

from __future__ import annotations

import os
import time
from collections import deque
from unittest.mock import patch

import pytest

from bytefault.ui.state import ViewState

# Import renderables — these require Rich
rich = pytest.importorskip("rich")

from bytefault.fuzzers.rich_renderables import (
    BYTE_STYLE_CONTROL,
    BYTE_STYLE_FF,
    BYTE_STYLE_HIGH,
    BYTE_STYLE_NEWLINE,
    BYTE_STYLE_NULL,
    BYTE_STYLE_TEXT,
    HexDumpRenderable,
    RingBufferEntry,
    _append_rain_fill,
    _build_raw_field_diagram,
    _estimate_entry_rows,
    _field_display_width,
    _format_entry_v0,
    _format_entry_v1,
    _format_entry_v2,
    _format_entry_v3,
    _format_entry_v4,
    _hex_spaced,
    _partition_fields_into_rows,
    _RAIN_CHARS,
    _RAIN_STYLES,
    _styled_hex_snippet,
    build_crash_screen,
    build_crash_table,
    build_dashboard,
    build_header,
    build_help_panel,
    build_matrix_rain,
    build_menu_row,
    build_progress_bars,
    build_protocol_diagram,
    build_sparkline,
    build_test_section,
    compute_field_byte_ranges,
    build_field_byte_styles,
    style_hex_byte,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def mock_state():
    """A populated terminal-owned ViewState for rendering tests."""
    state = ViewState(
        protocol="Raw",
        host="192.0.2.1",
        port=49152,
        start_time=time.time(),
        fuzz_mode="fuzz_field",
        targets=["payload:random:1-512"],
        generator_type="sweep",
        strategy="single",
        schema_name="framed_fixture",
        health_check_mode="new_connection",
        total_iterations=65536,
        current_iteration=1234,
        crash_count=2,
        current_field_bytes={"prefix": b"\x4e\x4f", "payload": b"\x00\x01\x02"},
        last_sent=b"\x00\x01\x02\x03",
        last_received=b"\x04\x05\x06\x07",
        total_bytes_sent=50000,
        total_bytes_received=30000,
        elapsed_seconds=872.5,
        tests_per_second=12.4,
        verbosity_level=0,
    )
    return state


@pytest.fixture
def test_entry():
    """A sample test entry for the ring buffer."""
    return RingBufferEntry(
        timestamp=time.time(),
        iteration=42,
        entry_type="test",
        sent_bytes=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b",
        recv_bytes=b"\x10\x11\x12\x13",
        sent_len=12,
        recv_len=4,
        field_bytes={"prefix": b"\x4e\x4f"},
    )


@pytest.fixture
def crash_entry():
    """A crash event entry."""
    return RingBufferEntry(
        timestamp=time.time(),
        iteration=99,
        entry_type="crash",
        message="Device crash detected at iteration 99",
    )


@pytest.fixture
def recovery_entry():
    """A recovery event entry."""
    return RingBufferEntry(
        timestamp=time.time(),
        iteration=99,
        entry_type="recovery",
        message="Device recovered after 12s",
    )


@pytest.fixture
def health_entry():
    """A health check warning entry."""
    return RingBufferEntry(
        timestamp=time.time(),
        iteration=100,
        entry_type="health",
        message="Health check: 192.0.2.1:49152 not responding",
    )


# ── style_hex_byte ───────────────────────────────────────────────────


class TestStyleHexByte:
    def test_ascii_text_digits(self):
        for b in range(0x30, 0x3A):
            assert style_hex_byte(b) == BYTE_STYLE_TEXT

    def test_ascii_text_upper(self):
        for b in range(0x41, 0x5B):
            assert style_hex_byte(b) == BYTE_STYLE_TEXT

    def test_ascii_text_lower(self):
        for b in range(0x61, 0x7B):
            assert style_hex_byte(b) == BYTE_STYLE_TEXT

    def test_ascii_text_printable_symbols(self):
        """All printable non-alnum (space, punctuation) are TEXT."""
        for b in (0x20, 0x21, 0x2F, 0x3A, 0x40, 0x5B, 0x60, 0x7E):
            assert style_hex_byte(b) == BYTE_STYLE_TEXT

    def test_tab_is_text(self):
        """Tab (0x09) is treated as readable text, not control."""
        assert style_hex_byte(0x09) == BYTE_STYLE_TEXT

    def test_null(self):
        assert style_hex_byte(0x00) == BYTE_STYLE_NULL

    def test_newlines(self):
        assert style_hex_byte(0x0A) == BYTE_STYLE_NEWLINE
        assert style_hex_byte(0x0D) == BYTE_STYLE_NEWLINE

    def test_control_chars(self):
        """Control chars excluding null, CR/LF, and tab."""
        for b in (0x01, 0x02, 0x08, 0x0B, 0x0C, 0x0E, 0x1F):
            assert style_hex_byte(b) == BYTE_STYLE_CONTROL

    def test_high_bytes(self):
        for b in (0x80, 0xA0, 0xFE):
            assert style_hex_byte(b) == BYTE_STYLE_HIGH

    def test_ff_byte(self):
        """0xFF gets its own darker style."""
        assert style_hex_byte(0xFF) == BYTE_STYLE_FF

    def test_all_bytes_return_a_style(self):
        """Every possible byte value (0-255) should return a valid Style."""
        for b in range(256):
            result = style_hex_byte(b)
            assert result is not None


# ── build_menu_row ───────────────────────────────────────────────────


class TestLogThemeStyles:
    def test_log_levels_follow_repeated_theme_changes(self):
        from bytefault.ui import rich_renderables as renderables, theme
        original = theme.get_theme_name()
        try:
            for name in ('tangled-in-blue', 'mordor', 'matrix-solarized', 'tangled-in-blue'):
                theme.apply_theme(name)
                for level in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
                    result = renderables._style_log_line(
                        '2026-11-05 00:00:00.000 [' + level + '] message', 'ss')
                    styles = {result.plain[span.start:span.end]: span.style for span in result.spans}
                    expected = getattr(renderables, 'LOG_LEVEL_' + level)
                    assert styles[level] == expected
                    assert styles['ss'] == renderables.LOG_SEARCH_STYLE
                    message_style = expected if level in ('WARNING', 'ERROR', 'CRITICAL') else renderables.LOG_MESSAGE_STYLE
                    assert styles[' me'] == message_style
                    assert styles['age'] == message_style
        finally:
            theme.apply_theme(original)

    def test_search_default_follows_current_theme_and_explicit_style(self):
        from bytefault.ui import rich_renderables as renderables, theme
        from rich.style import Style
        original = theme.get_theme_name()
        explicit = Style(color='cyan')
        try:
            for name in ('tangled-in-blue', 'mordor', 'matrix-solarized'):
                theme.apply_theme(name)
                searched = renderables._style_log_line('unformatted message', 'absent')
                assert searched.spans[0].style == renderables.LOG_MESSAGE_STYLE
                supplied = rich.text.Text()
                renderables._append_with_highlight(supplied, 'unformatted message', '', explicit)
                assert supplied.spans[0].style == explicit
        finally:
            theme.apply_theme(original)


class TestLogScreenProjection:
    @pytest.mark.parametrize('lines,ready,issue,expected', (
        (['projected needle'], True, '', 'projected needle'),
        ([], False, '', 'indexing configured log'),
        ([], False, 'fixture unavailable', 'fixture unavailable')))
    def test_log_screen_uses_projection_without_opening_source(
            self, mock_state, tmp_path, monkeypatch, lines, ready, issue, expected):
        from io import StringIO
        from rich.console import Console
        from bytefault.ui import rich_renderables as renderables
        mock_state.log_file = str(tmp_path / 'not-opened.log')
        mock_state.log_lines = lines
        mock_state.log_index_ready = ready
        mock_state.log_issue = issue
        output = StringIO()
        console = Console(file=output, width=80, height=24, color_system=None)
        def unexpected_open(*args, **kwargs):
            raise AssertionError('renderer must not open the configured log')
        monkeypatch.setattr('builtins.open', unexpected_open)
        monkeypatch.setattr(renderables.shutil, 'get_terminal_size',
                            lambda *args: os.terminal_size((80, 24)))
        console.print(renderables.build_log_screen(mock_state))
        assert expected in output.getvalue()


class TestBuildMenuRow:
    def test_returns_text(self, mock_state):
        result = build_menu_row(mock_state)
        assert isinstance(result, rich.text.Text)

    def test_contains_dashboard(self, mock_state):
        result = build_menu_row(mock_state)
        assert "Dashboard" in result.plain

    def test_contains_crashes_count(self, mock_state):
        mock_state.crash_records = [{"id": "first"}, {"id": "second"}]
        result = build_menu_row(mock_state)
        assert "Findings(2)" in result.plain

    def test_active_dashboard_marker(self, mock_state):
        mock_state.active_screen = "dashboard"
        result = build_menu_row(mock_state)
        assert "Dashboard*" in result.plain

    def test_active_crashes_marker(self, mock_state):
        mock_state.active_screen = "crashes"
        mock_state.crash_records = [{"id": "first"}, {"id": "second"}]
        result = build_menu_row(mock_state)
        assert "Findings(2)*" in result.plain

    def test_contains_protocol(self, mock_state):
        """Protocol diagram is now embedded in header, not a tab."""
        result = build_menu_row(mock_state)
        # F4 Protocol tab removed; menu should NOT contain it
        assert "Protocol" not in result.plain

    def test_shows_running_status(self, mock_state):
        result = build_menu_row(mock_state)
        assert "RUNNING" in result.plain

    def test_shows_paused_status(self, mock_state):
        mock_state.paused = True
        result = build_menu_row(mock_state)
        assert "PAUSED" in result.plain

    def test_shows_quit_hint(self, mock_state):
        with patch("shutil.get_terminal_size", return_value=os.terminal_size((120, 24))):
            result = build_menu_row(mock_state)
        assert "Q Quit" in result.plain

    def test_shows_verbosity_level(self, mock_state):
        mock_state.verbosity_level = 2
        result = build_menu_row(mock_state)
        assert "V:2" in result.plain


# ── build_header ─────────────────────────────────────────────────────


class TestBuildHeader:
    def test_returns_table(self, mock_state):
        result = build_header(mock_state)
        assert isinstance(result, rich.console.Group)

    def test_contains_protocol(self, mock_state):
        """The header should include the protocol name."""
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=200)
        console.print(build_header(mock_state))
        output = buf.getvalue()
        assert "Raw" in output

    def test_contains_host(self, mock_state):
        from rich.console import Console
        from io import StringIO
        import os
        buf = StringIO()
        term_size = os.terminal_size((200, 50))
        with patch("shutil.get_terminal_size", return_value=term_size):
            header = build_header(mock_state)
        console = Console(file=buf, force_terminal=True, width=200, no_color=True)
        console.print(header)
        output = buf.getvalue()
        assert "192.0.2.1" in output

    def test_hidden_fields_filtered(self, mock_state):
        """Hide the summary value without hiding the packet diagram."""
        mock_state.packet_schema = FRAMED_SCHEMA
        mock_state.current_field_bytes = FRAMED_FIELD_BYTES
        mock_state.current_fields = [
            {"action_id": "outbound", "buffer_id": "packet", "field_id": "marker", "value": b"\x15"},
            {"action_id": "outbound", "buffer_id": "packet", "field_id": "payload", "value": b"ABC"},
        ]
        mock_state.hidden_fields = ["marker"]
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=200)
        with patch("shutil.get_terminal_size", return_value=os.terminal_size((200, 50))):
            console.print(build_header(mock_state))
        output = buf.getvalue()
        assert "PAYLOAD" in output
        assert "MARKER" in output
        assert "outbound/packet/payload" in output
        assert "outbound/packet/marker" not in output


# ── build_sparkline ──────────────────────────────────────────────────


class TestBuildSparkline:
    def test_returns_text(self):
        tx = deque([100, 200, 300], maxlen=100)
        rx = deque([50, 100, 150], maxlen=100)
        result = build_sparkline(tx, rx, width=80)
        assert isinstance(result, rich.text.Text)

    def test_contains_tx_rx_labels(self):
        tx = deque([100], maxlen=100)
        rx = deque([50], maxlen=100)
        result = build_sparkline(tx, rx, width=80)
        assert "TX:" in result.plain
        assert "RX:" in result.plain

    def test_empty_history(self):
        result = build_sparkline(deque(maxlen=100), deque(maxlen=100), width=80)
        assert "TX:" in result.plain
        assert "RX:" in result.plain

    def test_sparkline_chars_present(self):
        tx = deque([0, 100, 200, 300, 400, 500], maxlen=100)
        rx = deque([0, 50], maxlen=100)
        result = build_sparkline(tx, rx, width=60)
        # Should contain braille characters (U+2800 block)
        found = any("\u2800" <= c <= "\u28FF" for c in result.plain)
        assert found


# ── HexDumpRenderable ────────────────────────────────────────────────


class TestHexDumpRenderable:
    def test_basic_build(self):
        data = bytes(range(32))
        hd = HexDumpRenderable(data, direction="sent", term_width=120)
        result = hd.build()
        assert isinstance(result, rich.text.Text)

    def test_offset_column(self):
        data = bytes(range(32))
        hd = HexDumpRenderable(data, direction="sent")
        result = hd.build()
        assert "00000000" in result.plain
        assert "00000010" in result.plain

    def test_ascii_decode(self):
        data = b"Hello, World!\x00\x01\x02"
        hd = HexDumpRenderable(data, direction="sent")
        result = hd.build()
        # ASCII decode column should contain printable chars
        assert "Hello" in result.plain

    def test_empty_data(self):
        hd = HexDumpRenderable(b"", direction="sent")
        result = hd.build()
        assert isinstance(result, rich.text.Text)

    def test_recv_direction(self):
        data = b"\x00\x01\x02"
        hd = HexDumpRenderable(data, direction="recv")
        result = hd.build()
        assert isinstance(result, rich.text.Text)
        # recv direction: fixed 16 bpl, indented to right-align
        # against terminal edge, so first char is a space
        assert result.plain[0] == " "


# ── Test entry formatters ───────────────────────────────────────────


class TestEntryFormatters:
    def test_v0_test_entry(self, test_entry):
        result = _format_entry_v0(test_entry, 120)
        assert "Test 42" in result.plain
        assert "12B" in result.plain
        assert "4B" in result.plain

    def test_v0_crash_entry(self, crash_entry):
        result = _format_entry_v0(crash_entry, 120)
        assert "[FINDING]" in result.plain
        assert "crash" in result.plain.lower()

    def test_v0_recovery_entry(self, recovery_entry):
        result = _format_entry_v0(recovery_entry, 120)
        assert "recovered" in result.plain.lower()

    def test_v0_health_entry(self, health_entry):
        result = _format_entry_v0(health_entry, 120)
        assert "WARNING" in result.plain

    def test_v1_test_entry(self, test_entry):
        result = _format_entry_v1(test_entry, 120)
        assert "Test 42" in result.plain
        assert "->" in result.plain

    def test_v1_crash_renders_as_v0(self, crash_entry):
        """Non-test entries always render as v0 at all levels."""
        result = _format_entry_v1(crash_entry, 120)
        assert "[FINDING]" in result.plain

    def test_v2_test_entry(self, test_entry):
        result = _format_entry_v2(test_entry, 120)
        assert "Test 42" in result.plain
        assert "Offered" in result.plain
        assert "Recv" in result.plain

    def test_v3_test_entry_with_fields(self, test_entry):
        """v3 renders same as v2 (fields shown in header, not per-test)."""
        result = _format_entry_v3(test_entry, 120)
        assert "Test 42" in result.plain
        assert "Offered" in result.plain
        assert "Recv" in result.plain

    def test_v4_shows_conversation_log(self, test_entry):
        """v4 shows pre-test conversation exchanges."""
        test_entry.conversation_log = [
            ("->", "auth_probe", b"\x00\x04\x08\x10"),
            ("<-", "auth_probe", b"\x00\x04\x08\x20\x30"),
        ]
        result = _format_entry_v4(test_entry, 120)
        plain = result.plain
        assert "Test 42" in plain
        assert "auth_probe" in plain
        assert "Offered" in plain

    def test_v4_no_conversation_log(self, test_entry):
        """v4 without conversation log still renders the test packet."""
        test_entry.conversation_log = None
        result = _format_entry_v4(test_entry, 120)
        plain = result.plain
        assert "Test 42" in plain
        assert "Offered" in plain

    def test_v4_non_test_falls_back_to_v0(self):
        """v4 falls back to v0 for non-test entries."""
        entry = RingBufferEntry(
            timestamp=0.0,
            iteration=1,
            entry_type="crash",
            message="crash detected",
        )
        result = _format_entry_v4(entry, 120)
        assert "[FINDING]" in result.plain and "crash detected" in result.plain.lower()


class TestEstimateEntryRows:
    def test_v0_always_1(self, test_entry):
        assert _estimate_entry_rows(0, test_entry) == 1

    def test_v1_with_recv(self, test_entry):
        assert _estimate_entry_rows(1, test_entry) == 2

    def test_v1_without_recv(self, test_entry):
        test_entry.recv_bytes = None
        assert _estimate_entry_rows(1, test_entry) == 1

    def test_crash_always_1(self, crash_entry):
        for v in range(4):
            assert _estimate_entry_rows(v, crash_entry) == 1


class TestStyledHexSnippet:
    def test_short_data(self):
        result = _styled_hex_snippet(b"\x41\x42", 100)
        assert "4142" in result.plain

    def test_truncation(self):
        data = bytes(range(50))
        result = _styled_hex_snippet(data, 20)
        assert "..." in result.plain


# ── build_test_section ──────────────────────────────────────────────


class TestBuildTestSection:
    def test_empty_buffer(self, mock_state):
        result = build_test_section(mock_state, 20)
        assert "Waiting" in result.plain

    def test_with_entries(self, mock_state, test_entry):
        mock_state.recent_tests.append(test_entry)
        result = build_test_section(mock_state, 20)
        assert "Test 42" in result.plain

    def test_respects_available_rows(self, mock_state, test_entry):
        # Fill buffer with many entries
        for i in range(50):
            e = RingBufferEntry(
                timestamp=time.time(),
                iteration=i,
                entry_type="test",
                sent_len=10,
                recv_len=5,
            )
            mock_state.recent_tests.append(e)
        # At v0, each entry = 1 row. With 10 rows, should render ~10
        mock_state.verbosity_level = 0
        result = build_test_section(mock_state, 10)
        lines = [l for l in result.plain.split("\n") if l.strip()]
        assert len(lines) <= 10


# ── build_progress_bars ──────────────────────────────────────────────


class TestBuildProgressBars:
    def test_finite_progress(self, mock_state):
        result = build_progress_bars(mock_state)
        assert isinstance(result, rich.table.Table)

    def test_infinite_progress(self, mock_state):
        mock_state.total_iterations = None
        result = build_progress_bars(mock_state)
        assert isinstance(result, rich.table.Table)


# ── build_crash_table ────────────────────────────────────────────────


class TestBuildCrashTable:
    def test_empty_crashes(self):
        result = build_crash_table([])
        assert isinstance(result, rich.table.Table)

    def test_with_crashes(self):
        records = [
            {
                "iteration": 42,
                "timestamp": time.time(),
                "payload_hex": "deadbeef" * 10,
                "has_core": True,
                "crash_dir": "/artifacts/20260215_125728_iter_42_val_0x00_crash",
                "recovery_time_s": 12.3,
            },
            {
                "iteration": 99,
                "timestamp": time.time(),
                "payload_hex": "cafebabe",
                "has_core": False,
                "crash_dir": "",
                "recovery_time_s": 5.1,
            },
        ]
        result = build_crash_table(records)
        assert isinstance(result, rich.table.Table)
        assert result.row_count == 2


# ── build_dashboard / build_crash_screen ─────────────────────────────


class TestBuildDashboard:
    def test_returns_group(self, mock_state):
        result = build_dashboard(mock_state)
        assert isinstance(result, rich.console.Group)

    def test_renders_without_error(self, mock_state):
        """Full dashboard render should not raise."""
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(build_dashboard(mock_state))
        output = buf.getvalue()
        assert len(output) > 0


class TestBuildCrashScreen:
    def test_returns_group(self, mock_state):
        result = build_crash_screen(mock_state)
        assert isinstance(result, rich.console.Group)

    def test_no_crashes_message(self, mock_state):
        mock_state.crash_records = []
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(build_crash_screen(mock_state))
        output = buf.getvalue()
        assert "No crashes" in output

    def test_with_crash_records(self, mock_state):
        mock_state.crash_records = [
            {"iteration": 10, "timestamp": time.time(), "payload_hex": "aa", "has_core": False, "crash_dir": ""},
        ]
        result = build_crash_screen(mock_state)
        assert isinstance(result, rich.console.Group)


# ── Protocol diagram helpers ─────────────────────────────────────────


FRAMED_SCHEMA = {
    "fields": [
        {"name": "length", "size": 2},
        {"name": "kind", "size": 1},
        {"name": "ordinal", "size": 2},
        {"name": "marker", "size": 1},
        {"name": "mode", "size": 1},
        {"name": "payload", "size": "var"},
    ],
    "order": ["length", "kind", "ordinal", "marker", "mode", "payload"],
    "defaults": {
        "length": b"\x00\x07",
        "kind": b"\x5a",
        "ordinal": b"\x12\x34",
        "marker": b"\x7e",
        "mode": b"\xc0",
        "payload": b"\xd1\xd2",
    },
}

FRAMED_FIELD_BYTES = {
    "length": b"\x00\x08",
    "kind": b"\x5a",
    "ordinal": b"\x12\x34",
    "marker": b"\x7e",
    "mode": b"\xc0",
    "payload": b"\xd1\xd2\xd3",
}

TEXT_COMMAND_SCHEMA = {
    "fields": [
        {"name": "prefix", "size": "var", "default_len": 3},
        {"name": "content", "size": "var"},
        {"name": "suffix", "size": 1},
    ],
    "order": ["prefix", "content", "suffix"],
    "defaults": {
        "prefix": b"TAG",
        "content": b"",
        "suffix": b"\x00",
    },
}


class TestFieldDisplayWidth:
    def test_fixed_1byte(self):
        # 1-byte hex = "XX" (2 chars). Name "marker" = 6 chars. Result: 6 + 2 = 8
        assert _field_display_width("marker", 1, 1) == 8

    def test_fixed_2byte(self):
        # 2-byte hex = "XX XX" (5 chars). Name "length" = 6. Result: max(6, 5) + 2 = 8
        assert _field_display_width("length", 2, 2) == 8

    def test_var_with_data(self):
        # 3-byte data hex = "XX XX XX" (8 chars). Name "payload" = 7. Result: max(7, 8) + 2 = 10
        assert _field_display_width("payload", "var", 3) == 10

    def test_var_no_data(self):
        # No data: hex_w defaults to 3. Name "payload" = 7. Result: max(7, 3) + 2 = 9
        assert _field_display_width("payload", "var", 0) == 9


class TestHexSpaced:
    def test_basic(self):
        assert _hex_spaced(b"\xaa\xbb\xcc") == "aa bb cc"

    def test_empty(self):
        assert _hex_spaced(b"") == ""

    def test_single(self):
        assert _hex_spaced(b"\xff") == "ff"

    def test_truncation(self):
        result = _hex_spaced(b"\xaa\xbb\xcc\xdd\xee", max_width=8)
        # Should be truncated to fit within 8 chars with ".." suffix
        assert result.endswith("..")
        assert len(result) <= 10  # some slack for boundary rounding


class TestPartitionFieldsIntoRows:
    def _make_entry(self, name, size, data, is_var=False):
        dw = _field_display_width(name, size if not is_var else "var", len(data))
        return (name, size if not is_var else "var", data, is_var, dw)

    def test_all_fit_one_row(self):
        entries = [
            self._make_entry("marker", 1, b"\x10"),
            self._make_entry("mode", 1, b"\x00"),
            self._make_entry("payload", None, b"\xaa\xbb", is_var=True),
        ]
        rows = _partition_fields_into_rows(entries, term_width=120)
        assert len(rows) == 1
        assert len(rows[0]) == 3

    def test_wraps_on_narrow(self):
        entries = [
            self._make_entry("length", 2, b"\x00\x08"),
            self._make_entry("kind", 1, b"\x01"),
            self._make_entry("ordinal", 1, b"\x00"),
            self._make_entry("marker", 1, b"\x10"),
            self._make_entry("mode", 1, b"\x00"),
            self._make_entry("payload", None, b"\xaa\xbb", is_var=True),
        ]
        # Very narrow: should force wrapping
        rows = _partition_fields_into_rows(entries, term_width=25)
        assert len(rows) >= 2

    def test_single_field(self):
        entries = [
            self._make_entry("payload", None, b"\xaa", is_var=True),
        ]
        rows = _partition_fields_into_rows(entries, term_width=80)
        assert len(rows) == 1
        assert len(rows[0]) == 1

    def test_min_one_per_row(self):
        """Even if terminal is absurdly narrow, at least 1 field per row."""
        entries = [
            self._make_entry("length", 2, b"\x00\x08"),
            self._make_entry("payload", None, b"\xaa", is_var=True),
        ]
        rows = _partition_fields_into_rows(entries, term_width=5)
        assert len(rows) >= 1
        assert all(len(r) >= 1 for r in rows)


class TestBuildProtocolDiagram:
    def test_framed_schema(self):
        result = build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes=FRAMED_FIELD_BYTES,
            term_width=120,
        )
        assert isinstance(result, rich.console.Group)

    def test_no_schema_raw(self):
        """Without schema, falls back to raw field diagram."""
        result = build_protocol_diagram(
            schema=None,
            field_bytes={"prefix": b"\x4e\x4f", "payload": b"\x01\x02\x03"},
            term_width=80,
        )
        assert isinstance(result, rich.console.Group)

    def test_empty_field_bytes(self):
        result = build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes={},
            term_width=80,
        )
        assert isinstance(result, rich.console.Group)

    def test_fuzz_target_highlight(self):
        """Fuzz target field should render without error."""
        result = build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes=FRAMED_FIELD_BYTES,
            fuzz_target="marker",
            term_width=120,
        )
        assert isinstance(result, rich.console.Group)

    def test_narrow_terminal_wraps(self):
        """Very narrow terminal should still produce valid output."""
        result = build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes=FRAMED_FIELD_BYTES,
            term_width=30,
        )
        assert isinstance(result, rich.console.Group)

    def test_empty_fields_hidden(self):
        """Fields with empty data (b'') should be excluded from diagram."""
        from rich.console import Console
        from io import StringIO
        field_bytes = dict(FRAMED_FIELD_BYTES)
        field_bytes["mode"] = b""  # empty field
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes=field_bytes,
            term_width=120,
        ))
        output = buf.getvalue()
        assert "MODE" not in output
        assert "PAYLOAD" in output

    def test_empty_fuzz_target_still_shown(self):
        """A fuzz target with empty data should still appear (it's being fuzzed)."""
        from rich.console import Console
        from io import StringIO
        field_bytes = dict(FRAMED_FIELD_BYTES)
        field_bytes["marker"] = b""  # empty but being fuzzed
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes=field_bytes,
            fuzz_target="marker",
            term_width=120,
        ))
        output = buf.getvalue()
        assert "MARKER" in output  # still shown because it's the fuzz target

    def test_comma_separated_fuzz_targets(self):
        """Multi-field fuzz target (comma-separated) should highlight all."""
        result = build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes=FRAMED_FIELD_BYTES,
            fuzz_target="marker,mode",
            term_width=120,
        )
        assert isinstance(result, rich.console.Group)

    def test_renders_without_error(self):
        """Full render to string should not raise."""
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(build_protocol_diagram(
            schema=FRAMED_SCHEMA,
            field_bytes=FRAMED_FIELD_BYTES,
            fuzz_target="payload",
            term_width=120,
        ))
        output = buf.getvalue()
        assert "LENGTH" in output
        assert "PAYLOAD" in output


class TestBuildRawFieldDiagram:
    def test_with_data(self):
        result = _build_raw_field_diagram(
            field_bytes={"prefix": b"\x4e\x4f", "content": b"\x01"},
            fuzz_target="prefix",
            term_width=80,
        )
        assert isinstance(result, rich.console.Group)

    def test_empty(self):
        """Empty field_bytes should show 'No field data' message."""
        result = _build_raw_field_diagram(
            field_bytes={},
            fuzz_target=None,
            term_width=80,
        )
        assert isinstance(result, rich.console.Group)


class TestBuildProtocolScreen:
    """Protocol diagram is now embedded in the dashboard header.

    These tests verify it renders correctly via build_header instead
    of the removed build_protocol_screen function.
    """

    def test_header_with_schema(self, mock_state):
        mock_state.packet_schema = FRAMED_SCHEMA
        mock_state.current_field_bytes = FRAMED_FIELD_BYTES
        result = build_header(mock_state)
        assert isinstance(result, rich.console.Group)

    def test_header_no_schema(self, mock_state):
        mock_state.packet_schema = None
        result = build_header(mock_state)
        assert isinstance(result, rich.console.Group)

    def test_header_renders_field_labels(self, mock_state):
        mock_state.packet_schema = FRAMED_SCHEMA
        mock_state.current_field_bytes = FRAMED_FIELD_BYTES
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        with patch("shutil.get_terminal_size", return_value=os.terminal_size((120, 50))):
            console.print(build_header(mock_state))
        output = buf.getvalue()
        # Protocol diagram shows field names as column headers
        assert "LENGTH" in output
        assert "PAYLOAD" in output


class TestComputeFieldByteRanges:
    def test_all_fixed_fields(self):
        """Returns all field ranges for framed schema."""
        ranges = compute_field_byte_ranges(
            FRAMED_SCHEMA, FRAMED_FIELD_BYTES, 10,
        )
        # length(2) + kind(1) + ordinal(2) + marker(1) + mode(1) + payload(3) = 10
        names = [r[0] for r in ranges]
        assert "length" in names
        assert "marker" in names
        assert "payload" in names
        # Check specific offsets
        offsets = {r[0]: (r[1], r[2]) for r in ranges}
        assert offsets["length"] == (0, 2)
        assert offsets["marker"] == (5, 1)
        assert offsets["payload"] == (7, 3)

    def test_var_field_included(self):
        """Var-size fields are included in the result."""
        ranges = compute_field_byte_ranges(
            FRAMED_SCHEMA, FRAMED_FIELD_BYTES, 10,
        )
        payload_ranges = [(n, o, l) for n, o, l in ranges if n == "payload"]
        assert len(payload_ranges) == 1
        assert payload_ranges[0] == ("payload", 7, 3)

    def test_no_schema(self):
        assert compute_field_byte_ranges(None, {}, 10) == []

    def test_expanded_packet_adjusts_var_field(self):
        """When packet is bigger than schema fields, first var field expands."""
        # Neutral variable layout: prefix(var,3) + content(var,0) + suffix(1) = 4.
        fb = {"prefix": b"TAG", "content": b"", "suffix": b"\x00"}
        ranges = compute_field_byte_ranges(TEXT_COMMAND_SCHEMA, fb, 100)
        prefix_ranges = [(n, o, l) for n, o, l in ranges if n == "prefix"]
        assert prefix_ranges[0] == ("prefix", 0, 99)  # prefix absorbs 96 excess bytes

    def test_build_field_byte_styles(self):
        """build_field_byte_styles maps byte positions to FIELD_COLORS."""
        styles = build_field_byte_styles(FRAMED_SCHEMA, FRAMED_FIELD_BYTES, 10)
        assert isinstance(styles, dict)
        # Every byte should be mapped (10-byte packet, all fields have data)
        assert len(styles) == 10
        # Bytes in different fields should potentially have different styles
        # (length at pos 0 vs payload at pos 7)
        assert 0 in styles
        assert 7 in styles


class TestHexDumpByteStyles:
    def test_byte_styles_applied(self):
        """Custom byte styles should override default category coloring."""
        from rich.style import Style
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        custom = {2: Style(color="red"), 3: Style(color="red"), 4: Style(color="red")}
        hd = HexDumpRenderable(
            data, direction="sent", term_width=120,
            byte_styles=custom,
        )
        result = hd.build()
        assert isinstance(result, rich.text.Text)

    def test_no_byte_styles(self):
        """Without byte_styles, no crash."""
        data = b"\xaa\xbb\xcc"
        hd = HexDumpRenderable(data, direction="sent", term_width=80)
        result = hd.build()
        assert isinstance(result, rich.text.Text)

    def test_v3_with_schema_renders_field_colors(self):
        """V:3 renderer accepts schema and renders without error."""
        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=1,
            entry_type="test",
            sent_bytes=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            recv_bytes=b"\x10\x11",
            sent_len=10,
            recv_len=2,
            field_bytes=dict(FRAMED_FIELD_BYTES),
        )
        result = _format_entry_v3(entry, 120, schema=FRAMED_SCHEMA)
        assert isinstance(result, rich.text.Text)
        assert "Offered" in result.plain

    def test_v2_entry_renders_without_field_styles(self):
        """V:2 renders standard hexdump without field coloring."""
        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=1,
            entry_type="test",
            sent_bytes=b"\x00\x01\x02\x03\x04\x05\x06\x07",
            recv_bytes=b"\x10\x11",
            sent_len=8,
            recv_len=2,
        )
        result = _format_entry_v2(entry, 120)
        assert isinstance(result, rich.text.Text)


# ── Matrix rain ──────────────────────────────────────────────────────


class TestMatrixRain:
    """Tests for the matrix digital rain animation."""

    def test_horizontal_returns_text(self):
        """Horizontal rain returns a Rich Text object."""
        result = build_matrix_rain(width=80, height=2, orientation="horizontal")
        assert isinstance(result, rich.text.Text)

    def test_vertical_returns_text(self):
        """Vertical rain returns a Rich Text object."""
        result = build_matrix_rain(width=80, height=2, orientation="vertical")
        assert isinstance(result, rich.text.Text)

    def test_horizontal_exact_width(self):
        """Each row of horizontal rain is exactly *width* characters wide."""
        result = build_matrix_rain(width=60, height=2, orientation="horizontal")
        lines = result.plain.split("\n")
        assert len(lines) == 2
        for line in lines:
            assert len(line) == 60

    def test_vertical_exact_width(self):
        """Each row of vertical rain is exactly *width* characters wide."""
        result = build_matrix_rain(width=60, height=2, orientation="vertical")
        lines = result.plain.split("\n")
        assert len(lines) == 2
        for line in lines:
            assert len(line) == 60

    def test_single_row(self):
        """Height=1 produces exactly one line (no trailing newline)."""
        result = build_matrix_rain(width=40, height=1, orientation="horizontal")
        assert "\n" not in result.plain
        assert len(result.plain) == 40

    def test_deterministic_same_time(self):
        """Same seed + same time produces identical output."""
        with patch("bytefault.fuzzers.rich_renderables.time") as mock_time:
            mock_time.time.return_value = 1000.0
            mock_time.strftime = time.strftime
            mock_time.localtime = time.localtime
            r1 = build_matrix_rain(width=80, height=2, seed=99)

        with patch("bytefault.fuzzers.rich_renderables.time") as mock_time:
            mock_time.time.return_value = 1000.0
            mock_time.strftime = time.strftime
            mock_time.localtime = time.localtime
            r2 = build_matrix_rain(width=80, height=2, seed=99)

        assert r1.plain == r2.plain

    def test_animation_advances(self):
        """Different timestamps produce different output."""
        with patch("bytefault.fuzzers.rich_renderables.time") as mock_time:
            mock_time.time.return_value = 1000.0
            mock_time.strftime = time.strftime
            mock_time.localtime = time.localtime
            r1 = build_matrix_rain(width=80, height=2, seed=42)

        with patch("bytefault.fuzzers.rich_renderables.time") as mock_time:
            mock_time.time.return_value = 1005.0
            mock_time.strftime = time.strftime
            mock_time.localtime = time.localtime
            r2 = build_matrix_rain(width=80, height=2, seed=42)

        assert r1.plain != r2.plain

    def test_rain_chars_used(self):
        """Non-space characters are drawn from _RAIN_CHARS."""
        result = build_matrix_rain(width=200, height=2, density=0.3, seed=42)
        non_space = [c for c in result.plain if c not in (" ", "\n")]
        assert len(non_space) > 0
        for c in non_space:
            assert c in _RAIN_CHARS, f"Unexpected rain char: {c!r}"

    def test_rain_styles_applied(self):
        """Rain characters get styles from _RAIN_STYLES palette."""
        result = build_matrix_rain(width=200, height=2, density=0.3, seed=42)
        # Collect styles on non-space characters
        styled_spans = []
        for start, end, style in result._spans:
            text_slice = result.plain[start:end]
            if text_slice.strip():
                styled_spans.append(style)
        assert len(styled_spans) > 0
        for style in styled_spans:
            assert style in _RAIN_STYLES

    def test_dashboard_includes_rain(self, mock_state):
        """build_dashboard still returns a Group (regression guard)."""
        result = build_dashboard(mock_state)
        assert isinstance(result, rich.console.Group)


class TestAppendRainFill:
    """Tests for inline rain fill on entry formatter lines."""

    def test_fills_remaining_width(self):
        """Rain fills exactly (width - used_cols) characters."""
        text = rich.text.Text()
        _append_rain_fill(text, width=80, used_cols=20, row_id=1)
        assert len(text.plain) == 60

    def test_disabled_rain_keeps_spacing_without_animation(self):
        text = rich.text.Text()
        _append_rain_fill(text, width=80, used_cols=20, row_id=1, enabled=False)
        assert text.plain == " " * 60

    @pytest.mark.parametrize("formatter", [_format_entry_v2, _format_entry_v3, _format_entry_v4])
    def test_entry_rain_is_opt_in(self, formatter):
        entry = RingBufferEntry(timestamp=time.time(), iteration=1, entry_type="test",
                                sent_bytes=b"A", sent_len=1)
        plain = formatter(entry, 300)
        animated = formatter(entry, 300, rain_enabled=True)
        assert not any(span.style in _RAIN_STYLES for span in plain.spans)
        assert any(span.style in _RAIN_STYLES for span in animated.spans)

    def test_test_section_honors_rain_toggle(self):
        state = ViewState(verbosity_level=2, test_banner=False)
        state.recent_tests.append(RingBufferEntry(timestamp=time.time(), iteration=1,
                                                  entry_type="test", sent_bytes=b"A", sent_len=1))
        with patch("bytefault.ui.rich_renderables.shutil.get_terminal_size",
                   return_value=os.terminal_size((300, 24))):
            plain = build_test_section(state, 12)
            state.rain_enabled = True
            animated = build_test_section(state, 12)
        assert not any(span.style in _RAIN_STYLES for span in plain.spans)
        assert any(span.style in _RAIN_STYLES for span in animated.spans)

    def test_no_fill_when_full(self):
        """No characters appended when used_cols >= width."""
        text = rich.text.Text()
        _append_rain_fill(text, width=80, used_cols=80, row_id=1)
        assert text.plain == ""

    def test_no_fill_when_over(self):
        """No characters appended when used_cols > width."""
        text = rich.text.Text()
        _append_rain_fill(text, width=80, used_cols=100, row_id=1)
        assert text.plain == ""

    def test_chars_from_rain_set(self):
        """Non-space fill characters come from _RAIN_CHARS."""
        text = rich.text.Text()
        _append_rain_fill(text, width=200, used_cols=0, row_id=42)
        non_space = [c for c in text.plain if c != " "]
        assert len(non_space) > 0
        for c in non_space:
            assert c in _RAIN_CHARS

    def test_different_row_ids_differ(self):
        """Different row_ids produce different patterns at the same time."""
        with patch("bytefault.fuzzers.rich_renderables.time") as mock_time:
            mock_time.time.return_value = 1000.0
            mock_time.strftime = time.strftime
            mock_time.localtime = time.localtime
            t1 = rich.text.Text()
            _append_rain_fill(t1, width=80, used_cols=10, row_id=1)
            t2 = rich.text.Text()
            _append_rain_fill(t2, width=80, used_cols=10, row_id=2)
        assert t1.plain != t2.plain

    def test_v2_entry_has_rain_fill(self):
        """V:2 entries include rain fill on timestamp and sent lines."""
        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=1,
            entry_type="test",
            sent_bytes=b"\x00\x01\x02\x03",
            recv_bytes=b"\x10",
            sent_len=4,
            recv_len=1,
        )
        result = _format_entry_v2(entry, 120, rain_enabled=True)
        lines = result.plain.split("\n")
        # Timestamp line should be close to full width (rain fills it)
        assert len(lines[0]) >= 100

    def test_v3_entry_has_rain_fill(self):
        """V:3 entries include rain fill on timestamp and sent lines."""
        entry = RingBufferEntry(
            timestamp=time.time(),
            iteration=1,
            entry_type="test",
            sent_bytes=b"\x00\x01\x02\x03",
            recv_bytes=b"\x10",
            sent_len=4,
            recv_len=1,
        )
        result = _format_entry_v3(entry, 120, rain_enabled=True)
        lines = result.plain.split("\n")
        assert len(lines[0]) >= 100


# ── Help overlay ─────────────────────────────────────────────────────


class TestBuildHelpPanel:
    def test_returns_group(self):
        result = build_help_panel()
        assert isinstance(result, rich.console.Group)

    def test_contains_title(self):
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=100)
        console.print(build_help_panel())
        output = buf.getvalue()
        assert "BYTEFAULT HELP" in output

    def test_contains_key_bindings(self):
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=100)
        console.print(build_help_panel())
        output = buf.getvalue()
        assert "Pause" in output
        assert "Quit" in output
        assert "Cycle screens" in output
        assert "Verbosity" in output

    def test_contains_dismiss_hint(self):
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=100)
        console.print(build_help_panel())
        output = buf.getvalue()
        assert "to close" in output

    @patch("shutil.get_terminal_size", return_value=os.terminal_size((100, 24)))
    def test_wide_layout_two_columns(self, _mock):
        """Wide terminals (>= 60 cols) use a two-column table layout."""
        result = build_help_panel()
        # Group should contain header, table, footer
        renderables = list(result.renderables)
        assert len(renderables) == 3
        # Middle renderable should be a Table (two-column layout)
        assert isinstance(renderables[1], rich.table.Table)

    @patch("shutil.get_terminal_size", return_value=os.terminal_size((50, 24)))
    def test_narrow_layout_single_column(self, _mock):
        """Narrow terminals (< 60 cols) collapse to stacked single column."""
        result = build_help_panel()
        renderables = list(result.renderables)
        # Single-column layout: one Text object in the Group
        assert len(renderables) == 1
        assert isinstance(renderables[0], rich.text.Text)

    def test_contains_f2_f3_bindings(self):
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=100)
        console.print(build_help_panel())
        output = buf.getvalue()
        assert "F2" in output
        assert "F3" in output
        assert "Dashboard" in output
        assert "Findings" in output


class TestHelpOverlayIntegration:
    """Test that show_help=True replaces content in screen composers."""

    def test_dashboard_shows_help_when_toggled(self, mock_state):
        mock_state.show_help = True
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(build_dashboard(mock_state))
        output = buf.getvalue()
        assert "BYTEFAULT HELP" in output

    def test_dashboard_no_help_by_default(self, mock_state):
        mock_state.show_help = False
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(build_dashboard(mock_state))
        output = buf.getvalue()
        assert "BYTEFAULT HELP" not in output

    def test_crash_screen_shows_help_when_toggled(self, mock_state):
        mock_state.show_help = True
        result = build_crash_screen(mock_state)
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(result)
        output = buf.getvalue()
        assert "BYTEFAULT HELP" in output

    def test_crash_screen_no_help_by_default(self, mock_state):
        mock_state.show_help = False
        result = build_crash_screen(mock_state)
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(result)
        output = buf.getvalue()
        assert "BYTEFAULT HELP" not in output

    def test_menu_row_shows_help_hint(self, mock_state):
        result = build_menu_row(mock_state)
        assert "? Help" in result.plain


# ── Heartbeat cell ───────────────────────────────────────────────────


class TestHeartbeatCell:
    """Tests for the ICMP heartbeat header indicator (aesthetic slider)."""

    @pytest.mark.parametrize('verbosity', (0, 1, 2))
    def test_slider_advances_at_each_verbosity(self, mock_state, monkeypatch, verbosity):
        from bytefault.ui import rich_renderables as renderables
        mock_state.heartbeat_alive = True
        mock_state.verbosity_level = verbosity
        frames = []
        for position in range(3):
            now = (position + 0.25) * renderables._HB_PULSE_PERIOD / 3
            monkeypatch.setattr(renderables.time, 'monotonic', lambda: now)
            cell = renderables.build_heartbeat_cell(mock_state)
            frames.append(cell.plain)
            assert len(cell.plain) == 4 and cell.plain[position + 1] == '\u25b0'
            bright = next(span.style for span in cell.spans if span.start == position + 1)
            assert bright == renderables._heartbeat_green_style(1.0)
        assert len(set(frames)) == 3

    def test_unknown_state(self, mock_state):
        from bytefault.fuzzers.rich_renderables import build_heartbeat_cell
        mock_state.heartbeat_enabled = True
        mock_state.heartbeat_alive = None
        cell = build_heartbeat_cell(mock_state)
        assert "\u25b1" in cell.plain  # dim blocks when no result yet
        assert len(cell.plain) == 4

    def test_alive_v0_static(self, mock_state):
        from bytefault.fuzzers.rich_renderables import build_heartbeat_cell
        mock_state.heartbeat_enabled = True
        mock_state.heartbeat_alive = True
        mock_state.verbosity_level = 0
        cell = build_heartbeat_cell(mock_state)
        assert len(cell.plain) == 4
        # Should contain at least one filled block and one outline
        assert "\u25b0" in cell.plain or "\u25b1" in cell.plain

    def test_alive_v1_pulse(self, mock_state):
        from bytefault.fuzzers.rich_renderables import build_heartbeat_cell
        mock_state.heartbeat_enabled = True
        mock_state.heartbeat_alive = True
        mock_state.verbosity_level = 1
        cell = build_heartbeat_cell(mock_state)
        assert len(cell.plain) == 4
        # Alive: head + trail + dim background
        assert "\u25b0" in cell.plain

    def test_alive_v2_dot_only(self, mock_state):
        from bytefault.fuzzers.rich_renderables import build_heartbeat_cell
        mock_state.heartbeat_enabled = True
        mock_state.heartbeat_alive = True
        mock_state.verbosity_level = 2
        cell = build_heartbeat_cell(mock_state)
        assert len(cell.plain) == 4

    def test_dead_v0(self, mock_state):
        from bytefault.fuzzers.rich_renderables import build_heartbeat_cell
        mock_state.heartbeat_enabled = True
        mock_state.heartbeat_alive = False
        mock_state.verbosity_level = 0
        cell = build_heartbeat_cell(mock_state)
        assert cell.plain == " \u25b1\u25b1\u25b1"  # all dim blocks, red
        assert len(cell.plain) == 4

    def test_dead_v2_dot_only(self, mock_state):
        from bytefault.fuzzers.rich_renderables import build_heartbeat_cell
        mock_state.heartbeat_enabled = True
        mock_state.heartbeat_alive = False
        mock_state.verbosity_level = 2
        cell = build_heartbeat_cell(mock_state)
        assert cell.plain == " \u25b1\u25b1\u25b1"
        assert len(cell.plain) == 4

    def test_header_includes_heartbeat(self, mock_state):
        mock_state.heartbeat_enabled = True
        mock_state.heartbeat_alive = True
        result = build_header(mock_state)
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(result)
        output = buf.getvalue()
        # Aesthetic slider uses ▰ (filled) and ▱ (outline)
        assert "\u25b0" in output or "\u25b1" in output

    def test_header_no_heartbeat_when_disabled(self, mock_state):
        mock_state.heartbeat_enabled = False
        result = build_header(mock_state)
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        console.print(result)
        output = buf.getvalue()
        # Neither block character should appear when heartbeat is off
        assert "\u25b0" not in output
