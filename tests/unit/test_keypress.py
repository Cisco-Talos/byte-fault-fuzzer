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

"""Tests for KeypressReader daemon thread."""

from __future__ import annotations

import threading
import sys
from unittest.mock import MagicMock, patch

import pytest

from bytefault.fuzzers.keypress import SCREENS, KeypressReader


# ── Construction / defaults ─────────────────────────────────────────


class TestKeypressReaderDefaults:
    def test_initial_flags(self):
        kr = KeypressReader()
        assert kr.should_stop is False
        assert kr.paused is False
        assert kr.verbosity_level == 0
        assert kr.rain_enabled is False
        assert kr.active_screen == "dashboard"
        assert kr.show_help is False

    def test_screens_order(self):
        assert SCREENS == ("dashboard", "crashes", "log")


# ── _handle_char tests (no threading needed) ────────────────────────


class TestHandleChar:
    @pytest.fixture
    def kr(self):
        return KeypressReader()

    # Q → should_stop
    @pytest.mark.parametrize("ch", ["q", "Q"])
    def test_quit(self, kr, ch):
        kr._handle_char(ch)
        assert kr.should_stop is True

    # Space → toggle paused
    def test_pause_toggle(self, kr):
        assert kr.paused is False
        kr._handle_char(" ")
        assert kr.paused is True
        kr._handle_char(" ")
        assert kr.paused is False

    # v -> increment verbosity (clamp 0-4)
    def test_verbosity_increment(self, kr):
        assert kr.verbosity_level == 0
        kr._handle_char("v")
        assert kr.verbosity_level == 1
        kr._handle_char("v")
        assert kr.verbosity_level == 2
        kr._handle_char("v")
        assert kr.verbosity_level == 3
        kr._handle_char("v")
        assert kr.verbosity_level == 4
        kr._handle_char("v")
        assert kr.verbosity_level == 4  # clamped

    # V (Shift-V) -> decrement verbosity (clamp 0-4)
    def test_verbosity_decrement(self, kr):
        kr.verbosity_level = 4
        kr._handle_char("V")
        assert kr.verbosity_level == 3
        kr._handle_char("V")
        assert kr.verbosity_level == 2
        kr._handle_char("V")
        assert kr.verbosity_level == 1
        kr._handle_char("V")
        assert kr.verbosity_level == 0
        kr._handle_char("V")
        assert kr.verbosity_level == 0  # clamped

    def test_digital_rain_toggle(self, kr):
        kr._handle_char("m")
        assert kr.rain_enabled is True
        kr._handle_char("m")
        assert kr.rain_enabled is False

    # < / , -> cycle screen left
    @pytest.mark.parametrize("ch", ["<", ","])
    def test_cycle_left(self, kr, ch):
        assert kr.active_screen == "dashboard"
        kr._handle_char(ch)
        assert kr.active_screen == "log"  # wraps to last
        kr._handle_char(ch)
        assert kr.active_screen == "crashes"
        kr._handle_char(ch)
        assert kr.active_screen == "dashboard"

    # > / . -> cycle screen right
    @pytest.mark.parametrize("ch", [">", "."])
    def test_cycle_right(self, kr, ch):
        assert kr.active_screen == "dashboard"
        kr._handle_char(ch)
        assert kr.active_screen == "crashes"
        kr._handle_char(ch)
        assert kr.active_screen == "log"
        kr._handle_char(ch)
        assert kr.active_screen == "dashboard"  # wraps

    def test_unknown_char_ignored(self, kr):
        """Unknown characters should not raise or change state."""
        kr._handle_char("x")
        assert kr.should_stop is False
        assert kr.paused is False
        assert kr.verbosity_level == 0

    # ? → toggle help overlay
    def test_help_toggle(self, kr):
        assert kr.show_help is False
        kr._handle_char("?")
        assert kr.show_help is True
        kr._handle_char("?")
        assert kr.show_help is False


# ── Scan-code tests (Windows function keys) ────────────────────────


@pytest.mark.parametrize('navigation', ('scan', 'ss3', 'csi', 'cycle'))
def test_controls_only_ignores_display_modes_and_keeps_quit_pause(navigation):
    reader = KeypressReader(controls_only=True)
    if navigation == 'scan':
        reader._handle_scan_code(chr(0x3E))
    elif navigation == 'ss3':
        reader._handle_escape_O('S')
    elif navigation == 'csi':
        reader._dispatch_csi('14~')
    else:
        reader._handle_char('<')
    for character in '/tmv?':
        reader._handle_char(character)
    reader._handle_char(' ')
    assert reader.paused
    reader._handle_char(' ')
    assert not reader.paused
    reader._handle_char('q')
    assert reader.should_stop and reader.active_screen == 'dashboard'
    assert not reader.show_help and not reader.rain_enabled and reader.verbosity_level == 0
    assert reader.consume_theme_signal() == 0
    signals = reader.consume_log_signals()
    assert not signals['search_start'] and signals['search_chars'] == []


def test_default_reader_retains_search_input_semantics():
    reader = KeypressReader()
    reader._handle_scan_code(chr(0x3E))
    for character in '/q ':
        reader._handle_char(character)
    assert not reader.should_stop and not reader.paused
    assert reader.consume_log_signals()['search_chars'] == ['q', ' ']
    reader._handle_char('\x1b')
    reader._handle_char('q')
    assert reader.should_stop


class TestHandleScanCode:
    @pytest.fixture
    def kr(self):
        return KeypressReader()

    def test_f2_scan_code(self, kr):
        # Set to crashes first so we can verify F2 switches to dashboard
        kr._handle_char(">")  # move to crashes
        assert kr.active_screen == "crashes"
        kr._handle_scan_code(chr(0x3C))  # F2
        assert kr.active_screen == "dashboard"

    def test_f3_scan_code(self, kr):
        kr._handle_scan_code(chr(0x3D))  # F3
        assert kr.active_screen == "crashes"

    def test_unknown_scan_code_ignored(self, kr):
        kr._handle_scan_code(chr(0x44))  # F10 — not handled
        assert kr.active_screen == "dashboard"


# ── Escape sequence tests (Unix function keys) ─────────────────────


class TestHandleEscapeO:
    @pytest.fixture
    def kr(self):
        return KeypressReader()

    def test_f2_escape(self, kr):
        kr._handle_char(">")
        assert kr.active_screen == "crashes"
        kr._handle_escape_O("Q")  # \x1bOQ = F2
        assert kr.active_screen == "dashboard"

    def test_f3_escape(self, kr):
        kr._handle_escape_O("R")  # \x1bOR = F3
        assert kr.active_screen == "crashes"

    def test_unknown_escape_O_ignored(self, kr):
        kr._handle_escape_O("P")  # F1 — not handled
        assert kr.active_screen == "dashboard"


class TestHandleEscapeBracket:
    @pytest.fixture
    def kr(self):
        kr = KeypressReader()
        return kr

    def test_f2_bracket(self, kr):
        """\\x1b[12~ = F2 on some terminals."""
        kr._handle_char(">")
        assert kr.active_screen == "crashes"
        # Simulate: first char '1', then os.read yields '2', '~'
        with patch("os.read", side_effect=[b"2", b"~"]), \
             patch("select.select", return_value=([True], [], [])):
            kr._handle_escape_bracket("1", fd=0)
        assert kr.active_screen == "dashboard"

    def test_f3_bracket(self, kr):
        """\\x1b[13~ = F3 on some terminals."""
        with patch("os.read", side_effect=[b"3", b"~"]), \
             patch("select.select", return_value=([True], [], [])):
            kr._handle_escape_bracket("1", fd=0)
        assert kr.active_screen == "crashes"



# ── Shared CSI dispatch tests ──────────────────────────────────────


class TestDispatchCSI:
    """Tests for _dispatch_csi shared by Unix and Windows paths."""

    @pytest.fixture
    def kr(self):
        return KeypressReader()

    def test_f2_csi(self, kr):
        kr._handle_char(">")
        assert kr.active_screen == "crashes"
        kr._dispatch_csi("12~")
        assert kr.active_screen == "dashboard"

    def test_f3_csi(self, kr):
        kr._dispatch_csi("13~")
        assert kr.active_screen == "crashes"

    def test_unknown_csi_ignored(self, kr):
        kr._dispatch_csi("15~")  # F5 — not handled
        assert kr.active_screen == "dashboard"


# ── Windows VT escape sequence tests ───────────────────────────────


@pytest.mark.skipif(sys.platform != "win32", reason="msvcrt is available only on Windows")
class TestReadVtEscapeWin:
    """Test VT escape sequences on Windows (ConPTY / Windows Terminal).

    These tests verify that F-keys delivered as VT sequences
    (e.g. \\x1bOQ for F2) are correctly parsed instead of having
    their trailing bytes mis-interpreted as regular characters.
    """

    @pytest.fixture
    def kr(self):
        return KeypressReader()

    def test_f2_vt_esc_O_Q(self, kr):
        """\\x1bOQ should set active_screen to 'dashboard', not trigger quit."""
        kr._handle_char(">")
        assert kr.active_screen == "crashes"
        # Simulate: after \x1b, msvcrt.getwch() yields 'O', then 'Q'
        with patch("msvcrt.kbhit", return_value=True), \
             patch("msvcrt.getwch", side_effect=["O", "Q"]):
            kr._read_vt_escape_win()
        assert kr.active_screen == "dashboard"
        assert kr.should_stop is False  # must NOT have quit

    def test_f3_vt_esc_O_R(self, kr):
        """\\x1bOR should set active_screen to 'crashes'."""
        with patch("msvcrt.kbhit", return_value=True), \
             patch("msvcrt.getwch", side_effect=["O", "R"]):
            kr._read_vt_escape_win()
        assert kr.active_screen == "crashes"

    def test_f2_vt_csi_bracket(self, kr):
        """\\x1b[12~ should set active_screen to 'dashboard'."""
        kr._handle_char(">")
        assert kr.active_screen == "crashes"
        with patch("msvcrt.kbhit", return_value=True), \
             patch("msvcrt.getwch", side_effect=["[", "1", "2", "~"]):
            kr._read_vt_escape_win()
        assert kr.active_screen == "dashboard"

    def test_f3_vt_csi_bracket(self, kr):
        """\\x1b[13~ should set active_screen to 'crashes'."""
        with patch("msvcrt.kbhit", return_value=True), \
             patch("msvcrt.getwch", side_effect=["[", "1", "3", "~"]):
            kr._read_vt_escape_win()
        assert kr.active_screen == "crashes"

    def test_lone_escape_ignored(self, kr):
        """\\x1b with no follow-up should be ignored (lone Escape)."""
        with patch("msvcrt.kbhit", return_value=False):
            kr._read_vt_escape_win()
        assert kr.active_screen == "dashboard"
        assert kr.should_stop is False

    def test_unknown_esc_O_ignored(self, kr):
        """\\x1bOP (F1) should not change state."""
        with patch("msvcrt.kbhit", return_value=True), \
             patch("msvcrt.getwch", side_effect=["O", "P"]):
            kr._read_vt_escape_win()
        assert kr.active_screen == "dashboard"

    def test_f2_does_not_trigger_quit(self, kr):
        """Regression: \\x1bOQ must NOT set should_stop (the 'Q' trap)."""
        with patch("msvcrt.kbhit", return_value=True), \
             patch("msvcrt.getwch", side_effect=["O", "Q"]):
            kr._read_vt_escape_win()
        assert kr.should_stop is False


# ── Thread lifecycle tests ──────────────────────────────────────────


class TestLifecycle:
    def test_start_creates_daemon_thread(self):
        kr = KeypressReader()
        # Mock the _run method to avoid actual stdin reads
        kr._run = MagicMock()
        kr.start()
        try:
            assert kr._thread is not None
            assert kr._thread.daemon is True
            assert kr._thread.name == "keypress-reader"
            kr._thread.join(timeout=1.0)
        finally:
            kr.stop()

    def test_start_is_idempotent(self):
        kr = KeypressReader()
        kr._run = MagicMock()
        kr.start()
        first_thread = kr._thread
        kr.start()  # second call should be no-op
        assert kr._thread is first_thread
        kr.stop()

    def test_stop_clears_thread(self):
        kr = KeypressReader()
        kr._run = MagicMock()
        kr.start()
        kr._thread.join(timeout=1.0)
        kr.stop()
        assert kr._thread is None
        assert kr._running is False


# ── Thread-safety tests ────────────────────────────────────────────


class TestThreadSafety:
    def test_concurrent_flag_access(self):
        """Multiple threads reading/writing flags should not corrupt state."""
        kr = KeypressReader()
        errors = []

        def writer():
            try:
                for _ in range(100):
                    kr._handle_char("v")
                    kr._handle_char("V")
                    kr._handle_char(" ")
                    kr._handle_char(" ")
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(100):
                    _ = kr.should_stop
                    _ = kr.paused
                    _ = kr.verbosity_level
                    _ = kr.active_screen
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        assert errors == []
        # After 200 v + 200 V toggles, verbosity should be back near
        # starting point (but exact value depends on interleaving)
        assert 0 <= kr.verbosity_level <= 3


# ── Verbosity setter clamp ──────────────────────────────────────────


class TestVerbositySetter:
    def test_clamp_high(self):
        kr = KeypressReader()
        kr.verbosity_level = 10
        assert kr.verbosity_level == 4

    def test_clamp_low(self):
        kr = KeypressReader()
        kr.verbosity_level = -5
        assert kr.verbosity_level == 0

    def test_normal_set(self):
        kr = KeypressReader()
        kr.verbosity_level = 2
        assert kr.verbosity_level == 2
