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

"""Keypress daemon thread for interactive Rich UI controls.

Reads keypresses in a background daemon thread and sets shared flags
that the main fuzzer loop polls via ``_check_flags()``.

Platform support:
- Windows: ``msvcrt.getwch()``
- Linux/macOS: ``tty``/``termios``/``sys.stdin.read(1)``

Thread safety: the daemon thread only *writes* flags (under a lock),
the main thread only *reads* them.
"""

from __future__ import annotations

import atexit
import logging
import os
import sys
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# Screen names in cycle order
SCREENS = ("dashboard", "crashes", "log")


class KeypressReader:
    """Background daemon that translates keypresses into shared flags.

    Supported keys::

        Q           -> should_stop = True
        Space       -> toggle paused
        V / v       -> increment verbosity_level (clamp 0-4)
        Shift-V (V) -> decrement verbosity_level (clamp 0-4)
        t           -> cycle color theme forward
        m           -> toggle digital rain
        F2          -> active_screen = "dashboard"
        F3          -> active_screen = "crashes"
        F4          -> active_screen = "log"
        < / ,       -> cycle active_screen left (wraps)
        > / .       -> cycle active_screen right (wraps)
        ?           -> toggle help overlay

    Log screen keys::
        Up/Down     -> scroll log by 1 line
        PgUp/PgDn   -> scroll log by page
        Home/End    -> jump to top/bottom of log
        /           -> begin search input
        n           -> next search match
        N / p       -> previous search match
        Esc         -> cancel search input

    Note on V/Shift-V: on most terminals, lowercase ``v`` and uppercase
    ``V`` are distinguishable.  We map lowercase ``v`` to increment and
    uppercase ``V`` (Shift-V) to decrement.
    """

    def __init__(self, *, controls_only: bool = False) -> None:
        self._lock = threading.Lock()
        self._controls_only = controls_only
        self._should_stop = False
        self._paused = False
        self._verbosity_level = 0
        self._rain_enabled = False
        self._active_screen = "dashboard"
        self._show_help = False
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # Terminal settings saved before cbreak, restored on stop()
        self._orig_termios = None
        self._termios_fd: Optional[int] = None
        self._atexit_registered = False
        # Log viewer navigation signals (consumed and cleared by render)
        self._log_scroll_delta = 0       # +N = down, -N = up
        self._log_jump = ""              # "home" | "end" | ""
        self._log_search_start = False   # True = user pressed /
        self._log_search_chars = []      # accumulated chars typed during search
        self._log_search_submit = False  # True = user pressed Enter
        self._log_search_cancel = False  # True = user pressed Esc
        self._log_search_next = 0        # +1 = n, -1 = N
        self._log_detail_toggle = False  # d = inspect/back from exact record
        # Theme cycling signal
        self._theme_cycle = 0            # +1 = next, -1 = prev

    # ── Public property accessors (main thread reads) ───────────────

    @property
    def should_stop(self) -> bool:
        with self._lock:
            return self._should_stop

    @property
    def paused(self) -> bool:
        with self._lock:
            return self._paused

    @property
    def verbosity_level(self) -> int:
        with self._lock:
            return self._verbosity_level

    @verbosity_level.setter
    def verbosity_level(self, value: int) -> None:
        with self._lock:
            self._verbosity_level = max(0, min(4, value))

    @property
    def rain_enabled(self) -> bool:
        with self._lock:
            return self._rain_enabled

    @rain_enabled.setter
    def rain_enabled(self, value: bool) -> None:
        with self._lock:
            self._rain_enabled = bool(value)

    @property
    def active_screen(self) -> str:
        with self._lock:
            return self._active_screen

    @property
    def show_help(self) -> bool:
        with self._lock:
            return self._show_help

    def consume_theme_signal(self) -> int:
        """Consume and reset the theme-cycle signal.

        Returns +1 (next), -1 (previous), or 0 (no change).
        """
        with self._lock:
            val = self._theme_cycle
            self._theme_cycle = 0
            return val

    def consume_log_signals(self) -> dict:
        """Consume and reset all log viewer navigation signals.

        Returns a dict with keys: scroll_delta, jump, search_start,
        search_char, search_submit, search_cancel, search_next.
        Called by the render loop so that signals are consumed exactly
        once per frame.
        """
        with self._lock:
            signals = {
                "scroll_delta": self._log_scroll_delta,
                "jump": self._log_jump,
                "search_start": self._log_search_start,
                "search_chars": list(self._log_search_chars),
                "search_submit": self._log_search_submit,
                "search_cancel": self._log_search_cancel,
                "search_next": self._log_search_next,
                "detail_toggle": self._log_detail_toggle,
            }
            self._log_scroll_delta = 0
            self._log_jump = ""
            self._log_search_start = False
            self._log_search_chars = []
            self._log_search_submit = False
            self._log_search_cancel = False
            self._log_search_next = 0
            self._log_detail_toggle = False
            return signals

    # ── Lifecycle ───────────────────────────────────────────────────

    def start(self) -> None:
        """Start the daemon keypress-reading thread."""
        if self._thread is not None:
            return
        # Save terminal settings from the main thread BEFORE the daemon
        # switches to cbreak.  Daemon threads don't get their finally
        # blocks executed on process exit, so the main thread must own
        # the restore.
        if os.name != "nt":
            try:
                import termios
                fd = sys.stdin.fileno()
                self._orig_termios = termios.tcgetattr(fd)
                self._termios_fd = fd
            except Exception:
                pass
            if not self._atexit_registered:
                atexit.register(self._restore_terminal)
                self._atexit_registered = True
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name="keypress-reader",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the daemon to stop and restore terminal settings."""
        self._running = False
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=0.3)
        if thread is None or not thread.is_alive():
            self._thread = None
        self._restore_terminal()

    def _restore_terminal(self) -> None:
        """Restore terminal settings saved before cbreak mode."""
        if self._orig_termios is not None and self._termios_fd is not None:
            try:
                import termios
                termios.tcsetattr(
                    self._termios_fd, termios.TCSADRAIN, self._orig_termios,
                )
            except Exception:
                pass
            self._orig_termios = None

    # ── Internal reader loop ────────────────────────────────────────

    def _run(self) -> None:
        """Main loop — blocks on single-char reads until stopped."""
        try:
            if os.name == "nt":
                self._run_windows()
            else:
                self._run_unix()
        except Exception:
            logger.debug("Keypress reader exiting", exc_info=True)

    def _run_windows(self) -> None:
        """Windows keypress reader using ``msvcrt``."""
        import msvcrt

        while self._running:
            try:
                # Poll before reading so stop owns actual thread disposal even
                # when the operator supplies no final key.
                if not self._kbhit_wait(0.05):
                    continue
                ch = msvcrt.getwch()

                # Function keys on Windows: getwch returns '\x00' or '\xe0'
                # followed by a scan-code character
                if ch in ("\x00", "\xe0"):
                    # getwch has already consumed the first half of one native
                    # key event; its scan byte is pending even when kbhit does
                    # not report a *new* event.
                    scan = msvcrt.getwch()
                    self._handle_scan_code(scan)
                    continue

                # VT escape sequences (ConPTY / Windows Terminal / VS Code).
                # Modern terminals deliver F-keys as VT sequences like
                # \x1bOQ (F2) and \x1bOR (F3).  Without this handler the
                # trailing 'Q' of \x1bOQ is mis-parsed as the quit key.
                if ch == "\x1b":
                    self._read_vt_escape_win()
                    continue

                self._handle_char(ch)
            except Exception:
                if not self._running:
                    break
                logger.debug("Keypress read error", exc_info=True)

    def _read_vt_escape_win(self) -> None:
        """Parse a VT escape sequence using msvcrt on Windows.

        Reads remaining bytes of an escape sequence after the leading
        ``\x1b`` has already been consumed.  Uses ``msvcrt.kbhit()``
        with a short timeout to avoid blocking if no further input
        arrives (lone Escape key).
        """
        import msvcrt

        if not self._kbhit_wait(0.05):
            # Lone Escape -- route through _handle_char so it can
            # cancel log search mode (among other things).
            self._handle_char("\x1b")
            return

        seq = msvcrt.getwch()

        if seq == "O":
            # \x1bO* — F1-F4 on many terminals
            if not self._kbhit_wait(0.05):
                return
            code = msvcrt.getwch()
            self._handle_escape_O(code)
        elif seq == "[":
            # CSI: \x1b[...  Read digits + tilde.
            if not self._kbhit_wait(0.05):
                return
            buf = msvcrt.getwch()
            while buf and not buf.endswith("~") and len(buf) < 10:
                if not self._kbhit_wait(0.05):
                    break
                buf += msvcrt.getwch()
            self._dispatch_csi(buf)
        # else: unknown sequence — discard

    @staticmethod
    def _kbhit_wait(timeout: float) -> bool:
        """Wait up to *timeout* seconds for a key in the console buffer."""
        import msvcrt
        import time

        deadline = time.monotonic() + timeout
        while not msvcrt.kbhit():
            if time.monotonic() > deadline:
                return False
            time.sleep(0.002)
        return True

    @staticmethod
    def _read1(fd: int) -> str:
        """Read exactly one byte from *fd* using unbuffered ``os.read``.

        ``sys.stdin.read(1)`` must NEVER be used alongside
        ``select(fd)`` because Python's buffered IO layer may
        consume additional bytes from the fd into its internal buffer,
        causing subsequent ``select()`` calls to report "no data" even
        though the bytes are available (just trapped in the buffer).
        """
        raw = os.read(fd, 1)
        return raw.decode("utf-8", errors="replace") if raw else ""

    def _run_unix(self) -> None:
        """Unix keypress reader using ``tty``/``termios``."""
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        # Terminal settings are saved by start() on the main thread.
        # Keep a local copy for the daemon's own finally as a best-effort.
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd, termios.TCSANOW)
            while self._running:
                # Use select with a short timeout so we can check
                # self._running periodically and not block forever.
                ready, _, _ = select.select([fd], [], [], 0.1)
                if not ready:
                    continue
                ch = self._read1(fd)
                if not ch:
                    break

                # Escape sequences (function keys)
                if ch == "\x1b":
                    # Check if more bytes follow quickly (escape sequence).
                    # If nothing arrives within 50ms, treat as lone Escape.
                    r2, _, _ = select.select([fd], [], [], 0.05)
                    if not r2:
                        # Lone Escape -- route through _handle_char so it
                        # can cancel log search mode.
                        self._handle_char("\x1b")
                        continue
                    seq = self._read1(fd)
                    if seq == "O":
                        r3, _, _ = select.select([fd], [], [], 0.05)
                        if r3:
                            code = self._read1(fd)
                            self._handle_escape_O(code)
                    elif seq == "[":
                        r3, _, _ = select.select([fd], [], [], 0.05)
                        if r3:
                            code = self._read1(fd)
                            self._handle_escape_bracket(code, fd)
                    continue

                self._handle_char(ch)
        except Exception:
            if self._running:
                logger.debug("Keypress read error", exc_info=True)
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    # ── Key dispatch ────────────────────────────────────────────────

    def _handle_char(self, ch: str) -> None:
        """Handle a single printable/control character."""
        if self._controls_only and ch not in ('q', 'Q', ' '):
            return
        with self._lock:
            on_log = not self._controls_only and self._active_screen == "log"
            searching = getattr(self, '_log_searching', False)

        # When search input is active, capture all printable chars
        if on_log and searching:
            if ch == "\r" or ch == "\n":
                with self._lock:
                    self._log_search_submit = True
                    self._log_searching = False
            elif ch == "\x1b":
                with self._lock:
                    self._log_search_cancel = True
                    self._log_searching = False
            elif ch == "\x7f" or ch == "\x08":
                # Backspace
                with self._lock:
                    self._log_search_chars.append("\x08")
            else:
                with self._lock:
                    self._log_search_chars.append(ch)
            return

        if ch in ("q", "Q"):
            with self._lock:
                self._should_stop = True
        elif ch == " ":
            with self._lock:
                self._paused = not self._paused
        elif ch == "v":
            # Lowercase v -> increment verbosity
            with self._lock:
                self._verbosity_level = min(4, self._verbosity_level + 1)
        elif ch == "V":
            # Uppercase V (Shift-V) -> decrement verbosity
            with self._lock:
                self._verbosity_level = max(0, self._verbosity_level - 1)
        elif ch == "t":
            # Cycle color theme forward
            with self._lock:
                self._theme_cycle = 1
        elif ch == "m":
            with self._lock:
                self._rain_enabled = not self._rain_enabled
        elif ch == "?":
            with self._lock:
                self._show_help = not self._show_help
        elif ch == "\x1b":
            with self._lock:
                if self._show_help:
                    self._show_help = False
                elif on_log:
                    self._log_search_cancel = True
        elif ch in ("<", ","):
            self._cycle_screen(-1)
        elif ch in (">", "."):
            self._cycle_screen(1)
        elif ch == "/" and on_log:
            with self._lock:
                self._log_search_start = True
                self._log_searching = True
        elif ch == "n" and on_log:
            with self._lock:
                self._log_search_next = 1
        elif ch in ("N", "p", "P") and on_log:
            with self._lock:
                self._log_search_next = -1
        elif ch == "d" and on_log:
            with self._lock:
                self._log_detail_toggle = True

    def _handle_scan_code(self, scan: str) -> None:
        """Handle Windows function-key scan codes.

        F2 = 0x3C, F3 = 0x3D, F4 = 0x3E.
        PgUp = 0x49, PgDn = 0x51, Up = 0x48, Down = 0x50.
        Home = 0x47, End = 0x4F.
        """
        if self._controls_only:
            return
        code = ord(scan)
        if code == 0x3C:  # F2
            with self._lock:
                self._active_screen = "dashboard"
        elif code == 0x3D:  # F3
            with self._lock:
                self._active_screen = "crashes"
        elif code == 0x3E:  # F4
            with self._lock:
                self._active_screen = "log"
        elif code == 0x48:  # Up
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta -= 1
        elif code == 0x50:  # Down
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta += 1
        elif code == 0x49:  # PgUp
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta -= 30
        elif code == 0x51:  # PgDn
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta += 30
        elif code == 0x47:  # Home
            with self._lock:
                if self._active_screen == "log":
                    self._log_jump = "home"
        elif code == 0x4F:  # End
            with self._lock:
                if self._active_screen == "log":
                    self._log_jump = "end"

    def _handle_escape_O(self, code: str) -> None:
        """Handle \\x1bO* escape sequences (F1-F4 on many terminals)."""
        if self._controls_only:
            return
        if code == "Q":  # F2
            with self._lock:
                self._active_screen = "dashboard"
        elif code == "R":  # F3
            with self._lock:
                self._active_screen = "crashes"
        elif code == "S":  # F4
            with self._lock:
                self._active_screen = "log"

    def _handle_escape_bracket(self, code: str, fd: int) -> None:
        """Handle \\x1b[* CSI escape sequences.

        Reads remaining chars for multi-char codes like ``\\x1b[12~``.
        Uses *fd* with ``select`` to avoid blocking on missing bytes.
        """
        import select

        # Accumulate digits and tilde for extended codes
        buf = code
        while buf and not buf.endswith("~"):
            if len(buf) > 10:
                break
            try:
                ready, _, _ = select.select([fd], [], [], 0.05)
                if not ready:
                    break
                next_ch = self._read1(fd)
                if not next_ch:
                    break
                buf += next_ch
            except Exception:
                break

        self._dispatch_csi(buf)

    def _dispatch_csi(self, buf: str) -> None:
        """Dispatch a CSI payload (after ``\\x1b[``).  Shared by both
        Unix (``_handle_escape_bracket``) and Windows
        (``_read_vt_escape_win``) paths.
        """
        if self._controls_only:
            return
        # \x1b[12~ = F2 on some terminals
        # \x1b[13~ = F3 on some terminals
        # \x1b[14~ = F4 on some terminals
        if buf == "12~":
            with self._lock:
                self._active_screen = "dashboard"
        elif buf == "13~":
            with self._lock:
                self._active_screen = "crashes"
        elif buf == "14~":
            with self._lock:
                self._active_screen = "log"
        # Arrow keys: \x1b[A=Up, \x1b[B=Down
        elif buf == "A":
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta -= 1
        elif buf == "B":
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta += 1
        # Page keys: \x1b[5~ = PgUp, \x1b[6~ = PgDn
        elif buf == "5~":
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta -= 30
        elif buf == "6~":
            with self._lock:
                if self._active_screen == "log":
                    self._log_scroll_delta += 30
        # Home/End: \x1b[H or \x1b[1~ = Home, \x1b[F or \x1b[4~ = End
        elif buf in ("H", "1~"):
            with self._lock:
                if self._active_screen == "log":
                    self._log_jump = "home"
        elif buf in ("F", "4~"):
            with self._lock:
                if self._active_screen == "log":
                    self._log_jump = "end"

    def _cycle_screen(self, direction: int) -> None:
        """Cycle active screen left (-1) or right (+1), wrapping."""
        if self._controls_only:
            return
        with self._lock:
            try:
                idx = SCREENS.index(self._active_screen)
            except ValueError:
                idx = 0
            idx = (idx + direction) % len(SCREENS)
            self._active_screen = SCREENS[idx]
