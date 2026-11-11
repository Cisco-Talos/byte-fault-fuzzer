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

"""Fuzz event listener interface and plain-text implementation.

The ``FuzzEventListener`` base class defines the observer interface that
``ProtocolFuzzer`` emits events to during fuzzing.  All methods have
empty default implementations so listeners can subscribe selectively.

``PlainTextListener`` replicates the current (pre-Rich) stdout behavior:
progress line, test banners, and session-complete summary.
"""

from __future__ import annotations

import logging
import shutil
import sys
import time
from collections import deque
from typing import Dict, List, Optional, Tuple

from bytefault.fuzzers.event_listener import FuzzEventListener

logger = logging.getLogger(__name__)


class ApplicationPlainClient:
    """Plain presentation of the same application records used by Rich."""
    def __init__(self,view,*,stream=None,output_formatter=None):
        self.view,self.stream=view,stream or sys.stderr
        self.output_formatter=output_formatter
        self._seen_actions=set()
        self._recent_actions=deque()
        self._last_reports={}
        self._last_progress=None
        self._progress_at=0
        self._last_summary=None
        self._last_resume=None

    def refresh(self):
        self.view.refresh()
        self.render(self.view.state,self.view.action_updates)

    def render(self,st,updates):
        from types import SimpleNamespace
        from bytefault.ui.resume import resume_lines
        resume='\n'.join(resume_lines(st.resume,progress=st.progress,accepted_bytes=st.total_bytes_sent))
        if resume and resume!=self._last_resume:
            self.stream.write(resume+'\n')
            self._last_resume=resume
        for update in updates:
            event=SimpleNamespace(**update)
            signature=(event.attempt_id,event.acceptance,event.receive_outcome)
            if signature in self._seen_actions:
                continue
            if len(self._recent_actions)==200:
                self._seen_actions.discard(self._recent_actions.popleft())
            self._seen_actions.add(signature)
            self._recent_actions.append(signature)
            if st.test_banner:
                self.stream.write('-'*72+'\n')
            label=f'Test {event.current_iteration}' if event.iteration_id else 'Setup'
            self.stream.write(f'{label} run={event.run_id} case={event.case_id} '
                f'variant={event.variant_id} stage={event.stage_id} action={event.action_id} attempt={event.attempt_id}\n')
            summaries=[]
            for f in event.current_fields:
                if f['field_id'] not in st.hidden_fields:
                    summaries.append('/'.join((f['action_id'],f['buffer_id'],f['field_id']))+'='+
                        (f['value'].hex() if f['value'] is not None else 'unavailable'))
            if summaries:
                self.stream.write('FIELDS '+ ' '.join(summaries)+'\n')
            self.stream.write(f'INTENDED {(event.intended or b"").hex()}\n'
                f'OFFERED {event.last_sent.hex()} acceptance={event.acceptance} accepted={event.accepted_count}\n'
                f'ACCEPTED_PREFIX {event.accepted_prefix.hex()}\n'
                f'RESPONSE {(event.last_received or b"").hex()} receive={event.receive_outcome} meaning={event.response_meaning}\n')
            if self.output_formatter:
                try:
                    text=self.output_formatter(dict(event.current_field_bytes),event.last_received)
                    if text:
                        self.stream.write(str(text)+'\n')
                except Exception as exc:
                    self.stream.write('BYTEFAULT DISPLAY DEGRADED: formatter failed: '+str(exc)+'\n')
        for finding in st.crash_records:
            cores=finding.get('acquired_cores',())
            summary=repr((finding.get('assessments'),finding.get('reports'),finding.get('report_status'),
                finding.get('acquired_core_count',0),
                tuple((core.get('name'),core['path']) for core in cores)))
            if self._last_reports.get(finding['key'])!=summary:
                self._last_reports[finding['key']]=summary
                self.stream.write('FINDING '+finding['observation_id']+' '+summary+'\n')
                if len(cores)>1:
                    self.stream.write('MULTIPLE CORES ACQUIRED '+str(len(cores))+'\n')
                    for core in cores:
                        self.stream.write('CORE '+repr(core.get('name') or 'exact remote name unavailable')+
                            ' '+core['path']+'\n')
        # Only bounded displayed finding identities are retained locally.
        keys={r['key'] for r in st.crash_records}
        self._last_reports={k:v for k,v in self._last_reports.items() if k in keys}
        p=st.progress
        def counter(name):
            return p.get(name,'unknown')
        totals=(f"prepared={counter('prepared_cases')} selected={counter('selected_cases')} "
            f"omitted={counter('omitted_cases')} tests={counter('fuzz_tests')} "
            f"attempts={counter('attempts')} setup={counter('setup_attempts')}")
        progress=(st.current_iteration,st.variant_id,st.current_selected,totals,st.followup_pending,st.paused)
        if progress!=self._last_progress or (st.run_active and time.monotonic()-self._progress_at>=1):
            self._last_progress=progress; self._progress_at=time.monotonic()
            self.stream.write(f'PROGRESS case={st.current_iteration} variant={st.variant_id or "—"} '
                f'{"SELECTED" if st.current_selected else "SETUP"} {totals} '
                f'case-limit={p.get("case_limit") if p.get("case_limit") is not None else "none"} '
                f'{"final accounted" if p.get("final") else "total unknown"} '
                f'view-rate={st.tests_per_second:.1f} attempts/s '
                f'TX={st.tx_bytes_per_second:.1f} B/s RX={st.rx_bytes_per_second:.1f} B/s '
                f'follow-up={st.followup_pending}\n')
        if not st.run_active:
            summary=(st.exit_reason,st.execution_state,totals,st.total_bytes_sent,st.total_bytes_received,
                     st.crash_count,st.followup_pending)
            if summary!=self._last_summary:
                self._last_summary=summary
                self.stream.write(f'SUMMARY outcome={st.exit_reason or st.execution_state} '
                    f'state={st.execution_state} {totals} known-accepted-bytes={st.total_bytes_sent} '
                    f'received-bytes={st.total_bytes_received} potential={st.crash_count} '
                    f'follow-up={st.followup_pending}\n')
        self.stream.flush()


# ── Plain-text listener (pre-Rich stdout behavior) ──────────────────


class PlainTextListener(FuzzEventListener):
    """Replicates the current pre-Rich console output.

    Handles:
    - Progress line (single-line overwrite via ``\\r``)
    - Test banners (``-`` * 80 + "Test N of M (P%)")
    - Session-complete summary via ``_finish_progress``
    - Output formatter passthrough

    Constructor params:
        output_formatter: Protocol-specific formatter callback.
        test_banner: Show per-test delimiter lines.
    """

    def __init__(
        self,
        output_formatter=None,
        test_banner: bool = True,
    ) -> None:
        self.output_formatter = output_formatter
        self.test_banner = test_banner

        # Display state
        self._crash_count = 0
        self._last_payload_hex: Optional[str] = None
        self._last_send_len: Optional[int] = None
        self._last_recv_len: Optional[int] = None

    # ── sampling logic (moved from _should_log_test) ────────────────

    def _should_log_test(self, index: int, total: int) -> bool:
        """Decide whether to emit a test banner for this iteration."""
        if total <= 0:
            return index % 100 == 0
        if total <= 1000:
            return True
        return index % 1000 == 0

    # ── progress line ───────────────────────────────────────────────

    def _update_progress_line(
        self,
        index: int,
        total: int,
        target: Optional[str] = None,
    ) -> None:
        if total > 0:
            pct = ((index + 1) / total) * 100
            prefix = f"Test {index + 1}/{total} ({pct:.1f}%)"
        else:
            prefix = f"Test {index + 1}"
        parts = [prefix]
        if target:
            parts.append(f"target={target}")
        parts.append(f"crashes={self._crash_count}")
        term_width = shutil.get_terminal_size((80, 24)).columns
        if self._last_payload_hex:
            stub = " | ".join(parts + ["payload="])
            avail = term_width - len(stub) - 1
            preview = self._last_payload_hex
            if avail >= 6 and len(preview) > avail:
                preview = preview[: avail - 3] + "..."
            elif avail < 6:
                preview = preview[:32] if len(preview) > 32 else preview
            parts.append(f"payload={preview}")
        else:
            if self._last_send_len is not None:
                parts.append(f"sent={self._last_send_len}B")
            if self._last_recv_len is not None:
                parts.append(f"recv={self._last_recv_len}B")
        line = " | ".join(parts)

        if len(line) >= term_width:
            line = line[: term_width - 4] + "..."
        pad = max(0, term_width - len(line) - 1)
        sys.stdout.write("\r" + line + " " * pad)
        sys.stdout.flush()

    def _clear_progress_line(self) -> None:
        term_width = shutil.get_terminal_size((80, 24)).columns
        sys.stdout.write("\r" + " " * (term_width - 1) + "\r")
        sys.stdout.flush()

    def _finish_progress(self, summary: str) -> None:
        """Log summary and replace the progress line with it."""
        logger.info(summary)
        self._clear_progress_line()
        sys.stdout.write(summary + "\n")
        sys.stdout.flush()

    # ── event handlers ──────────────────────────────────────────────

    def on_progress(
        self,
        iteration: int,
        total: Optional[int],
        target_label: str,
        outer_pos: Optional[Tuple[int, int]] = None,
        inner_pos: Optional[Tuple[int, int]] = None,
    ) -> None:
        self._update_progress_line(iteration, total or 0, target=target_label)

    def on_test_start(
        self,
        iteration: int,
        total: Optional[int],
        field_bytes: Dict[str, bytes],
    ) -> None:
        t = total or 0
        if self._should_log_test(iteration, t):
            self._clear_progress_line()
            if t > 0:
                pct = ((iteration + 1) / t) * 100
                msg = f"Test {iteration + 1} of {t} ({pct:.1f}%)"
            else:
                msg = f"Test {iteration + 1} (run-until-stopped)"
            if self.test_banner:
                logger.info("-" * 80)
            logger.info(msg)

    def on_packet_sent(
        self,
        iteration: int,
        packet_bytes: bytes,
        length: int,
    ) -> None:
        self._last_send_len = length
        self._last_payload_hex = packet_bytes.hex()

    def on_response_received(
        self,
        iteration: int,
        response_bytes: bytes,
        length: int,
    ) -> None:
        self._last_recv_len = length

    def on_crash_detected(
        self,
        iteration: int,
        crash_info: Dict,
    ) -> None:
        self._crash_count += 1

    def on_test_complete(
        self,
        iteration: int,
        result: Dict,
    ) -> None:
        # Output formatter passthrough (e.g., "CMD : RESPONSE")
        if self.output_formatter and result.get("_field_bytes") and result.get("_response") is not None:
            try:
                formatted = self.output_formatter(
                    result["_field_bytes"], result["_response"],
                )
                if formatted:
                    self._clear_progress_line()
                    print(formatted)
            except Exception:
                pass

    def on_session_complete(
        self,
        total_tests: int,
        total_crashes: int,
        elapsed_s: float,
    ) -> None:
        self._finish_progress(
            f"Fuzzing complete: {total_tests} tests, {total_crashes} crashes"
        )

    def on_session_opened(
        self,
        fuzz_stage: str,
        conversation_log: List[Tuple[str, str, bytes]],
    ) -> None:
        if conversation_log:
            for direction, stage, data in conversation_log:
                logger.debug(
                    "Session %s %s: %s (%d bytes)",
                    stage,
                    direction,
                    data.hex()[:64],
                    len(data),
                )
