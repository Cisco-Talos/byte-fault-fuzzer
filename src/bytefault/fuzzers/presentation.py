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

"""Bounded optional observers; engine progress never calls a consumer inline.

A stalled consumer owns at most one executing callback and `capacity` queued
snapshots. Progress may coalesce; overflow of a nonreplaceable event explicitly
fails that attachment. Required records must use a separate acknowledged port.
"""
from __future__ import annotations
import queue
import threading
from bytefault.core.contracts import ControlOutcome


class PresentationAttachment:
    def __init__(self, consumer, capacity):
        if capacity < 1:
            raise ValueError("presentation capacity must be positive")
        self.consumer = consumer
        self.queue = queue.Queue(capacity)
        self.dropped = 0
        self.discarded_on_close = 0
        self.failed = False
        self.closed = False
        self.in_callback = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name="bytefault-presentation")
        self.thread.start()

    def offer(self, name, snapshot):
        if self.closed or self.failed:
            return
        try:
            self.queue.put_nowait((name, snapshot))
        except queue.Full:
            if name == "on_progress":
                self.dropped += 1
            else:
                self.failed = True

    def _run(self):
        while not self.closed:
            try:
                name, snapshot = self.queue.get(timeout=0.1)
            except queue.Empty:
                if self.failed:
                    return
                continue
            if self.closed:
                self.discarded_on_close += 1
                self.queue.task_done()
                return
            try:
                method = getattr(self.consumer, name, None)
                if method:
                    self.in_callback.set()
                    method(**snapshot)
            except Exception:
                self.failed = True
                return
            finally:
                self.in_callback.clear()
                self.queue.task_done()

    def close(self):
        self.closed = True
        while True:
            try:
                self.queue.get_nowait()
            except queue.Empty:
                break
            self.discarded_on_close += 1
            self.queue.task_done()
        pending = self.in_callback.is_set()
        reason = f'{self.discarded_on_close} queued optional snapshots discarded'
        if pending:
            reason += '; executing optional callback is not awaited'
        return ControlOutcome('detach_observer', 'pending' if pending else 'completed', reason)
