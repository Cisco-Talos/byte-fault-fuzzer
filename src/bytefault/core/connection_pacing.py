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

"""Shared start pacing for connections initiated by one application owner."""
import threading
import time


class ConnectionPacer:
    def __init__(self, *, sleep=None, clock=None):
        self.sleep = sleep or time.sleep
        self.clock = clock or time.monotonic
        self._lock = threading.Condition()
        self._started = False
        self._active = False

    def before_start(self, seconds, *, cancelled=lambda: False, sleep=None,
                     pre_delay=0.0, pre_wait=None):
        if seconds < 0:
            raise ValueError('connection delay must be nonnegative')
        with self._lock:
            while self._active and not cancelled():
                self._lock.wait(0.1)
            started_at = self.clock()
            applied = seconds if self._started else 0.0
            reserved = not cancelled()
            if reserved:
                self._active = True
            try:
                if applied and reserved:
                    selected_sleep = sleep or self.sleep
                    if selected_sleep is time.sleep:
                        deadline = self.clock() + applied
                        while not cancelled() and self.clock() < deadline:
                            self._lock.wait(min(0.05, deadline - self.clock()))
                    else:
                        selected_sleep(applied)
                pre_fact = pre_wait(pre_delay) if pre_wait is not None and not cancelled() else None
                outcome = 'cancelled' if cancelled() else 'completed'
                if outcome == 'completed':
                    self._started = True
                elif reserved:
                    self._active = False
                    self._lock.notify_all()
            except BaseException:
                if reserved:
                    self._active = False
                    self._lock.notify_all()
                raise
            return {'seconds': applied, 'started_at': started_at,
                'completed_at': self.clock(), 'outcome': outcome}, pre_fact

    def finished(self):
        with self._lock:
            self._active = False
            self._lock.notify_all()
