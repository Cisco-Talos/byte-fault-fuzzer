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

"""Independent ICMP reachability observations, separate from service readiness."""
from datetime import datetime, timezone
import sys
import subprocess
import threading
import time
from uuid import uuid4

from bytefault.core.contracts import Correlation, Observation, TransportResult, freeze


class HeartbeatMonitor:
    def __init__(self, host, *, interval=2.0, process=None, record=None, clock=None):
        from bytefault.monitoring.configuration import number
        number(interval, 'heartbeat.interval')
        if interval == 0:
            raise ValueError('heartbeat interval must be positive')
        self.host, self.interval = host, interval
        self.process, self.record, self.clock = process or subprocess.run, record, clock or time.monotonic
        self.alive, self.consecutive_failures = None, 0
        self.latest_observation, self.observed_at, self.error = None, None, None
        self.heartbeat_id = str(uuid4())
        self._stop_event, self._lock = threading.Event(), threading.RLock()
        self._thread, self.closed, self._running = None, False, False
        self.on_stopped = None
        self._is_windows = sys.platform == 'win32'

    def start(self):
        with self._lock:
            if self.closed:
                raise OSError('heartbeat owner closed')
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._running = True
            self._thread = threading.Thread(target=self._run, name='heartbeat-monitor', daemon=True)
            try:
                self._thread.start()
            except BaseException:
                self._running, self._thread = False, None
                self._stop_event.set()
                raise

    def stop(self):
        self._stop_event.set()
        if self._thread is not None and threading.current_thread() is not self._thread:
            self._thread.join(timeout=5)
        return self.status()

    def close(self):
        self.closed = True
        return self.stop()

    def status(self):
        with self._lock:
            return freeze({'enabled': True, 'host': self.host, 'interval': self.interval,
                'alive': self.alive, 'consecutive_failures': self.consecutive_failures,
                'latest_observation': self.latest_observation, 'observed_at': self.observed_at,
                'running': self._running,
                'closed': self.closed, 'error': self.error})

    def _run(self):
        try:
            while not self._stop_event.is_set():
                self._ping_once()
                self._stop_event.wait(self.interval)
        finally:
            self._running = False
            if self.on_stopped is not None:
                try:
                    self.on_stopped()
                except Exception as exc:
                    self.error = str(exc)

    def _ping_once(self):
        command = (['ping', '-n', '1', '-w', '1000', self.host] if self._is_windows else
                   ['ping', '-c', '1', '-W', '1', self.host])
        operation = {'argv': tuple(command), 'timeout': 3.0, 'capture_output': True, 'text': True,
            'creationflags': subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            'started_at': datetime.now(timezone.utc).isoformat(), 'interval': self.interval}
        try:
            result = self.process(command, capture_output=True, text=True, timeout=3.0,
                                  creationflags=operation['creationflags'])
            alive = result.returncode == 0
            operation.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except Exception as exc:
            alive = None
            operation.update(error=str(exc), error_type=type(exc).__name__)
        operation['completed_at'] = datetime.now(timezone.utc).isoformat()
        observation = Observation(str(uuid4()), Correlation('heartbeat:' + self.heartbeat_id,
            'independent', self.heartbeat_id, 'icmp', str(uuid4())),
            TransportResult(b'', receive_requested=False, receive_outcome='unrequested'),
            kind='heartbeat', observed_at=self.clock(), parameters={'alive': alive,
                'host': self.host, 'operation': operation, 'service_state': 'independent',
                'measurement': 'completed' if alive is not None else 'unavailable'})
        try:
            if self.record is not None:
                self.record(observation)
        except Exception as exc:
            with self._lock:
                self.error = str(exc)
            self._stop_event.set()
            return
        with self._lock:
            self.alive, self.latest_observation, self.observed_at = alive, observation, observation.observed_at
            if alive is True:
                self.consecutive_failures = 0
            elif alive is False:
                self.consecutive_failures += 1
