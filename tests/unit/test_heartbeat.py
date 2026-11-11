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

"""Independent heartbeat observations with a controlled process collaborator."""

import threading
from types import SimpleNamespace

import pytest

from bytefault.monitoring.heartbeat import HeartbeatMonitor


def test_operator_interval_is_preserved_and_zero_is_rejected():
    monitor = HeartbeatMonitor("controlled", interval=0.1, process=lambda *a, **k: None)
    assert monitor.status()["interval"] == 0.1
    with pytest.raises(ValueError, match="positive"):
        HeartbeatMonitor("controlled", interval=0)


def test_completed_and_unavailable_pings_have_distinct_facts():
    outcomes = iter((0, 1, OSError("ping unavailable"), 0))
    recorded = []

    def process(*args, **kwargs):
        outcome = next(outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(returncode=outcome, stdout="controlled", stderr="")

    monitor = HeartbeatMonitor("controlled", interval=0.1, process=process,
                               record=recorded.append, clock=lambda: 17.0)
    expected = ((True, 0, 0), (False, 1, 1), (None, 1, None), (True, 0, 0))
    for index, (alive, failures, returncode) in enumerate(expected, 1):
        monitor._ping_once()
        status = monitor.status()
        assert status["alive"] is alive
        assert status["consecutive_failures"] == failures
        observation = status["latest_observation"]
        assert observation.kind == "heartbeat"
        assert observation.correlation.run_id.startswith("heartbeat:")
        assert observation.observed_at == 17.0
        assert observation.parameters["host"] == "controlled"
        assert observation.parameters["alive"] is alive
        assert observation.parameters["service_state"] == "independent"
        assert observation.parameters["measurement"] == ("unavailable" if alive is None else "completed")
        operation = observation.parameters["operation"]
        if returncode is None:
            assert operation["error_type"] == "OSError"
        else:
            assert operation["returncode"] == returncode
        assert len(recorded) == index and recorded[-1].observation_id == observation.observation_id


def test_required_record_failure_stops_before_publishing_measurement():
    def fail_record(observation):
        raise OSError("journal unavailable")

    monitor = HeartbeatMonitor("controlled", process=lambda *a, **k:
                               SimpleNamespace(returncode=0, stdout="ok", stderr=""),
                               record=fail_record)
    monitor._ping_once()
    status = monitor.status()
    assert status["alive"] is None and status["latest_observation"] is None
    assert status["error"] == "journal unavailable"
    assert monitor._stop_event.is_set()


def test_thread_lifecycle_uses_controlled_ping_and_closes():
    observed = threading.Event()
    monitor = HeartbeatMonitor("controlled", interval=60,
                               process=lambda *a, **k: SimpleNamespace(returncode=0, stdout="ok", stderr=""),
                               record=lambda observation: observed.set())
    monitor.start()
    try:
        assert observed.wait(2)
        thread = monitor._thread
        assert thread is not None and thread.daemon
        monitor.start()
        assert monitor._thread is thread
        assert monitor.status()["running"]
    finally:
        monitor.close()
    assert monitor.status()["closed"] and not monitor.status()["running"]
    assert not thread.is_alive()
