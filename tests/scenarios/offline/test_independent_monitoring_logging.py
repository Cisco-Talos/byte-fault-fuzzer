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

"""Actual independent Monitoring/Logging/store path, without engine construction."""
from dataclasses import replace
import threading

import pytest

from bytefault.core.contracts import (Correlation, Observation, TransportResult, ContractError,
    MonitoringDecision, freeze)
from bytefault.core.records import RequiredServiceSaveFailure
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.logging import ActionLog
from bytefault.monitoring import Monitoring, ConfiguredPolicy


def observation(label='one'):
    return Observation(label, Correlation('external-run', 'case', 'conversation', 'send',
        'attempt-' + label, 'iteration', 'S0'),
        TransportResult(b'\x00\xff\x80', offered=b'\x00\xff\x80', accepted_prefix=b'\x00',
            accepted_count=None, acceptance='uncertain', receive_requested=True,
            received=b'\x00\xff', receive_outcome='reset', response_boundary='unknown'))


def test_independent_history_survives_bounded_projection(tmp_path, application_factory):
    path = tmp_path / 'monitoring.bfr'
    log = ActionLog.open(path, owner='application')
    monitor = Monitoring(history_capacity=1)
    app, transports = application_factory(monitoring=monitor, action_logs=(log,))
    supplied = (observation('one'), observation('two'), observation('three'))
    decisions = tuple(app.service('monitoring', item) for item in supplied)
    assert not transports and len(monitor.observations) == 1 and monitor.history_dropped == 2
    records = reopen_records(path).records
    assert [r.kind for r in records] == ['monitoring_observation', 'monitoring_decision'] * 3
    for index, (item, decision) in enumerate(zip(supplied, decisions)):
        record, result = records[index * 2:index * 2 + 2]
        assert record.data['action']['observation'] == freeze(item)
        assert result.data['action']['decision'] == freeze(decision)
        assert record.identity['observation_id'] == result.identity['observation_id'] == item.observation_id
        assert record.identity['attempt_id'] == item.correlation.attempt_id
        assert record.identity['service_id'] == result.identity['service_id']
        assert record.data['action']['observation']['transport']['received'] == b'\x00\xff'
    assert app.close()['outcome'] == 'completed' and log.closed
    assert len(reopen_records(path).records) == 6


@pytest.mark.parametrize('failure_point', ['observation', 'decision'])
def test_required_sink_failure_withholds_service_result(tmp_path, application_factory, monkeypatch, capsys, failure_point):
    path = tmp_path / 'monitoring.bfr'
    store = LocalRecordStore(path)
    monitor = Monitoring(history_capacity=1)
    app, transports = application_factory(monitoring=monitor, action_logs=(ActionLog(store),))
    if failure_point == 'observation':
        store.close()
    else:
        append = store.append
        def fail_decision(kind, identity, data):
            if kind == 'monitoring_decision':
                raise OSError('controlled decision save failed')
            return append(kind, identity, data)
        monkeypatch.setattr(store, 'append', fail_decision)
    try:
        with pytest.raises(RequiredServiceSaveFailure) as error:
            app.service('monitoring', observation())
        diagnostic = error.value.diagnostic
        assert error.value.status == 'recording_failed'
        assert diagnostic['required_record_kind'] == 'monitoring_' + failure_point
        assert diagnostic['original_request'] == freeze(observation())
        assert diagnostic['engine_transport'] == 'not_constructed' and not transports
        assert diagnostic['required_sink_ordinal'] == 1
        if failure_point == 'observation':
            assert diagnostic['evaluation_state'] == 'not_started' and not monitor.observations
            assert not diagnostic['available_record_refs']
        else:
            assert diagnostic['evaluation_state'] == 'produced_decision'
            assert diagnostic['available_decision']['observation_id'] == 'one'
            assert len(diagnostic['available_record_refs']) == 1
            assert [r.kind for r in reopen_records(path).records] == ['monitoring_observation']
        terminal = capsys.readouterr().err
        assert 'BYTEFAULT REQUIRED RECORDING STOP' in terminal and '00ff80' in terminal
        assert 'external-run' in terminal and 'attempt-one' in terminal
    finally:
        app.close(); store.close()


@pytest.mark.parametrize('bad_decision', [False, True])
def test_policy_failure_has_required_history(tmp_path, application_factory, capsys, bad_decision):
    class Policy:
        def evaluate(self, observation):
            if bad_decision:
                return {'unsupported': 'decision'}
            raise RuntimeError('controlled policy failure')
    store = LocalRecordStore(tmp_path / 'monitoring.bfr')
    app, transports = application_factory(monitoring=Monitoring(Policy()), action_logs=(ActionLog(store),))
    try:
        with pytest.raises(ContractError if bad_decision else RuntimeError) as failure:
            app.service('monitoring', observation())
        records = store.snapshot().records
        assert [r.kind for r in records] == ['monitoring_observation', 'monitoring_failure']
        retained = records[-1].data['action']
        assert retained['observation'] == freeze(observation())
        assert retained['error'] == str(failure.value)
        assert not capsys.readouterr().err and not transports and not store.closed
    finally:
        app.close(); store.close()


def test_failure_evidence_save_failure_remains_required_failure(tmp_path, application_factory, monkeypatch, capsys):
    class Policy:
        def evaluate(self, observation):
            raise RuntimeError('controlled policy failure')
    store = LocalRecordStore(tmp_path / 'monitoring.bfr')
    append = store.append
    def fail(kind, identity, data):
        if kind == 'monitoring_failure':
            raise OSError('controlled failure evidence save failed')
        return append(kind, identity, data)
    monkeypatch.setattr(store, 'append', fail)
    app, transports = application_factory(monitoring=Monitoring(Policy()), action_logs=(ActionLog(store),))
    try:
        with pytest.raises(RequiredServiceSaveFailure) as error:
            app.service('monitoring', observation())
        assert error.value.diagnostic['policy_failure'] == 'controlled policy failure'
        assert error.value.diagnostic['evaluation_state'] == 'failed'
        assert error.value.diagnostic['required_record_kind'] == 'monitoring_failure'
        assert [r.kind for r in store.snapshot().records] == ['monitoring_observation']
        assert 'controlled failure evidence save failed' in capsys.readouterr().err
        assert not transports
    finally:
        app.close(); store.close()


@pytest.mark.parametrize('invalid_kind', ['untyped', 'correlation', 'unresolved'])
def test_alternate_monitoring_port_decisions_are_validated(tmp_path, application_factory, capsys, invalid_kind):
    class Port:
        def observe(self, observation):
            if invalid_kind == 'untyped':
                return {'disposition': 'continue'}
            if invalid_kind == 'correlation':
                return MonitoringDecision('decision', 'another-observation', observation.correlation, 'continue')
            return MonitoringDecision('decision', observation.observation_id, observation.correlation,
                                      'hold', 'awaited', ('external',))
    store = LocalRecordStore(tmp_path / 'monitoring.bfr')
    app, transports = application_factory(monitoring=Port(), action_logs=(ActionLog(store),))
    try:
        with pytest.raises(ContractError):
            app.service('monitoring', observation())
        records = store.snapshot().records
        assert [r.kind for r in records] == ['monitoring_observation', 'monitoring_failure']
        assert records[-1].data['action']['error_type'] == 'ContractError'
        assert not capsys.readouterr().err and not transports and not store.closed
    finally:
        app.close(); store.close()


def test_absent_log_and_closed_application_are_unavailable(tmp_path, application_factory):
    monitor = Monitoring()
    app, transports = application_factory(monitoring=monitor)
    result = app.service('monitoring', observation())
    assert result.status == 'unavailable' and result.owner == 'Logging'
    assert not monitor.observations and not transports
    store = LocalRecordStore(tmp_path / 'caller.bfr')
    app, transports = application_factory(monitoring=monitor, action_logs=(ActionLog(store),))
    app.close()
    result = app.service('monitoring', observation())
    assert result.status == 'unavailable' and result.owner == 'Application'
    assert not monitor.observations and not transports and not store.closed
    store.close()


def test_close_preserves_inflight_service_and_log_ownership(tmp_path, application_factory, monkeypatch):
    log = ActionLog.open(tmp_path / 'application.bfr', owner='application')
    caller_store = LocalRecordStore(tmp_path / 'caller.bfr')
    entered, release = threading.Event(), threading.Event()
    append = log.store.append
    def blocked(kind, identity, data):
        if kind == 'monitoring_observation':
            entered.set()
            assert release.wait(5)
        return append(kind, identity, data)
    monkeypatch.setattr(log.store, 'append', blocked)
    app, transports = application_factory(monitoring=Monitoring(), action_logs=(log, ActionLog(caller_store)))
    results, errors = [], []
    def submit():
        try:
            results.append(app.service('monitoring', observation()))
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=submit); thread.start()
    try:
        assert entered.wait(5)
        closed = app.close()
        assert closed['outcome'] == 'pending' and closed['pending_monitoring']
        assert not log.closed and not caller_store.closed
        assert app.service('monitoring', observation('late')).status == 'unavailable'
        release.set(); thread.join(5)
        assert not thread.is_alive() and not errors and results[0].disposition == 'continue'
        assert len(log.store.snapshot().records) == len(caller_store.snapshot().records) == 2
        assert app.close()['outcome'] == 'completed' and log.closed
        assert not caller_store.closed and not transports
    finally:
        release.set(); thread.join(5); app.close(); caller_store.close()


def test_engine_monitoring_is_not_double_logged(tmp_path, application_factory):
    from test_logging_lifetime import app_request
    log = ActionLog.open(tmp_path / 'application.bfr', owner='application')
    app, transports = application_factory(monitoring=Monitoring(), action_logs=(log,))
    request = app_request(tmp_path)
    assert app.submit(request).outcome == 'completed'
    records = log.store.snapshot().records
    assert sum(record.kind == 'observation' for record in records) == 1
    assert sum(record.kind == 'monitoring_decision' for record in records) == 1
    assert not any(record.kind == 'monitoring_observation' for record in records)
    assert len(records) == len(app.read_records(request.conversation.run_id).records)
