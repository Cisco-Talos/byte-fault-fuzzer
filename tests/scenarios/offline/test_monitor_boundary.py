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

from dataclasses import replace
from pathlib import Path
import socket
import threading
import time
from uuid import uuid4

import pytest


def request(receive=None):
    from bytefault.core.contracts import ConversationAction, PassivePlan, PreparedRow, ConversationRequest, ReceiveRequest
    return ConversationRequest(PassivePlan('monitor-fixture', 1,
        (ConversationAction('first', b'\x10', receive=receive or ReceiveRequest(requested=False)),
         ConversationAction('second', b'ABC'))), PreparedRow('row-monitor', 1),
        ('first', 'second'), 'run-monitor', 'case-monitor', 'conversation-monitor')


class FirstHold:
    """Configured contract fixture: no inference about process crash."""
    def evaluate(self, observation):
        from bytefault.core.contracts import MonitoringDecision
        if observation.kind == 'action' and observation.correlation.action_id == 'first':
            return MonitoringDecision(str(uuid4()), observation.observation_id, observation.correlation,
                'hold', 'awaited', ('report', 'readiness'), reason='explicit fixture hold')
        return MonitoringDecision(str(uuid4()), observation.observation_id, observation.correlation, 'continue')


def wait_for_hold(engine, thread):
    deadline = time.monotonic() + 2
    while not engine.status().monitoring_hold and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert engine.status().monitoring_hold
    return engine.continuation.hold


def completion(hold, condition, status='succeeded'):
    from bytefault.core.contracts import MonitoringCompletion
    return MonitoringCompletion(str(uuid4()), hold.decision_id, hold.observation_id,
                                hold.correlation, condition, status)


def test_facts_and_correlated_gate(engine_factory):
    from bytefault.core.contracts import ReceiveRequest, ProbeRequest
    from bytefault.monitoring import Monitoring, ConfiguredPolicy
    variants = ((ReceiveRequest(cap=4, deadline=10), (), 'deadline', b'', True),
                (ReceiveRequest(requested=False), (), 'unrequested', b'', False),
                (ReceiveRequest(cap=4, deadline=10, length_offset=0, length_size=2),
                 (b'\x00', ConnectionResetError('reset')), 'reset', b'\x00', True),
                (ReceiveRequest(cap=4, deadline=10), (b'\x00\x01\x02\x03',), 'read_cap', b'\x00\x01\x02\x03', True))
    for receive, reads, outcome, exact, requested in variants:
        engine, trace, _, _ = engine_factory(reads=reads, monitoring=Monitoring(ConfiguredPolicy()))
        result = engine.execute_conversation(request(receive))
        observation = engine.monitoring.observations[0]
        assert observation.transport.receive_outcome == outcome
        assert observation.transport.receive_requested is requested
        assert observation.transport.received == exact
        assert observation.transport.response_boundary == 'unknown'
        assert observation.correlation.run_id == 'run-monitor'
        assert observation.correlation.action_id == 'first'
        assert observation.correlation.attempt_id.endswith('first:attempt-1')
        assert all(not decision.assessments for decision in engine.monitoring.decisions)
        # The same facts accept two independently configured monitoring policies.
        continued = Monitoring(ConfiguredPolicy()).observe(observation)
        held = Monitoring(ConfiguredPolicy('hold', mode='awaited', conditions=('assessment',))).observe(observation)
        assert continued.disposition == 'continue' and held.disposition == 'hold'

    engine, trace, _, _ = engine_factory(monitoring=Monitoring(FirstHold()))
    results = []
    thread = threading.Thread(target=lambda: results.append(engine.execute_conversation(request())))
    thread.start()
    hold = wait_for_hold(engine, thread)
    try:
        assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10']
        wrong = replace(completion(hold, 'report'), decision_id='decision-for-B')
        assert engine.complete_monitoring(wrong) is False
        assert engine.status().monitoring_hold == hold.decision_id
        assert engine.complete_monitoring(completion(hold, 'report', 'failed'))
        assert engine.status().monitoring_hold == hold.decision_id
        # Controls, required storage, and an actual engine-owned probe work held.
        assert engine.control('pause').outcome == 'completed'
        probe = ProbeRequest('probe-A', hold.observation_id, hold.correlation, b'P',
                             decision_id=hold.decision_id)
        fact = engine.execute_probe(probe).transport
        assert fact.accepted_prefix == b'P'
        assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'P']
        assert engine.monitoring.observations[-1].kind == 'probe'
        assert engine.complete_monitoring(completion(hold, 'report'))
        assert engine.status().monitoring_hold
        assert engine.control('resume').outcome == 'completed'
        assert engine.complete_monitoring(completion(hold, 'readiness'))
        thread.join(2)
        assert not thread.is_alive() and results[0].outcome == 'completed'
        assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'P', b'ABC']
        stored = engine.record_store.snapshot()
        assert any(r.kind == 'probe_result' for r in stored.records)
        assert sum(r.kind == 'monitoring_completion' for r in stored.records) == 4
    finally:
        engine.control('stop')
        thread.join(2)


def test_stop_required_failure_and_nonblocking_modes(engine_factory):
    from bytefault.monitoring import Monitoring, ConfiguredPolicy
    # Explicit nonblocking required-work selections do not imply an awaited hold.
    engine, trace, _, _ = engine_factory(monitoring=Monitoring(
        ConfiguredPolicy('continue', conditions=('report',))))
    assert engine.execute_conversation(request()).outcome == 'completed'
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'ABC']
    assert engine.monitoring.decisions[0].required_conditions == ('report',)

    engine, trace, _, _ = engine_factory(monitoring=Monitoring(ConfiguredPolicy('stop')))
    assert engine.execute_conversation(request()).outcome == 'monitoring_stopped'
    assert engine.status().state == 'monitoring_stopped'
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10']

    for required_failure in (False, True):
        engine, trace, _, _ = engine_factory(monitoring=Monitoring(FirstHold()))
        result = []
        thread = threading.Thread(target=lambda: result.append(engine.execute_conversation(request())))
        thread.start()
        hold = wait_for_hold(engine, thread)
        if required_failure:
            engine.record_store.close()
            from bytefault.core.records import RequiredSaveFailure
            with pytest.raises(RequiredSaveFailure):
                engine.complete_monitoring(completion(hold, 'report'))
        else:
            assert engine.control('stop').outcome == 'completed'
        thread.join(2)
        assert not thread.is_alive()
        assert result[0].outcome == ('recording_failed' if required_failure else 'stopped')
        assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10']


def test_monitoring_owner_and_bounded_history(engine_factory):
    import ast
    from bytefault.monitoring import Monitoring
    engine, _, _, _ = engine_factory(monitoring=Monitoring(history_capacity=1))
    assert engine.execute_conversation(request()).outcome == 'completed'
    assert len(engine.monitoring.observations) == 1
    assert engine.monitoring.history_dropped == 1
    assert sum(r.kind == 'observation' for r in engine.record_store.snapshot().records) == 2
    root = Path(__file__).resolve().parents[3] / 'src/bytefault'
    for path in ('core/contracts.py', 'core/records.py', 'core/storage.py'):
        tree = ast.parse((root / path).read_text())
        assert not any(isinstance(n, ast.ImportFrom) and (n.module or '').startswith(
            ('bytefault.fuzzers', 'bytefault.monitoring', 'bytefault.management')) for n in ast.walk(tree))
    policy = (root / 'monitoring/policy.py').read_text()
    assert 'socket' not in policy and '.recv(' not in policy
    assert 'class HeartbeatMonitor' in (root / 'monitoring/heartbeat.py').read_text()
    from bytefault.management.collection import Collection
    from bytefault.management.maintenance import remove_local_cache, remove_remote_cores
    assert callable(Collection.retrieve_coredumps)
    assert callable(remove_local_cache) and callable(remove_remote_cores)


def test_releasing_hold_during_probe_serializes_io_and_evidence(engine_factory):
    from bytefault.monitoring import Monitoring
    from bytefault.core.contracts import ProbeRequest, ReceiveRequest
    engine, trace, stream, _ = engine_factory(monitoring=Monitoring(FirstHold()))
    results, probe_results = [], []
    campaign = threading.Thread(target=lambda: results.append(engine.execute_conversation(request())))
    campaign.start()
    hold = wait_for_hold(engine, campaign)
    entered, release, next_prepared = threading.Event(), threading.Event(), threading.Event()
    real_preoffer = engine._action_pre_offer
    def preoffer(req, action, materialized, attempt):
        if action.action_id == 'second':
            next_prepared.set()
        return real_preoffer(req, action, materialized, attempt)
    engine._action_pre_offer = preoffer
    def pending_read(cap):
        entered.set()
        assert release.wait(2)
        return b'R'
    stream.recv = pending_read
    probe = ProbeRequest('probe-slow', hold.observation_id, hold.correlation, b'P',
                         ReceiveRequest(cap=4, deadline=10), decision_id=hold.decision_id)
    observer = threading.Thread(target=lambda: probe_results.append(engine.execute_probe(probe)))
    observer.start()
    try:
        assert entered.wait(1)
        assert engine.complete_monitoring(completion(hold, 'report'))
        assert engine.complete_monitoring(completion(hold, 'readiness'))
        assert not next_prepared.wait(0.05)
        assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'P']
        release.set()
        observer.join(2)
        campaign.join(2)

        assert not observer.is_alive() and not campaign.is_alive()
        assert probe_results[0].transport.received == b'R'
        assert results[0].outcome == 'completed'
        assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'P', b'ABC']
        records = engine.record_store.snapshot().records
        probe_index = next(i for i, r in enumerate(records) if r.kind == 'probe_result')
        second_index = next(i for i, r in enumerate(records) if r.kind == 'materialization'
                            and r.identity['action_id'] == 'second')
        assert probe_index < second_index
    finally:
        release.set()
        engine.control('stop')
        observer.join(2)
        campaign.join(2)


def test_required_failure_closes_inflight_probe_without_stale_transport_progress(engine_factory):
    from bytefault.monitoring import Monitoring
    from bytefault.core.contracts import ProbeRequest, ReceiveRequest
    from bytefault.core.records import RequiredSaveFailure
    engine, trace, stream, _ = engine_factory(monitoring=Monitoring(FirstHold()))
    results, probe_errors = [], []
    campaign = threading.Thread(target=lambda: results.append(engine.execute_conversation(request())))
    campaign.start()
    hold = wait_for_hold(engine, campaign)
    entered, release = threading.Event(), threading.Event()
    def pending_read(cap):
        entered.set()
        assert release.wait(2)
        if stream.closed:
            raise OSError('controlled stream closed during receive')
        return b'R'
    stream.recv = pending_read
    probe = ProbeRequest('probe-stop', hold.observation_id, hold.correlation, b'P',
                         ReceiveRequest(cap=4, deadline=10), decision_id=hold.decision_id)
    def run_probe():
        try:
            engine.execute_probe(probe)
        except Exception as exc:
            probe_errors.append(exc)
    observer = threading.Thread(target=run_probe)
    observer.start()
    try:
        assert entered.wait(1)
        engine.record_store.close()
        with pytest.raises(RequiredSaveFailure):
            engine.complete_monitoring(completion(hold, 'report'))
        assert stream.closed
        assert engine.storage_failure['transport_progress_state'] == 'inflight_unknown'
        assert engine.storage_failure['known_transport_progress'] is None
        assert engine.storage_failure['known_transport_identity']['action_id'] == 'probe-stop'
        release.set()
        observer.join(2)
        campaign.join(2)
        assert not observer.is_alive() and not campaign.is_alive()
        assert len(probe_errors) == 1 and isinstance(probe_errors[0], RequiredSaveFailure)
        assert results[0].outcome == 'recording_failed'
        assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'P']
        assert engine.last_transport_result.acceptance == 'accepted'
        assert engine.last_transport_result.receive_outcome == 'error'
    finally:
        release.set()
        engine.control('stop')
        observer.join(2)
        campaign.join(2)


def test_monitoring_resolves_keyed_and_external_obligations_in_current_value_contract(application_factory, tmp_path):
    import json
    from bytefault.core.contracts import (Correlation, Observation, TransportResult, MonitoringAction,
        MonitoringDecision, MonitoringCompletion)
    from bytefault.core.records import encode_value, decode_value
    from bytefault.fuzzers.cli import execute_arguments
    from bytefault.fuzzers.continuation import ContinuationGate
    from bytefault.monitoring import Monitoring
    correlation = Correlation('run', 'case', 'conversation', 'send', 'attempt')
    observation = Observation('observation', correlation, TransportResult(b'A'))
    class Policy:
        def evaluate(self, supplied):
            parameters = ({'collect': True, 'report': True}, {'collect': True}, {'report': True})
            actions = tuple(MonitoringAction(f'followup-{i}', 'event', supplied.observation_id,
                supplied.correlation, 'followup', options) for i, options in enumerate(parameters))
            return MonitoringDecision('decision', supplied.observation_id, supplied.correlation,
                'hold', 'awaited', ('collection', 'report', 'readiness'), actions=actions)
    from bytefault.logging import ActionLog
    log = ActionLog.open(tmp_path / 'monitoring.bfr', owner='application')
    app, traces = application_factory(monitoring=Monitoring(Policy()), action_logs=(log,))
    try:
        decision = execute_arguments(['service', 'monitoring', json.dumps(encode_value(observation))], app)
        expected = [('collection', 'followup-0'), ('collection', 'followup-1'),
                    ('report', 'followup-0'), ('report', 'followup-2'), ('readiness', None)]
        assert [(v.condition, v.followup_action_id) for v in decision.obligations] == expected
        class PartialPolicy:
            def evaluate(self, supplied):
                return replace(decision, obligations=decision.obligations[:-1])
        from bytefault.core.contracts import ContractError
        with pytest.raises(ContractError, match='inconsistent_wait'):
            Monitoring(PartialPolicy()).observe(observation)
        encoded = decode_value(json.loads(json.dumps(encode_value(decision))))
        assert [(v['condition'], v['followup_action_id']) for v in encoded['obligations']] == expected
        assert not traces  # the independent Monitoring operation created no executor
        gate = ContinuationGate()
        gate.select(decision)
        def complete(condition, identity=None, status='succeeded'):
            value = MonitoringCompletion(str(uuid4()), decision.decision_id, observation.observation_id,
                correlation, condition, status, followup_action_id=identity)
            roundtrip = decode_value(json.loads(json.dumps(encode_value(value))))
            assert roundtrip['followup_action_id'] == identity
            return gate.complete(value)
        assert complete('collection') is False
        assert complete('readiness', 'followup-0') is False
        for condition, identity in expected[:-1]:
            assert complete(condition, identity)
        assert gate.hold is decision
        # A non-success update cannot retain a formerly satisfied obligation
        # while another condition still holds testing.
        assert complete('collection', 'followup-1', 'failed')
        assert complete('readiness')
        assert gate.hold is decision
        assert complete('collection', 'followup-1')
        assert gate.hold is None
    finally:
        app.close()
