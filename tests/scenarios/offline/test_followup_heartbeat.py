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

"""Actual service owners feed the accepted engine gate; only external ports are controlled."""
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
import threading
import time

import pytest

from bytefault.application import ApplicationRequest, CampaignRequest
from bytefault.core.contracts import (ConversationAction, ConversationRequest, PassivePlan,
    PreparedRow, ReceiveRequest, TransportRequest)
from bytefault.management.configuration import ServiceConfiguration
from bytefault.monitoring import Monitoring
from bytefault.monitoring.configuration import MonitoringConfig, ObservationRule
from test_reporting_collection import await_followup


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(.005)
    assert predicate()


def request(tmp_path, run='run', host='controlled-A', *, two=True):
    actions = (ConversationAction('A', b'A', receive=ReceiveRequest(requested=False)),)
    if two:
        actions += (ConversationAction('B', b'B', receive=ReceiveRequest(cap=1, deadline=2)),)
    conversation = ConversationRequest(PassivePlan('neutral', 1, actions), PreparedRow('row', 1),
        tuple(a.action_id for a in actions), run, 'case', 'conversation')
    return ApplicationRequest(conversation, TransportRequest(host, 1234, 3), str(tmp_path / (run + '.bfr')))


def configure(tmp_path):
    return ServiceConfiguration(result_root=str(tmp_path / 'results'), ssh_key='controlled-key', core_write_wait=0)


def collection_port(monkeypatch, *, failure=False, gates=()):
    import bytefault.management.collection as module
    commands, ordinal = [], [0]
    def process(command, **options):
        commands.append(command)
        if command[0] == 'rsync':
            index = ordinal[0]; ordinal[0] += 1
            if index < len(gates):
                entered, release = gates[index]
                entered.set(); assert release.wait(8)
            if failure:
                return SimpleNamespace(returncode=23, stdout='', stderr='controlled collection failure')
            name = f'core-{index}'
            (Path(command[-1]) / name).write_bytes(b'C')
            return SimpleNamespace(returncode=0,
                stdout=f'BF|>f+++++++++|1|2026/10/22-15:00:57|{name}\nNumber of files: 2 (reg: 1, dir: 1)',
                stderr='')
        raise AssertionError(f'unexpected collection command: {command[0]}')
    monkeypatch.setattr(module.subprocess, 'run', process)
    return commands


def offers(traces):
    return [entry[1] for trace, _, _ in traces for entry in trace if entry[0] == 'offer']


@pytest.mark.parametrize('report_required', [False, True])
def test_actual_readiness_collection_and_independent_report_wait(tmp_path, application_factory, monkeypatch, report_required):
    entered, release, report_entered, report_release = (threading.Event() for _ in range(4))
    collection_port(monkeypatch, gates=((entered, release),))
    app, traces = application_factory(service_configuration=configure(tmp_path), stream_options={'reads': (b'R',)})
    factory = app.transport_factory
    def controlled_transport(target):
        adapter = factory(target)
        stream = traces[-1][1]
        connect = stream.connect
        count = [0]
        def controlled(address):
            count[0] += 1
            stream.open_error = OSError('service unavailable') if count[0] == 2 else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = controlled_transport
    conditions = ('readiness', 'collection', 'report') if report_required else ('readiness', 'collection')
    config = MonitoringConfig(retries=0, recovery_delays=(0,), delayed_check=0, crash_throttle=0,
        rules=(ObservationRule('service_failure', 'service_failure', disposition='hold', conditions=conditions,
            actions=({'collect': True, 'report': True},)),))
    base = request(tmp_path)
    handle = app.start(CampaignRequest(base.conversation, base.transport, base.record_path, monitoring_configuration=config))
    try:
        assert entered.wait(5)
        actual = app.reporting.port
        def slow_report(value):
            report_entered.set(); assert report_release.wait(8)
            return actual(value)
        app.reporting.port = slow_report
        wait_until(lambda: any(r.kind == 'monitoring_completion' and r.data['completion']['condition'] == 'readiness'
                              for r in app.read_records('run').records))
        assert offers(traces) == [b'A', b'B']
        records = app.read_records('run').records
        assert any(r.kind == 'observation' and r.data['observation']['service_readiness'] == 'available' for r in records)
        release.set(); assert report_entered.wait(5)
        assert not app.management.pending_collection('run')
        if report_required:
            assert handle.wait(.1) is None and offers(traces) == [b'A', b'B']
        else:
            assert handle.wait(5) is not None and offers(traces) == [b'A', b'B']
        report_release.set()
        result = handle.wait(5)
        assert result.outcome == 'monitoring_failed'
        assert result.reason == 'configured test policy exhausted or service unrecovered'
        records = app.read_records('run').records
        directives = [r.data['directive'] for r in records if r.kind == 'campaign_directive']
        assert any(d['facts'].get('retry_exhausted') and d['facts'].get('failed_test') for d in directives)
        assert not any(r.kind == 'monitoring_failure' for r in records)
        outcome = await_followup(app)
        assert outcome['collection']['status'] == outcome['report']['status'] == 'succeeded'
        service = app.read_service_records('run')
        assert [r.data['completion']['condition'] for r in service if r.kind == 'management_completion'] == ['collection', 'report']
        assert any(r.kind == 'management_outcome' for r in service)
    finally:
        release.set(); report_release.set(); app.control('run', 'stop'); handle.wait(5); app.close()


@pytest.mark.parametrize('readiness_required', [False, True])
def test_repeated_recovery_checks_keep_one_hold_until_report_finishes(
        tmp_path, application_factory, monkeypatch, readiness_required):
    entered, release, report_entered, report_release = (threading.Event() for _ in range(4))
    collection_port(monkeypatch, gates=((entered, release),))
    app, traces = application_factory(service_configuration=configure(tmp_path))
    factory = app.transport_factory
    def transport(target):
        adapter = factory(target)
        stream = traces[-1][1]; connect = stream.connect; count = [0]
        def controlled(address):
            count[0] += 1
            stream.open_error = OSError('controlled service down') if count[0] in (2, 3) else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = transport
    conditions = ('readiness', 'collection', 'report') if readiness_required else ('collection', 'report')
    config = MonitoringConfig(retries=0, recovery_delays=(0, 0), delayed_check=0, crash_throttle=0,
        rules=(ObservationRule('service_failure', 'service_failure', disposition='hold',
            conditions=conditions,
            actions=({'collect': True, 'report': True},), on_failure='stop'),))
    base = request(tmp_path, two=False)
    campaign = CampaignRequest(base.conversation, base.transport, base.record_path,
        monitoring_configuration=config, cases=(base.conversation, base.conversation))
    handle = app.start(campaign)
    try:
        assert entered.wait(5)
        original_report = app.reporting.port
        def slow_report(value):
            report_entered.set(); assert report_release.wait(8)
            return original_report(value)
        app.reporting.port = slow_report
        def observations():
            return [r.data['observation'] for r in app.read_records('run').records
                    if r.kind == 'observation' and r.data['observation']['kind'] == 'service_check']
        wait_until(lambda: len(observations()) >= 3)
        checks = observations()[:3]
        assert [o['parameters']['purpose'] for o in checks] == ['periodic', 'recovery', 'recovery']
        assert [o['service_readiness'] for o in checks] == ['unavailable', 'unavailable', 'available']
        assert offers(traces) == [b'A']
        decisions = {r.data['decision']['observation_id']: r.data['decision']
            for r in app.read_records('run').records if r.kind == 'monitoring_decision'}
        original = decisions[checks[0]['observation_id']]
        repeated = decisions[checks[1]['observation_id']]
        assert original['disposition'] == 'hold' and len(original['actions']) == 1
        assert repeated['disposition'] == 'continue' and not repeated['actions']
        readiness = [r.data['completion'] for r in app.read_records('run').records
            if r.kind == 'monitoring_completion' and r.data['completion']['condition'] == 'readiness']
        assert len(readiness) == int(readiness_required)
        if readiness_required:
            assert readiness[0]['decision_id'] == original['decision_id']
        release.set(); assert report_entered.wait(5)
        assert handle.wait(.1) is None and offers(traces) == [b'A']
        report_release.set()
        result = handle.wait(5)
        assert result.fuzz_tests == 2 and offers(traces) == [b'A', b'A']
        assert not any(r.kind == 'monitoring_failure' for r in app.read_records('run').records)
        outcome = await_followup(app)
        assert outcome['collection']['status'] == outcome['report']['status'] == 'succeeded'
        assert len(app.management.status()['outcomes']) == 1
    finally:
        release.set(); report_release.set(); app.control('run', 'stop'); handle.wait(5); app.close()


@pytest.mark.parametrize('treatment,expected_offers', [('stop', 1), ('advance', 2)])
def test_recovery_exhaustion_applies_selected_readiness_failure_treatment(
        tmp_path, application_factory, treatment, expected_offers):
    app, traces = application_factory()
    factory = app.transport_factory
    def transport(target):
        adapter = factory(target)
        stream = traces[-1][1]; connect = stream.connect; count = [0]
        def controlled(address):
            count[0] += 1
            stream.open_error = OSError('controlled service down') if count[0] in (2, 3) else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = transport
    config = MonitoringConfig(retries=0, recovery_delays=(0,), delayed_check=0, crash_throttle=0,
        rules=(ObservationRule('service_failure', 'service_failure', disposition='hold',
            conditions=('readiness',), on_failure=treatment),))
    base = request(tmp_path, two=False)
    campaign = CampaignRequest(base.conversation, base.transport, base.record_path,
        monitoring_configuration=config, cases=(base.conversation, base.conversation))
    result = app.submit(campaign)
    assert result.outcome == ('monitoring_stopped' if treatment == 'stop' else 'monitoring_failed')
    assert offers(traces) == [b'A'] * expected_offers
    records = app.read_records('run').records
    checks = [r.data['observation'] for r in records if r.kind == 'observation'
        and r.data['observation']['kind'] == 'service_check']
    assert [o['parameters']['purpose'] for o in checks[:2]] == ['periodic', 'recovery']
    assert [o['service_readiness'] for o in checks[:2]] == ['unavailable', 'unavailable']
    hold = next(r.data['decision'] for r in records if r.kind == 'monitoring_decision'
        and r.data['decision']['observation_id'] == checks[0]['observation_id'])
    failure = [r.data['completion'] for r in records if r.kind == 'monitoring_completion'
        and r.data['completion']['condition'] == 'readiness']
    assert len(failure) == 1 and failure[0]['decision_id'] == hold['decision_id']
    assert failure[0]['status'] == 'failed'
    assert not any(r.kind == 'monitoring_failure' for r in records)


def test_actual_multiple_action_collections_each_release_their_own_obligation(tmp_path, application_factory, monkeypatch):
    first, first_release, second, second_release = (threading.Event() for _ in range(4))
    collection_port(monkeypatch, gates=((first, first_release), (second, second_release)))
    monitor = Monitoring(configuration=MonitoringConfig(health_check_mode='disabled', rules=(
        ObservationRule('unrequested', 'unrequested', disposition='hold', conditions=('collection',),
            actions=({'collect': True}, {'collect': True})),)))
    app, traces = application_factory(monitoring=monitor, service_configuration=configure(tmp_path), stream_options={'reads': (b'R',)})
    handle = app.start(request(tmp_path))
    try:
        assert first.wait(5); first_release.set(); assert second.wait(5)
        assert offers(traces) == [b'A'] and handle.wait(.05) is None
        completions = [r.data['completion'] for r in app.read_service_records('run') if r.kind == 'management_completion']
        assert len(completions) == 1
        first_action = completions[0]['followup_action_id']
        second_release.set(); assert handle.wait(5).outcome == 'completed'
        app.management.wait(5)
        completions = [r.data['completion'] for r in app.read_service_records('run') if r.kind == 'management_completion']
        assert len(completions) == 2 and completions[1]['followup_action_id'] != first_action
        assert offers(traces) == [b'A', b'B']
    finally:
        first_release.set(); second_release.set(); app.control('run', 'stop'); handle.wait(5); app.close()


def test_nonblocking_late_a_cannot_release_b_and_pending_close_autofinalizes(tmp_path, application_factory, monkeypatch):
    first, first_release, second, second_release = (threading.Event() for _ in range(4))
    commands = collection_port(monkeypatch, gates=((first, first_release), (second, second_release)))
    def monitor(blocking):
        return Monitoring(configuration=MonitoringConfig(health_check_mode='disabled', rules=(
            ObservationRule('unrequested', 'unrequested', disposition='hold' if blocking else 'continue',
                conditions=('collection',) if blocking else (), actions=({'collect': True, 'report': True},)),)))
    app, traces = application_factory(monitoring=monitor(False), service_configuration=configure(tmp_path))
    assert app.submit(request(tmp_path, 'A', 'controlled-A', two=False)).outcome == 'completed'
    assert first.wait(5)
    app.monitoring = monitor(True)
    handle = app.start(request(tmp_path, 'B', 'controlled-B'))
    try:
        wait_until(lambda: len(app.management.status()['pending']) == 2)
        first_release.set(); assert second.wait(5)
        assert handle.wait(.1) is None
        a = [r for r in app.read_service_records('A') if r.kind == 'management_outcome']
        assert a and all(r.identity['run_id'] == 'A' for r in a)
        assert not any(r.kind == 'management_outcome' for r in app.read_service_records('B'))
        # Close accounts for accepted B work without cancelling its external port.
        closed = app.close()
        assert closed['outcome'] == 'pending' and not app.management.store.closed and not app.reporting.root.closed
        second_release.set(); handle.wait(5); app.management.wait(5)
        assert app.management.store.closed and app.reporting.root.closed
        assert any(r.kind == 'management_outcome' for r in app.read_service_records('B'))
        assert any('root@controlled-A' in str(c) for c in commands) and any('root@controlled-B' in str(c) for c in commands)
    finally:
        first_release.set(); second_release.set(); handle.wait(5); app.close()


@pytest.mark.parametrize('treatment', ['stop', 'advance', 'hold'])
def test_actual_collection_failure_treatment_and_report_survives(tmp_path, application_factory, monkeypatch, treatment):
    collection_port(monkeypatch, failure=True)
    monitor = Monitoring(configuration=MonitoringConfig(health_check_mode='disabled', rules=(
        ObservationRule('unrequested', 'unrequested', disposition='hold', conditions=('collection',),
            on_failure=treatment, actions=({'collect': True, 'report': True},)),)))
    app, traces = application_factory(monitoring=monitor, service_configuration=configure(tmp_path), stream_options={'reads': (b'R',)})
    handle = app.start(request(tmp_path))
    try:
        outcome = await_followup(app)
        assert outcome['collection']['status'] == 'failed' and outcome['report']['status'] == 'succeeded'
        if treatment == 'hold':
            assert handle.wait(.1) is None and offers(traces) == [b'A']
            assert app.control('run', 'stop').outcome == 'completed'
        result = handle.wait(5)
        if treatment == 'advance':
            assert result.outcome == 'completed' and offers(traces) == [b'A', b'B']
        else:
            assert offers(traces) == [b'A'] and result.outcome in ('monitoring_stopped', 'stopped')
        if treatment == 'stop':
            assert result.execution_outcome == 'monitoring_stopped'
    finally:
        app.control('run', 'stop'); handle.wait(5); app.close()


@pytest.mark.parametrize('service_down', [False, True])
def test_application_heartbeat_is_independent_and_headless(tmp_path, application_factory, monkeypatch, service_down):
    import bytefault.monitoring.heartbeat as module
    observed = threading.Event()
    def process(command, **options):
        observed.set()
        return SimpleNamespace(returncode=0 if service_down else 1, stdout='controlled ICMP', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', process)
    config = ServiceConfiguration(result_root=str(tmp_path / 'results'), heartbeat=True, heartbeat_interval=.05)
    app, traces = application_factory(service_configuration=config)
    factory = app.transport_factory
    def transport(target):
        adapter = factory(target)
        stream = traces[-1][1]; connect = stream.connect; calls = [0]
        def controlled(address):
            calls[0] += 1
            stream.open_error = OSError('service down') if service_down and calls[0] > 1 else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = transport
    base = request(tmp_path, two=False)
    policy = MonitoringConfig(retries=0, recovery_delays=(), delayed_check=0, crash_throttle=0)
    app.submit(CampaignRequest(base.conversation, base.transport, base.record_path, monitoring_configuration=policy))
    assert observed.wait(5)
    wait_until(lambda: app.status('run')['heartbeat']['alive'] is not None)
    status = app.status('run')['heartbeat']
    assert status['interval'] == .05 and status['alive'] is service_down
    checks = [r.data['observation'] for r in app.read_records('run').records
              if r.kind == 'observation' and r.data['observation']['kind'] == 'service_check']
    assert checks and checks[0]['service_readiness'] == ('unavailable' if service_down else 'available')
    assert status['latest_observation']['parameters']['service_state'] == 'independent'
    app.close(); app.management.wait(5)
    wait_until(lambda: not app.status('run')['heartbeat']['running'])
    assert app.status('run')['heartbeat']['closed']
    heartbeat = [r for r in app.read_service_records() if r.kind == 'heartbeat_observation']
    assert heartbeat and heartbeat[0].data['action']['observation']['parameters']['operation']['argv'][0] == 'ping'
    # Standalone stop remains restartable; final disposal is a distinct close.
    standalone = module.HeartbeatMonitor('standalone-controlled', interval=.01, process=process)
    standalone.start(); wait_until(lambda: standalone.alive is not None)
    standalone.stop(); assert not standalone.closed
    prior = standalone.latest_observation.observation_id
    standalone.start(); wait_until(lambda: standalone.latest_observation.observation_id != prior)
    standalone.close(); assert standalone.closed and not standalone.status()['running']


def test_service_history_poll_reuses_complete_recovery_and_preserves_changed_sources(
        tmp_path, application_factory, monkeypatch):
    import os
    from bytefault.core.records import Record
    from bytefault.core.storage import LocalRecordStore, frame_record
    from bytefault.management import Management
    from bytefault.reporting import Reporting, ResultRoot
    from bytefault.ui.application_client import ApplicationView
    store = LocalRecordStore(tmp_path / 'caller.bfr')
    first = store.append('fixture', {'run_id': 'A'}, {'marker': 'before', 'context': {'bytes': b'X' * 4096}})
    other = store.append('fixture', {'run_id': 'B'}, {'marker': 'other'})
    root = ResultRoot(tmp_path / 'results')
    root.store.append('fixture', {'run_id': 'A'}, {'marker': 'reporting'})
    management = Management(store, reporting=Reporting(root))
    app, _ = application_factory(management=management)
    calls = []
    original = LocalRecordStore.snapshot
    def snapshot(value):
        calls.append(str(value.path))
        return original(value)
    monkeypatch.setattr(LocalRecordStore, 'snapshot', snapshot)
    view = None
    try:
        req = request(tmp_path, 'A', two=False)
        assert app.submit(req).outcome == 'completed'
        assert not management.wait(5)['pending']
        view = ApplicationView(app, 'A', request=req); view.refresh()
        initial = app.read_service_history('A')
        assert first in initial.refs and other not in initial.refs and not initial.issues
        assert all(record.record_id == ref.record_id for record, ref in zip(initial.records, initial.refs))
        assert app.service_record_refs('A') == initial.refs
        assert app.read_service_records('A') == initial.records
        stable_calls = tuple(calls)
        for _ in range(20):
            assert app.read_service_history('A') == initial
        assert tuple(calls) == stable_calls  # Paired polling does no unchanged recovery.
        assert not store.closed and not root.closed
        view._reset(); view.refresh()
        assert app.read_service_history('A') == initial
        assert any(record.record_id == other.record_id for record in app.read_service_records())
        # Existing direct APIs still inspect afresh; the terminal's polling
        # migration consumes read_service_history after producer review.
        before = len(calls)
        app.service_record_refs('A'); app.read_service_records('A')
        assert len(calls) == before + 4
        stable_calls = tuple(calls)

        entered, release = threading.Event(), threading.Event()
        saved_snapshot = store.snapshot
        outcomes, errors = [], []
        def held_snapshot():
            entered.set(); assert release.wait(5)
            return saved_snapshot()
        monkeypatch.setattr(store, 'snapshot', held_snapshot)
        def recover():
            try:
                outcomes.append(app.read_service_history('A', refresh=True))
            except BaseException as error:
                errors.append(error)
        reader = threading.Thread(target=recover); reader.start()
        try:
            assert entered.wait(2)
            control = []
            def observe_and_stop():
                control.append(app.status('A'))
                control.append(app.control('A', 'stop'))
            controller = threading.Thread(target=observe_and_stop); controller.start(); controller.join(.5)
            assert not controller.is_alive() and control[0]['state'] == 'completed'
            assert control[1].outcome == 'rejected'
        finally:
            release.set(); reader.join(5)
            monkeypatch.setattr(store, 'snapshot', saved_snapshot)
        assert not reader.is_alive() and outcomes and not errors
        stable_calls = tuple(calls)
        generations = dict(initial.generations)
        late = store.append('fixture', {'run_id': 'A'}, {'marker': 'late after primary'})
        appended = app.read_service_history('A')
        assert late in appended.refs and dict(appended.generations) == generations
        assert calls.count(str(store.path)) == stable_calls.count(str(store.path)) + 1
        assert calls.count(str(root.store.path)) == stable_calls.count(str(root.store.path))
        assert initial.records[0].data['marker'] == 'before'

        # An append AFTER the real reader returns must not be stamped as seen.
        saved_snapshot = store.snapshot
        appended_during_read = []
        def raced_snapshot():
            recovered = saved_snapshot()
            if not appended_during_read:
                appended_during_read.append(store.append('fixture', {'run_id': 'A'}, {'marker': 'after EOF'}))
            return recovered
        monkeypatch.setattr(store, 'snapshot', raced_snapshot)
        raced = app.read_service_history('A', refresh=True)
        assert appended_during_read[0] not in raced.refs
        assert appended_during_read[0] in app.read_service_history('A').refs
        monkeypatch.setattr(store, 'snapshot', saved_snapshot)

        # Opaque snapshot ports cannot borrow filesystem-cache semantics.
        class Opaque:
            def __init__(self):
                self.path, self.calls = store.path, 0
            def snapshot(self):
                self.calls += 1
                return original(store)
        opaque = Opaque()
        management.store = opaque
        app.service_record_refs('A'); app.service_record_refs('A')
        assert opaque.calls == 2
        management.store = store
        app.close()
        assert not store.closed and not root.closed  # Caller lifetime survives application close.
        management.close(); management.wait(5); store.close(); root.close()
        previous = app.read_service_history('A')
        valid = store.path.read_bytes()
        with store.path.open('ab') as stream:
            stream.write(b'BF')
        partial = app.read_service_history('A')
        assert partial.records == previous.records
        issue = dict(partial.issues)[str(store.path)]
        assert issue.kind == 'incomplete' and issue.offset == len(valid)
        assert app.read_service_history('A') == partial
        # Removal of the tail is a truncation, even with the same valid records.
        assert store.path.stat().st_size > len(valid)
        store.path.write_bytes(valid)
        repaired = app.read_service_history('A')
        assert not repaired.issues and dict(repaired.generations)[str(store.path)] > dict(partial.generations)[str(store.path)]
        prior_identity = app._service_stamp(store.path)[:2]
        copy = tmp_path / 'replacement.bfr'; copy.write_bytes(valid); copy.replace(store.path)
        assert app._service_stamp(store.path)[:2] != prior_identity
        same_content = app.read_service_history('A')
        assert same_content.records == repaired.records
        assert dict(same_content.generations)[str(store.path)] > dict(repaired.generations)[str(store.path)]
        replacement = Record('replacement', 'fixture', {'run_id': 'A'}, {'marker': 'replacement'})
        replacement_frame = frame_record(replacement)
        assert store.path.stat().st_size > len(replacement_frame)
        store.path.write_bytes(replacement_frame)
        replaced = app.read_service_history('A')
        assert replaced.records[0] == replacement and first not in replaced.refs
        assert dict(replaced.generations)[str(store.path)] > dict(same_content.generations)[str(store.path)]
        corrupt = bytearray(replacement_frame); corrupt[-1] ^= 1
        cached_stamp, cached_recovery, _ = app._service_snapshots[str(store.path)]
        assert cached_recovery.records == (replacement,) and cached_recovery.issue is None
        assert cached_stamp == app._service_stamp(store.path)
        stat = store.path.stat()
        store.path.write_bytes(corrupt)
        # Ordinary same-size writes may retain all sampled metadata. Give the
        # polling-invalidation assertion a controlled, verified changed hint.
        os.utime(store.path, ns=(stat.st_atime_ns, cached_stamp[3] + 2_000_000_000))
        changed_stamp = app._service_stamp(store.path)
        assert changed_stamp[:3] == cached_stamp[:3]  # Same file and byte length.
        assert changed_stamp[3] != cached_stamp[3]
        before = calls.count(str(store.path))
        corrupted = app.read_service_history('A')
        assert calls.count(str(store.path)) == before + 1
        assert dict(corrupted.issues)[str(store.path)].kind == 'corrupt'
        assert all(ref.path != str(store.path) for ref in corrupted.refs)

        # Separately prime a valid recovery, then force inspection immediately
        # after changed bytes, without assuming that write changes metadata.
        store.path.write_bytes(replacement_frame)
        primed = app.read_service_history('A', refresh=True)
        assert replacement in primed.records and not primed.issues
        store.path.write_bytes(corrupt)
        assert store.path.stat().st_size == len(replacement_frame)
        before = len(calls)
        forced_corrupt = app.read_service_history('A', refresh=True)
        assert len(calls) == before + 2
        assert dict(forced_corrupt.issues)[str(store.path)].kind == 'corrupt'
        assert all(ref.path != str(store.path) for ref in forced_corrupt.refs)
        store.path.unlink()
        assert not store.path.exists()
        assert dict(app.read_service_history('A').issues)[str(store.path)].kind == 'not_found'
        store.path.write_bytes(replacement_frame)
        assert replacement in app.read_service_history('A').records
        # Fresh inspection also recovers again when bytes are unchanged.
        before = len(calls)
        fresh = app.read_service_history('A', refresh=True)
        assert replacement in fresh.records and len(calls) == before + 2
        assert fresh.records == app.read_service_records('A')
    finally:
        management.store = store
        if view is not None:
            view.close()
        app.close(); management.close(); management.wait(5); store.close(); root.close()


@pytest.mark.parametrize('failure', ['run_completion_history', 'management_history', 'report_write', 'operator_stop'])
def test_accepted_report_survives_stop_and_required_history_failure(tmp_path, application_factory, monkeypatch, failure):
    entered, release = threading.Event(), threading.Event()
    collection_port(monkeypatch, gates=((entered, release),))
    monitor = Monitoring(configuration=MonitoringConfig(health_check_mode='disabled', rules=(
        ObservationRule('unrequested', 'unrequested', disposition='hold', conditions=('collection', 'report'),
            on_failure='stop', actions=({'collect': True, 'report': True},)),)))
    app, traces = application_factory(monitoring=monitor, service_configuration=configure(tmp_path), stream_options={'reads': (b'R',)})
    handle = app.start(request(tmp_path))
    try:
        assert entered.wait(5)
        if failure == 'run_completion_history':
            # Required application persistence boundary, after event admission.
            engine = app._run('run').engine
            append = engine.record_store.append
            def broken(kind, identity, data):
                if kind == 'monitoring_completion':
                    raise OSError('controlled run completion history failure')
                return append(kind, identity, data)
            monkeypatch.setattr(engine.record_store, 'append', broken)
        elif failure == 'management_history':
            append = app.management.store.append
            def broken(kind, identity, data):
                if kind == 'collection_outcome':
                    raise OSError('controlled Management outcome history failure')
                return append(kind, identity, data)
            monkeypatch.setattr(app.management.store, 'append', broken)
        elif failure == 'report_write':
            monkeypatch.setattr(app.reporting.layout, '_render', lambda *args:
                (_ for _ in ()).throw(OSError('controlled report output failure')))
        else:
            assert app.control('run', 'stop').outcome == 'completed'
        release.set()
        result = handle.wait(5)
        app.management.wait(5)
        service = app.read_service_records('run')
        if failure == 'report_write':
            assert result.outcome == 'monitoring_stopped'
            assert any(r.kind == 'report_outcome' and r.data['outcome']['status'] == 'failed' for r in service)
        else:
            assert any(r.kind == 'report_outcome' and r.data['outcome']['status'] == 'succeeded' for r in service)
            assert app.reporting.layout.snapshot()
            assert result.outcome == ('stopped' if failure == 'operator_stop' else 'recording_failed')
        assert offers(traces) == [b'A']
        if failure == 'run_completion_history':
            assert any(r.kind == 'management_completion_delivery_failed' for r in service)
        if failure == 'management_history':
            assert any(r.kind == 'management_failure' for r in service)
    finally:
        release.set(); app.control('run', 'stop'); handle.wait(5); app.close()


def test_heartbeat_output_is_in_source_alias_admission(tmp_path, application_factory):
    from hashlib import sha256
    from bytefault.core.contracts import ContractError, PreparedContribution, SourceInvocation
    base = request(tmp_path, two=False)
    root = tmp_path / 'results'; root.mkdir()
    path = root / ('heartbeat-' + sha256(base.transport.host.encode()).hexdigest()[:16] + '.bfr')
    path.write_bytes(b'SOURCE')
    contribution = PreparedContribution('source', b'X', SourceInvocation('s', 'file', options={'path': str(path)}))
    base = replace(base, conversation=replace(base.conversation, row=PreparedRow('row', 1, (contribution,))))
    app, traces = application_factory(service_configuration=ServiceConfiguration(result_root=str(root), heartbeat=True))
    with pytest.raises(ContractError, match='source_collision'):
        app.submit(base)
    assert not traces and path.read_bytes() == b'SOURCE' and not (root / 'results.bfr').exists()


def test_direct_owner_route_is_admitted_until_close_autofinalizes(tmp_path, application_factory, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    collection_port(monkeypatch, gates=((entered, release),))
    app, _ = application_factory(service_configuration=configure(tmp_path))
    # Establish ordinary owned service attachments without selecting follow-up.
    assert app.submit(request(tmp_path, two=False)).outcome == 'completed'
    from test_reporting_collection import action
    selected = action('direct', collect=True, report=True)
    results = []
    thread = threading.Thread(target=lambda: results.append(app.service('management', selected)))
    thread.start()
    try:
        assert entered.wait(5)
        assert app.close()['outcome'] == 'pending'
        assert not app.management.store.closed and not app.reporting.root.closed
        assert app.service('management', selected).status == 'unavailable'
        release.set(); thread.join(5); app.management.wait(5)
        assert not thread.is_alive() and results[0].report.status == 'succeeded'
        assert app.management.store.closed and app.reporting.root.closed
        assert any(r.kind == 'management_outcome' for r in app.read_service_records('direct'))
    finally:
        release.set(); thread.join(5); app.close()


@pytest.mark.parametrize('reserved', [False, True])
def test_required_heartbeat_history_failure_stops_same_host_offers(tmp_path, application_factory, monkeypatch, reserved):
    import bytefault.monitoring.heartbeat as heartbeat_module
    from bytefault.logging import ActionLog
    ping_entered, ping_release, collect_entered, collect_release, initialize_release = (threading.Event() for _ in range(5))
    def process(command, **options):
        if command[0] == 'ping':
            ping_entered.set(); assert ping_release.wait(8)
            return SimpleNamespace(returncode=0, stdout='alive', stderr='')
        collect_entered.set(); assert collect_release.wait(8)
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(heartbeat_module.subprocess, 'run', process)
    opened = ActionLog.open
    def log_open(path, *, owner='run'):
        log = opened(path, owner=owner)
        if Path(path).name.startswith('heartbeat-'):
            monkeypatch.setattr(log.store, 'append', lambda *args:
                (_ for _ in ()).throw(OSError('controlled required heartbeat history failure')))
        return log
    monkeypatch.setattr(ActionLog, 'open', log_open)
    monitor = Monitoring(configuration=MonitoringConfig(health_check_mode='disabled', rules=(
        ObservationRule('unrequested', 'unrequested', disposition='hold', conditions=('collection',), actions=({'collect': True},)),)))
    config = replace(configure(tmp_path), heartbeat=True, heartbeat_interval=.01)
    app, traces = application_factory(monitoring=monitor, service_configuration=config)
    if reserved:
        engine = app._engine
        def delayed(request):
            assert initialize_release.wait(8)
            return engine(request)
        app._engine = delayed
    handle = app.start(request(tmp_path))
    try:
        assert ping_entered.wait(5)
        if not reserved:
            assert collect_entered.wait(5) and offers(traces) == [b'A']
        ping_release.set()
        wait_until(lambda: app.status('run')['storage_failure'] is not None)
        initialize_release.set()
        result = handle.wait(5)
        assert result.outcome == 'recording_failed'
        assert offers(traces) == ([] if reserved else [b'A'])
        assert app.status('run')['storage_failure']['required_record_kind'] == 'heartbeat_required_history'
        collect_release.set(); app.management.wait(5)
        assert app.status('run')['heartbeat']['error']
    finally:
        ping_release.set(); collect_release.set(); initialize_release.set(); handle.wait(5); app.close()


@pytest.mark.parametrize('mode,exit_code', [('success', 0), ('report_failure', 1),
    ('replay_module', 0), ('replay_script', 0), ('replay_root', 0), ('replay_root_partial', 1)])
def test_actual_process_cli_drains_selected_work_and_retains_primary_result(services_child, mode, exit_code):
    from bytefault.core.records import decode_value
    process, root = services_child(mode)
    stdout, stderr = process.communicate(timeout=20)
    assert process.returncode == exit_code, stderr.decode(errors='replace')
    marker = json.loads((root / 'exit.json').read_text())
    ordered_replay = mode in ('replay_module', 'replay_script', 'replay_root')
    offered = (['41', '42', '43', '44'] if ordered_replay else
               ['41', '4242', '42', '43'] if mode == 'replay_root_partial' else ['00ff'])
    assert marker == {'code': exit_code, 'store_closed': True, 'root_closed': True,
                      'pending': 0, 'pending_close_observed': True, 'ui_imported': False, 'offered': offered}
    rows = [decode_value(json.loads(line)) for line in stdout.decode().splitlines()]
    assert rows[0]['outcome'] == ('transport_failed' if mode == 'replay_root_partial' else 'completed')
    if mode.startswith('replay_'):
        items = rows[0]['literal_items']
        assert [item['state'] for item in items] == (['completed'] * 4 if ordered_replay else
            ['completed', 'transport_failed', 'completed'])
        if ordered_replay:
            assert 'packets.txt:4:' in stderr.decode()
        else:
            failed = items[1]['result']['actions'][-1]['transport']
            assert (failed['offered'], failed['accepted_count'], failed['accepted_prefix'], failed['acceptance']) == (
                b'BB', 1, b'B', 'partial')
    followup = next(row['followup'] for row in rows if 'followup' in row)
    # This caller selects RulePolicy's no-retry advance; the failed item stays
    # failed while the third item actually runs. Callable stop/no-policy cases
    # above independently retain the unsent remainder.
    assert followup['completed_total'] == (4 if ordered_replay else 3 if mode == 'replay_root_partial' else 1)
    assert not followup['pending']
    assert followup['outcome'] == ('failed' if mode == 'report_failure' else 'completed')
    assert followup['outcomes'][0]['outcome']['report']['status'] == ('failed' if mode == 'report_failure' else 'succeeded')


@pytest.mark.parametrize('held_callback_return', [False, True])
def test_one_close_finalizes_when_services_drain_before_run_cleanup(
        tmp_path, application_factory, monkeypatch, held_callback_return):
    from bytefault.logging import ActionLog
    log = ActionLog.open(tmp_path / 'application.bfr', owner='application')
    app, traces = application_factory(action_logs=(log,), service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results')))
    entered, release = threading.Event(), threading.Event()
    callback_entered, callback_release = threading.Event(), threading.Event()
    closer, close_results, close_errors = None, [], []
    release_root = app._release_owned_result_root
    def release_result_root():
        release_root()
        if (held_callback_return and threading.current_thread() is closer and
                app.management._finalizing and not callback_entered.is_set()):
            # Stores have settled and the callback found the active run. Pause
            # only its return, exposing the gap before Management.finalized.
            callback_entered.set(); assert callback_release.wait(8)
    monkeypatch.setattr(app, '_release_owned_result_root', release_result_root)
    factory = app.transport_factory
    def transport(target):
        adapter = factory(target)
        stream = traces[-1][1]; close = stream.close
        def blocked():
            entered.set(); assert release.wait(8); close()
        stream.close = blocked
        return adapter
    app.transport_factory = transport
    handle = app.start(request(tmp_path, two=False))
    try:
        assert entered.wait(5)
        if held_callback_return:
            def close():
                try:
                    close_results.append(app.close())
                except BaseException as error:
                    close_errors.append(error)
            closer = threading.Thread(target=close)
            closer.start(); assert callback_entered.wait(5)
            assert app.management.store.closed and not app.management.status()['finalized']
        else:
            assert app.close()['outcome'] == 'pending'
            assert app.management.status()['finalized']
        assert not log.closed
        assert not app.reporting.root.closed and not app.reporting.root.store.closed
        release.set(); assert handle.wait(5) is not None
        if held_callback_return:
            # The last run must release the drained root without waiting for
            # callback return or requiring a second caller close.
            assert app.reporting.root.closed and not app.management.status()['finalized']
            callback_release.set(); closer.join(5)
            assert not closer.is_alive() and close_results and not close_errors
        wait_until(lambda: log.closed)
        assert app.management.store.closed and app.reporting.root.closed
    finally:
        release.set(); callback_release.set()
        if closer is not None:
            closer.join(5)
        handle.wait(5); app.close()


def test_uncompleted_ping_is_unavailable_without_execution_stop(tmp_path, application_factory, monkeypatch):
    import bytefault.monitoring.heartbeat as module
    def unavailable(*args, **kwargs):
        raise OSError('controlled ping executable unavailable')
    monkeypatch.setattr(module.subprocess, 'run', unavailable)
    config = ServiceConfiguration(result_root=str(tmp_path / 'results'), heartbeat=True, heartbeat_interval=.01)
    app, traces = application_factory(service_configuration=config)
    assert app.submit(request(tmp_path, two=False)).outcome == 'completed'
    wait_until(lambda: app.status('run')['heartbeat']['latest_observation'] is not None)
    status = app.status('run')['heartbeat']
    assert status['alive'] is None and status['consecutive_failures'] == 0 and status['error'] is None
    assert status['latest_observation']['parameters']['measurement'] == 'unavailable'
    assert status['latest_observation']['parameters']['operation']['error_type'] == 'OSError'
    assert app.status('run')['storage_failure'] is None and offers(traces) == [b'A']
    app.close()


def test_expired_hold_keeps_actual_late_collection_and_report(tmp_path, application_factory, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    collection_port(monkeypatch, gates=((entered, release),))
    monitor = Monitoring(configuration=MonitoringConfig(health_check_mode='disabled', rules=(
        ObservationRule('unrequested', 'unrequested', disposition='hold', conditions=('collection',),
            hold_timeout=.1, on_expiry='advance', actions=({'collect': True, 'report': True},)),)))
    app, traces = application_factory(monitoring=monitor, service_configuration=configure(tmp_path), stream_options={'reads': (b'R',)})
    handle = app.start(request(tmp_path))
    try:
        assert entered.wait(5)
        result = handle.wait(5)
        assert result.outcome == 'completed' and offers(traces) == [b'A', b'B']
        records = app.read_records('run').records
        assert any(r.kind == 'monitoring_expiry_result' and r.data['applied'] for r in records)
        assert app.management.status()['outcome'] == 'pending'
        release.set(); app.management.wait(5)
        service = app.read_service_records('run')
        assert any(r.kind == 'management_completion' and r.data['completion']['status'] == 'succeeded' for r in service)
        assert any(r.kind == 'report_outcome' and r.data['outcome']['status'] == 'succeeded' for r in service)
    finally:
        release.set(); handle.wait(5); app.close()


@pytest.mark.parametrize('disabled_success', [False, True])
def test_readiness_only_actual_service_recovery_needs_no_management(tmp_path, application_factory, disabled_success):
    config = MonitoringConfig(retries=0, recovery_delays=(0,), delayed_check=0, crash_throttle=0,
        disabled_rules=('service_success',) if disabled_success else (),
        rules=(ObservationRule('service_failure', 'service_failure', disposition='hold', conditions=('readiness',)),))
    app, traces = application_factory(stream_options={'reads': (b'R',)})
    factory = app.transport_factory
    def transport(target):
        adapter = factory(target)
        stream = traces[-1][1]; connect = stream.connect; count = [0]
        def controlled(address):
            count[0] += 1
            stream.open_error = OSError('controlled service down') if count[0] == 2 else None
            return connect(address)
        stream.connect = controlled
        return adapter
    app.transport_factory = transport
    base = request(tmp_path)
    handle = app.start(CampaignRequest(base.conversation, base.transport, base.record_path, monitoring_configuration=config))
    try:
        if disabled_success:
            wait_until(lambda: any(r.kind == 'observation' and r.data['observation']['service_readiness'] == 'available'
                                  for r in app.read_records('run').records))
            assert handle.wait(.1) is None and offers(traces) == [b'A', b'B']
            completions = [r.data['completion'] for r in app.read_records('run').records
                if r.kind == 'monitoring_completion']
            assert len(completions) == 1 and completions[0]['condition'] == 'readiness'
            assert completions[0]['status'] == 'failed'
            return
        assert handle.wait(5).outcome == 'monitoring_failed'
        assert app.management is None and offers(traces) == [b'A', b'B']
        assert any(r.kind == 'monitoring_completion' and r.data['completion']['condition'] == 'readiness'
                   for r in app.read_records('run').records)
    finally:
        app.control('run', 'stop'); handle.wait(5); app.close()


def test_supplied_actual_owner_outputs_are_admitted_without_service_configuration(tmp_path, application_factory):
    from bytefault.core.contracts import ContractError, PreparedContribution, SourceInvocation
    from bytefault.core.storage import LocalRecordStore
    from bytefault.management import Management
    from bytefault.reporting import Reporting, ResultRoot
    from bytefault.logging import ActionLog
    first, second = ResultRoot(tmp_path / 'first'), ResultRoot(tmp_path / 'second')
    store = LocalRecordStore(tmp_path / 'caller-management.bfr')
    management = Management(store, reporting=Reporting(second))
    application_log = ActionLog.open(tmp_path / 'application.bfr', owner='application')
    app, traces = application_factory(management=management, reporting=Reporting(first), action_logs=(application_log,))
    try:
        targets = (store.path, management.action_log.store.path, first.store.path, application_log.store.path)
        for number, path in enumerate(targets):
            before = path.read_bytes()
            base = request(tmp_path, 'source-' + str(number), two=False)
            contribution = PreparedContribution('source', b'X', SourceInvocation('s', 'file', options={'path': str(path)}))
            base = replace(base, conversation=replace(base.conversation, row=PreparedRow('row', 1, (contribution,))))
            with pytest.raises(ContractError, match='source_collision'):
                app.submit(base)
            assert path.read_bytes() == before and not traces
    finally:
        app.close(); management.close(); management.wait(5); store.close(); first.close(); second.close()


def test_automatic_finalization_failure_keeps_primary_result_and_actual_cleanup(tmp_path, application_factory, monkeypatch):
    from bytefault.logging import ActionLog
    log = ActionLog.open(tmp_path / 'application.bfr', owner='application')
    app, traces = application_factory(action_logs=(log,), service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results')))
    entered, release = threading.Event(), threading.Event()
    factory = app.transport_factory
    def transport(target):
        adapter = factory(target)
        stream = traces[-1][1]; close = stream.close
        def blocked():
            entered.set(); assert release.wait(8); close()
        stream.close = blocked
        return adapter
    app.transport_factory = transport
    end = log.end
    def failure(boundary):
        if boundary == 'application':
            raise OSError('controlled application log finalization failure')
        return end(boundary)
    monkeypatch.setattr(log, 'end', failure)
    handle = app.start(request(tmp_path, two=False))
    try:
        assert entered.wait(5) and app.close()['outcome'] == 'pending'
        release.set(); result = handle.wait(5)
        assert result.execution_outcome == 'completed' and result.outcome == 'cleanup_failed'
        assert result.application_cleanup_errors[-1]['operation'] == 'application_finalize'
        actual = app.status('run')['application_finalization']
        assert actual['outcome'] == 'failed' and actual['cleanup_failures']
        assert any(r.kind == 'application_cleanup_failure' for r in log.store.snapshot().records)
        assert offers(traces) == [b'A']
    finally:
        release.set(); handle.wait(5); monkeypatch.setattr(log, 'end', end); app.close()
