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
import threading
import time
from uuid import uuid4

import pytest

from bytefault.core.contracts import (Correlation, MonitoringAction, MonitoringDecision, ContractError,
    ReceiveRequest, ConversationAction, PassivePlan, PreparedRow, ConversationRequest, TransportRequest)
from bytefault.core.storage import LocalRecordStore
from bytefault.management import Management, CollectionOutcome
from bytefault.reporting import ResultRoot, Reporting, ReportRequest, ReportOutcome, WriterAttachedError
from bytefault.application import ApplicationRequest
from bytefault.monitoring import Monitoring


def action(**parameters):
    return MonitoringAction('action', 'event', 'observation',
        Correlation('run', 'case', 'conversation', 'send', 'attempt'), 'followup', parameters)


def test_independent_owner_attachments_and_caller_lifetime(tmp_path, application_factory, monkeypatch):
    from bytefault.core.contracts import Observation, TransportResult
    root = ResultRoot(tmp_path / 'results')
    store = LocalRecordStore(tmp_path / 'management.bfr')
    independent = LocalRecordStore(tmp_path / 'independent-monitoring.bfr')
    management = Management(store)
    def report(request):
        return ReportOutcome(request.report_id, request.action.event_id,
            request.action.action_id, 'succeeded', 'fixture/independent-report')
    reporting = Reporting(root, port=report)
    app, traces = application_factory(reporting=reporting)
    selected = action(report=True)
    request = ReportRequest('independent', selected, 'disabled')
    try:
        assert app.service('reporting', request).status == 'succeeded'
        assert app.inspect()['service_attachments']['reporting']['attached']
        assert not traces  # No Management or engine required for Reporting.
        app.close()
        assert not root.closed and not root.store.closed
        management.close(); management._worker.join(5)
        monitoring = Monitoring()
        from bytefault.logging import ActionLog
        app2, traces2 = application_factory(monitoring=monitoring, management=management,
                                           reporting=reporting, action_logs=(ActionLog(independent),))
        observation = Observation('standalone', selected.correlation, TransportResult(b'A'))
        assert app2.service('monitoring', observation).observation_id == 'standalone'
        # This acknowledged path belongs to no attached service store. Its
        # complete selected history is still independently discoverable.
        own = app2.read_service_history('run')
        admitted = tuple(ref for ref in own.refs if ref.path == str(independent.path))
        assert admitted and {r.kind for r, ref in zip(own.records, own.refs)
                             if ref in admitted} >= {'monitoring_observation', 'monitoring_decision'}
        unrelated = independent.append('fixture', {'run_id': 'run'}, {'unacknowledged_by_application': True})
        assert unrelated not in app2.service_record_refs('run')
        assert unrelated.record_id not in {r.record_id for r in app2.read_service_records()}
        import bytefault.application as module
        reopen = module.reopen_records
        calls = []
        def reader(path):
            calls.append(str(path))
            return reopen(path)
        monkeypatch.setattr(module, 'reopen_records', reader)
        for _ in range(10):
            assert app2.read_service_history('run').refs == own.refs
        assert not calls
        second_observation = replace(observation, observation_id='standalone-second')
        assert app2.service('monitoring', second_observation).observation_id == 'standalone-second'
        advanced = app2.read_service_history('run')
        assert len(advanced.refs) > len(own.refs) and unrelated not in advanced.refs
        assert calls == [str(independent.path)]
        assert app2.service('reporting', replace(request, report_id='after-management-close')).status == 'succeeded'
        assert app2.service('management', selected).status == 'unavailable'
        assert not traces2
        assert not root.closed and not store.closed
        root.close()
        assert app2.service('reporting', request).status == 'unavailable'
        app2.close()
        assert not independent.closed
        independent.close()
        with independent.path.open('ab') as stream:
            stream.write(b'BF')
        inspected = app2.read_service_history('run')
        assert dict(inspected.issues)[str(independent.path)].kind == 'incomplete'
        assert tuple(ref for ref in inspected.refs if ref.path == str(independent.path)) == tuple(
            ref for ref in advanced.refs if ref.path == str(independent.path))
    finally:
        app.close(); management.close(); management._worker.join(5); store.close(); independent.close(); root.close()


def test_followup_and_shared_root(tmp_path, application_factory):
    missing = tmp_path / 'absent'
    assert ResultRoot.read(missing).issue.kind == 'not_found'
    assert not missing.exists()
    root = ResultRoot(tmp_path / 'results')
    store = LocalRecordStore(tmp_path / 'management.bfr')
    seen = []
    def reporter(request):
        seen.append(request)
        return ReportOutcome(request.report_id, request.action.event_id,
            request.action.action_id, 'succeeded', 'fixture/report')
    management = Management(store, reporting=Reporting(root, port=reporter))
    try:
        for bad in (replace(action(), kind='recover'), action(collec=True), action(collect='yes')):
            with pytest.raises(ContractError):
                management.route(bad)
        assert not store.snapshot().records
        before = tuple(p.name for p in root.path.iterdir())
        with pytest.raises(WriterAttachedError):
            ResultRoot(root.path / '.')
        assert tuple(p.name for p in root.path.iterdir()) == before
        reader_a = ResultRoot.read(root.path)
        app, traces = application_factory(management=management)
        result = app.service('management', action(report=True, collect=False))
        assert result.collection.status == 'disabled' and result.report.status == 'succeeded'
        assert seen[0].collection_status == 'disabled'
        assert not traces  # independent service uses no engine or fuzz transport
        reader_b = ResultRoot.read(root.path)
        assert not reader_a.records and len(reader_b.records) == 2
        management.collection = lambda _: CollectionOutcome('failed', error='fixture collection failed')
        result = management.route(action(report=True, collect=True))
        assert result.collection.status == 'failed' and result.report.status == 'succeeded'
        assert seen[-1].collection_error == 'fixture collection failed'
        management.reporting.port = lambda _: (_ for _ in ()).throw(OSError('fixture report failed'))
        failed = management.route(action(report=True))
        assert failed.report.status == 'failed' and failed.report.error == 'fixture report failed'
        assert reader_b == reader_b and len(reader_b.records) == 2
        root.close()
        reopened = ResultRoot(root.path)
        try:
            assert len(reopened.store.snapshot().records) == 6
        finally:
            reopened.close()
    finally:
        management.close()
        root.close()
        store.close()


def test_result_root_process_owner_application_release_and_abrupt_recovery(tmp_path, result_owner_child, monkeypatch):
    import json
    import os
    from bytefault.application import Application
    from bytefault.management.configuration import ServiceConfiguration
    def forbidden(*args): raise AssertionError('filesystem owner workflow constructed transport')
    def application(label):
        return Application(transport_factory=forbidden,
            service_configuration=ServiceConfiguration(result_root=str(root_path),heartbeat=False))
    def report(app,label):
        selected = MonitoringAction(label+'-action',label+'-event',label+'-observation',
            Correlation(label+'-run','independent',label+'-session','result_owner','1'),'followup',{'report':True})
        outcome = app.service('reporting',ReportRequest(label+'-report',selected,'disabled',
            context={'independent':True,'bytes':b'\0\xff'}))
        assert outcome.status == 'succeeded'
        return outcome.report_id
    def wait_ready(child,work):
        deadline = time.monotonic()+5
        while not (work/'ready').exists() and child.poll() is None and time.monotonic()<deadline:
            time.sleep(.01)
        assert (work/'ready').exists(),child.communicate(timeout=2)
    def finish(child,work):
        out,err = child.communicate(timeout=5)
        (work/'output.txt').write_bytes(out); (work/'error.txt').write_bytes(err)
        assert child.returncode == 0,(out,err)
        return json.loads((work/'observed.json').read_text())
    def namespace():
        return {str(p.relative_to(root_path)):
            ('owner_control',p.stat().st_dev,p.stat().st_ino,p.stat().st_size)
            if p.name == '.bytefault-owner.lock' else p.read_bytes()
            for p in root_path.rglob('*') if p.is_file()}
    root_path = tmp_path/'results'
    missing = tmp_path/'read-only-missing'
    assert ResultRoot.read(missing).issue.kind == 'not_found' and not missing.exists()
    owner = application('parent')
    try:
        with owner.independent_operation(TransportRequest('offline.invalid',1234,1),services=True,
                log_path=str(tmp_path/'parent-actions.bfr')):
            first = report(owner,'parent')
            assert not owner._runs and not owner._heartbeats
            before = namespace()
            child,work = result_owner_child('attempt',root_path/'..'/'results')
            contender = finish(child,work)
            assert not contender['admitted'],contender
            assert contender['error_type'] == 'WriterAttachedError'
            assert namespace() == before
            if os.name == 'nt':
                with pytest.raises(WriterAttachedError):
                    ResultRoot(str(root_path).swapcase())
                assert namespace() == before
            from bytefault.management.maintenance import MaintenanceRequest, run_maintenance
            with pytest.raises(ContractError, match='maintenance.destinations'):
                run_maintenance(MaintenanceRequest(local_cache=str(root_path), remote=False,
                    local_entries=(ResultRoot.OWNER_FILE,), log_path=str(tmp_path/'maintenance-actions.bfr')), owner)
            assert namespace() == before
            # Same-process configured attachment must also reject before opening
            # even an otherwise valid action-log destination under that namespace.
            rival = application('rival')
            try:
                with pytest.raises(WriterAttachedError):
                    with rival.independent_operation(TransportRequest('offline.invalid',1234,1),services=True,
                            log_path=str(root_path/'contender-actions.bfr')): pass
                assert namespace() == before
            finally: rival.close()
            reader = ResultRoot.read(root_path)
            assert reader.issue is None and any(r.kind == 'report_result' for r in reader.records)
        assert not owner.reporting.root.closed
    finally: owner.close()
    expected = {r.record_id for r in ResultRoot.read(root_path).records}
    child,work = result_owner_child('hold',root_path)
    wait_ready(child,work)
    snapshot = ResultRoot.read(root_path)
    assert snapshot.issue is None and expected < {r.record_id for r in snapshot.records}
    before = namespace()
    with pytest.raises(WriterAttachedError): ResultRoot(root_path/'.')
    assert namespace() == before
    (work/'release').write_text('release')
    closed = finish(child,work)
    assert closed['closed'] and closed['close']['outcome'] == 'completed'
    refreshed = ResultRoot.read(root_path)
    assert len(refreshed.records)>len(snapshot.records) and len(snapshot.records)>len(reader.records)
    expected = {r.record_id for r in refreshed.records}
    child,work = result_owner_child('abrupt',root_path)
    wait_ready(child,work)
    acknowledged = ResultRoot.read(root_path)
    assert acknowledged.issue is None and expected < {r.record_id for r in acknowledged.records}
    child.kill(); child.wait(timeout=5)
    after = application('after-death')
    try:
        with after.independent_operation(TransportRequest('offline.invalid',1234,1),services=True,
                log_path=str(tmp_path/'after-actions.bfr')):
            assert {r.record_id for r in acknowledged.records} <= {r.record_id for r in after.reporting.root.store.snapshot().records}
            report(after,'after')
            events = after.reporting.layout.snapshot()
            report_ids = {revision['report_id'] for event in events for occurrence in event['occurrences'].values()
                for revision in occurrence['revisions']}
            assert report_ids == {first,'hold-report-0','hold-report-1','abrupt-report-0','after-report'}
            assert len(events) == 4
            assert not (root_path/'INDEX.md').exists() and not (root_path/'LATEST.md').exists()
    finally: after.close()
    # Failed construction must release both reservation mechanisms before retry.
    failed_root = tmp_path/'failed-constructor'
    from bytefault.logging import ActionLog
    with monkeypatch.context() as patch:
        patch.setattr(ActionLog,'open',lambda *args,**kwargs: (_ for _ in ()).throw(OSError('controlled reporting log open failure')))
        with pytest.raises(OSError,match='controlled reporting log'): ResultRoot(failed_root)
    reopened = ResultRoot(failed_root)
    reopened.close()


def test_no_selected_action_does_no_management_work(tmp_path, application_factory):
    store = LocalRecordStore(tmp_path / 'management.bfr')
    management = Management(store)
    app, _ = application_factory(management=management)
    try:
        from test_logging_lifetime import app_request
        assert app.submit(app_request(tmp_path)).outcome == 'completed'
        assert not store.snapshot().records
        assert not management.status()['pending']
    finally:
        app.close(); management.close(); management._worker.join(5); store.close()


def test_queue_pressure_and_pending_shutdown(tmp_path):
    store = LocalRecordStore(tmp_path / 'management.bfr')
    entered, release = threading.Event(), threading.Event()
    def collect(action):
        entered.set(); assert release.wait(5)
        return CollectionOutcome('succeeded')
    management = Management(store, collection=collect, capacity=1)
    completions = []
    selected = action(collect=True)
    decision = MonitoringDecision('decision', selected.observation_id, selected.correlation,
        'continue', actions=(selected,))
    try:
        management.dispatch(decision, completions.append)
        assert entered.wait(5)
        management.dispatch(decision, completions.append)
        management.dispatch(decision, completions.append)
        assert len(management.status()['pending']) == 2  # one active + one queued
        rejected = [value for value in completions if value.status == 'failed']
        assert len(rejected) == 1
        assert rejected[0].condition == 'collection' and rejected[0].followup_action_id == 'action'
        assert any(r.kind == 'management_rejected' for r in store.snapshot().records)
        assert management.close()['outcome'] == 'pending'
        assert not management.action_log.closed
        release.set()
        management._worker.join(5)
        assert not management._worker.is_alive() and management.action_log.closed
        assert len(management.status()['outcomes']) == 1  # bounded view, full store retained
    finally:
        release.set(); management.close(); management._worker.join(5); store.close()


def test_required_service_history_failure_stops_held_engine(tmp_path, application_factory, monkeypatch, capsys):
    store = LocalRecordStore(tmp_path / 'management.bfr')
    management = Management(store)
    original = store.append
    def save(kind, identity, data):
        if kind == 'management_request':
            raise OSError('required Management history unavailable')
        return original(kind, identity, data)
    monkeypatch.setattr(store, 'append', save)
    class Policy:
        def evaluate(self, observation):
            selected = MonitoringAction('followup', 'event', observation.observation_id,
                observation.correlation, 'followup', {'report': True})
            return MonitoringDecision('hold', observation.observation_id, observation.correlation,
                'hold', 'awaited', ('report',), actions=(selected,))
    app, traces = application_factory(monitoring=Monitoring(Policy()), management=management)
    from test_logging_lifetime import app_request
    from bytefault.fuzzers.inputs import positional_plan
    request = app_request(tmp_path)
    request = replace(request, conversation=replace(request.conversation,
        plan=positional_plan((b'A', b'B')), selected_actions=('1', '2')))
    results = []
    thread = threading.Thread(target=lambda: results.append(app.submit(request)))
    thread.start()
    thread.join(5)
    try:
        assert not thread.is_alive() and results[0].outcome == 'recording_failed'
        assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == [b'A']
        assert 'required Management history unavailable' in capsys.readouterr().err
    finally:
        app.close(); thread.join(5); management.close(); management._worker.join(5); store.close()


def test_selected_route_correlated_hold_and_nonblocking(tmp_path, application_factory):
    root = ResultRoot(tmp_path / 'results')
    store = LocalRecordStore(tmp_path / 'management.bfr')
    entered, release = threading.Event(), threading.Event()
    def reporter(request):
        entered.set()
        assert release.wait(5)
        return ReportOutcome(request.report_id, request.action.event_id,
                             request.action.action_id, 'succeeded', 'fixture/report')
    management = Management(store, reporting=Reporting(root, port=reporter))
    class Policy:
        awaited = True
        def evaluate(self, observation):
            if observation.correlation.action_id != 'first':
                return MonitoringDecision('continue', observation.observation_id,
                                          observation.correlation, 'continue')
            selected = MonitoringAction('action', 'event', observation.observation_id,
                observation.correlation, 'followup', {'report': True})
            return MonitoringDecision('hold', observation.observation_id, observation.correlation,
                'hold' if self.awaited else 'continue', 'awaited' if self.awaited else 'nonblocking',
                ('report',) if self.awaited else (), actions=(selected,))
    policy = Policy()
    app, traces = application_factory(monitoring=Monitoring(policy), management=management)
    request = ConversationRequest(PassivePlan('neutral', 1, (
        ConversationAction('first', b'A'), ConversationAction('second', b'B'))),
        PreparedRow('row', 1), ('first', 'second'), 'run', 'case', 'conversation')
    request = ApplicationRequest(request, TransportRequest('offline.invalid', 1234, 10),
                                 str(tmp_path / 'run.bfr'), str(tmp_path / 'run.log'))
    result = []
    thread = threading.Thread(target=lambda: result.append(app.submit(request)))
    thread.start()
    try:
        assert entered.wait(5)
        assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == [b'A']
        assert app.status('run')['engine']['monitoring_hold'] == 'hold'
        release.set()
        thread.join(5)
        assert not thread.is_alive() and result[0].outcome == 'completed'
        assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == [b'A', b'B']
        # Nonblocking selection advances even while the selected report is stalled.
        entered.clear(); release.clear(); policy.awaited = False
        request = replace(request, conversation=replace(request.conversation, run_id='run2'),
            record_path=str(tmp_path / 'run2.bfr'), log_path=str(tmp_path / 'run2.log'))
        assert app.submit(request).outcome == 'completed'
        assert entered.wait(5) and management.status()['pending']
        assert management.close()['outcome'] == 'pending'
        release.set()
        management._worker.join(5)
        assert not management._worker.is_alive()
        assert not management.status()['pending']
    finally:
        release.set()
        app.close()
        thread.join(5)
        management.close()
        management._worker.join(5)
        root.close(); store.close()


def test_each_required_collection_holds_until_its_own_completion(tmp_path, application_factory):
    """R01: two selected collections are two obligations, never one vote."""
    from bytefault.core.contracts import MonitoringCompletion
    entered_first, release_first, entered_second, release_second = (
        threading.Event() for _ in range(4))
    def collect(selected):
        entered, release = ((entered_first, release_first) if selected.action_id == 'collect-one'
                            else (entered_second, release_second))
        entered.set()
        assert release.wait(5)
        return CollectionOutcome('succeeded')
    store = LocalRecordStore(tmp_path / 'management.bfr')
    management = Management(store, collection=collect)
    class Policy:
        def evaluate(self, observation):
            if observation.correlation.action_id != 'first':
                return MonitoringDecision('continue', observation.observation_id,
                                          observation.correlation, 'continue')
            selected = tuple(MonitoringAction(identity, 'event', observation.observation_id,
                observation.correlation, 'followup', {'collect': True})
                for identity in ('collect-one', 'collect-two'))
            return MonitoringDecision('wait-all', observation.observation_id,
                observation.correlation, 'hold', 'awaited', ('collection',), actions=selected)
    app, traces = application_factory(monitoring=Monitoring(Policy()), management=management)
    conversation = ConversationRequest(PassivePlan('neutral', 1, (
        ConversationAction('first', b'A'), ConversationAction('second', b'B'))),
        PreparedRow('row', 1), ('first', 'second'), 'multi-followup', 'case', 'conversation')
    request = ApplicationRequest(conversation, TransportRequest('offline.invalid', 1234, 10),
                                 str(tmp_path / 'run.bfr'), str(tmp_path / 'run.actions.bfr'))
    results = []
    thread = threading.Thread(target=lambda: results.append(app.submit(request)))
    thread.start()
    try:
        assert entered_first.wait(5)
        deadline = time.monotonic() + 3
        while len(management.status()['pending']) < 2 and time.monotonic() < deadline:
            time.sleep(.005)
        assert len(management.status()['pending']) == 2
        release_first.set()
        # The serial Management worker reaches collection two only after one
        # has returned its actual completion through the ordinary application.
        assert entered_second.wait(5)
        engine = app._run('multi-followup').engine
        hold = engine.continuation.hold
        assert hold is not None and hold.decision_id == 'wait-all'
        assert [(value.condition, value.followup_action_id) for value in hold.obligations] == [
            ('collection', 'collect-one'), ('collection', 'collect-two')]
        assert [v[1] for v in traces[0][0] if v[0] == 'offer'] == [b'A']
        assert len(management.status()['pending']) == 1
        def complete(identity, status='succeeded', decision_id=hold.decision_id, completion_id=None):
            return engine.complete_monitoring(MonitoringCompletion(completion_id or str(uuid4()),
                decision_id, hold.observation_id, hold.correlation, 'collection', status,
                followup_action_id=identity))
        assert complete(None) is False  # a condition-only completion is ambiguous
        assert complete('unselected-action') is False
        assert complete('collect-two', decision_id='old-decision') is False
        malformed = MonitoringCompletion(str(uuid4()), hold.decision_id, hold.observation_id,
            hold.correlation, 'collection', 'succeeded', followup_action_id=['collect-two'])
        with pytest.raises(ContractError, match='monitoring.completion.followup_action_id'):
            engine.complete_monitoring(malformed)
        malformed = replace(malformed, followup_action_id='collect-two',
                            correlation=replace(hold.correlation, attempt_id=['attempt']))
        with pytest.raises(ContractError, match='monitoring.completion.correlation.attempt_id'):
            engine.complete_monitoring(malformed)
        retained = next(record.data['completion'] for record in app.read_records('multi-followup').records
                        if record.kind == 'monitoring_completion' and
                        record.data['completion']['followup_action_id'] == 'collect-one' and
                        record.data['completion']['condition'] == 'collection')
        assert complete('collect-one', completion_id=retained['completion_id'])
        assert complete('collect-one', completion_id=retained['completion_id'])
        for status in ('failed', 'pending', 'disabled'):
            assert complete('collect-two', status)
            assert engine.continuation.hold is hold
        assert engine.continuation.satisfied == {('collection', 'collect-one')}
        assert [v[1] for v in traces[0][0] if v[0] == 'offer'] == [b'A']
        release_second.set()
        thread.join(5)
        assert not thread.is_alive() and results[0].outcome == 'completed'
        assert [v[1] for v in traces[0][0] if v[0] == 'offer'] == [b'A', b'B']
        records = app.read_records('multi-followup').records
        decision = next(r.data['decision'] for r in records if r.kind == 'monitoring_decision')
        assert tuple(value['followup_action_id'] for value in decision['obligations']) == (
            'collect-one', 'collect-two')
        completions = [r.data['completion'] for r in records if r.kind == 'monitoring_completion']
        assert any(value['followup_action_id'] == 'collect-two' and value['status'] == 'succeeded'
                   for value in completions)
        assert any(value['followup_action_id'] == 'collect-two' and value['status'] == 'failed'
                   for value in completions)
        assert any(value['followup_action_id'] == 'unselected-action' for value in completions)
    finally:
        release_first.set(); release_second.set()
        app.control('multi-followup', 'stop')
        thread.join(5)
        app.close(); management.close(); management._worker.join(5); store.close()


@pytest.mark.parametrize('inconsistency', ['unresolved', 'partial', 'duplicate-action'])
def test_alternate_monitoring_cannot_dispatch_an_unresolved_wait(tmp_path, application_factory, inconsistency):
    from bytefault.core.contracts import MonitoringObligation
    store = LocalRecordStore(tmp_path / 'management.bfr')
    management = Management(store)
    class Port:
        def observe(self, observation):
            selected = tuple(MonitoringAction(identity, 'event', observation.observation_id,
                observation.correlation, 'followup', {'collect': True})
                for identity in ('one', 'one' if inconsistency == 'duplicate-action' else 'two'))
            obligations = (MonitoringObligation('collection', 'one'),) if inconsistency == 'partial' else ()
            return MonitoringDecision('wait', observation.observation_id,
                observation.correlation, 'hold', 'awaited', ('collection',),
                actions=selected, obligations=obligations)
    app, traces = application_factory(monitoring=Port(), management=management)
    conversation = ConversationRequest(PassivePlan('neutral', 1, (
        ConversationAction('first', b'A'), ConversationAction('second', b'B'))),
        PreparedRow('row', 1), ('first', 'second'), 'unresolved-followup', 'case', 'conversation')
    try:
        result = app.submit(ApplicationRequest(conversation, TransportRequest('offline.invalid', 1234, 10),
            str(tmp_path / 'run.bfr'), str(tmp_path / 'run.actions.bfr')))
        assert result.outcome == 'failed'
        assert [v[1] for v in traces[0][0] if v[0] == 'offer'] == [b'A']
        assert not management.status()['pending']
        assert not store.snapshot().records
        assert 'unresolved_wait' in result.reason or 'duplicate_identity' in result.reason
    finally:
        app.close(); management.close(); management._worker.join(5); store.close()
