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

"""Service concurrency checks through actual owners and controlled external ports."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json
import threading

import pytest

from bytefault.application import CampaignRequest
from bytefault.core.contracts import MonitoringDecision, freeze
from bytefault.core.records import decode_value
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.management import Management
from bytefault.management.collection import Collection
from bytefault.management.configuration import ServiceConfiguration
from bytefault.reporting import Reporting, ResultRoot
from test_followup_heartbeat import offers, request, wait_until
from test_reporting_collection import action


@pytest.mark.parametrize('auxiliary', ['heartbeat', 'preparation'])
def test_close_stops_active_and_reserved_runs_before_blocking_auxiliary(
        tmp_path, application_factory, monkeypatch, auxiliary):
    auxiliary_entered, auxiliary_release, first_entered, send_release, reserved_entered, reserved_release = (
        threading.Event() for _ in range(6))
    configuration = (ServiceConfiguration(result_root=str(tmp_path / 'results'), heartbeat=True)
                     if auxiliary == 'heartbeat' else None)
    if auxiliary == 'heartbeat':
        import bytefault.monitoring.heartbeat as module
        ping_entered = threading.Event()
        def process(command, **options):
            assert command[0] == 'ping'
            ping_entered.set(); assert auxiliary_release.wait(8)
            return SimpleNamespace(returncode=0, stdout='controlled ping', stderr='')
        monkeypatch.setattr(module.subprocess, 'run', process)
    app, traces = application_factory(service_configuration=configuration)
    original_engine = app._engine
    def engine(value):
        if value.conversation.run_id == 'reserved':
            reserved_entered.set(); assert reserved_release.wait(8)
        return original_engine(value)
    monkeypatch.setattr(app, '_engine', engine)
    original_transport = app.transport_factory
    def transport(target):
        adapter = original_transport(target)
        stream = traces[-1][1]
        send = stream.send
        def held(data):
            accepted = send(data)
            if not first_entered.is_set():
                first_entered.set(); assert send_release.wait(8)
            return accepted
        stream.send = held
        return adapter
    app.transport_factory = transport
    active = app.start(request(tmp_path, 'active'))
    reserved = None
    closer = None
    closed, failures = [], []
    try:
        assert first_entered.wait(5)
        reserved = app.start(request(tmp_path, 'reserved'))
        assert reserved_entered.wait(5)
        if auxiliary == 'heartbeat':
            assert ping_entered.wait(5)
            owner = app._heartbeats['controlled-A']
        else:
            base = request(tmp_path, 'inspection')
            owner = app.prepare(CampaignRequest(base.conversation, base.transport, base.record_path))
        close = owner.close
        def held_close():
            auxiliary_entered.set()
            if auxiliary == 'preparation':
                assert auxiliary_release.wait(8)
            return close()
        monkeypatch.setattr(owner, 'close', held_close)
        def shutdown():
            try:
                closed.append(app.close())
            except BaseException as error:
                failures.append(error)
        closer = threading.Thread(target=shutdown)
        closer.start(); assert auxiliary_entered.wait(5)
        assert active.status()['stop_requested'] and reserved.status()['stop_requested']
        assert active.status()['engine']['stop_requested']
        assert offers(traces) == [b'A']
        send_release.set(); reserved_release.set()
        wait_until(lambda: not active.status()['active'] and not reserved.status()['active'])
        assert offers(traces) == [b'A']
        # A was already in flight: its actual acceptance remains recorded.
        records = app.read_records('active').records
        accepted = next(r.data['result']['transport'] for r in records if r.kind == 'action_result')
        assert accepted['offered'] == accepted['accepted_prefix'] == b'A'
        auxiliary_release.set(); closer.join(5)
        assert not closer.is_alive() and not failures
        assert closed[0]['pending_runs'] == ()
        assert active.wait(5).outcome == reserved.wait(5).outcome == 'stopped'
        assert all(stream.closed for trace, stream, _ in traces if any(e[0] == 'open' for e in trace))
        assert active.status()['finalized'] and reserved.status()['finalized']
    finally:
        send_release.set(); reserved_release.set(); auxiliary_release.set()
        if closer is not None:
            closer.join(5)
        active.control('stop'); active.wait(5)
        if reserved is not None:
            reserved.control('stop'); reserved.wait(5)
        app.close()


@pytest.mark.parametrize('second_mode', ['direct', 'queued'])
def test_overlapping_acquisitions_keep_exact_outcomes_and_persisted_report_context(tmp_path, second_mode):
    first_listing, second_listing, release_first = (threading.Event() for _ in range(3))
    results, errors = {}, []
    def process(command, **options):
        label = threading.current_thread().name
        assert label in ('A', 'B')
        if command[0] == 'ssh':
            assert label == 'A' and command[-1].endswith('/core-A')
            return SimpleNamespace(returncode=0, stdout='A cleanup', stderr='')
        assert command[0] == 'rsync'
        destination = Path(command[-1])
        if label == 'A':
            first_listing.set(); assert release_first.wait(5)
            (destination / 'core-A').write_bytes(b'A')
            return SimpleNamespace(returncode=0,
                stdout='BF|>f+++++++++|1|2026/10/22-15:00:57|core-A\nNumber of files: 2 (reg: 1, dir: 1)',
                stderr='')
        second_listing.set()
        partial = destination / '.rsync-partial'; partial.mkdir(exist_ok=True)
        (partial / 'core-B').write_bytes(b'')
        return SimpleNamespace(returncode=23, stdout='', stderr='B partial transfer')
    store = LocalRecordStore(tmp_path / 'management.bfr')
    root = ResultRoot(tmp_path / 'results')
    collection = Collection('controlled', ssh_key='controlled-key', cache_dir=tmp_path / 'collected',
                            core_write_wait=0, process=process)
    management = Management(store, collection=collection, reporting=Reporting(root))
    management._worker.name = 'B'
    selected = {label: action('run-' + label, 'event-' + label, 'observation-' + label,
                             collect=True, report=True, **({'cleanup': True} if label == 'A' else {}))
                for label in ('A', 'B')}
    context = {label: {'marker': label, 'transport': {'host': 'controlled'}} for label in ('A', 'B')}
    def direct(label):
        try:
            results[label] = freeze(management.route(selected[label], context=context[label]))
        except BaseException as error:
            errors.append(error)
    threads = [threading.Thread(target=direct, args=('A',), name='A')]
    try:
        threads[0].start(); assert first_listing.wait(5)
        if second_mode == 'direct':
            threads.append(threading.Thread(target=direct, args=('B',), name='B'))
            threads[1].start()
        else:
            item = selected['B']
            decision = MonitoringDecision('decision-B', item.observation_id, item.correlation,
                                          'continue', actions=(item,))
            management.dispatch(decision, lambda completion: None, errors.append, context=context['B'])
        assert not second_listing.wait(.05)  # shared cache serializes acquisition
        release_first.set()
        for thread in threads:
            thread.join(6)
        management.wait(6)
        assert not errors and not any(thread.is_alive() for thread in threads)
        if second_mode == 'queued':
            results['B'] = management.status()['outcomes'][0]['outcome']
        assert management.status()['completed_total'] == 2 and management.status()['failed_total'] == 1
        for label, count, status in (('A', 3, 'succeeded'), ('B', 2, 'failed')):
            collected = results[label]['collection']
            assert collected['status'] == status and len(collected['operations']) == count
            assert len(collected['items']) == 1
            assert collected['operations'][0]['operation'] == 'core_write_wait'
            transfer = collected['operations'][1]
            assert transfer['argv'][0] == 'rsync'
            assert all(op['started_at'] <= op['completed_at'] for op in collected['operations'])
            assert results[label]['report']['status'] == 'succeeded'
        assert Path(results['A']['collection']['artifacts'][0]).read_bytes() == b'A'
        assert not results['B']['collection']['artifacts']
        assert Path(results['B']['collection']['items'][0]['path']).read_bytes() == b''
        assert results['A']['collection']['items'][0]['cleanup']['status'] == 'succeeded'
        management.close(); management.wait(5); store.close(); root.close()
        persisted = reopen_records(store.path).records
        reports = ResultRoot.read(root.path).records
        for label in ('A', 'B'):
            history = next(r.data['collection'] for r in persisted if r.kind == 'collection_outcome'
                           and r.identity['run_id'] == 'run-' + label)
            assert history == results[label]['collection']
            indexed = next(r.data['result'] for r in reports if r.kind == 'report_result'
                          and r.identity['run_id'] == 'run-' + label)
            assert indexed['projection'] == 'event_json_v1'
            report = decode_value(json.loads(Path(indexed['event_path']).read_text(encoding='utf-8')))
            assert report['context']['marker'] == label
            assert report['collection_status'] == history['status']
            assert report['collection_items'] == history['items']
            assert report['collection_operations'] == history['operations']
            if label == 'A':
                assert Path(report['artifacts'][0]['path']).read_bytes() == b'A'
            else:
                assert report['artifacts'] == ()
    finally:
        release_first.set()
        for thread in threads:
            thread.join(6)
        management.close(); management.wait(6); store.close(); root.close()
