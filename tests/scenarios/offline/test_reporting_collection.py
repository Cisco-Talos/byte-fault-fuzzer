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

"""Actual service owner fixtures; process and transport ports are controlled offline."""
from dataclasses import replace
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
import shutil
import threading
from types import SimpleNamespace
import time

import pytest

from bytefault.application import ApplicationRequest, SavedCaseIntent, SavedStepIntent
from bytefault.core.contracts import (Calculation, ConversationAction, ConversationRequest,
    Correlation, FieldLocation, MonitoringAction, MonitoringDecision, PassivePlan, Placement, PreparedContribution,
    PreparedRow, ReceiveRequest, SourceInvocation, TransportRequest)
from bytefault.core.storage import LocalRecordStore
from bytefault.core.records import decode_value, encode_value
from bytefault.fuzzers.cli import execute_arguments
from bytefault.management import CollectionOutcome, Management
from bytefault.management.collection import Collection
from bytefault.management.configuration import ServiceConfiguration
from bytefault.monitoring import Monitoring
from bytefault.monitoring.configuration import MonitoringConfig, ObservationRule
from bytefault.reporting import Reporting, ResultRoot, ReportRequest, WriterAttachedError


def await_followup(app):
    deadline = time.monotonic() + 8
    while (app.management is None or app.management.status()['pending'] or
           (not app.management.status()['outcomes'] and not app.management.status()['failures'])) and time.monotonic() < deadline:
        time.sleep(.005)
    assert not app.management.status()['pending']
    assert not app.management.status()['failures']
    return app.management.status()['outcomes'][-1]['outcome']


def reporting_monitor(collect=False):
    return Monitoring(configuration=MonitoringConfig(rules=(ObservationRule('unrequested', 'unrequested',
        actions=({'report': True, 'collect': collect},)),), health_check_mode='disabled', retries=0))


def literal(tmp_path, identity='original'):
    plan = PassivePlan('neutral', 1, (
        ConversationAction('S', b'S', receive=ReceiveRequest(cap=2, deadline=3)),
        ConversationAction('A', bytes.fromhex('000061626364'), receive=ReceiveRequest(requested=False),
            fields=(FieldLocation('left', 2, 2), FieldLocation('right', 4, 2))),))
    row = PreparedRow('row', 1, tuple(PreparedContribution(k, v, SourceInvocation(k, 'literal'))
        for k, v in (('left', b'XY'), ('right', b'\x00\xff'), ('tail', b'Z'))), (
            Placement('left', 'left', 'A', 'replace', field_id='left'),
            Placement('right', 'right', 'A', 'replace', field_id='right'),
            Placement('tail', 'tail', 'A', 'append')))
    request = ConversationRequest(plan, row, ('A',), identity, 'case', 'conversation', repair=True,
        calculations=(Calculation('size', 'A', 'payload_length', offset=0, size=2, payload_offset=2, required=True),))
    return ApplicationRequest(request, TransportRequest('offline.invalid', 1234, 3), str(tmp_path / (identity + '.bfr')))


def action(run='run', event='event', observation='occurrence', **parameters):
    return MonitoringAction('followup-' + observation, event, observation,
        Correlation(run, 'case', 'conversation', 'A', 'attempt'), 'followup', parameters)


def test_real_collection_items_changed_basename_and_selected_cleanup(tmp_path):
    commands = []
    content = [b'AB']
    def process(command, **options):
        commands.append(command)
        if command[0] == 'ssh':
            assert command[-1].startswith('rm -f -- ')
            return SimpleNamespace(returncode=1 if command[-1].endswith('large') else 0,
                                   stdout='', stderr='cleanup failure' if command[-1].endswith('large') else '')
        assert command[0] == 'rsync' and options['timeout'] is None
        destination = Path(command[-1]) / 'small'
        if not destination.exists() or destination.read_bytes() != content[0]:
            if destination.exists():
                backup = Path(next(arg.split('=', 1)[1] for arg in command if arg.startswith('--backup-dir=')))
                backup.mkdir(parents=True)
                shutil.copy2(destination, backup / 'small')
            staged = destination.with_name('incoming')
            staged.write_bytes(content[0]); staged.replace(destination)
        return SimpleNamespace(returncode=0, stderr='', stdout=(
            f'BF|.f         |{len(content[0])}|2026/10/22-15:00:57|small\n'
            'large is over max-size\nNumber of files: 3 (reg: 2, dir: 1)'))
    collection = Collection('controlled-A', ssh_key='controlled-key', cache_dir=tmp_path / 'cache',
                            process=process, core_write_wait=0, max_file_size_mb=1)
    first = collection.acquire()
    assert [i['status'] for i in first.items] == ['cached', 'skipped']
    assert first.status == 'failed' and Path(first.artifacts[0]).read_bytes() == b'AB'
    assert not any(c[-1].startswith('rm ') for c in commands)
    content[0] = b'CD'
    changed = collection.acquire()
    assert Path(changed.artifacts[0]).read_bytes() == b'CD'
    assert Path(first.artifacts[0]).read_bytes() == b'AB'
    cleanup = collection.acquire(cleanup=True)
    assert [i['cleanup']['status'] for i in cleanup.items] == ['failed', 'succeeded']
    assert len([c for c in commands if c[-1].startswith('rm ')]) == 2
    outcome = collection(action(collect=True), context={'transport': {'host': 'controlled-B'}})
    assert outcome.artifacts and any('root@controlled-B' in str(c) for c in commands)


def test_run_event_occurrences_late_revision_and_root_reopen(tmp_path):
    root = ResultRoot(tmp_path / 'results')
    reporting = Reporting(root)
    artifact = tmp_path / 'core'; artifact.write_bytes(b'core')
    with pytest.raises(WriterAttachedError):
        ResultRoot(root.path)
    for run, event, occurrence in (('run-A', 'event-A', 'one'), ('run-B', 'event-A', 'one'),
                                    ('run-A', 'event-B', 'two'), ('run-A', 'event-A', 'three')):
        selected = action(run, event, occurrence, report=True)
        outcome = reporting.report(ReportRequest(str(time.monotonic_ns()), selected, 'disabled'))
        assert outcome.status == 'succeeded' and Path(outcome.location).is_file()
    late = reporting.report(ReportRequest('late', action('run-A', 'event-A', 'one', report=True),
                                          'succeeded', (str(artifact),)))
    snapshot = reporting.layout.snapshot()
    assert not (root.path / 'INDEX.md').exists() and not (root.path / 'LATEST.md').exists()
    event = next(e for e in snapshot if e['run_id'] == 'run-A' and e['event_id'] == 'event-A')
    assert len(event['occurrences']) == 2 and len(event['occurrences']['one']['revisions']) == 2
    assert event['occurrences']['one']['revisions'][-1]['artifacts']
    before = (root.path / 'results.bfr').read_bytes()
    assert reporting.layout.snapshot() == snapshot
    assert (root.path / 'results.bfr').read_bytes() == before
    content = Path(late.location).read_bytes()
    refused = reporting.report(ReportRequest('source-alias', action('run-A', 'event-A', 'one', report=True),
        'disabled', context={'source_inventory': {'paths': (late.location,), 'directories': ()}}))
    assert refused.status == 'failed' and Path(late.location).read_bytes() == content
    assert reporting.layout.snapshot() == snapshot
    other = reporting.report(ReportRequest('other-event-source', action('run-A', 'event-B', 'two', report=True),
        'disabled', context={'source_inventory': {'paths': (late.location,), 'directories': ()}}))
    assert other.status == 'succeeded' and Path(late.location).read_bytes() == content
    snapshot = reporting.layout.snapshot()
    root.close()
    reopened = ResultRoot(root.path)
    try:
        assert Reporting(reopened).layout.snapshot() == snapshot
        assert 'artifact-0003-0001-core' in Path(late.location).read_text()
        assert not (Path(late.location).parent / 'artifacts').exists()
        assert (Path(late.location).parent / 'event.json').is_file()
        assert len([p for p in root.path.iterdir() if p.is_dir()]) == 3
    finally:
        reopened.close()


def test_retained_inline_event_accepts_late_revision_after_reopen(tmp_path):
    """A baseline inline result has revision_path/event.json, no event_path."""
    root_path = tmp_path / 'selected-bin'
    root = ResultRoot(root_path)
    part = lambda value: hashlib.sha256(value.encode()).hexdigest()[:16]
    event_dir = root.path / 'runs' / part('run') / 'events' / part('event')
    revision_dir = event_dir / 'occurrences' / part('occurrence') / part('old')
    revision_dir.mkdir(parents=True)
    selected = action('run', 'event', 'occurrence', report=True)
    old_info = {'run_id': 'run', 'event_id': 'event', 'occurrence_id': 'occurrence',
        'report_id': 'old', 'correlation': selected.correlation,
        'followup_action_id': selected.action_id, 'observation_id': 'occurrence',
        'collection_status': 'disabled', 'collection_error': '',
        'collection_items': (), 'collection_operations': (),
        'collection_inventory_status': 'not_requested', 'context': {}, 'artifacts': (),
        'updated_at': '2026-10-23T00:00:00+00:00',
        'report_path': str(event_dir / 'REPORT.md'), 'revision_path': str(revision_dir)}
    old_evidence = json.dumps(encode_value(old_info), ensure_ascii=True, indent=2).encode('utf-8')
    old_path = revision_dir / 'event.json'
    old_path.write_bytes(old_evidence)
    (event_dir / 'REPORT.md').write_text('# Existing old report\n', encoding='utf-8')
    root.append('report_result', {'run_id': 'run', 'event_id': 'event',
        'occurrence_id': 'occurrence', 'report_id': 'old'}, {'result': old_info})
    root.close()

    root = ResultRoot(root_path)
    reporter = Reporting(root)
    try:
        prior = reporter.layout.snapshot()
        assert prior[0]['occurrences']['occurrence']['revisions'][0]['report_id'] == 'old'
        outcome = reporter.report(ReportRequest('new', selected, 'disabled',
            context={'observation_time_utc': '2026-10-24T14:20:30-04:00', 'protocol_id': 'raw'}))
        assert outcome.status == 'succeeded', outcome
        revisions = reporter.layout.snapshot()[0]['occurrences']['occurrence']['revisions']
        assert [revision['report_id'] for revision in revisions] == ['old', 'new']
        assert old_path.read_bytes() == old_evidence
        assert Path(revisions[1]['event_path']).is_file()
        assert Path(revisions[1]['event_path']).parent == event_dir
        report = (event_dir / 'REPORT.md').read_text(encoding='utf-8')
        assert report.count('## Report ') == 2
        assert '[Exact event evidence](' + old_path.relative_to(event_dir).as_posix() + ')' in report
        assert '[Exact event evidence](' + Path(revisions[1]['event_path']).name + ')' in report
        assert 'Collection: disabled (not_requested)' in report
    finally:
        root.close()


def test_named_bin_same_second_events_and_readable_revisions(tmp_path, application_factory):
    app, _ = application_factory(monitoring=reporting_monitor(),
        service_configuration=ServiceConfiguration(core_write_wait=0),
        stream_options={'reads': (b'OK',)})
    request = literal(tmp_path)
    assert app.submit(request).outcome == 'completed'
    assert await_followup(app)['report']['status'] == 'succeeded'
    default_bin = app.reporting.root.path
    assert default_bin.parent == tmp_path and re.fullmatch(r'\d{8}_\d{6}_raw', default_bin.name)
    first = app.reporting.layout.snapshot()[0]['occurrences']
    result = next(iter(first.values()))['revisions'][0]
    report = Path(result['report_path'])
    assert report.parent.parent == default_bin
    assert report.parent.name == datetime.fromisoformat(result['observed_at_utc']).strftime('%H%M%S_raw')
    assert report.stat().st_size < 12000
    assert Path(result['event_path']).stat().st_size > report.stat().st_size
    assert Path(result['case_path']).is_file()
    assert not (report.parent / 'artifacts').exists()
    assert not (default_bin / 'INDEX.md').exists() and not (default_bin / 'LATEST.md').exists()
    app.close()

    root = ResultRoot(tmp_path / 'chosen-bin')
    reporter = Reporting(root)
    try:
        at = {'observation_time_utc': '2026-10-24T14:20:30-04:00', 'protocol_id': 'raw'}
        a = reporter.report(ReportRequest('a', action('run', 'event-a', 'a', report=True), 'disabled', context=at))
        b = reporter.report(ReportRequest('b', action('run', 'event-b', 'b', report=True), 'disabled', context=at))
        later = reporter.report(ReportRequest('a-later', action('run', 'event-a', 'a', report=True), 'disabled', context=at))
        assert Path(a.location).parent.name == '142030_raw'
        assert Path(b.location).parent.name == '142030_raw_1'
        assert later.location == a.location
        assert (Path(a.location).parent / 'event.json').is_file()
        assert len(list(Path(a.location).parent.glob('event-*.json'))) == 1
        assert len(reporter.layout.snapshot()) == 2
        event_file = Path(a.location).parent / 'event.json'
        original = event_file.read_bytes()
        altered = original.replace(b'disabled', b'enabled!', 1)
        assert altered != original and len(altered) == len(original)
        event_file.write_bytes(altered)
        with pytest.raises(OSError, match='acknowledged event evidence content mismatch'):
            reporter.layout.snapshot()
        event_file.write_bytes(original)
        assert len(reporter.layout.snapshot()) == 2
        event_file.unlink()
        with pytest.raises(OSError, match='acknowledged event evidence unavailable'):
            reporter.layout.snapshot()
    finally:
        root.close()


def test_multi_core_report_retains_collection_window_and_all_copies(tmp_path):
    from bytefault.logging import ActionLog
    root = ResultRoot(tmp_path / 'chosen-bin')
    log = ActionLog.open(tmp_path / 'actions.bfr')
    store = LocalRecordStore(root.path / 'management.bfr')
    first = tmp_path / 'cache-first'; first.write_bytes(b'first')
    second = tmp_path / 'cache-second'; second.write_bytes(b'second')
    calls = [0]
    def collect(_action):
        calls[0] += 1
        if calls[0] == 1:
            return CollectionOutcome('succeeded', inventory_status='empty')
        items = ({'status':'cached', 'name':'alpha [first]', 'path':str(first),
                  'association':'unpaired_new_core'},
                 {'status':'cached', 'name':'beta', 'path':str(second),
                  'association':'provisional_newest_for_detected_crash'})
        return CollectionOutcome('succeeded', (str(first), str(second)), items=items,
                                 inventory_status='available')
    management = Management(store, reporting=Reporting(root), collection=collect)
    try:
        root.register_run_log('run', log.store.path)
        context = {'log_path':str(log.store.path), 'decision': {'correlation': {'run_id':'run'}},
                   'observation_time_utc':'2026-10-24T14:20:30-04:00', 'protocol_id':'raw'}
        initial = action('run', 'initial', 'initial', collect=True)
        management.route(initial, context=context)
        for number in (1, 2):
            log('action_result', {'run_id':'run', 'case_id':f'case-{number}',
                'conversation_id':f'conversation-{number}', 'action_id':'A',
                'attempt_id':f'attempt-{number}'}, {'result': {'offered': bytes([number])}})
        selected = action('run', 'event', 'check', collect=True, report=True)
        outcome = management.route(selected, context=context)
        assert outcome.report.status == 'succeeded'
        assert outcome.report.acquired_core_count == 2
        assert [core['name'] for core in outcome.report.acquired_cores] == ['alpha [first]', 'beta']
        cli_followup = decode_value(json.loads(json.dumps(encode_value({'followup': outcome}))))
        assert cli_followup['followup']['report']['acquired_core_count'] == 2
        assert [core['name'] for core in cli_followup['followup']['report']['acquired_cores']] == [
            'alpha [first]', 'beta']
        assert [core['path'] for core in cli_followup['followup']['report']['acquired_cores']] == [
            core['path'] for core in outcome.report.acquired_cores]
        result = next(iter(management.reporting.layout.snapshot()[0]['occurrences'].values()))['revisions'][0]
        assert [Path(a['path']).read_bytes() for a in result['artifacts']] == [b'first', b'second']
        assert [a['association'] for a in result['artifacts']] == [
            'unpaired_new_core', 'provisional_newest_for_detected_crash']
        assert result['acquired_core_count'] == 2
        assert [core['name'] for core in result['acquired_cores']] == ['alpha [first]', 'beta']
        assert [core['path'] for core in result['acquired_cores']] == [
            artifact['path'] for artifact in result['artifacts']]
        event_json = decode_value(json.loads(Path(result['event_path']).read_text(encoding='utf-8')))
        assert event_json['acquired_core_count'] == 2
        assert [core['name'] for core in event_json['acquired_cores']] == ['alpha [first]', 'beta']
        assert all(Path(a['path']).parent == Path(outcome.report.location).parent for a in result['artifacts'])
        assert first.read_bytes() == b'first' and second.read_bytes() == b'second'
        assert result['context']['collection_boundary']['followup_action_id'] == initial.action_id
        assert [t['identity']['case_id'] for t in result['context']['intervening_test_identities']] == [
            'case-1', 'case-2']
        assert result['context']['intervening_test_scope'] == 'complete_registered_action_logs'
        readable = Path(outcome.report.location).read_text()
        assert '**Multiple cores acquired: 2**' in readable
        assert '[alpha \\[first\\]](' in readable and '[beta](' in readable
        assert 'unpaired_new_core' in readable and 'provisional_newest_for_detected_crash' in readable
        assert 'Known tests since that collection' in readable
        assert 'case-1' in readable and 'case-2' in readable
        assert 'ValueSnapshot object' not in readable
    finally:
        management.close(); log.end('run'); root.close()
        store.close()
    # A new owner must discover a run which had no report or collection.
    root = ResultRoot(tmp_path / 'chosen-bin')
    store = LocalRecordStore(root.path / 'management.bfr')
    middle_log = ActionLog.open(tmp_path / 'middle.actions.bfr')
    last_log = ActionLog.open(tmp_path / 'last.actions.bfr')
    management = Management(store, reporting=Reporting(root), collection=collect)
    try:
        root.register_run_log('middle-run', middle_log.store.path)
        middle_log('action_result', {'run_id':'middle-run', 'case_id':'case-3',
            'conversation_id':'conversation-3', 'action_id':'A', 'attempt_id':'attempt-3'},
            {'result': {'offered': b'\x03'}})
        root.register_run_log('last-run', last_log.store.path)
        last_log('action_result', {'run_id':'last-run', 'case_id':'case-4',
            'conversation_id':'conversation-4', 'action_id':'A', 'attempt_id':'attempt-4'},
            {'result': {'offered': b'\x04'}})
        next_action = action('last-run', 'later-event', 'later-check', collect=True, report=True)
        last_context = {**context, 'log_path':str(last_log.store.path),
            'decision': {'correlation': {'run_id':'last-run'}}}
        later = management.route(next_action, context=last_context)
        later_result = next(iter(management.reporting.layout.snapshot()[1]['occurrences'].values()))['revisions'][0]
        assert later_result['context']['intervening_test_scope'] == 'complete_registered_action_logs'
        assert [t['identity']['case_id'] for t in later_result['context']['intervening_test_identities']] == [
            'case-3', 'case-4']
        assert 'case-3' in Path(later.report.location).read_text()
    finally:
        management.close(); middle_log.end('run'); last_log.end('run'); root.close(); store.close()


@pytest.mark.parametrize('failure', ('hardlink', 'inventory'))
def test_partial_core_handoff_preserves_report_and_retry(tmp_path, monkeypatch, failure):
    remote = {}
    calls = []
    failing = [True]
    def process(command, **options):
        calls.append(command)
        assert command[0] == 'rsync'
        for name, data in remote.items():
            target = Path(command[-1]) / name
            if not target.exists():
                target.write_bytes(data)
        lines = [f'BF|.f         |{len(data) + int(failing[0] and failure == "inventory" and name == "core-B")}|2026/11/04-12:00:00|{name}'
                 for name, data in remote.items()]
        return SimpleNamespace(returncode=0, stderr='', stdout='\n'.join((*lines,
            f'Number of files: {len(remote) + 1} (reg: {len(remote)}, dir: 1)')))

    root = ResultRoot(tmp_path / 'reports')
    store = LocalRecordStore(tmp_path / 'management.bfr')
    collector = Collection('controlled', ssh_key='key', cache_dir=tmp_path / 'cache',
        core_write_wait=0, process=process)
    management = Management(store, reporting=Reporting(root), collection=collector)
    original_link = Path.hardlink_to
    def fail_second(path, target):
        if path.name == 'core-B' and failure == 'hardlink':
            raise OSError('controlled second-core handoff failure')
        return original_link(path, target)
    try:
        management.route(action(observation='initial', collect=True))
        boundary = management._last_successful_collection
        remote.update({'core-A': b'first-core', 'core-B': b'second-core'})
        with monkeypatch.context() as patch:
            patch.setattr(Path, 'hardlink_to', fail_second)
            partial = management.route(action(observation='partial', collect=True, report=True))
        assert partial.collection.status == 'failed'
        assert partial.collection.inventory_status == 'failed'
        assert len(partial.collection.artifacts) == 1
        assert Path(partial.collection.artifacts[0]).read_bytes() == b'first-core'
        assert partial.collection.items[0]['association'] == 'unpaired_new_core'
        assert not partial.collection.items[0]['selected']
        assert management._last_successful_collection == boundary
        assert partial.report.status == 'succeeded' and partial.report.acquired_core_count == 1
        assert Path(partial.report.acquired_cores[0]['path']).read_bytes() == b'first-core'
        assert 'Collection: failed' in Path(partial.report.location).read_text(encoding='utf-8')
        assert len(list((tmp_path / 'cache').glob('*/pending/core-B'))) == 1
        assert not list((tmp_path / 'cache').glob('*/pending/core-A'))
        failing[0] = False
        recovered = management.route(action(observation='retry', collect=True, report=True))
        assert recovered.collection.status == 'succeeded'
        assert [item['name'] for item in recovered.collection.items] == ['core-B']
        assert recovered.report.acquired_core_count == 1
        assert Path(recovered.report.acquired_cores[0]['path']).read_bytes() == b'second-core'
        assert collector.acquire().artifacts == ()
        assert not list((tmp_path / 'cache').glob('*/pending/core-*'))
        assert all(command[0] == 'rsync' for command in calls)
    finally:
        management.close()
        management.wait(5)
        store.close()
        root.close()


def test_core_notice_counts_copied_cached_items_only_and_keeps_partial_status(tmp_path):
    root = ResultRoot(tmp_path / 'selected-bin')
    reporting = Reporting(root)
    cached = tmp_path / 'cached'; cached.write_bytes(b'core')
    supplied = tmp_path / 'other'; supplied.write_bytes(b'other')
    try:
        partial = reporting.report(ReportRequest('partial', action(report=True), 'failed',
            (str(cached), str(supplied)), 'size cap skipped a core',
            collection_items=(
                {'status': 'cached', 'path': str(cached), 'association': 'unpaired_new_core'},
                {'status': 'skipped', 'name': 'not-acquired', 'path': str(tmp_path / 'skipped')}),
            collection_inventory_status='skipped'))
        assert partial.status == 'succeeded' and partial.acquired_core_count == 1
        assert partial.acquired_cores[0]['name'] is None
        assert partial.acquired_cores[0]['name_status'] == 'unavailable'
        assert Path(partial.acquired_cores[0]['path']).read_bytes() == b'core'
        rendered = Path(partial.location).read_text(encoding='utf-8')
        assert 'Collection: failed (skipped)' in rendered
        assert 'Acquired core: 1' in rendered and 'Multiple cores acquired' not in rendered
        assert '[Exact remote name unavailable](' in rendered
        assert 'not-acquired' not in rendered
        assert '### Acquired files' in rendered and 'artifact-' in rendered

        no_new = reporting.report(ReportRequest('no-new', action(event='later', report=True),
            'succeeded', collection_inventory_status='no_new'))
        assert no_new.status == 'succeeded' and no_new.acquired_core_count == 0
        assert not no_new.acquired_cores
        no_new_text = Path(no_new.location).read_text(encoding='utf-8')
        assert 'Collection: succeeded (no_new)' in no_new_text
        assert 'Acquired core:' not in no_new_text and 'Multiple cores acquired' not in no_new_text
    finally:
        root.close()


def test_unreported_application_run_registers_action_log(tmp_path, application_factory):
    app, _ = application_factory(service_configuration=ServiceConfiguration(
        result_root=str(tmp_path / 'chosen-bin'), core_write_wait=0),
        stream_options={'reads': (b'OK',)})
    request = literal(tmp_path)
    try:
        assert app.submit(request).outcome == 'completed'
        registrations = [record for record in app.reporting.root.store.snapshot().records
            if record.kind == 'run_action_log']
        assert len(registrations) == 1
        assert registrations[0].identity['run_id'] == request.conversation.run_id
        assert registrations[0].data['log_path'] == str(Path(request.record_path + '.actions.bfr').resolve())
        assert not app.reporting.layout.snapshot()
    finally:
        app.close()


def test_management_final_close_preserves_worker_base_exception(tmp_path, monkeypatch):
    store = LocalRecordStore(tmp_path / 'management.bfr')
    management = Management(store)
    entered, release = threading.Event(), threading.Event()
    errors = []
    monkeypatch.setattr(threading, 'excepthook', lambda args: errors.append(args.exc_value))
    def explode(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        raise BaseException('controlled worker failure')
    monkeypatch.setattr(management, 'route', explode)
    selected = action('run', 'event', 'check')
    decision = MonitoringDecision('decision', selected.observation_id,
        selected.correlation, 'continue', actions=(selected,))
    try:
        management.dispatch(decision, lambda completion: None)
        assert entered.wait(3)
        management.close()
        release.set()
        management._worker.join(3)
        assert not management._worker.is_alive()
        assert len(errors) == 1 and str(errors[0]) == 'controlled worker failure'
    finally:
        release.set()
        store.close()


@pytest.mark.parametrize('collect,client', [(False, 'api'), (True, 'argument'), (False, 'plain'), (True, 'rich')])
def test_actual_report_copied_literal_case_ordinary_loader(tmp_path, application_factory, monkeypatch, collect, client):
    import bytefault.management.collection as module
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs:
        SimpleNamespace(returncode=1, stdout='', stderr='controlled listing unavailable'))
    app, traces = application_factory(monitoring=reporting_monitor(collect),
        service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results'),
            ssh_key='controlled-key' if collect else None, core_write_wait=0),
        stream_options={'reads': (b'OK', b'SENTINEL')})
    request = literal(tmp_path)
    result = app.submit(request)
    outcome = await_followup(app)
    assert result.outcome == 'completed' and outcome['collection']['status'] == ('failed' if collect else 'disabled')
    assert outcome['report']['status'] == 'succeeded', outcome['report']['error']
    event = app.reporting.layout.snapshot()[0]
    report = next(iter(event['occurrences'].values()))['revisions'][0]
    assert report['context']['decision']['assessments']
    assert any(r['kind'] == 'action_result' for r in report['context']['records'])
    bundle = tmp_path / 'copied'; shutil.copytree(Path(report['report_path']).parent, bundle)
    request_path = next(bundle.rglob('case.json'))
    Path(request.record_path).unlink()
    rerun, replay = application_factory(monitoring=reporting_monitor(),
        service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'rerun-results'),
            core_write_wait=0, heartbeat_interval=.25) if client == 'api' else None,
        stream_options={'reads': (b'OK', b'SENTINEL')})
    supplied_monitor = rerun.monitoring
    displayed = []
    if client in ('plain', 'rich'):
        from bytefault.ui import controller
        if client == 'rich':
            import rich.console  # This case qualifies actual Rich, not fallback.
        run_terminal = controller.run_terminal
        def display(application, request, options):
            displayed.append((request, options))
            return run_terminal(application, request, options)
        monkeypatch.setattr(controller, 'run_terminal', display)
    arguments = ['saved-case', json.dumps({'path': str(request_path)}),
        '--records', str(tmp_path / 'rerun.bfr'), '--log-file', str(tmp_path / 'rerun.actions.bfr'),
        '--results', str(tmp_path / 'rerun-results'),
        '--core-dump-wait', '0', '--heartbeat-interval', '.25', '--hide-field', 'left',
        '--no-test-banner', '-vv', '--debug', '--ui' if client == 'rich' else '--no-ui']
    if client == 'argument':
        arguments.append('--heartbeat')
    prepared = execute_arguments(arguments, rerun, terminal=client in ('plain', 'rich'))
    assert not replay and rerun.management is None and not (tmp_path / 'rerun-results').exists()
    assert prepared.conversation.original_request['prepared_client']['argv'] == tuple(arguments)
    if client == 'api':
        actual = rerun.submit(prepared)
    else:
        actual = execute_arguments([*arguments, '--execute'], rerun, terminal=client in ('plain', 'rich'))
        assert rerun.management is not None and rerun.reporting is not None
        assert rerun.service_configuration.core_write_wait == 0
        assert rerun.service_configuration.heartbeat_interval == .25
        assert rerun.status(actual.run_id)['heartbeat']['enabled'] == (client == 'argument')
    assert rerun.monitoring is supplied_monitor
    assert await_followup(rerun)['report']['status'] == 'succeeded'
    if client in ('plain', 'rich'):
        assert len(displayed) == 1
        shown_request, options = displayed[0]
        assert shown_request.log_path == str(tmp_path / 'rerun.actions.bfr')
        assert options['verbose'] == 2 and options['debug'] and options['hide_field'] == ['left']
        assert not options['test_banner'] and options['no_ui'] == (client == 'plain')
    assert [a.transport.offered.hex() for a in actual.actions] == ['53', '0005585900ff5a']
    assert actual.actions[0].transport.received == b'OK'
    assert actual.actions[1].transport.receive_outcome == 'unrequested'
    assert replay[0][1].reads == [b'SENTINEL'] and replay[0][1].closed
    assert prepared.conversation.run_id != request.conversation.run_id
    assert actual.run_id != request.conversation.run_id
    current_case = next(record for record in rerun.read_records(actual.run_id).records if record.kind == 'case_start')
    assert current_case.identity['run_id'] == actual.run_id
    assert current_case.data['request']['original_request']['saved_case']['origin']['identity']['run_id'] == request.conversation.run_id
    assert 'Runnable recorded case' in Path(report['report_path']).read_text()
    assert any(r.kind == 'report_context' for r in app.management.store.snapshot().records)


def test_ordinary_cli_attaches_real_owners(tmp_path, application_factory, monkeypatch, capsys):
    from bytefault.fuzzers.inputs import request_to_data, value_from_data
    from bytefault.reporting.layout import _plain
    from bytefault.core.contracts import freeze
    from bytefault.logging import ActionLog
    source = tmp_path / 'source.bin'
    source.write_bytes(b'AB')
    commands = []
    def process(command, **options):
        commands.append(command)
        assert command[0] == 'rsync'
        name = f'core-{len(commands)}'
        (Path(command[-1]) / name).write_bytes(b'CC')
        return SimpleNamespace(returncode=0,
            stdout=f'BF|>f+++++++++|2|2026/10/22-15:00:57|{name}\nNumber of files: 2 (reg: 1, dir: 1)',
            stderr='')
    original_init = Collection.__init__
    def controlled_collection(self, *args, **options):
        original_init(self, *args, **dict(options, process=process))
    monkeypatch.setattr(Collection, '__init__', controlled_collection)
    actions = tuple(ConversationAction('P' + str(i), bytes([i]) + b'ab',
        fields=(FieldLocation('body', 1, 2, variable=True),)) for i in range(1, 7))
    conversation = ConversationRequest(PassivePlan('seven', 1, (
        ConversationAction('setup', b'S', receive=ReceiveRequest(cap=1, deadline=3)), *actions)),
        PreparedRow('row', 1), tuple(a.action_id for a in actions), 'many', 'case', 'conversation')
    generation = {'sources': ({'source_id':'source', 'kind':'file',
        'options':{'path':str(source), 'source_mode':'whole'}},),
        'sets': ({'set_id':'S', 'source_id':'source', 'transforms':({'mutator_id':'reverse', 'kind':'reverse'},)},),
        'positions': ({'position_id':'body', 'set_id':'S', 'operation':'replace', 'field_id':'body'},)}
    def arguments(identity):
        return ['submit', 'offline.invalid', '--port', '1234', '--no-ui', '--request-json',
            json.dumps(request_to_data(replace(conversation, run_id=identity))),
            '--records', str(tmp_path / (identity + '.bfr')), '--results', str(tmp_path / ('results-' + identity)),
            '--ssh-key', 'controlled-key', '--core-dump-wait', '0',
            '--generation-json', json.dumps(encode_value(generation)),
            '--monitoring-json', json.dumps(encode_value({'health_check_mode':'disabled', 'retries':0, 'rules':[
                {'rule_id':'unrequested', 'kind':'unrequested', 'actions':[{'collect':True, 'report':True}]}]}))]
    app, traces = application_factory(stream_options={'reads':(b'R', b'SENTINEL')})
    result = execute_arguments(arguments('many'), app)
    assert app.management.wait(30)
    assert app.reporting.root.path == (tmp_path / 'results-many').resolve()
    assert result.outcome == 'completed' and result.fuzz_tests == 6 and result.setup_sends == 1
    expected = [b'S', *(bytes([i]) + b'BA' for i in range(1,7))]
    assert [step[1] for step in traces[0][0] if step[0] == 'offer'] == expected
    assert traces[0][1].reads == [b'SENTINEL'] and traces[0][1].closed
    outcomes = tuple(entry['outcome'] for entry in app.management.status()['outcomes'])
    assert len(outcomes) == 6 and not app.management.status()['failures']
    assert all(o['collection']['status'] == o['report']['status'] == 'succeeded' for o in outcomes)
    assert len({o['event_id'] for o in outcomes}) == len({o['action_id'] for o in outcomes}) == 6
    assert not [c for c in commands if c[0] == 'ssh']
    assert len([c for c in commands if c[0] == 'rsync']) == 6
    history = app.read_records(result.run_id)
    assert history.issue is None
    contexts = [(r, ref) for r, ref in zip(history.records, history.refs) if r.kind == 'report_context']
    assert len(contexts) == 6
    for index, (record, _) in enumerate(contexts):
        context = record.data.context
        assert context.history_projection == 'flat_case_v1'
        assert len(context.records) == len(context.record_refs)
        assert len({r.record_id for r in context.records}) == len(context.records)
        assert tuple(r.record_id for r in context.records) == tuple(ref.record_id for ref in context.record_refs)
        key = tuple(record.identity[name] for name in ('run_id','case_id','conversation_id'))
        expected_refs = tuple(ref for raw, ref in zip(history.records, history.refs)
            if tuple(raw.identity.get(name) for name in ('run_id','case_id','conversation_id')) == key and
            ref.offset <= context.record_refs[-1].offset)
        assert context.record_refs == freeze(expected_refs)
        earlier = [r for r in context.records if r.kind == 'report_context']
        assert len(earlier) == index
        for r in earlier:
            assert r.projection == 'reference_only' and 'context' not in r.data
            assert r.record_reference.record_id == r.record_id
            original = next(item for item in history.records if item.record_id == r.record_id)
            assert original.data.context  # authoritative retained journal is unchanged
        selected = next(r for r in context.records if r.kind == 'action_result' and
            r.identity.action_id == record.identity.action_id)
        assert selected.identity.attempt_id == context.decision.correlation.attempt_id
        assert selected.data.result.transport.acceptance == 'accepted'
        origin = value_from_data(_plain(context.portable_case)['origin'])
        assert origin['history_projection'] == 'flat_case_v1'
        assert all(r['projection'] == 'reference_only' and 'context' not in r['data']
                   for r in origin['records'] if r['kind'] == 'report_context')
    # This fixed fixture's wire evidence follows flat facts/refs, not geometric
    # copies of preceding report contexts. Preserve actual frame sizes on failure.
    sizes = tuple(ref.length for _, ref in contexts)
    assert max(sizes) < 4 * sizes[0], sizes
    (tmp_path / 'context-sizes.json').write_text(json.dumps({'report_context_frame_bytes':sizes,
        'record_counts':tuple(len(record.data.context.records) for record, _ in contexts),
        'journal_bytes':Path(tmp_path / 'many.bfr').stat().st_size}), encoding='utf-8')
    reports = app.reporting.layout.snapshot()
    assert len(reports) == 6
    from bytefault.core.storage import reopen_records
    run_log = reopen_records(str(tmp_path / 'many.bfr') + '.actions.bfr')
    compact_contexts = [r for r in run_log.records if r.kind == 'report_context']
    assert len(compact_contexts) == 6
    assert all(r.data['action']['projection'] == 'reference_only' and
               r.data['action']['record_reference']['path'] == str(tmp_path / 'many.bfr')
               for r in compact_contexts)
    assert all(r.data['context']['projection'] == 'reference_only'
               for r in app.management.store.snapshot().records if r.kind == 'management_pending')
    assert all(r.data['request']['context']['projection'] == 'reference_only'
               for r in app.reporting.root.store.snapshot().records if r.kind == 'report_request')
    assert all(r.data['action']['projection'] == 'reference_only'
               for r in app.reporting.root.action_log.store.snapshot().records if r.kind == 'report_result')
    revisions = [r for event in reports for occurrence in event['occurrences'].values() for r in occurrence['revisions']]
    assert len({r['report_id'] for r in revisions}) == 6
    assert all(len(r['artifacts']) == 1 and Path(r['artifacts'][0]['path']).read_bytes() == b'CC' for r in revisions)
    latest = next(r for r in revisions if r['correlation']['action_id'] == 'P6')
    copied = tmp_path / 'copied.case.json'
    shutil.copyfile(latest['case_path'], copied)
    assert app.close().outcome == 'completed'
    original = tmp_path / 'many.bfr'
    original.rename(tmp_path / 'retained-original.bfr')
    source.write_bytes(b'XYZ')
    for mode, reapply, payload in (('literal', False, b'BA'), ('fresh_dynamic', False, b'XYZ'),
                                  ('fresh_dynamic', True, b'ZYX')):
        replay, replay_traces = application_factory(stream_options={'reads':(b'R', b'SENTINEL')})
        choices = tuple(SavedStepIntent(a.action_id, 'recorded' if mode == 'literal' else mode, reapply) for a in actions)
        prepared = replay.saved_case(SavedCaseIntent(str(copied), mode=mode, steps=choices),
            record_path=str(tmp_path / (mode + str(reapply) + '.bfr')))
        actual = replay.submit(prepared)
        assert actual.outcome == 'completed'
        assert [a.transport.offered for a in actual.actions] == [b'S', *(bytes([i]) + payload for i in range(1,7))]
        assert replay_traces[0][1].reads == [b'SENTINEL'] and replay_traces[0][1].closed
    # A required context-log acknowledgment still precedes queue admission and
    # stops the next fuzz offer; the smaller projection does not soften failure.
    ordinary_log = ActionLog.__call__
    def broken_context_log(self, kind, identity, data, reference=None):
        if kind == 'report_context' and identity['run_id'] == 'broken':
            raise OSError('controlled context action-log failure')
        return ordinary_log(self, kind, identity, data, reference)
    monkeypatch.setattr(ActionLog, '__call__', broken_context_log)
    broken, broken_traces = application_factory(stream_options={'reads':(b'R',)})
    before = len(commands)
    failed = execute_arguments(arguments('broken'), broken)
    assert failed.outcome == 'recording_failed'
    assert [step[1] for step in broken_traces[0][0] if step[0] == 'offer'] == [b'S', b'\x01ZYX']
    assert len(commands) == before and not broken.management.status()['outcomes']
    assert 'report_context' in capsys.readouterr().err


def test_report_retains_fresh_derivation_through_recorded_generation(tmp_path, application_factory):
    source = tmp_path / 'source.bin'; source.write_bytes(b'AB')
    app, _ = application_factory(monitoring=reporting_monitor(),
        service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results')),
        stream_options={'reads': (b'OK',)})
    base = literal(tmp_path)
    selected = replace(base.conversation.plan.actions[1], seed=b'\0\0AB',
        fields=(FieldLocation('body', 2, 2, variable=True),))
    base = replace(base, conversation=replace(base.conversation,
        plan=replace(base.conversation.plan, actions=(base.conversation.plan.actions[0], selected)),
        row=PreparedRow('row', 1)))
    configuration = {'sources': ({'source_id': 'src', 'kind': 'file',
        'options': {'path': str(source), 'source_mode': 'whole'}},),
        'sets': ({'set_id': 'set', 'source_id': 'src', 'transforms': (
            {'mutator_id': 'reverse', 'kind': 'reverse'},)},),
        'positions': ({'position_id': 'body', 'set_id': 'set', 'operation': 'replace',
                       'field_id': 'body', 'action_ids': ('A',)},)}
    from contextlib import closing
    with closing(app.generate(base, configuration, limit=1)) as generated:
        original = next(generated)
        assert app.submit(original).actions[-1].transport.offered.hex() == '00024241'
    await_followup(app)
    first = app.reporting.layout.snapshot()[0]
    case = next(iter(first['occurrences'].values()))['revisions'][0]['case_path']
    recorded = app.saved_case(SavedCaseIntent(case), record_path=str(tmp_path / 'recorded.bfr'))
    assert app.campaign(recorded).last_conversation.actions[-1].transport.offered.hex() == '00024241'
    await_followup(app)
    event = next(e for e in app.reporting.layout.snapshot() if e['run_id'] == recorded.conversation.run_id)
    copied = tmp_path / 'copied.case.json'
    copied.write_bytes(Path(next(iter(event['occurrences'].values()))['revisions'][0]['case_path']).read_bytes())
    # An intermediate uncertain continuation carries the recorded request and
    # original derivation through the actual shared resume entry.
    history = app.read_records(recorded.conversation.run_id)
    index = next(i for i, record in enumerate(history.records) if record.kind == 'case_start')
    ref = history.refs[index]
    prefix = tmp_path / 'recorded-prefix.bfr'
    prefix.write_bytes(Path(recorded.record_path).read_bytes()[:ref.offset + ref.length])
    inspection = app.inspect_resume(str(prefix))
    logical = inspection.cases[0]['conversation_id']
    resumed = execute_arguments(['resume-run', json.dumps({'path': str(prefix), 'choices': [
        {'conversation_id': logical, 'disposition': 'rerun'}]}), '--records', str(tmp_path / 'resumed.bfr'),
        '--results', str(app.reporting.root.path), '--no-ui', '--execute'], app)
    assert resumed.last_conversation.actions[-1].transport.offered.hex() == '00024241'
    await_followup(app)
    event = next(e for e in app.reporting.layout.snapshot() if e['run_id'] == resumed.run_id)
    copied.write_bytes(Path(next(iter(event['occurrences'].values()))['revisions'][0]['case_path']).read_bytes())
    Path(original.record_path).unlink(); Path(recorded.record_path).unlink(); prefix.unlink()
    (tmp_path / 'resumed.bfr').unlink()
    source.write_bytes(b'XYZ')
    def arguments(choice, destination):
        return ['saved-intent', json.dumps({'path': str(copied), 'steps': choice}),
            '--records', str(tmp_path / destination), '--no-ui']
    assert execute_arguments([*arguments([], 'literal.bfr'), '--execute'], app).actions[-1].transport.offered.hex() == '00024241'
    without = execute_arguments([*arguments([{'action_id': 'A', 'choice': 'fresh_dynamic',
        'dynamic_source_reference': 'src'}], 'fresh-without.bfr'), '--execute'], app)
    assert without.actions[-1].transport.offered.hex() == '000358595a'
    fresh = app.saved_case(SavedCaseIntent(str(copied), steps=(SavedStepIntent('A', 'fresh_dynamic', True, 'src'),)),
                          record_path=str(tmp_path / 'fresh.bfr'))
    actual = execute_arguments([*arguments([{'action_id': 'A', 'choice': 'fresh_dynamic',
        'reapply_mutations': True, 'dynamic_source_reference': 'src'}], 'fresh-argument.bfr'), '--execute'], app, terminal=True)
    assert actual.actions[-1].transport.offered.hex() == '00035a5958'
    await_followup(app)
    assert fresh.conversation.row.contributions[-1].source.options['path'] == str(source)
    source.unlink()
    from bytefault.core.contracts import ContractError
    with pytest.raises(ContractError, match='source_configuration'):
        execute_arguments(arguments([{'action_id': 'A', 'choice': 'fresh_dynamic'}], 'missing.bfr'), app)


def test_callable_default_delayed_failure_selects_real_report(tmp_path, application_factory):
    app, traces = application_factory(service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'results')))
    factory = app.transport_factory
    def transport(request):
        adapter = factory(request)
        stream = traces[-1][1]
        connect = stream.connect
        count = [0]
        def controlled(target):
            count[0] += 1
            if count[0] > 1:
                stream.open_error = OSError('controlled service down')
            return connect(target)
        stream.connect = controlled
        return adapter
    app.transport_factory = transport
    base = literal(tmp_path)
    # One no-receive action avoids introducing response retries before the check.
    base = replace(base, conversation=replace(base.conversation,
        plan=PassivePlan('one', 1, (base.conversation.plan.actions[1],)), row=PreparedRow('row', 1)))
    app.campaign(base)
    outcome = await_followup(app)
    assert outcome['report']['status'] == 'succeeded'
    context = app.reporting.layout.snapshot()[0]['occurrences']
    revision = next(iter(context.values()))['revisions'][0]
    observed = [r['data']['observation'] for r in revision['context']['records'] if r['kind'] == 'observation']
    assert any(o['kind'] == 'service_check' and o['service_readiness'] == 'unavailable' for o in observed)


def test_service_outputs_refuse_source_and_seed_directory_aliases(tmp_path, application_factory):
    from bytefault.core.contracts import ContractError
    source = tmp_path / 'results' / 'results.bfr'
    source.parent.mkdir(); source.write_bytes(b'UNCHANGED')
    app, traces = application_factory(service_configuration=ServiceConfiguration(result_root=str(source.parent)))
    request = literal(tmp_path)
    row = replace(request.conversation.row, contributions=(PreparedContribution('source', b'X',
        SourceInvocation('source', 'file', options={'path': str(source)})),))
    request = replace(request, conversation=replace(request.conversation, row=row))
    with pytest.raises(ContractError, match='source_collision'):
        app.submit(request)
    assert source.read_bytes() == b'UNCHANGED' and not traces
    assert not (source.parent / 'management.bfr').exists()
    # A generic prepared client can name a consumed file without smuggling a
    # filesystem path into its independently valid literal source recipe.
    explicit = replace(request, conversation=replace(request.conversation,
        input_files=(str(source),), row=replace(row, contributions=(PreparedContribution('source', b'X',
            SourceInvocation('source', 'literal', options={'data': b'X'}, input_reference='dataset:opaque:2')),))))
    with pytest.raises(ContractError, match='source_collision'):
        app.submit(explicit)
    assert source.read_bytes() == b'UNCHANGED' and not traces
    assert not (source.parent / 'management.bfr').exists()
    seed_dir = tmp_path / 'seeds'; seed_dir.mkdir()
    seed = seed_dir / 'one.bin'; seed.write_bytes(b'XY')
    app2, traces2 = application_factory(service_configuration=ServiceConfiguration(result_root=str(seed_dir)))
    base = literal(tmp_path, 'seed-directory')
    from bytefault.application import CampaignRequest
    generation = {'sources': ({'source_id': 's', 'kind': 'seed', 'options': {'seed_directory': str(seed_dir)}},),
        'sets': ({'set_id': 's', 'source_id': 's'},),
        'positions': ({'position_id': 'left', 'set_id': 's', 'operation': 'replace',
                       'field_id': 'left', 'action_ids': ('A',)},)}
    campaign = CampaignRequest(base.conversation, base.transport, base.record_path, generation=generation,
        monitoring_configuration=MonitoringConfig(health_check_mode='disabled'))
    with pytest.raises(ContractError, match='source_collision'):
        app2.submit(campaign)
    assert not traces2 and not (seed_dir / 'results.bfr').exists()
    # The source inventory selects immediate files; nested result files remain usable.
    app3, traces3 = application_factory(service_configuration=ServiceConfiguration(result_root=str(seed_dir / 'nested')))
    nested = literal(tmp_path, 'nested-results')
    nested_campaign = CampaignRequest(nested.conversation, nested.transport, nested.record_path,
        generation=generation, monitoring_configuration=MonitoringConfig(health_check_mode='disabled'))
    result = app3.submit(nested_campaign)
    assert result.outcome == 'completed' and result.fuzz_tests == 1 and traces3
    assert (seed_dir / 'nested' / 'results.bfr').is_file()
    assert seed.read_bytes() == b'XY'


def test_dispatch_owns_acknowledged_context_before_queue_execution(tmp_path):
    import threading
    from bytefault.core.contracts import MonitoringDecision
    entered, release = threading.Event(), threading.Event()
    contexts = []
    class BlockedManagement(Management):
        def route(self, selected, *, context=None, _accepted=False, progress=None, required_failure=None):
            entered.set(); assert release.wait(5)
            contexts.append(context)
            return super().route(selected, context=context, _accepted=_accepted, progress=progress, required_failure=required_failure)
    store = LocalRecordStore(tmp_path / 'management.bfr')
    owner = BlockedManagement(store)
    selected = action(report=False)
    decision = MonitoringDecision('decision', selected.observation_id, selected.correlation, 'continue', actions=(selected,))
    context = {'transport': TransportRequest('original', 1234, 3), 'values': [b'original']}
    try:
        owner.dispatch(decision, lambda completion: None, context=context)
        assert entered.wait(5)
        pending = next(r for r in store.snapshot().records if r.kind == 'management_pending')
        assert pending.data['context']['transport']['host'] == 'original'
        context['transport'] = TransportRequest('changed', 1234, 3); context['values'][0] = b'changed'
        release.set(); owner._queue.join()
        assert contexts[0]['transport']['host'] == 'original' and contexts[0]['values'] == (b'original',)
    finally:
        release.set(); owner.close(); owner._worker.join(5); store.close()


def test_collection_basename_containment_and_case_collision(tmp_path):
    commands = []
    def process(command, **options):
        commands.append(command)
        assert command[0] == 'rsync'
        return SimpleNamespace(returncode=0, stderr='', stdout=(
            'BF|>f+++++++++|1|2026/10/22-15:00:57|../escape\n'
            'Number of files: 2 (reg: 1, dir: 1)'))
    owner = Collection('controlled', ssh_key='key', cache_dir=tmp_path / 'cache', process=process)
    result = owner.acquire()
    assert result.status == 'failed' and result.inventory_status == 'failed'
    assert not result.artifacts
    assert not (tmp_path / 'escape').exists()
    assert all(operation['argv'] and operation['host'] == 'controlled' and 'returncode' in operation for operation in result.operations)
    assert all(operation['started_at'] <= operation['completed_at'] for operation in result.operations)
    selected = owner.acquire(cleanup=True)
    assert selected.status == 'failed' and not selected.artifacts
    assert not any(command[-1].startswith('rm ') and '../escape' in command[-1] for command in commands)

    local_paths = []
    def case_collision(command, **options):
        directory = Path(command[-1]); local_paths.extend((directory / 'a', directory / 'A'))
        local_paths[-2].write_bytes(b'a'); local_paths[-1].write_bytes(b'A')
        return SimpleNamespace(returncode=0, stderr='', stdout=(
            'BF|>f+++++++++|1|2026/10/22-15:00:57|a\n'
            'BF|>f+++++++++|1|2026/10/22-15:00:57|A\n'
            'Number of files: 3 (reg: 2, dir: 1)'))
    case_result = Collection('controlled', ssh_key='key', cache_dir=tmp_path / 'case-cache',
        process=case_collision).acquire()
    if local_paths[0].samefile(local_paths[1]):
        assert case_result.status == 'failed' and 'alias' in case_result.error
    else:
        assert case_result.status == 'succeeded' and len(case_result.items) == 2

    unsupported = Collection('controlled', ssh_key='key', cache_dir=tmp_path / 'unsupported-cache',
        process=lambda *_args, **_kw: SimpleNamespace(returncode=0, stderr='', stdout=(
            'BF|>f+++++++++|1|2026/10/22-15:00:57|C:escape\n'
            'Number of files: 2 (reg: 1, dir: 1)'))).acquire()
    assert unsupported.status == 'failed' and not unsupported.artifacts


def test_supplied_reporting_owner_is_consumed_and_never_replaced(tmp_path, application_factory):
    from bytefault.core.contracts import ContractError
    root = ResultRoot(tmp_path / 'caller-results')
    reporter = Reporting(root)
    try:
        for number, configured in enumerate((None, str(root.path))):
            app, _ = application_factory(reporting=reporter, monitoring=reporting_monitor(),
                service_configuration=ServiceConfiguration(result_root=configured))
            assert app.submit(literal(tmp_path, 'supplied-' + str(number))).outcome == 'completed'
            assert await_followup(app)['report']['status'] == 'succeeded'
            assert app.reporting is reporter and app.management.reporting is reporter
            assert app.close()['outcome'] == 'completed' and not root.closed
        before = (root.path / 'results.bfr').read_bytes()
        with pytest.raises(ContractError, match='conflicting_input'):
            application_factory(reporting=reporter,
                service_configuration=ServiceConfiguration(result_root=str(tmp_path / 'different')))
        assert (root.path / 'results.bfr').read_bytes() == before and not (tmp_path / 'different').exists()
    finally:
        root.close()
