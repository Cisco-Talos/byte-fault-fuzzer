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

"""Focused offline checks for selected connection pacing and incremental collection."""
from types import SimpleNamespace
import threading
import time
import os
import shutil
from pathlib import Path
import pytest

from bytefault.core.connection_pacing import ConnectionPacer
from bytefault.core.contracts import TransportRequest
from bytefault.fuzzers.transport import EngineTransport
from bytefault.management.collection import Collection


@pytest.mark.parametrize('entry,disabled', (
    ('cli', False), ('cli', True), ('api', False), ('api', True)))
def test_ordinary_campaign_default_check_and_disabled_pacing(tmp_path, entry, disabled):
    from bytefault.application import Application, CampaignRequest
    from bytefault.cli import execute_arguments as public_execute
    from bytefault.monitoring import MonitoringConfig

    events, connections = [], []
    class Clock:
        now = 0.0
        def __call__(self):
            return self.now
        def sleep(self, seconds):
            if seconds:
                events.append(('wait', seconds))
                self.now += seconds
    clock = Clock()

    class Socket:
        def __init__(self):
            self.index = len(connections)
            connections.append(self)
        def settimeout(self, value):
            pass
        def connect(self, address):
            events.append(('connect', self.index))
        def send(self, data):
            events.append(('send', bytes(data)))
            return len(data)
        def close(self):
            events.append(('close', self.index))

    app = Application(transport_factory=lambda request: EngineTransport(request,
        socket_factory=lambda *_: Socket(), sleep=clock.sleep, clock=clock))
    app._connection_pacer_type = lambda: ConnectionPacer(sleep=clock.sleep, clock=clock)
    record_path = str(tmp_path / f'{entry}-{disabled}.bfr')
    try:
        if entry == 'cli':
            args = ['fuzz', 'raw', 'offline.invalid', '--port', '1234', '--seed-hex', '41',
                '--no-recv', '--no-ui', '--records', record_path, '--tcp-pre-delay', '.25',
                '--tcp-post-delay', '.5', '--connection-delay', '1.5']
            if disabled:
                args += ['--health-check-mode', 'disabled']
            result = public_execute(args, app)
        else:
            base = app.protocol_request('raw', 'offline.invalid', port=1234, seed=b'A',
                no_receive=True, pre_delay=.25, post_delay=.5, connection_delay=1.5,
                record_path=record_path)
            result = (app.submit(CampaignRequest(base.conversation, base.transport,
                base.record_path, monitoring_configuration=MonitoringConfig(health_check_mode='disabled')))
                if disabled else app.campaign(base))
        records = app.read_records(result.run_id).records
        checks = [record.data['observation'] for record in records if record.kind == 'observation'
            and record.data['observation']['kind'] == 'service_check']
        assert result.outcome == 'completed' and result.fuzz_tests == 1
        assert len(checks) == (0 if disabled else 1)
        assert all(check['service_readiness'] == 'available'
            and check['correlation']['run_id'] == result.run_id for check in checks)
        assert events == ([('wait', .25), ('connect', 0), ('send', b'A'),
            ('close', 0), ('wait', .5)] + ([] if disabled else
            [('wait', 1.5), ('wait', .25), ('connect', 1), ('close', 1), ('wait', .5)]))
        actions = [record.data['result'] for record in records if record.kind == 'action_result']
        assert actions[0]['transport']['connection']['connection_throttle']['seconds'] == 0
        if checks:
            probe = next(record.data for record in records if record.kind == 'probe_result')
            assert probe['transport']['connection']['connection_throttle']['seconds'] == 1.5
    finally:
        app.close()


def test_public_cli_and_structured_timing_selection(tmp_path):
    from bytefault.fuzzers.cli import argument_request
    from bytefault.management.maintenance import resolve_arguments as maintenance_arguments
    from bytefault.replay.replay_packet import resolve_arguments as replay_arguments, replay_packets
    from bytefault.application import Application

    fuzz = argument_request(['offline.invalid', '--port', '1234', '--seed-hex', '41',
        '--records', str(tmp_path / 'fuzz.bfr'), '--connection-delay', '1.5'])
    maintenance = maintenance_arguments(['offline.invalid', '--ssh-key', 'key',
        '--remote-only', '--connection-delay', '1.5'])
    structured = Application().protocol_request('raw', 'offline.invalid', port=1234,
        seed=b'A', connection_delay=1.5, record_path=str(tmp_path / 'structured.bfr'))
    replay = replay_arguments(['offline.invalid', '41', '--port', '1234',
        '--connection-delay', '1.5'], Application())
    callable_replay = replay_packets('offline.invalid', 1234, (b'A',),
        connection_delay_s=1.5, wait_between=.25, prepare=True)
    assert all(request.transport.connection_delay == 1.5
        for request in (fuzz, structured, replay.request, callable_replay))
    assert callable_replay.transport.pre_delay == .25
    assert maintenance.connection_delay == 1.5


def test_generic_wait_follows_close_and_post_then_precedes_next_pre():
    events = []

    class Socket:
        def settimeout(self, value):
            pass

        def connect(self, address):
            events.append('connect')

        def close(self):
            events.append('close')

    transport = EngineTransport(TransportRequest('controlled', 1234, 1, .5, .25, 2),
        socket_factory=lambda *_: Socket(), sleep=lambda seconds: events.append(('wait', seconds)))
    transport.pacer = ConnectionPacer(sleep=lambda seconds: events.append(('wait', seconds)))
    assert transport.open()
    transport.close()
    assert transport.open()
    transport.close()
    assert events == [('wait', .5), 'connect', 'close', ('wait', .25),
        ('wait', 2), ('wait', .5), 'connect', 'close', ('wait', .25)]


def test_stop_after_pacing_does_not_open_or_hold_pacer():
    stopped = threading.Event()
    events = []
    transport = EngineTransport(TransportRequest('controlled', 1234, 1, .5, 0, 1),
        socket_factory=lambda *_: events.append('constructed'),
        sleep=lambda seconds: stopped.set())
    transport.pacer = ConnectionPacer()
    transport.bind_stop_event(stopped)
    assert not transport.open()
    assert events == [] and not transport.pacer._active


def test_builtin_pacing_waits_to_deadline_after_early_event_return(monkeypatch):
    class EarlyWait:
        now = 0.0

        def __init__(self, quantum=.4):
            self.calls = []
            self.quantum = quantum

        def is_set(self):
            return False

        def wait(self, seconds):
            self.calls.append(seconds)
            self.now += min(seconds, self.quantum)
            return False

    event = EarlyWait()
    transport = EngineTransport(TransportRequest('controlled', 1234, 1),
        clock=lambda: event.now)
    transport.bind_stop_event(event)
    with monkeypatch.context() as patch:
        patch.setattr('bytefault.fuzzers.transport.time.monotonic', lambda: event.now)
        pacing = transport._pace(1)
    assert pacing['outcome'] == 'completed'
    assert pacing['completed_at'] - pacing['started_at'] >= 1
    assert len(event.calls) == 3 and event.calls[0] == 1

    for pre, generic, minimum in ((.03, 0, .03), (0, .03, .03), (.03, .03, .06)):
        event = EarlyWait(quantum=.01)
        connects = []

        class Socket:
            def settimeout(self, value):
                pass

            def connect(self, address):
                connects.append(event.now)

            def close(self):
                pass

        transport = EngineTransport(TransportRequest('controlled', 1234, 1,
            pre, 0, generic), socket_factory=lambda *_: Socket(), clock=lambda: event.now)
        transport.bind_stop_event(event)
        transport.pacer = ConnectionPacer(clock=lambda: event.now)
        with monkeypatch.context() as patch:
            patch.setattr('bytefault.fuzzers.transport.time.monotonic', lambda: event.now)
            assert transport.open()
            assert transport.last_open['connection_throttle']['seconds'] == 0
            transport.close()
            first_close = event.now
            assert transport.open()
            assert transport.last_open['connection_throttle']['seconds'] == generic
            transport.close()
        assert connects[1] - first_close >= minimum
        assert not transport.pacer._active


def test_incremental_rsync_cache_and_stable_handoff(tmp_path):
    remote, calls = {}, []

    def process(argv, **kwargs):
        calls.append((argv, kwargs))
        assert argv[0] == 'rsync' and '--checksum' in argv
        assert '--timeout=30' in argv and kwargs['timeout'] is None
        current = Path(argv[-1])
        backup = Path(next(arg.split('=', 1)[1] for arg in argv if arg.startswith('--backup-dir=')))
        for name, (data, modified) in remote.items():
            target = current / name
            if target.exists() and target.read_bytes() == data:
                continue
            if target.exists():
                backup.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup / name)
            staged = current / (name + '.incoming')
            staged.write_bytes(data)
            os.utime(staged, ns=(modified, modified))
            staged.replace(target)
        lines = [f'BF|.f         |{len(data)}|2026/10/22-15:00:57|{name}'
            for name, (data, _) in remote.items()]
        return SimpleNamespace(returncode=0, stdout='\n'.join((*lines,
            f'Number of files: {len(remote) + 1} (reg: {len(remote)}, dir: 1)')), stderr='')

    collector = Collection('controlled', ssh_key='key', cache_dir=tmp_path, process=process)
    empty = collector.acquire()
    assert empty.status == 'succeeded' and empty.inventory_status == 'empty'
    remote['core A'] = (b'first', 1_000_000_000)
    first = collector.acquire()
    assert len(first.artifacts) == 1 and Path(first.artifacts[0]).read_bytes() == b'first'
    unchanged = collector.acquire()
    assert unchanged.artifacts == () and unchanged.items == ()
    remote['core A'] = (b'changed', 1_000_000_000)  # same name and mtime
    remote['core B'] = (b'newer', 2_000_000_000)
    second = collector.acquire()
    assert [item['name'] for item in second.items] == ['core A', 'core B']
    assert [item['association'] for item in second.items] == [
        'unpaired_new_core', 'provisional_newest_for_detected_crash']
    assert Path(first.artifacts[0]).read_bytes() == b'first'
    assert [Path(path).read_bytes() for path in second.artifacts] == [b'changed', b'newer']
    assert len(calls) == 4 and all(argv[0] == 'rsync' for argv, _ in calls)


def test_failed_stable_handoff_is_published_by_later_collection_owner(tmp_path, monkeypatch):
    calls = []

    def process(argv, **kwargs):
        calls.append(argv)
        cached = Path(argv[-1]) / 'core-A'
        if not cached.exists():
            cached.write_bytes(b'complete-core')
        return SimpleNamespace(returncode=0, stderr='',
            stdout='BF|.f         |13|2026/10/22-17:00:00|core-A\n'
                'Number of files: 2 (reg: 1, dir: 1)')

    def collector():
        return Collection('controlled', ssh_key='key', cache_dir=tmp_path, process=process)

    def fail_hardlink(*args):
        raise OSError('controlled transient handoff failure')

    with monkeypatch.context() as patch:
        patch.setattr(Path, 'hardlink_to', fail_hardlink)
        failed = collector().acquire()
    assert failed.status == 'failed' and failed.artifacts == ()
    assert 'stable acquired core link failed' in failed.error
    assert len(list(tmp_path.glob('*/pending/core-A'))) == 1

    later = collector()
    recovered = later.acquire()
    unchanged = later.acquire()
    assert recovered.status == 'succeeded' and recovered.inventory_status == 'available'
    assert len(recovered.artifacts) == 1 and Path(recovered.artifacts[0]).read_bytes() == b'complete-core'
    assert recovered.items[0]['association'] == 'provisional_newest_for_detected_crash'
    assert unchanged.status == 'succeeded' and unchanged.inventory_status == 'no_new'
    assert unchanged.artifacts == () and not list(tmp_path.glob('*/pending/core-A'))
    assert len(calls) == 3 and all(argv[0] == 'rsync' for argv in calls)


def test_rsync_absence_partial_and_selected_cap_are_truthful(tmp_path):
    mode = ['absent']

    def process(argv, **kwargs):
        if mode[0] == 'absent':
            return SimpleNamespace(returncode=23,
                stderr='rsync: [sender] change_dir "/root/cores" failed: No such file or directory (2)', stdout='')
        if mode[0] == 'raced_file':
            return SimpleNamespace(returncode=23, stderr='core vanished: No such file or directory', stdout='')
        if mode[0] == 'unavailable':
            return SimpleNamespace(returncode=255, stderr='connection refused', stdout='')
        if mode[0] == 'partial':
            partial = Path(argv[-1]) / '.rsync-partial'
            partial.mkdir(exist_ok=True)
            (partial / 'core').write_bytes(b'incomplete')
            return SimpleNamespace(returncode=23, stderr='transfer failed', stdout='')
        if mode[0] == 'skipped':
            return SimpleNamespace(returncode=0, stderr='',
                stdout='oversize is over max-size\nNumber of files: 2 (reg: 1, dir: 1)')
        if mode[0] == 'named_partial_file':
            (Path(argv[-1]) / '.rsync-partial').write_bytes(b'complete')
            return SimpleNamespace(returncode=0, stderr='',
                stdout='BF|>f+++++++++|8|2026/10/22-15:00:57|.rsync-partial\n'
                    'Number of files: 2 (reg: 1, dir: 1)')
        if mode[0] == 'named_partial_failure':
            return SimpleNamespace(returncode=23, stderr='controlled later transfer failure', stdout='')
        return SimpleNamespace(returncode=0, stderr='', stdout='Number of files: 1 (dir: 1)')

    collector = Collection('controlled', ssh_key='key', cache_dir=tmp_path, process=process,
        max_file_size_mb=1)
    assert collector.acquire().inventory_status == 'absent'
    mode[0] = 'raced_file'
    assert collector.acquire().inventory_status == 'failed'
    mode[0] = 'unavailable'
    assert collector.acquire().inventory_status == 'unavailable'
    mode[0] = 'partial'
    partial = collector.acquire()
    assert partial.status == 'failed' and partial.artifacts == ()
    assert partial.items[0]['status'] == 'partial_or_unverified'
    mode[0] = 'empty'
    capped = collector.acquire()
    assert capped.status == 'succeeded' and capped.inventory_status == 'empty'
    assert capped.artifacts == ()
    mode[0] = 'skipped'
    skipped = collector.acquire()
    assert skipped.status == 'failed' and skipped.inventory_status == 'skipped'
    assert skipped.items[0]['name'] == 'oversize' and skipped.items[0]['size'] is None
    named_collector = Collection('controlled', ssh_key='key', cache_dir=tmp_path / 'named', process=process)
    mode[0] = 'named_partial_file'
    named = named_collector.acquire()
    assert named.status == 'succeeded' and Path(named.artifacts[0]).read_bytes() == b'complete'
    mode[0] = 'named_partial_failure'
    later = named_collector.acquire()
    assert later.status == 'failed' and later.inventory_status == 'failed'
    assert later.error == 'controlled later transfer failure' and later.artifacts == ()
    assert Path(named.artifacts[0]).read_bytes() == b'complete'


def test_rsync_inventory_decodes_escaped_names_once():
    from bytefault.management.collection import _rsync_inventory
    import pytest
    files, skipped = _rsync_inventory('BF|.f         |2|2026/10/22-15:00:57|line\\#012name\n'
        'BF|.f         |2|2026/10/22-15:00:57|literal\\#134#012name\n'
        'BF|.f         |2|2026/10/22-15:00:57|pipe|name\n'
        'large\\#012core is over max-size\nNumber of files: 5 (reg: 4, dir: 1)')
    assert set(files) == {'line\nname', 'literal\\#012name', 'pipe|name'}
    assert skipped == {'large\ncore'}
    with pytest.raises(OSError, match='file count differs'):
        _rsync_inventory('BF|.d         |4096|2026/10/22-15:00:57|./\n'
            'Number of files: 2 (reg: 1, dir: 1)')


def test_one_pacer_covers_test_and_core_acquisition(tmp_path):
    events = []
    pacer = ConnectionPacer(sleep=lambda seconds: events.append(('generic', seconds)))

    class Socket:
        def settimeout(self, value):
            pass

        def connect(self, address):
            events.append('test-connect')

        def close(self):
            events.append('close')

    transport = EngineTransport(TransportRequest('controlled', 1234, 1, .2, .3, 2),
        socket_factory=lambda *_: Socket(), sleep=lambda seconds: events.append(('wait', seconds)))
    transport.pacer = pacer
    assert transport.open()
    transport.close()
    collection = Collection('controlled', ssh_key='key', cache_dir=tmp_path,
        process=lambda *_a, **_k: (events.append('inventory') or
            SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')),
        sleep=lambda seconds: events.append(('wait', seconds)), pacer=pacer, connection_delay=2)
    assert collection.acquire().inventory_status == 'empty'
    assert events == [('wait', .2), 'test-connect', 'close', ('wait', .3),
        ('wait', 2), 'inventory']


def test_default_collection_wait_stops_before_next_connection(tmp_path):
    stopped = threading.Event()
    calls, results = [], []

    def process(*_args, **_kwargs):
        calls.append('rsync')
        return SimpleNamespace(returncode=0, stdout='Number of files: 1 (dir: 1)', stderr='')

    collector = Collection('controlled', ssh_key='key', cache_dir=tmp_path,
        connection_delay=.5, cancelled=stopped.is_set, process=process)
    assert collector.acquire().inventory_status == 'empty'
    worker = threading.Thread(target=lambda: results.append(collector.acquire()))
    worker.start()
    time.sleep(.05)
    stopped.set()
    worker.join(.2)
    assert not worker.is_alive()
    assert len(calls) == 1
    assert results[0].status == 'failed'
    assert results[0].operations[0]['error_type'] == 'InterruptedError'


def test_default_pacer_wait_reserves_one_connection_at_a_time():
    pacer = ConnectionPacer()
    pacer.before_start(0)
    pacer.finished()
    started, release, failures = [], threading.Event(), []

    def worker(identity):
        try:
            fact, _ = pacer.before_start(.15)
            assert fact['outcome'] == 'completed'
            started.append(identity)
            assert release.wait(2)
            pacer.finished()
        except BaseException as error:
            failures.append(error)

    threads = [threading.Thread(target=worker, args=(identity,)) for identity in (1, 2)]
    for thread in threads:
        thread.start()
    try:
        deadline = time.monotonic() + 1
        while not started and time.monotonic() < deadline:
            time.sleep(.005)
        assert len(started) == 1
        time.sleep(.05)
        assert len(started) == 1
    finally:
        release.set()
        for thread in threads:
            thread.join(2)
    assert not failures and len(started) == 2 and not any(thread.is_alive() for thread in threads)
