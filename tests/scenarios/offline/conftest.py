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

"""Offline scenario guard, active during collection and import.

Install denial before any product import. An audit hook also catches code that
retained a constructor/method reference before monkeypatching. All subprocesses
are denied in this slice (including ping/ssh and shell launchers).
"""
import os
import socket
import subprocess
import sys
import unittest.mock  # Initialize Windows mock/asyncio before Popen is replaced by the guard.
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
_original_popen = subprocess.Popen
_permitted_child = None


def deny(*args, **kwargs):
    raise AssertionError("Offline guard forbids real networking and unguarded subprocesses")


def audit(event, args):
    if event == 'subprocess.Popen' and _permitted_child is not None:
        executable, command, cwd, env = args
        exact_command = (command == subprocess.list2cmdline(_permitted_child) if
                         isinstance(command, str) else tuple(command) == _permitted_child)
        if (exact_command and executable is not None and
                str(Path(executable).resolve()) == str(Path(sys.executable).resolve()) and
                Path(cwd).resolve() == Path(_permitted_child[4]).resolve()):
            return
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.posix_spawn',
            'os.exec', 'os.spawn', 'os.fork', 'os.forkpty', 'os.startfile', 'os.startfile/2'):
        deny()


sys.addaudithook(audit)
for name in ('create_connection', 'create_server', 'socketpair',
             'fromfd', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex',
             'gethostbyaddr', 'getnameinfo', 'getfqdn'):
    if hasattr(socket, name):
        setattr(socket, name, deny)
subprocess.Popen = deny
subprocess.run = deny
subprocess.call = deny
subprocess.check_call = deny
subprocess.check_output = deny
for name in ('system', 'popen', 'startfile', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
             'spawnv', 'spawnve', 'spawnvp', 'spawnvpe'):
    if hasattr(os, name):
        setattr(os, name, deny)

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))


class Clock:
    def __init__(self, trace):
        self.now = 0
        self.trace = trace

    def __call__(self):
        return self.now

    def sleep(self, ticks):
        self.trace.append(('sleep', ticks))
        self.now += ticks


class Stream:
    def __init__(self, trace, clock, *, open_error=None, close_error=None, sends=(), reads=(b'\x00\xff',)):
        self.trace = trace
        self.clock = clock
        self.open_error = open_error
        self.close_error = close_error
        self.sends = list(sends)
        self.reads = list(reads)
        self.closed = False
        self.timeout = 10

    def settimeout(self, value):
        self.timeout = value

    def connect(self, target):
        self.trace.append(('open', target))
        if self.open_error:
            raise self.open_error

    def send(self, data):
        self.trace.append(('offer', bytes(data)))
        step = self.sends.pop(0) if self.sends else len(data)
        if isinstance(step, Exception):
            raise step
        return step

    def recv(self, cap):
        self.trace.append(('read', cap))
        step = self.reads.pop(0) if self.reads else socket.timeout('waiting')
        self.clock.now += 1
        if isinstance(step, Exception):
            raise step
        data = step[:cap]
        if len(step) > cap:
            self.reads.insert(0, step[cap:])
        return data

    def close(self):
        self.trace.append(('close',))
        if self.close_error:
            raise self.close_error
        self.closed = True


@pytest.fixture
def application_factory():
    applications = []
    def make(**options):
        from bytefault.application import Application
        from bytefault.fuzzers.transport import EngineTransport
        traces = []
        stream_options = options.pop('stream_options', {})
        def transport(request):
            trace = []
            clock = Clock(trace)
            stream = Stream(trace, clock, **stream_options)
            traces.append((trace, stream, clock))
            return EngineTransport(request, socket_factory=lambda *args: stream,
                sleep=clock.sleep, clock=clock)
        application = Application(transport_factory=transport, **options)
        applications.append(application)
        return application, traces
    yield make
    for application in applications:
        application.close()


@pytest.fixture
def engine_factory(tmp_path, monkeypatch):
    engines = []
    def make(*, record_store=None, monitoring=None, **stream_options):
        from bytefault.core.contracts import TransportRequest
        from bytefault.fuzzers.transport import EngineTransport
        import bytefault.fuzzers.fuzzer as fuzzer_module
        from bytefault.fuzzers.fuzzer import ProtocolFuzzer
        from bytefault.core.storage import LocalRecordStore
        artifact_root = tmp_path / f'engine-{len(engines)}'
        monkeypatch.setattr(fuzzer_module, 'ARTIFACTS_DIR', artifact_root)
        trace = []
        clock = Clock(trace)
        stream = Stream(trace, clock, **stream_options)
        adapter = EngineTransport(TransportRequest('offline.invalid', 1234, 10, 2, 3),
            socket_factory=lambda *args: stream, sleep=clock.sleep, clock=clock)
        store = record_store or LocalRecordStore(artifact_root / 'required.bfr')
        engine = ProtocolFuzzer('offline.invalid', timeout=10, transport=adapter,
                                presentation_capacity=2, record_store=store, monitoring=monitoring)
        assert engine.crash_manager is None and engine.monitor is None
        engines.append(engine)
        return engine, trace, stream, clock
    yield make
    for engine in engines:
        engine.disconnect()
        engine.close_observers()
        if engine.record_store is not None:
            engine.record_store.close()


@pytest.fixture
def storage_child(tmp_path):
    """Only this exact isolated, network-denying local child may launch.

    Product cannot use this permission: the original Popen is kept private here
    and the audit allowance is scoped to the exact command during construction.
    Child output and its store are confined to this fixture's temp directory.
    """
    children = []
    def start(point):
        global _permitted_child
        assert point in ('ack_start', 'ack_materialization', 'offer', 'ack_result', 'partial_tail')
        root = tmp_path / point
        root.mkdir()
        runner = Path(__file__).with_name('storage_child.py').resolve()
        command = (sys.executable, '-I', '-B', str(runner), str(root.resolve()), point)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        _permitted_child = command
        try:
            process = _original_popen(list(command), cwd=str(root), env=env,
                executable=sys.executable,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            _permitted_child = None
        children.append(process)
        return process, root
    yield start
    for process in children:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


@pytest.fixture
def result_owner_child(tmp_path):
    """Exact filesystem-only owner child; use the existing registered guard."""
    import json
    children = []
    def start(mode, result_root):
        global _permitted_child
        assert mode in ('attempt', 'hold', 'abrupt')
        result_root = Path(result_root).resolve()
        assert result_root.is_relative_to(tmp_path.resolve())
        work = tmp_path / ('owner-child-' + str(len(children))); work.mkdir()
        runner = Path(__file__).with_name('result_owner_child.py').resolve()
        command = (sys.executable, '-I', '-B', str(runner), str(work.resolve()), mode, str(result_root))
        (work / 'command.json').write_text(json.dumps({'executable':sys.executable,
            'argv':command,'cwd':str(work),'result_root':str(result_root)}),encoding='utf-8')
        _permitted_child = command
        try:
            child = _original_popen(list(command), cwd=str(work), executable=sys.executable,
                env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        finally:
            _permitted_child = None
        children.append(child)
        return child, work
    yield start
    for child in children:
        if child.poll() is None: child.kill()
        child.wait(timeout=5)
        child.stdout.close(); child.stderr.close()


@pytest.fixture
def campaign_storage_child(tmp_path):
    """Run the exact local, network-denying campaign storage child."""
    children = []

    def start(point, source=None):
        global _permitted_child
        assert point in ('materialized', 'postoffer', 'result', 'partialtail', 'retry_resume',
                         'resume_materialized', 'resume_postoffer', 'resume_result', 'resume_partialtail',
                         'resume_hold', 'resume_again', 'resume_expiry', 'resume_prepared',
                         'resume_partial_family_seeded', 'resume_partial_family_unseeded')
        root = tmp_path / point
        root.mkdir()
        if source is not None:
            (root / 'source.bfr').write_bytes(Path(source).read_bytes())
        runner = Path(__file__).with_name('campaign_storage_child.py').resolve()
        command = (sys.executable, '-I', '-B', str(runner), str(root.resolve()), point)
        _permitted_child = command
        try:
            process = _original_popen(list(command), cwd=str(root), executable=sys.executable,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            _permitted_child = None
        children.append(process)
        return process, root

    yield start
    for process in children:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()


@pytest.fixture
def services_child(tmp_path):
    """Run the exact local service child while target networking stays denied."""
    children = []

    def start(mode):
        global _permitted_child
        assert mode in ('success', 'report_failure', 'replay_module', 'replay_script',
                        'replay_root', 'replay_root_partial')
        root = tmp_path / mode
        root.mkdir()
        runner = Path(__file__).with_name('services_child.py').resolve()
        command = (sys.executable, '-I', '-B', str(runner), str(root.resolve()), mode)
        _permitted_child = command
        try:
            process = _original_popen(list(command), cwd=str(root), executable=sys.executable,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            _permitted_child = None
        children.append(process)
        return process, root

    yield start
    for process in children:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()
