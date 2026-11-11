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

"""Fixture-owned IPv4 TCP loopback boundary.

This guard is installed and self-checked before importing any product code.
Run it in a process separate from the offline total-denial audit hook.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest


assert not any(name == 'bytefault' or name.startswith('bytefault.') for name in sys.modules), (
    'N guard must load before every product import')
LOOPBACK = '127.0.0.1'
ROOT = Path(__file__).resolve().parents[3]
N_ROOT = Path(__file__).resolve().parent
ALLOWED_N_ROOTS = (N_ROOT,)
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'src'))
_owned_binds = set()
_destinations = set()
_registry_lock = threading.RLock()


def denied(*args, **kwargs):
    raise AssertionError('Owned loopback guard forbids unregistered networking, DNS and processes')


def audit(event, args):
    if event == 'socket.__new__':
        stream, family, kind, protocol = args
        if (type(stream) is socket.socket and family == socket.AF_INET and
                kind == socket.SOCK_STREAM and protocol in (0, socket.IPPROTO_TCP)):
            return
        denied()
    if event == 'socket.bind':
        stream, address = args
        with _registry_lock:
            if id(stream) in _owned_binds and address == (LOOPBACK, 0):
                return
        denied()
    if event == 'socket.connect':
        _, address = args
        with _registry_lock:
            if (isinstance(address, tuple) and len(address) == 2 and
                    address[0] == LOOPBACK and address in _destinations):
                return
        denied()
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system',
            'os.posix_spawn', 'os.exec', 'os.spawn', 'os.fork', 'os.forkpty',
            'os.startfile', 'os.startfile/2'):
        denied()


sys.addaudithook(audit)
# CPython has no listen audit event; listening on an unbound socket implicitly
# binds a wildcard address. Intercept that ordinary method before any socket can
# be created, and reject low-level constructor bypasses at socket.__new__ above.
_os_listen = socket.socket.listen
def registered_listen(stream, backlog=1):
    with _registry_lock:
        if id(stream) not in _owned_binds or stream.getsockname() not in _destinations:
            denied()
    return _os_listen(stream, backlog)
socket.socket.listen = registered_listen
for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr',
             'getnameinfo', 'getfqdn', 'create_connection', 'create_server', 'socketpair', 'fromfd'):
    if hasattr(socket, name):
        setattr(socket, name, denied)
for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
    setattr(subprocess, name, denied)
for name in ('system', 'popen', 'startfile', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
             'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'execl', 'execle', 'execlp',
             'execlpe', 'execv', 'execve', 'execvp', 'execvpe', 'fork', 'forkpty', 'posix_spawn'):
    if hasattr(os, name):
        setattr(os, name, denied)


def self_check():
    """Every attempted I/O below must be rejected before any network syscall."""
    observations = []
    def rejection(label, operation):
        try:
            operation()
        except AssertionError as exc:
            assert 'Owned loopback guard forbids' in str(exc)
            observations.append(label)
        else:
            raise AssertionError(f'N guard escaped: {label}')
    import _socket
    for label, operation in (
        ('IPv6', lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM)),
        ('datagram', lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM)),
        ('raw_ICMP', lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)),
        ('low_level_datagram', lambda: _socket.socket(socket.AF_INET, socket.SOCK_DGRAM)),
        ('low_level_stream_constructor', lambda: _socket.socket(socket.AF_INET, socket.SOCK_STREAM)),
        ('DNS', lambda: socket.getaddrinfo('localhost', 1)),
        ('low_level_DNS', lambda: _socket.getaddrinfo('localhost', 1)),
        ('hostname', lambda: socket.gethostbyname('localhost')),
        ('ping_process', lambda: subprocess.run(['ping', LOOPBACK])),
        ('SSH_process', lambda: subprocess.Popen(['ssh', LOOPBACK])),
        ('shell_process', lambda: os.system('ping 127.0.0.1')),
    ):
        rejection(label, operation)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        rejection('nonloopback_connect', lambda: stream.connect(('192.0.2.1', 1)))
        rejection('unregistered_loopback_connect', lambda: stream.connect((LOOPBACK, 1)))
        rejection('unregistered_connect_ex', lambda: stream.connect_ex((LOOPBACK, 1)))
        rejection('unregistered_loopback_bind', lambda: stream.bind((LOOPBACK, 0)))
        rejection('wildcard_bind', lambda: stream.bind(('0.0.0.0', 0)))
        rejection('named_bind', lambda: stream.bind(('localhost', 0)))
        rejection('unregistered_listen', lambda: stream.listen())
    return tuple(observations)


# Complete before any test module may import Application or other product code.
GUARD_SELF_CHECK = self_check()


def pytest_configure(config):
    for argument in config.args:
        selected = Path(str(argument).split('::', 1)[0]).resolve()
        if not any(selected.is_relative_to(root) for root in ALLOWED_N_ROOTS):
            raise pytest.UsageError('Run loopback separately, selecting only tests/scenarios/loopback')
    for module in config.pluginmanager.get_plugins():
        location = getattr(module, '__file__', None)
        if location and Path(location).resolve() == ROOT / 'tests/scenarios/offline/conftest.py':
            raise pytest.UsageError('N cannot share the process with O total-denial guards')


def owned_socket():
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with _registry_lock:
        _owned_binds.add(id(stream))
    try:
        stream.bind((LOOPBACK, 0))
    except BaseException:
        with _registry_lock:
            _owned_binds.discard(id(stream))
        stream.close()
        raise
    endpoint = stream.getsockname()
    with _registry_lock:
        _destinations.add(endpoint)
    return stream, endpoint


def release_socket(stream, endpoint):
    try:
        stream.close()
    finally:
        with _registry_lock:
            _owned_binds.discard(id(stream))
            _destinations.discard(endpoint)


class Peer:
    """Only external peer behavior is support code; it never sends fuzz input."""
    def __init__(self, handler, count=1):
        self.listener, self.endpoint = owned_socket()
        self.listener.listen(count)
        self.deadline = time.monotonic() + 5
        self.handler, self.count = handler, count
        self.connections = []
        self.receipts, self.writes, self.endings = [], [], []
        self.accepted = 0
        self.received = threading.Event()
        self.done = threading.Event()
        self.stop = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True, name='bytefault-N-peer')
        self.thread.start()

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('N peer exceeded 5 second fixture bound')
        return min(5, remaining)

    def recv_exact(self, connection, size):
        data = bytearray()
        while len(data) < size:
            connection.settimeout(self.remaining())
            chunk = connection.recv(size - len(data))
            self.receipts.append(chunk)
            if chunk:
                self.received.set()
            if not chunk:
                raise EOFError(f'peer received only {len(data)} of {size} expected bytes')
            data.extend(chunk)
        return bytes(data)

    def send_parts(self, connection, parts):
        for part in parts:
            connection.settimeout(self.remaining())
            connection.sendall(part)
            self.writes.append(bytes(part))

    def wait_client_end(self, connection, *, allow_reset=False):
        while True:
            connection.settimeout(self.remaining())
            try:
                chunk = connection.recv(4096)
            except ConnectionResetError:
                self.endings.append('reset')
                if allow_reset:
                    return
                raise
            self.receipts.append(chunk)
            if not chunk:
                self.endings.append('eof')
                return
            self.received.set()

    def _run(self):
        try:
            for index in range(self.count):
                self.listener.settimeout(self.remaining())
                connection, address = self.listener.accept()
                assert address[0] == LOOPBACK
                self.connections.append(connection)
                self.accepted += 1
                self.handler(self, connection, index)
                connection.close()
        except BaseException as exc:
            self.error = exc
        finally:
            self.done.set()

    def snapshot(self):
        return {'endpoint': self.endpoint, 'accepted_connections': self.accepted,
                'received_chunks_hex': [value.hex() for value in self.receipts],
                'received_aggregate_hex': b''.join(self.receipts).hex(),
                'local_response_writes_hex': [value.hex() for value in self.writes],
                'client_end_observations': self.endings,
                'error': repr(self.error) if self.error else None}

    def close(self):
        self.stop.set()
        # Test assertions must precede this harness shutdown. It only bounds
        # cleanup if a test failed; it cannot supply successful product teardown.
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        release_socket(self.listener, self.endpoint)
        self.thread.join(5)
        assert not self.thread.is_alive(), 'N peer failed to join'


class Case:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.started = time.monotonic()
        self.peers, self.reservations, self.apps, self.workers = [], [], [], []
        self.outcomes = []

    def peer(self, handler, *, count=1):
        peer = Peer(handler, count)
        self.peers.append(peer)
        return peer

    def refused(self):
        stream, endpoint = owned_socket()  # deliberately never listen
        self.reservations.append((stream, endpoint))
        return stream, endpoint

    def app(self, **options):
        from bytefault.application import Application
        assert 'transport_factory' not in options
        app = Application(**options)  # actual default OS adapter
        self.apps.append(app)
        return app

    def submit(self, app, request, *, operation=None):
        assert request.transport.host == LOOPBACK and request.transport.timeout <= 5
        assert all(not action.receive.requested or 0 < action.receive.deadline <= 2
                   for action in request.conversation.plan.actions)
        outcome = {'result': None, 'error': None}
        def run():
            try:
                outcome['result'] = operation() if operation else app.submit(request)
            except BaseException as exc:
                outcome['error'] = exc
        worker = threading.Thread(target=run, daemon=True, name='bytefault-N-application')
        self.workers.append((worker, app, request))
        self.outcomes.append(outcome)
        worker.start()
        return worker, outcome

    def complete(self, worker, outcome):
        worker.join(max(0, min(5, self.started + 10 - time.monotonic())))
        assert not worker.is_alive(), 'N application exceeded bounded case work'
        if outcome['error']:
            raise outcome['error']
        return outcome['result']

    def observe_finished(self, app, request, result, peer=None):
        """Verify actual lifecycle before fixture shutdown can affect sockets."""
        from bytefault.core.storage import reopen_records
        from bytefault.fuzzers.transport import EngineTransport
        status = app.status(result.run_id)
        engine = app._run(result.run_id).engine
        assert type(engine.transport) is EngineTransport
        assert engine.transport.socket_factory is socket.socket
        assert not status.active and not status.engine.connected
        assert result.cleanup.outcome == 'completed'
        assert engine.socket is None and engine.transport.stream is None
        assert engine.record_store.closed
        evidence, actions = reopen_records(request.record_path), reopen_records(request.log_path)
        assert evidence.issue is actions.issue is None
        assert evidence.records[-1].kind == ('campaign_terminal' if hasattr(result,'last_conversation') else 'case_terminal')
        assert evidence.records[-1].data.result.outcome == result.outcome
        cleanup = [r for r in evidence.records if r.kind == 'transport_cleanup']
        if hasattr(result,'last_conversation'):
            assert evidence.records[-1].data.result.cleanup.outcome=='completed'
        else:
            assert len(cleanup) == 1 and cleanup[0].data.cleanup.outcome == 'completed'
        assert len(evidence.records) == len(actions.records)
        assert [r.kind for r in evidence.records] == [r.kind for r in actions.records]
        assert app.close().outcome == 'completed'
        if peer is not None:
            assert peer.done.wait(peer.remaining()), 'peer has not observed product completion'
            peer.thread.join(peer.remaining())
            assert peer.error is None, repr(peer.error)
            assert not peer.thread.is_alive()
        # Separate artifacts, without interpreting local acceptance as peer receipt.
        (self.root / f'{result.run_id}-client.json').write_text(json.dumps({
            'outcome': result.outcome, 'run_id': result.run_id,
            'target': {'host': request.transport.host, 'port': request.transport.port,
                       'connect_timeout_seconds': request.transport.timeout},
            'transport': [{'action_id': a.action_id, 'offered_hex': a.transport.offered.hex(),
                'prepared_hex': a.transport.prepared.hex(), 'acceptance': a.transport.acceptance,
                'accepted_count': a.transport.accepted_count,
                'accepted_hex': a.transport.accepted_prefix.hex(),
                'received_hex': a.transport.received.hex(), 'receive_outcome': a.transport.receive_outcome,
                'receive_requested': a.transport.receive_requested, 'error': a.transport.error,
                'response_boundary': a.transport.response_boundary} for a in
                (result.last_conversation.actions if hasattr(result,'last_conversation') else result.actions)],
            'cleanup': {'phase': result.cleanup.phase, 'outcome': result.cleanup.outcome}}, indent=2), encoding='utf-8')
        if peer is not None:
            (self.root / f'{result.run_id}-peer.json').write_text(json.dumps(peer.snapshot(), indent=2), encoding='utf-8')
        return evidence, actions

    def close(self):
        errors = []
        def cleanup(operation):
            try:
                operation()
            except BaseException as exc:
                errors.append(repr(exc))
        try:
            for worker, app, request in self.workers:
                if worker.is_alive():
                    cleanup(app.close)  # includes retained stop during initialization
            for peer in self.peers:
                cleanup(peer.close)
            for stream, endpoint in self.reservations:
                cleanup(lambda: release_socket(stream, endpoint))
            for worker, app, _ in self.workers:
                worker.join(max(0, min(5, self.started + 15 - time.monotonic())))
                if worker.is_alive():
                    errors.append('N application failed to join after bounded cleanup')
            for app in self.apps:
                cleanup(app.close)
        finally:
            (self.root / 'guard-and-bound.json').write_text(json.dumps({
                'self_check_rejections_before_product_import': GUARD_SELF_CHECK,
                'elapsed_seconds': time.monotonic() - self.started,
                'cleanup_errors': errors,
                'peer_bound_seconds': 5, 'selected_receive_bound_seconds': 2,
                'overall_bound_seconds': 15}, indent=2), encoding='utf-8')
        assert time.monotonic() - self.started <= 15, 'N case exceeded 15 second fixture bound'
        assert not errors, errors


@pytest.fixture
def n_case(tmp_path):
    case = Case(tmp_path)
    try:
        yield case
    finally:
        case.close()


@pytest.fixture
def raw_root(tmp_path):
    root = tmp_path / 'protocols'
    root.mkdir()
    source = ROOT / 'src/bytefault/protocols/raw'
    shutil.copytree(source, root / 'raw',
                    ignore=shutil.ignore_patterns('__pycache__'))
    return root
