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

import ast
import importlib
import importlib.abc
import sys
import threading
from pathlib import Path

import pytest


def exchange(engine, data, cap=4):
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.core.contracts import ReceiveRequest
    result = engine.execute_conversation(raw_request(data, receive=ReceiveRequest(cap=cap, deadline=10)))
    return result.actions[-1].transport.received or None if result.actions else None


class NoUi(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'rich' or fullname.startswith(('rich.', 'bytefault.ui')):
            raise AssertionError(f'UI import forbidden: {fullname}')


def imports_at_load(nodes):
    """Imports executed by module loading, excluding callable entry bodies."""
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield from ([node.module or ''] if isinstance(node, ast.ImportFrom)
                        else [alias.name for alias in node.names])
        elif isinstance(node, ast.If):
            condition = ast.unparse(node.test)
            if '__name__' not in condition and 'TYPE_CHECKING' not in condition:
                yield from imports_at_load(node.body + node.orelse)
        elif isinstance(node, ast.Try):
            yield from imports_at_load(node.body + node.orelse + node.finalbody)
            for handler in node.handlers:
                yield from imports_at_load(handler.body)


def test_headless_without_ui_imports(engine_factory):
    original_modules = {name: module for name, module in sys.modules.items()
                        if name == 'bytefault' or name.startswith('bytefault.')}
    for name in list(sys.modules):
        if name == 'bytefault' or name.startswith('bytefault.'):
            del sys.modules[name]
    blocker = NoUi()
    sys.meta_path.insert(0, blocker)
    try:
        engine, trace, _, _ = engine_factory()
        assert exchange(engine, b'ABC', 4) == b'\x00\xff'
        assert not engine.status().connected
        assert engine.control('stop').outcome == 'completed'
        before = list(trace)
        assert exchange(engine, b'NEXT', 4) is None
        assert trace == before
        assert engine.status().stop_requested
        assert engine.control('invented').outcome == 'rejected'
        assert engine.control('resume').outcome == 'rejected'
        engine.disconnect()
        assert engine.status().state == 'stopped'
        # The same blocker rejects a deliberately introduced engine dependency.
        with pytest.raises(AssertionError, match='UI import forbidden'):
            exec('import bytefault.ui', {})
    finally:
        sys.meta_path.remove(blocker)
        for name in list(sys.modules):
            if name == 'bytefault' or name.startswith('bytefault.'):
                del sys.modules[name]
        sys.modules.update(original_modules)


def test_explicit_ui_request_reports_unavailable_module_and_runs_headless(
        tmp_path, application_factory, monkeypatch, capsys):
    from bytefault.fuzzers.cli import execute_arguments

    app, traces = application_factory()
    actual_find_spec = importlib.util.find_spec
    def without_ui(name, *args, **kwargs):
        return None if name == 'bytefault.ui' else actual_find_spec(name, *args, **kwargs)
    monkeypatch.setattr(importlib.util, 'find_spec', without_ui)
    result = execute_arguments(['offline.invalid', '--port', '1234', '--seed-hex', '414243',
        '--no-recv', '--ui', '--records', str(tmp_path / 'headless.bfr')], app, terminal=True)

    assert result.outcome == 'completed'
    assert 'Optional Bytefault UI is unavailable; executing through the headless Application.' \
        in capsys.readouterr().err
    assert [entry for trace, _, _ in traces for entry in trace if entry[0] == 'offer'] == [
        ('offer', b'ABC')]


def test_snapshot_consumer_isolation(engine_factory):
    engine, _, _, _ = engine_factory()
    done = threading.Event()
    class Consumer:
        def on_session_start(self, state):
            with pytest.raises(TypeError):
                state.host = 'mutated'
            with pytest.raises(TypeError):
                state.current_field_bytes['x'] = b'bad'
            done.set()
    engine.add_listener(Consumer())
    engine._emit('on_session_start', state=engine.session_state)
    engine.session_state.current_field_bytes['later'] = b'new'
    assert done.wait(1)
    assert engine.session_state.host == 'offline.invalid'
    assert 'x' not in engine.session_state.current_field_bytes


def test_throwing_and_blocked_optional_consumers(engine_factory):
    engine, trace, _, _ = engine_factory()
    entered = threading.Event()
    release = threading.Event()
    class Blocked:
        def on_progress(self, **kwargs):
            entered.set()
            release.wait(2)
    class Throwing:
        def on_progress(self, **kwargs):
            raise RuntimeError('presentation failed')
    engine.add_listener(Blocked())
    engine.add_listener(Throwing())
    try:
        engine._emit('on_progress', iteration=0)
        assert entered.wait(1)
        for i in range(10):
            engine._emit('on_progress', iteration=i)
        assert engine.status().presentation_dropped > 0
        assert exchange(engine, b'ABC', 4) == b'\x00\xff'
        assert engine.control('stop').outcome == 'completed'
        assert [t for t in trace if t[0] == 'offer'] == [('offer', b'ABC')]
        assert engine.status().presentation_failed >= 1
        outcomes = engine.close_observers()
        assert outcomes[0].outcome == 'pending'
        assert '2 queued optional snapshots discarded' in outcomes[0].reason
        assert engine.status().presentation_discarded_on_close >= 2
    finally:
        release.set()


def test_pause_controls_remain_usable(engine_factory):
    engine, trace, _, _ = engine_factory()
    assert engine.control('pause').outcome == 'completed'
    worker = threading.Thread(target=lambda: exchange(engine, b'ABC', 4))
    worker.start()
    assert engine.status().paused
    assert not any(t[0] == 'offer' for t in trace)
    assert engine.control('stop').outcome == 'completed'
    worker.join(1)
    assert not worker.is_alive()
    assert not any(t[0] == 'offer' for t in trace)


def test_stop_during_pending_receive(engine_factory):
    import socket
    engine, trace, stream, clock = engine_factory(reads=())
    start = clock.now
    def pending(cap):
        clock.now += 1
        assert engine.control('stop').outcome == 'completed'
        raise socket.timeout('controlled pending receive')
    stream.recv = pending
    assert exchange(engine, b'ABC', 4) is None
    assert engine.last_transport_result.receive_outcome == 'cancelled'
    assert engine.last_transport_result.accepted_count == 3
    assert clock.now - start <= 10
    before = list(trace)
    exchange(engine, b'NEXT', 4)
    assert trace == before


def test_static_dependency_direction():
    root = Path(__file__).resolve().parents[3] / 'src/bytefault'
    selected = ['fuzzers/fuzzer.py', 'fuzzers/session_mixin.py',
                'fuzzers/transport.py', 'fuzzers/presentation.py', 'fuzzers/session_state.py',
                'fuzzers/event_listener.py', 'fuzzers/conversation.py', 'fuzzers/inputs.py',
                'fuzzers/declarations.py', 'core/contracts.py', 'core/validation.py', 'core/byte_edits.py',
                'core/records.py', 'core/storage.py', 'fuzzers/recording.py', 'fuzzers/continuation.py',
                'monitoring/policy.py', 'monitoring/heartbeat.py']
    forbidden = ('bytefault.ui', 'rich', 'bytefault.fuzzers.rich',
                 'bytefault.fuzzers.theme', 'bytefault.fuzzers.keypress')
    for relative in selected:
        tree = ast.parse((root / relative).read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            names = [node.module or ''] if isinstance(node, ast.ImportFrom) else (
                [n.name for n in node.names] if isinstance(node, ast.Import) else [])
            assert not any(n.startswith(forbidden) for n in names), (relative, names)
    for source in ('contracts.py', 'validation.py', 'byte_edits.py', 'records.py', 'storage.py'):
        tree = ast.parse((root / 'core' / source).read_text(encoding='utf-8'))
        assert not any(isinstance(n, ast.ImportFrom) and (n.module or '').startswith(
            ('bytefault.fuzzers', 'bytefault.protocols', 'bytefault.generators',
             'bytefault.monitoring', 'bytefault.management')) for n in ast.walk(tree))

    seen = set()
    pending = ['bytefault.fuzzers.fuzzer', 'bytefault.fuzzers']
    while pending:
        module = pending.pop()
        if module in seen:
            continue
        seen.add(module)
        path = root.parent / (module.replace('.', '/') + '.py')
        if not path.is_file():
            path = root.parent / module.replace('.', '/') / '__init__.py'
        if not path.is_file():
            continue
        for name in imports_at_load(ast.parse(path.read_text(encoding='utf-8')).body):
            assert not name.startswith(forbidden), (module, name)
            if name.startswith('bytefault.'):
                pending.append(name)
    assert 'bytefault.fuzzers.transport' in seen
    assert 'bytefault.core.tcp_session' not in seen
    assert 'bytefault.core.crash_manager' not in seen


def test_preserved_ui_sources_and_owned_listener_state(engine_factory,application_factory):
    for name in ('keypress', 'rich_listener', 'rich_renderables', 'theme'):
        assert importlib.import_module('bytefault.fuzzers.' + name) is importlib.import_module(
            'bytefault.ui.' + name)
    from bytefault.ui.rich_listener import RichUIListener
    from bytefault.ui.state import ViewState
    from bytefault.core.contracts import freeze
    engine, _, _, _ = engine_factory()
    from bytefault.ui.controller import TerminalController
    from bytefault.ui.application_client import ApplicationView
    from bytefault.application import ApplicationRequest
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.core.contracts import TransportRequest
    application,_=application_factory()
    request=ApplicationRequest(raw_request(b'ABC'),TransportRequest('offline.invalid',1234,10),
        str(engine.record_store.path.parent/'view.bfr'))
    result=application.submit(request)
    controller = TerminalController(ApplicationView(application,result.run_id,request=request), object())
    controller.session_state.targets.append('view-only')
    controller.session_state.current_field_bytes['view-only'] = b'X'
    assert engine.session_state.targets == []
    assert engine.session_state.current_field_bytes == {}
    view = ViewState()
    listener = RichUIListener(view)
    listener.on_session_start(freeze(engine.session_state))
    listener.on_packet_sent(0, b'ABC', 3)
    listener.on_response_received(0, b'\x00\xff', 2)
    assert view.host == 'offline.invalid'
    assert view.last_sent == b'ABC' and view.total_bytes_sent == 3
    assert view.last_received == b'\x00\xff' and view.total_bytes_received == 2
    assert engine.session_state.last_sent is None
    root = Path(__file__).resolve().parents[3] / 'src/bytefault/ui'
    required = {'rich_listener.py': 'RichUIListener', 'rich_renderables.py': 'build_dashboard',
                'keypress.py': 'KeypressReader', 'theme.py': 'cycle_theme',
                'controller.py': '_process_log_signals'}
    for file, symbol in required.items():
        tree = ast.parse((root / file).read_text(encoding='utf-8'))
        assert any(isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == symbol
                   for n in ast.walk(tree)), (file, symbol)
