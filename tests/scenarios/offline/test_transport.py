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

import socket
import pytest


def run(engine, data=b'ABC', receive=None):
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.core.contracts import ReceiveRequest
    return engine.execute_conversation(raw_request(data,
        receive=receive or ReceiveRequest(cap=4, deadline=10)))


def test_engine_transport_trace(engine_factory, application_factory, tmp_path):
    engine, trace, stream, clock = engine_factory()
    result = run(engine)
    assert result.outcome == 'completed'
    fact = result.actions[0].transport
    assert fact.prepared == fact.offered == fact.accepted_prefix == b'ABC'
    assert fact.accepted_count == 3 and fact.acceptance == 'accepted'
    assert fact.received == b'\x00\xff' and fact.receive_requested
    assert fact.receive_outcome == 'bounded_chunk' and fact.response_boundary == 'unknown'
    assert trace == [('sleep', 2), ('open', ('offline.invalid', 1234)),
                     ('offer', b'ABC'), ('read', 4), ('close',), ('sleep', 3)]
    assert stream.closed
    assert fact.connection['outcome'] == 'completed'
    assert fact.connection['pacing']['seconds'] == 2
    assert fact.connection['pacing']['completed_at'] - fact.connection['pacing']['started_at'] == 2
    assert result.cleanup.pacing['seconds'] == 3 and result.cleanup.pacing['outcome'] == 'completed'

    failed, trace, stream, _ = engine_factory(open_error=OSError('refused'))
    result = run(failed)
    assert result.outcome == 'transport_failed' and result.unreached
    assert not any(t[0] == 'offer' for t in trace)
    assert stream.closed
    assert failed.last_transport_result.acceptance == 'not_offered'
    assert failed.last_transport_result.receive_requested
    assert failed.last_transport_result.receive_outcome == 'not_reached'

    from bytefault.fuzzers.transport import SendFailure
    partial, trace, _, _ = engine_factory(sends=(2, SendFailure('failed', accepted_count=0)))
    run(partial)
    fact = partial.last_transport_result
    assert fact.acceptance == 'partial' and fact.accepted_count == 2
    assert fact.accepted_prefix == b'AB' and fact.offered == b'ABC'
    assert fact.receive_requested and fact.receive_outcome == 'not_reached'
    assert not any(t[0] == 'read' for t in trace)

    uncertain, _, _, _ = engine_factory(sends=(OSError('unknown progress'),))
    run(uncertain)
    assert uncertain.last_transport_result.acceptance == 'uncertain'
    assert uncertain.last_transport_result.accepted_count is None
    assert uncertain.last_transport_result.accepted_prefix == b''
    assert uncertain.last_transport_result.receive_requested
    assert uncertain.last_transport_result.receive_outcome == 'not_reached'

    # The built-in wait, not only injected Clock.sleep, honors uninterrupted
    # selected intervals. Socket activity still uses the maintained fake port.
    from bytefault.application import ApplicationRequest
    from bytefault.core.contracts import TransportRequest, ReceiveRequest
    from bytefault.fuzzers.inputs import raw_request
    from bytefault.fuzzers.transport import EngineTransport
    app, traces = application_factory()
    prior = app.transport_factory
    def transport(request):
        prior(request)
        return EngineTransport(request, socket_factory=lambda *args: traces[-1][1])
    app.transport_factory = transport
    actual = app.submit(ApplicationRequest(raw_request(b'X', receive=ReceiveRequest(requested=False)),
        TransportRequest('offline.invalid', 1234, 1, .02, .03), str(tmp_path / 'timing.bfr')))
    pre = actual.actions[0].transport.connection['pacing']; post = actual.cleanup.pacing
    assert pre['outcome'] == post['outcome'] == 'completed'
    assert pre['completed_at'] - pre['started_at'] >= .02
    assert post['completed_at'] - post['started_at'] >= .03


@pytest.mark.parametrize('workflow,phase,port_error', [
    ('campaign', 'pre', None), ('literal', 'post', None),
    ('literal', 'post', OSError('controlled close uncertainty')),
    ('api', 'custom', None),
    ('api', 'factory', None),
    ('api', 'connect', None), ('api', 'connect', OSError('controlled connect failure'))])
def test_ordinary_pacing_stop_preserves_actual_lifecycle(tmp_path, application_factory, workflow, phase, port_error):
    """Real built-in Event pacing above fake socket ports, through public control."""
    from dataclasses import replace
    import threading
    from bytefault.application import ApplicationRequest, CampaignRequest
    from bytefault.core.contracts import TransportRequest, TransportResult, ReceiveRequest
    from bytefault.fuzzers.inputs import raw_request, request_to_data, value_from_data
    from bytefault.fuzzers.transport import EngineTransport
    from bytefault.monitoring import MonitoringConfig
    from bytefault.replay.replay_packet import resolve_arguments

    entered, release = threading.Event(), threading.Event()
    app, traces = application_factory(stream_options={'close_error': port_error if phase == 'post' else None})
    prior_factory = app.transport_factory
    created = []
    class ObservedStop:
        def __init__(self, event): self.event = event
        def is_set(self): return self.event.is_set()
        def wait(self, seconds):
            if seconds > 299: entered.set()
            return self.event.wait(seconds)
    def transport(request):
        prior_factory(request)  # reuse the maintained controlled Stream/trace
        trace, stream, _ = traces[-1]
        connect = stream.connect
        if phase == 'connect':
            def held(target):
                entered.set()
                assert release.wait(3)
                if port_error: raise port_error
                connect(target)
            stream.connect = held
        def socket_factory(*args):
            created.append(True)
            if phase == 'factory':
                entered.set()
                assert release.wait(3)
            return stream
        def custom_sleep(seconds):
            entered.set()
            assert release.wait(3)
        adapter = EngineTransport(request, socket_factory=socket_factory,
            **({'sleep': custom_sleep} if phase == 'custom' else {}))
        bind = adapter.bind_stop_event
        adapter.bind_stop_event = lambda event: bind(ObservedStop(event))
        return adapter
    app.transport_factory = transport
    target = TransportRequest('offline.invalid', 1234, 1, 300 if phase in ('pre', 'custom') else 0,
        300 if phase == 'post' else 0)
    request = ApplicationRequest(raw_request(b'A', receive=ReceiveRequest(requested=False)), target,
        str(tmp_path / 'ordinary.bfr'))
    if workflow == 'campaign':
        request = CampaignRequest(request.conversation, target, request.record_path,
            monitoring_configuration=MonitoringConfig(health_check_mode='disabled'))
    elif workflow == 'literal':
        request = resolve_arguments(['offline.invalid', '41', '42', '--port', '1234',
            '--wait', '0', '--no-recv', '--health-check-mode', 'disabled',
            '--records', request.record_path], app).request
        request = replace(request, transport=target)
    handle = app.start(request)
    try:
        assert entered.wait(3)
        if phase in ('pre', 'custom'): assert not created
        if phase == 'post': assert sum(t[0] == 'close' for t in traces[0][0]) == 1
        assert handle.control('stop').outcome == 'completed'
        if phase in ('custom', 'factory', 'connect'):
            assert handle.wait(.03) is None  # a caller port is still in flight
            release.set()
        result = handle.wait(1)
        assert result is not None and handle.status()['engine'].stop_requested
        conversation = (result.literal_items[0].result if workflow == 'literal' else
            result.last_conversation if workflow == 'campaign' else result)
        history = app.read_records(handle.run_id)
        assert history.issue is None
        if phase in ('pre', 'custom'):
            assert result.outcome == 'stopped' and not created
            assert not any(t[0] in ('open', 'offer', 'close') for t in traces[0][0])
            connection = conversation.actions[0].transport.connection
            assert connection['outcome'] == 'not_attempted' and not connection['connect_attempted']
            assert connection['pacing']['outcome'] == 'cancelled'
        elif phase == 'connect':
            assert result.outcome == 'stopped' and len(created) == 1
            connection = conversation.actions[0].transport.connection
            assert connection['outcome'] == ('failed' if port_error else 'completed')
            assert connection['connect_attempted'] and connection['pacing']['outcome'] == 'completed'
            assert not any(t[0] == 'offer' for t in traces[0][0])
            assert sum(t[0] == 'close' for t in traces[0][0]) == 1
        elif phase == 'factory':
            assert result.outcome == 'stopped' and len(created) == 1
            connection = conversation.actions[0].transport.connection
            assert connection['outcome'] == 'not_attempted' and not connection['connect_attempted']
            assert not any(t[0] in ('open', 'offer') for t in traces[0][0])
            assert sum(t[0] == 'close' for t in traces[0][0]) == 1
        else:
            assert conversation.actions[0].transport.accepted_prefix == b'A'
            assert [t[1] for trace, _, _ in traces for t in trace if t[0] == 'offer'] == [b'A']
            second = result.literal_items[1]
            assert second.state == ('not_started' if port_error else 'stopped')
            if not port_error:
                assert not second.result.actions  # fresh-case teardown preceded its first action
            cleanup = next(r.data.cleanup for r in history.records if r.kind == 'transport_cleanup'
                and r.data.cleanup.pacing and r.data.cleanup.pacing['seconds'] == 300)
            assert cleanup.outcome == ('uncertain' if port_error else 'completed')
            assert cleanup.pacing['outcome'] == 'cancelled' and cleanup.pacing['seconds'] == 300
            assert cleanup.pacing_error is None
        action = next(r for r in history.records if r.kind == 'action_result')
        assert action.data.result.transport.connection == conversation.actions[0].transport.connection
        # Closed typed export and old absent-field defaults remain readable.
        fact = conversation.actions[0].transport
        assert value_from_data(request_to_data(fact)) == fact
        old = request_to_data(TransportResult(**dict(fact)) if workflow == 'literal' else fact)
        old['fields'].pop('connection')
        assert value_from_data(old).connection is None
    finally:
        release.set()
        handle.control('stop')
        handle.wait(3)
        app.close()


def test_required_history_stop_skips_builtin_post_pacing(tmp_path, application_factory, monkeypatch, capsys):
    import time
    from bytefault.application import ApplicationRequest
    from bytefault.core.contracts import TransportRequest, ReceiveRequest
    from bytefault.core.storage import LocalRecordStore
    from bytefault.fuzzers.inputs import raw_request, request_to_data, value_from_data
    from bytefault.fuzzers.transport import EngineTransport
    app, traces = application_factory()
    prior = app.transport_factory
    def transport(request):
        prior(request)
        return EngineTransport(request, socket_factory=lambda *args: traces[-1][1])
    app.transport_factory = transport
    append = LocalRecordStore.append
    def fail(store, kind, identity, data):
        if kind == 'action_result': raise OSError('controlled required result failure')
        return append(store, kind, identity, data)
    monkeypatch.setattr(LocalRecordStore, 'append', fail)
    request = ApplicationRequest(raw_request(b'A', receive=ReceiveRequest(requested=False)),
        TransportRequest('offline.invalid', 1234, 1, 0, 300), str(tmp_path / 'required.bfr'))
    started = time.monotonic()
    result = app.submit(request)
    assert time.monotonic() - started < 1
    assert result.outcome == 'recording_failed'
    assert result.actions[0].transport.accepted_prefix == b'A'
    diagnostic = app.status(result.run_id)['storage_failure']
    cleanup = diagnostic.cleanup
    assert cleanup.outcome == 'completed' and cleanup.pacing['outcome'] == 'cancelled'
    assert cleanup.pacing_error is None and traces[0][1].closed
    assert sum(t[0] == 'close' for t in traces[0][0]) == 1
    assert 'controlled required result failure' in capsys.readouterr().err
    assert value_from_data(request_to_data(result.cleanup)) == result.cleanup
    old = request_to_data(result.cleanup); old['fields'].pop('pacing')
    assert value_from_data(old).pacing is None

def test_receive_distinctions(engine_factory):
    from bytefault.core.contracts import ReceiveRequest
    for sends in ((), (OSError('unknown progress'),)):
        engine, trace, _, _ = engine_factory(sends=sends)
        run(engine, receive=ReceiveRequest(requested=False, cap=4, deadline=10))
        assert engine.last_transport_result.receive_outcome == 'unrequested'
        assert not engine.last_transport_result.receive_requested
        assert not any(t[0] == 'read' for t in trace)

    engine, trace, _, clock = engine_factory(reads=())
    run(engine)
    assert engine.last_transport_result.receive_outcome == 'deadline'
    assert clock.now == 15

    engine, _, _, _ = engine_factory(reads=(b'\x00', ConnectionResetError('reset')))
    fact = run(engine, receive=ReceiveRequest(cap=4, deadline=10,
        length_offset=0, length_size=2)).actions[0].transport
    assert fact.received == b'\x00' and fact.receive_outcome == 'reset'
    assert fact.response_boundary == 'unknown'


def test_declared_receive_cap(engine_factory):
    engine, trace, _, _ = engine_factory(reads=(b'\x00\x20', b'0123456789'))
    from bytefault.core.contracts import ReceiveRequest
    fact = run(engine, receive=ReceiveRequest(cap=4, deadline=10,
        length_offset=0, length_size=2)).actions[0].transport
    assert fact.received == b'\x00\x2001'
    assert fact.receive_outcome == 'read_cap' and fact.response_boundary == 'unknown'
    assert [t for t in trace if t[0] == 'read'] == [('read', 2), ('read', 2)]


def test_guard_precedes_product_networking():
    import _socket
    import subprocess
    import os
    for operation in (lambda: socket.socket(), lambda: _socket.socket(),
                      lambda: socket.getaddrinfo('localhost', 1),
                      lambda: socket.create_connection(('127.0.0.1', 1)),
                      lambda: subprocess.run(['ping', '127.0.0.1']),
                      lambda: subprocess.Popen(['ssh', 'localhost']),
                      lambda: os.system('ping 127.0.0.1')):
        with pytest.raises(AssertionError, match='Offline guard forbids'):
            operation()
