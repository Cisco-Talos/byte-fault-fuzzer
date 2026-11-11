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

"""Owned loopback OS adapter via current discovered Raw/Application interfaces.

Peer receipt/response writes are separate observations, never inferred from
client local acceptance. Framed aggregates are exact; TCP partitions are not.
"""
from dataclasses import replace
import json
from pathlib import Path
import socket
import threading
from uuid import uuid4

import pytest

from bytefault.core.contracts import (ConversationAction, ConversationRequest,
    MonitoringCompletion, MonitoringDecision, PassivePlan, PreparedRow,
    ProbeRequest, ReceiveRequest)
from bytefault.fuzzers.cli import argument_request, execute_arguments
from bytefault.monitoring import Monitoring


def receive(**options):
    return ReceiveRequest(cap=16, deadline=1, **options)


def prepare(case, app, root, endpoint, *, seed=None, plan=None, selected=None,
            policy=None, no_receive=False, label='run', connect_timeout=2):
    if plan is not None:
        (root / 'raw/declaration.json').write_text(json.dumps(app.export_declaration(plan)), encoding='utf-8')
        discovered = app.resolve_protocol('tcp-raw', directory=str(root))
        conversation = ConversationRequest(discovered.entry.plan, PreparedRow('row-N', 1),
            selected or tuple(a.action_id for a in discovered.entry.plan.actions),
            str(uuid4()), 'case-N', 'conversation-N')
        kwargs = {'conversation': conversation}
    else:
        kwargs = {'seed': seed}
    request = app.protocol_request('tcp-raw', endpoint[0], directory=str(root),
        port=endpoint[1], timeout=connect_timeout, pre_delay=0, post_delay=0,
        receive=policy, no_receive=no_receive,
        record_path=str(case.root / f'{label}.bfr'), log_path=str(case.root / f'{label}-actions.bfr'),
        original_request={'N_fixture': label, 'password': 'N-exact-marker'}, **kwargs)
    provenance = request.conversation.original_request['protocol_input']
    assert provenance['source']['requested_selection'] == 'tcp-raw'
    assert Path(provenance['source']['descriptor_path']) == root / 'raw/protocol.json'
    assert provenance['supplied_original_request']['password'] == 'N-exact-marker'
    return request


def test_real_raw_success_and_cli_callable_parity(n_case, raw_root):
    exact = bytes.fromhex('00ff80414243')
    def handler(peer, connection, index):
        assert peer.recv_exact(connection, len(exact)) == exact
        peer.wait_client_end(connection)
    peer = n_case.peer(handler, count=2)
    cli = n_case.app()
    argv = ['raw', peer.endpoint[0], '--declaration-dir', str(raw_root), '--port', str(peer.endpoint[1]),
        '--timeout', '2', '--tcp-pre-delay', '0', '--tcp-post-delay', '0', '--seed-hex', exact.hex(),
        '--no-recv', '--no-ui', '--health-check-mode', 'disabled',
        '--records', str(n_case.root / 'cli.bfr'), '--log-file', str(n_case.root / 'cli-actions.bfr')]
    cli_request = argument_request(argv)
    worker, output = n_case.submit(cli, cli_request, operation=lambda: execute_arguments(argv, cli))
    cli_result = n_case.complete(worker, output)
    assert cli_result.outcome == 'completed'
    assert cli_result.last_conversation.actions[0].transport.accepted_prefix == exact
    assert cli_result.last_conversation.actions[0].transport.receive_outcome == 'unrequested'
    n_case.observe_finished(cli, cli_request, cli_result)
    callable_app = n_case.app()
    callable_request = prepare(n_case, callable_app, raw_root, peer.endpoint, seed=exact,
        no_receive=True, label='callable')
    worker, output = n_case.submit(callable_app, callable_request)
    callable_result = n_case.complete(worker, output)
    assert callable_result.outcome == 'completed'
    fact = callable_result.actions[0].transport
    assert fact.accepted_prefix == exact and fact.received == b''
    assert fact.receive_outcome == 'unrequested'
    assert fact.response_boundary == 'unknown'
    assert cli_result.run_id != callable_result.run_id
    _, actions = n_case.observe_finished(callable_app, callable_request, callable_result, peer)
    assert peer.accepted == 2
    assert b''.join(peer.receipts) == exact + exact
    assert peer.endings == ['eof', 'eof']
    cli_start = cli.read_records(cli_result.run_id).records[0]
    assert cli_start.data.application_request.conversation.original_request.argv == tuple(argv)
    assert any(r.kind == 'action_result' for r in actions.records)


def test_real_refusal_keeps_fixture_endpoint_reserved(n_case, raw_root):
    reservation, endpoint = n_case.refused()
    app = n_case.app()
    request = prepare(n_case, app, raw_root, endpoint, seed=b'ABC', policy=receive(), connect_timeout=5)
    worker, output = n_case.submit(app, request)
    result = n_case.complete(worker, output)
    assert result.outcome == 'transport_failed'
    assert result.actions[0].transport.acceptance == 'not_offered'
    assert result.actions[0].transport.receive_outcome == 'not_reached'
    error = result.actions[0].transport.error
    assert error and ('refused' in error.lower() or '10061' in error), error
    assert result.cleanup.phase == 'open_failure'
    assert reservation.fileno() >= 0  # still reserved before harness cleanup
    assert reservation.getsockname() == endpoint
    assert reservation.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
    evidence, _ = n_case.observe_finished(app, request, result)
    assert not any(r.kind == 'materialization' for r in evidence.records)
    (n_case.root / 'refusal-peer.json').write_text(json.dumps({
        'reserved_endpoint': endpoint, 'listening': False, 'peer_receipt': None}), encoding='utf-8')


@pytest.mark.parametrize('response_mode', ['chunked', 'combined'])
def test_declared_frames_across_real_tcp_writes(n_case, raw_root, response_mode):
    first, second = b'\x00\x03ABC', b'\x00\x02XY'
    def handler(peer, connection, index):
        assert peer.recv_exact(connection, 1) == b'A'
        if response_mode == 'chunked':
            peer.send_parts(connection, (first[:1], first[1:3], first[3:]))
        else:
            peer.send_parts(connection, (first + second,))
        assert peer.recv_exact(connection, 1) == b'B'
        if response_mode == 'chunked':
            peer.send_parts(connection, (second[:2], second[2:]))
        peer.wait_client_end(connection)
    peer = n_case.peer(handler)
    app = n_case.app()
    framed = receive(length_offset=0, length_size=2)
    plan = PassivePlan('neutral-N-framing', 1, (
        ConversationAction('first', b'A', receive=framed),
        ConversationAction('second', b'B', receive=framed)))
    request = prepare(n_case, app, raw_root, peer.endpoint, plan=plan)
    worker, output = n_case.submit(app, request)
    result = n_case.complete(worker, output)
    assert result.outcome == 'completed'
    assert [a.transport.received for a in result.actions] == [first, second]
    assert all(a.transport.response_boundary == 'declared' and a.transport.receive_outcome == 'complete'
               for a in result.actions)
    n_case.observe_finished(app, request, result, peer)
    assert peer.accepted == 1 and b''.join(peer.receipts) == b'AB'
    assert b''.join(peer.writes) == first + second


def test_bounded_opaque_read_is_not_a_complete_reply_claim(n_case, raw_root):
    response = bytes.fromhex('000102030405')
    def handler(peer, connection, index):
        assert peer.recv_exact(connection, 3) == b'ABC'
        peer.send_parts(connection, (response,))
        peer.wait_client_end(connection, allow_reset=True)
    peer = n_case.peer(handler)
    app = n_case.app()
    request = prepare(n_case, app, raw_root, peer.endpoint, seed=b'ABC',
                      policy=ReceiveRequest(cap=4, deadline=1))
    worker, output = n_case.submit(app, request)
    result = n_case.complete(worker, output)
    fact = result.actions[0].transport
    assert 0 < len(fact.received) <= 4
    assert response.startswith(fact.received)
    assert fact.receive_outcome in ('bounded_chunk', 'read_cap')
    assert fact.response_boundary == 'unknown'
    n_case.observe_finished(app, request, result, peer)
    assert b''.join(peer.receipts) == b'ABC'
    assert b''.join(peer.writes) == response


@pytest.mark.parametrize('partial', [False, True])
def test_peer_eof_halfclose_preserves_outbound_direction(n_case, raw_root, partial):
    response = b'\x00\x03A' if partial else b''
    def handler(peer, connection, index):
        assert peer.recv_exact(connection, 1) == b'A'
        if response:
            peer.send_parts(connection, (response,))
        connection.shutdown(socket.SHUT_WR)
        assert peer.recv_exact(connection, 1) == b'B'
        peer.wait_client_end(connection)
    peer = n_case.peer(handler)
    app = n_case.app()
    plan = PassivePlan('neutral-N-halfclose', 1, (
        ConversationAction('first', b'A', receive=receive(length_offset=0, length_size=2)),
        ConversationAction('second', b'B', receive=ReceiveRequest(requested=False))))
    request = prepare(n_case, app, raw_root, peer.endpoint, plan=plan)
    worker, output = n_case.submit(app, request)
    result = n_case.complete(worker, output)
    assert result.outcome == 'completed'
    assert result.actions[0].transport.received == response
    assert result.actions[0].transport.receive_outcome == 'eof'
    assert result.actions[1].transport.accepted_prefix == b'B'
    assert result.actions[1].transport.receive_outcome == 'unrequested'
    n_case.observe_finished(app, request, result, peer)
    assert peer.accepted == 1 and b''.join(peer.receipts) == b'AB'


def test_requested_response_deadline_is_retained(n_case, raw_root):
    def handler(peer, connection, index):
        assert peer.recv_exact(connection, 3) == b'ABC'
        peer.wait_client_end(connection)
    peer = n_case.peer(handler)
    app = n_case.app()
    request = prepare(n_case, app, raw_root, peer.endpoint, seed=b'ABC',
                      policy=ReceiveRequest(cap=4, deadline=0.2))
    worker, output = n_case.submit(app, request)
    result = n_case.complete(worker, output)
    fact = result.actions[0].transport
    assert fact.accepted_prefix == b'ABC'
    assert fact.receive_requested and fact.received == b'' and fact.receive_outcome == 'deadline'
    assert fact.response_boundary == 'unknown'
    n_case.observe_finished(app, request, result, peer)
    assert b''.join(peer.receipts) == b'ABC'


def test_stop_during_real_pending_read_prevents_next_send(n_case, raw_root):
    def handler(peer, connection, index):
        assert peer.recv_exact(connection, 1) == b'A'
        peer.wait_client_end(connection)
    peer = n_case.peer(handler)
    app = n_case.app()
    plan = PassivePlan('neutral-N-stop', 1, (
        ConversationAction('first', b'A', receive=ReceiveRequest(cap=4, deadline=2)),
        ConversationAction('second', b'NEXT', receive=ReceiveRequest(requested=False))))
    request = prepare(n_case, app, raw_root, peer.endpoint, plan=plan)
    worker, output = n_case.submit(app, request)
    assert peer.received.wait(2), 'peer did not receive the offered action'
    assert app.status(request.conversation.run_id).active
    assert app.control(request.conversation.run_id, 'stop').outcome == 'completed'
    result = n_case.complete(worker, output)
    assert result.outcome == 'stopped'
    assert result.actions[0].transport.accepted_prefix == b'A'
    assert result.actions[0].transport.receive_outcome == 'cancelled'
    assert result.unreached and result.unreached[0][0] == 'second'
    n_case.observe_finished(app, request, result, peer)
    assert b''.join(peer.receipts) == b'A'


def test_configured_engine_probe_uses_held_real_connection(n_case, raw_root):
    probed = threading.Event()
    class Policy:
        def evaluate(self, observation):
            if observation.correlation.action_id == 'first' and observation.kind == 'action':
                probe = ProbeRequest('N-probe', observation.observation_id, observation.correlation,
                    b'P', ReceiveRequest(cap=1, deadline=1), decision_id='N-hold')
                return MonitoringDecision('N-hold', observation.observation_id, observation.correlation,
                    'hold', 'awaited', ('test-release',), probes=(probe,))
            if observation.kind == 'probe':
                probed.set()
            return MonitoringDecision(str(uuid4()), observation.observation_id, observation.correlation, 'continue')
    def handler(peer, connection, index):
        assert peer.recv_exact(connection, 1) == b'A'
        assert peer.recv_exact(connection, 1) == b'P'
        peer.send_parts(connection, (b'Q',))
        assert peer.recv_exact(connection, 1) == b'B'
        peer.wait_client_end(connection)
    peer = n_case.peer(handler)
    monitoring = Monitoring(Policy())
    app = n_case.app(monitoring=monitoring)
    plan = PassivePlan('neutral-N-probe', 1, (
        ConversationAction('first', b'A', receive=ReceiveRequest(requested=False)),
        ConversationAction('second', b'B', receive=ReceiveRequest(requested=False))))
    request = prepare(n_case, app, raw_root, peer.endpoint, plan=plan)
    worker, output = n_case.submit(app, request)
    assert probed.wait(2)
    assert app.status(request.conversation.run_id).engine.monitoring_hold == 'N-hold'
    assert worker.is_alive()
    assert b''.join(peer.receipts) == b'AP'
    hold = next(d for d in monitoring.decisions if d.decision_id == 'N-hold')
    wrong = MonitoringCompletion('wrong', 'different-hold', hold.observation_id, hold.correlation,
                                'test-release', 'succeeded')
    engine = app._run(request.conversation.run_id).engine
    assert not engine.complete_monitoring(wrong)
    assert app.status(request.conversation.run_id).engine.monitoring_hold == 'N-hold'
    completion = replace(wrong, completion_id='N-complete', decision_id=hold.decision_id)
    assert engine.complete_monitoring(completion)
    result = n_case.complete(worker, output)
    assert result.outcome == 'completed'
    assert [a.transport.offered for a in result.actions] == [b'A', b'B']
    evidence, actions = n_case.observe_finished(app, request, result, peer)
    probe = next(r for r in evidence.records if r.kind == 'probe_result')
    assert probe.identity.iteration_id is None
    assert probe.data.result.transport.accepted_prefix == b'P'
    assert probe.data.result.transport.received == b'Q'
    assert any(r.kind == 'probe_result' for r in actions.records)
    assert peer.accepted == 1 and b''.join(peer.receipts) == b'APB'
