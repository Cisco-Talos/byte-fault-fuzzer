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

"""Actual movable Raw data -> current clients -> generic engine and records.

Only external transport/service ports are fake. Expected bytes below are literal
independent oracles, never produced by the implementation being checked.
"""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import threading
import time
from uuid import uuid4

import pytest

from bytefault.core.contracts import (Calculation, ConversationRequest, PreparedRow,
    PreparedContribution, SourceInvocation, Placement, ReceiveRequest, ContractError,
    MonitoringDecision, MonitoringCompletion, MonitoringAction, ProbeRequest)
from bytefault.core.storage import LocalRecordStore
from bytefault.fuzzers.cli import execute_arguments
from bytefault.fuzzers.inputs import request_to_data
from bytefault.fuzzers.protocol_directory import select_actions
from bytefault.monitoring import Monitoring, ConfiguredPolicy


REPOSITORY = Path(__file__).resolve().parents[3]
BASELINE = (b'\x10', b'\x20', b'\x30', b'\x31', b'\x40', b'\x50', b'ABC')
ACTION_IDS = ('a0', 'a1', 'a2a', 'a2b', 'a3', 'a4', 'a5')


@pytest.fixture
def raw_data(tmp_path):
    """Copy the actual companion, changing declaration data explicitly per test."""
    root = tmp_path / 'external'
    directory = root / 'movable-raw'
    shutil.copytree(REPOSITORY / 'src/bytefault/protocols/raw', directory,
                    ignore=shutil.ignore_patterns('__pycache__'))
    def install(app, actions, stages=()):
        value = {'declaration_id': 'raw-neutral', 'version': 1,
                 'stages': list(stages), 'actions': actions}
        (directory / 'declaration.json').write_text(json.dumps(value), encoding='utf-8')
        return app.resolve_protocol('raw', root).entry.plan
    return root, directory, install


def one_action(seed, receive=None):
    return [{'action_id': 'outbound', 'seed_hex': seed.hex(),
             'receive': receive or {'requested': False}}]


def seven_actions(*, negative=False, unknown=False):
    stages = ('S0', 'S1', 'S2', 'S2', 'S3', 'S4', 'S5')
    values = [{'action_id': identity, 'stage_id': stage, 'seed_hex': seed.hex(),
               'receive': {'requested': False},
               'next_action': ACTION_IDS[i + 1] if i < 6 else None}
              for i, (identity, stage, seed) in enumerate(zip(ACTION_IDS, stages, BASELINE))]
    values[0].pop('next_action')
    values[0].update(receive={'requested': True, 'cap': 4, 'deadline': 10},
        edges=[{'literal_hex': '01', 'target': 'a1', 'meaning': 'positive'},
               {'literal_hex': '00', 'target': 'negative' if negative else None, 'meaning': 'negative'}],
        unknown_target='negative' if unknown else None)
    if negative or unknown:
        values.append({'action_id': 'negative', 'stage_id': 'S1', 'seed_hex': 'ff',
                       'receive': {'requested': False}, 'next_action': None})
    return values


def contribution(identity, data):
    return PreparedContribution(identity, data, SourceInvocation(identity, 'literal'))


def bind(app, raw_data, tmp_path, plan, *, row=None, selected=('outbound',), name='run',
         repair=False, calculations=(), stage=None, **options):
    root, _, _ = raw_data
    conversation = ConversationRequest(plan, row or PreparedRow('row', 1), selected,
        name, 'case', 'conversation', repair, calculations, original_request={'password': 'marker-X'})
    return app.protocol_request('raw', 'offline.invalid', directory=root, conversation=conversation,
        stage=stage, port=1234, record_path=str(tmp_path / (name + '.bfr')), **options)


def offered(traces):
    return [value[1] for trace, _, _ in traces for value in trace if value[0] == 'offer']


def cli(app, raw_data, request, *, root_entry=False, stage=None):
    argv = ['raw', 'offline.invalid', '--declaration-dir', str(raw_data[0]), '--port', '1234',
        '--no-ui', '--health-check-mode', 'disabled', '--records', request.record_path,
        '--request-json', json.dumps(request_to_data(request.conversation))]
    for identity in request.conversation.selected_actions:
        argv.extend(('--action', identity))
    if stage:
        argv.extend(('--fuzz-stage', stage))
    if not root_entry:
        return execute_arguments(argv, app).last_conversation
    spec = importlib.util.spec_from_file_location('raw_root_vectors', REPOSITORY / 'bytefault.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.resolve_arguments(['fuzz', *argv[:2], '--', *argv[2:]], app).last_conversation


@pytest.mark.parametrize('operation,offset,end,expected,span', [
    ('insert', 1, None, b'AZBC', (1, 1)), ('overwrite', 1, None, b'AZC', (1, 2)),
    ('replace', 1, 3, b'AZ', (1, 3)), ('insert', 5, None, b'ABC\x00\x00Z', (5, 5))])
def test_exact_ordinary_placement(raw_data, tmp_path, application_factory, operation, offset, end, expected, span):
    app, traces = application_factory()
    plan = raw_data[2](app, one_action(b'ABC'))
    row = PreparedRow('row', 1, (contribution('Z', b'Z'),),
                      (Placement('edit', 'Z', 'outbound', operation, offset, end),))
    request = bind(app, raw_data, tmp_path, plan, row=row)
    assert request.conversation.plan.actions[0].seed == b'ABC'
    assert app.validate(request)['materialized'][0].final_bytes == expected
    result = cli(app, raw_data, request) if operation == 'insert' else app.submit(request)
    assert result.outcome == 'completed' and offered(traces) == [expected]
    materialized = result.actions[0].materialized
    assert materialized.seed == b'ABC' and materialized.placements[0].span == span
    record = next(r for r in app.read_records('run').records if r.kind == 'materialization')
    assert record.data['materialized']['placements'][0]['data'] == b'Z'
    assert record.data['materialized']['final_bytes'] == expected


@pytest.mark.parametrize('plural', [True, False])
def test_plural_and_overlap_are_one_packet(raw_data, tmp_path, application_factory, plural):
    app, traces = application_factory()
    seed, payloads, expected = ((b'U=aa;P=bb', (b'XXX', b'Y', b'ZZ'), b'U=XXX;P=YZZ')
                                if plural else (b'ABC', (b'X', b'Y'), b'AYC'))
    plan = raw_data[2](app, one_action(seed))
    values = tuple(contribution(f'C{i}', data) for i, data in enumerate(payloads))
    edits = ((Placement('P0', 'C0', 'outbound', 'replace', 2, 4),
              Placement('P1', 'C1', 'outbound', 'replace', 8, 10),
              Placement('P2', 'C2', 'outbound', 'append')) if plural else
             (Placement('P0', 'C0', 'outbound', 'overwrite', 1),
              Placement('P1', 'C1', 'outbound', 'overwrite', 1)))
    request = bind(app, raw_data, tmp_path, plan, row=PreparedRow('row', 1, values, edits))
    result = cli(app, raw_data, request)
    assert result.outcome == 'completed' and offered(traces) == [expected]
    assert len(result.actions) == 1 and result.actions[0].iteration_id == 'conversation:row:1:variant:normal:outbound'
    assert tuple(v.span for v in result.actions[0].materialized.placements) == (
        ((2, 4), (8, 10), (9, 9)) if plural else ((1, 2), (1, 2)))
    start = app.read_records('run').records[0].data['request']
    assert tuple(v['data'] for v in start['row']['contributions']) == payloads
    assert tuple(v.data for v in result.actions[0].materialized.placements) == payloads


@pytest.mark.parametrize('payload,repair,override,rule,expected,disposition', [
    (b'BC', True, False, 'payload_length', bytes.fromhex('0003414243'), 'repaired'),
    (b'BCDE', True, False, 'payload_length', bytes.fromhex('00054142434445'), 'repaired'),
    (b'BC', True, True, 'payload_length', bytes.fromhex('ffff414243'), 'repaired'),
    (b'BC', False, False, 'payload_length', bytes.fromhex('0001414243'), 'disabled'),
    (b'BC', True, False, 'optional-unknown', bytes.fromhex('0001414243'), 'unavailable_rule_or_location')])
def test_actual_current_calculation(raw_data, tmp_path, application_factory,
                                    payload, repair, override, rule, expected, disposition):
    app, traces = application_factory()
    plan = raw_data[2](app, one_action(bytes.fromhex('000141')))
    values = (contribution('body', payload),) + ((contribution('override', b'\xff\xff'),) if override else ())
    row = PreparedRow('row', 1, values, (Placement('append', 'body', 'outbound', 'append'),),
        final_overrides=(Placement('override', 'override', 'outbound', 'overwrite', 0),) if override else ())
    request = bind(app, raw_data, tmp_path, plan, row=row, repair=repair,
        calculations=(Calculation('length', 'outbound', rule, 0, 2, 'big', 2),))
    assert app.validate(request)['materialized'][0].final_bytes == expected
    result = cli(app, raw_data, request)
    assert result.outcome == 'completed' and offered(traces) == [expected]
    assert result.actions[0].materialized.calculations == (('length', disposition),)
    record = next(r for r in app.read_records('run').records if r.kind == 'materialization')
    assert record.data['materialized']['calculations'] == (('length', disposition),)


@pytest.mark.parametrize('selected,stage,override,expected', [
    ('a0', 'S0', b'\x11', (b'\x11', b'\x20', b'\x30', b'\x31', b'\x40', b'\x50', b'ABC')),
    ('a2b', 'S2', b'\x99', (b'\x10', b'\x20', b'\x30', b'\x99', b'\x40', b'\x50', b'ABC')),
    ('a5', 'S5', b'XYZ', (b'\x10', b'\x20', b'\x30', b'\x31', b'\x40', b'\x50', b'XYZ'))])
def test_seven_send_every_stage_whole_override(raw_data, tmp_path, application_factory,
                                              selected, stage, override, expected):
    app, traces = application_factory(stream_options={'reads': (b'\x01',)})
    plan = raw_data[2](app, seven_actions(), tuple(f'S{i}' for i in range(6)))
    selected_action = next(v for v in plan.actions if v.action_id == selected)
    row = PreparedRow('row', 1, (contribution('whole', override),),
        final_overrides=(Placement('whole', 'whole', selected, 'replace', 0, len(selected_action.seed)),))
    request = bind(app, raw_data, tmp_path, plan, row=row, selected=(selected,), stage=stage)
    with pytest.raises(ContractError, match='ambiguous_action'):
        select_actions(plan, stage='S2')
    with pytest.raises(ContractError, match='conflicting_selection'):
        app.protocol_request('raw', 'offline.invalid', directory=raw_data[0],
                             conversation=request.conversation, stage='S4', port=1234)
    assert not traces
    result = cli(app, raw_data, request, root_entry=selected == 'a0', stage=stage)
    assert result.outcome == 'completed' and not result.unreached
    assert offered(traces) == list(expected)
    assert tuple(v.action_id for v in result.actions) == ACTION_IDS
    assert tuple(v.stage_id for v in result.actions) == ('S0', 'S1', 'S2', 'S2', 'S3', 'S4', 'S5')
    assert all(v.iteration_id == (result.conversation_id + ':' + selected if v.action_id == selected else None)
               for v in result.actions)
    trace = traces[0][0]
    assert sum(v[0] == 'open' for v in trace) == sum(v[0] == 'close' for v in trace) == 1
    assert sum(v[0] == 'read' for v in trace) == 1
    start = app.read_records('run').records[0].data['request']
    assert start['plan']['actions'][ACTION_IDS.index(selected)]['seed'] == selected_action.seed
    assert start['original_request']['protocol_input']['stage'] == stage
    assert start['original_request']['protocol_input']['source']['protocol_id'] == 'raw'
    if selected == 'a0':
        assert start['original_request']['argv'][0:4] == ('fuzz', 'raw', 'offline.invalid', '--')


@pytest.mark.parametrize('response,negative,unknown,expected,outcome,meaning', [
    (b'\x01', False, False, BASELINE, 'completed', 'positive'),
    (b'\x00', False, False, (b'\x10',), 'unreached', 'negative'),
    (b'\x02', False, False, (b'\x10',), 'unknown', 'unknown'),
    (b'\x00', True, False, (b'\x10', b'\xff'), 'completed', 'negative'),
    (b'\x02', False, True, (b'\x10', b'\xff'), 'unknown', 'unknown')])
def test_observed_conditions_and_explicit_failure_path(raw_data, tmp_path, application_factory,
                                                       response, negative, unknown, expected, outcome, meaning):
    app, traces = application_factory(stream_options={'reads': (response,)})
    plan = raw_data[2](app, seven_actions(negative=negative, unknown=unknown), tuple(f'S{i}' for i in range(6)))
    selected = 'negative' if negative or unknown else 'a5'
    request = bind(app, raw_data, tmp_path, plan, selected=(selected,))
    result = app.submit(request)
    assert result.outcome == outcome and offered(traces) == list(expected)
    assert result.actions[0].response_meaning == meaning
    assert result.actions[0].transport.received == response
    assert result.planned_actions == tuple(v.action_id for v in plan.actions)
    assert bool(result.unreached) == (expected == (b'\x10',))
    assert all(v.iteration_id is None for v in result.actions if v.action_id != selected)
    assert app.status('run')['result']['actions'][0]['response_meaning'] == meaning
    if response == b'\x00' and not negative:
        # The same application's next independent run must not inherit the
        # previous negative transition, reached set or response attribution.
        original_factory = app.transport_factory
        def positive_transport(target):
            adapter = original_factory(target)
            traces[-1][1].reads = [b'\x01']
            return adapter
        app.transport_factory = positive_transport
        fresh = app.submit(bind(app, raw_data, tmp_path, plan, selected=('a5',), name='fresh'))
        assert fresh.outcome == 'completed' and not fresh.unreached
        assert tuple(v.transport.offered for v in fresh.actions) == BASELINE
        assert fresh.actions[0].response_meaning == 'positive'
        assert app.status('run')['result']['actions'][0]['response_meaning'] == 'negative'


def test_failed_setup_does_not_reconnect_or_relocate_selection(raw_data, tmp_path, application_factory):
    app, traces = application_factory(stream_options={'open_error': OSError('controlled refused setup')})
    plan = raw_data[2](app, seven_actions(), tuple(f'S{i}' for i in range(6)))
    result = app.submit(bind(app, raw_data, tmp_path, plan, selected=('a5',)))
    assert result.outcome == 'transport_failed' and result.unreached[0][0] == 'a5'
    assert offered(traces) == []
    assert sum(v[0] == 'open' for v in traces[0][0]) == 1
    assert result.actions[0].transport.acceptance == 'not_offered'
    assert result.actions[0].transport.receive_outcome == 'not_reached'


@pytest.mark.parametrize('receive,reads,outcome,received,boundary', [
    ({'requested': False, 'cap': 4, 'deadline': 10}, (b'sentinel',), 'unrequested', b'', 'unknown'),
    ({'requested': True, 'cap': 4, 'deadline': 10}, (), 'deadline', b'', 'unknown'),
    ({'requested': True, 'cap': 4, 'deadline': 10}, (b'',), 'eof', b'', 'unknown'),
    ({'requested': True, 'cap': 4, 'deadline': 10}, (b'\x00\x01\x02\x03\x04',),
     'read_cap', b'\x00\x01\x02\x03', 'unknown'),
    ({'requested': True, 'cap': 4, 'deadline': 10, 'length_offset': 0},
     (b'\x00', ConnectionResetError('observed reset')), 'reset', b'\x00', 'unknown'),
    ({'requested': True, 'cap': 4, 'deadline': 10, 'length_offset': 0},
     (b'\x00', b''), 'eof', b'\x00', 'unknown'),
    ({'requested': True, 'cap': 4, 'deadline': 10, 'length_offset': 0},
     (b'\x00', b'\x02', b'\xaa', b'\xbb'), 'complete', b'\x00\x02\xaa\xbb', 'declared'),
    ({'requested': True, 'cap': 4, 'deadline': 10, 'length_offset': 0},
     (b'\x00\x02\xaa\xbb',), 'complete', b'\x00\x02\xaa\xbb', 'declared')])
def test_requested_response_facts(raw_data, tmp_path, application_factory,
                                  receive, reads, outcome, received, boundary):
    app, traces = application_factory(stream_options={'reads': reads},monitoring=Monitoring(ConfiguredPolicy()))
    plan = raw_data[2](app, one_action(b'ABC', receive))
    result = app.submit(bind(app, raw_data, tmp_path, plan))
    fact = result.actions[0].transport
    assert fact.prepared == fact.offered == fact.accepted_prefix == b'ABC'
    assert fact.receive_requested == receive['requested']
    assert fact.receive_outcome == outcome and fact.received == received
    assert fact.response_boundary == boundary
    assert result.outcome == ('transport_failed' if outcome == 'reset' else 'completed')
    records = app.read_records('run').records
    observation = next(r.data['observation'] for r in records if r.kind == 'observation')
    assert observation['transport']['received'] == received
    assert observation['transport']['receive_outcome'] == outcome
    assert observation['service_readiness'] == 'unknown'
    assert all(not r.data['decision']['assessments'] for r in records if r.kind == 'monitoring_decision')
    stream, clock = traces[0][1:]
    if not receive['requested']:
        assert stream.reads == [b'sentinel']
        assert not any(v[0] == 'read' for v in traces[0][0])
    if outcome == 'deadline':
        assert clock.now == 10
    if outcome == 'read_cap':
        assert stream.reads == [b'\x04']


@pytest.mark.parametrize('known', [True, False])
def test_partial_and_uncertain_local_offer(raw_data, tmp_path, application_factory, known):
    from bytefault.fuzzers.transport import SendFailure
    sends = (2, SendFailure('known failure', accepted_count=0)) if known else (OSError('unknown progress'),)
    app, traces = application_factory(stream_options={'sends': sends})
    plan = raw_data[2](app, one_action(b'ABC', {'requested': True, 'cap': 4, 'deadline': 10}))
    result = app.submit(bind(app, raw_data, tmp_path, plan))
    fact = result.actions[0].transport
    assert result.outcome == 'transport_failed' and fact.prepared == fact.offered == b'ABC'
    assert fact.acceptance == ('partial' if known else 'uncertain')
    assert fact.accepted_count == (2 if known else None)
    assert fact.accepted_prefix == (b'AB' if known else b'')
    assert fact.receive_outcome == 'not_reached' and not fact.received
    assert not any(v[0] == 'read' for v in traces[0][0])


class HoldAfterControl:
    def evaluate(self, observation):
        if observation.kind == 'action' and observation.correlation.action_id == 'a0':
            return MonitoringDecision('hold-control', observation.observation_id, observation.correlation,
                'hold', 'awaited', ('readiness',))
        return MonitoringDecision(str(uuid4()), observation.observation_id, observation.correlation, 'continue')


def held_engine(app, thread):
    deadline = time.monotonic() + 3
    while thread.is_alive() and time.monotonic() < deadline:
        try:
            engine = app._run('run').engine
            if engine and engine.status().monitoring_hold:
                return engine
        except ContractError:
            pass
        time.sleep(.005)
    pytest.fail('ordinary Raw application did not reach its configured hold')


@pytest.mark.parametrize('stop', [False, True])
def test_held_raw_probe_and_control(raw_data, tmp_path, application_factory, stop):
    app, traces = application_factory(monitoring=Monitoring(HoldAfterControl()),
                                     stream_options={'reads': (b'\x01',)})
    plan = raw_data[2](app, seven_actions(), tuple(f'S{i}' for i in range(6)))
    request = bind(app, raw_data, tmp_path, plan, selected=('a5',))
    results = []
    thread = threading.Thread(target=lambda: results.append(app.submit(request)))
    thread.start()
    try:
        engine = held_engine(app, thread)
        hold = engine.continuation.hold
        assert offered(traces) == [b'\x10']
        unrelated = MonitoringCompletion(str(uuid4()), hold.decision_id, 'other-observation',
            hold.correlation, 'readiness', 'succeeded')
        assert engine.complete_monitoring(unrelated) is False
        probe = engine.execute_probe(ProbeRequest('probe', hold.observation_id, hold.correlation,
            b'\x7f', decision_id=hold.decision_id))
        assert probe.iteration_id is None and probe.transport.accepted_prefix == b'\x7f'
        assert offered(traces) == [b'\x10', b'\x7f']
        if stop:
            assert app.control('run', 'stop').outcome == 'completed'
        else:
            assert engine.complete_monitoring(replace(unrelated,
                completion_id=str(uuid4()), observation_id=hold.observation_id))
        thread.join(3)
        assert not thread.is_alive()
        assert results[0].outcome == ('stopped' if stop else 'completed')
        assert offered(traces) == ([b'\x10', b'\x7f'] if stop else [b'\x10', b'\x7f', *BASELINE[1:]])
        assert any(r.kind == 'probe_result' for r in app.read_records('run').records)
        assert all(r.data['result']['iteration_id'] is None for r in app.read_records('run').records
                   if r.kind == 'probe_result')
    finally:
        app.control('run', 'stop')
        thread.join(3)


def test_stop_during_raw_setup_read(raw_data, tmp_path, application_factory):
    app, traces = application_factory()
    plan = raw_data[2](app, seven_actions(), tuple(f'S{i}' for i in range(6)))
    request = bind(app, raw_data, tmp_path, plan, selected=('a5',))
    original_factory = app.transport_factory
    def transport(target):
        adapter = original_factory(target)
        stream, clock = traces[-1][1:]
        def pending(cap):
            clock.now += 1
            assert app.control('run', 'stop').outcome == 'completed'
            raise socket.timeout('controlled pending Raw read')
        stream.recv = pending
        return adapter
    app.transport_factory = transport
    result = app.submit(request)
    assert result.outcome == 'stopped' and result.unreached[0][0] == 'a5'
    assert offered(traces) == [b'\x10']
    assert result.actions[0].transport.acceptance == 'accepted'
    assert result.actions[0].transport.receive_outcome == 'cancelled'
    assert traces[0][2].now <= 10 and result.cleanup.outcome == 'completed'


@pytest.mark.parametrize('failed_kind', ['case_start', 'materialization'])
def test_required_raw_saves_gate_actual_steps(raw_data, tmp_path, application_factory, monkeypatch, capsys, failed_kind):
    app, traces = application_factory(stream_options={'reads': (b'\x01',)})
    plan = raw_data[2](app, seven_actions(), tuple(f'S{i}' for i in range(6)))
    request = bind(app, raw_data, tmp_path, plan, selected=('a5',))
    original_append = LocalRecordStore.append
    def save(store, kind, identity, data):
        if (str(store.path) == str(Path(request.record_path).resolve()) and kind == failed_kind and
                (kind == 'case_start' or identity['action_id'] == 'a2b')):
            raise OSError('controlled Raw required save failure')
        return original_append(store, kind, identity, data)
    monkeypatch.setattr(LocalRecordStore, 'append', save)
    result = app.submit(request)
    assert result.outcome == 'recording_failed'
    assert offered(traces) == ([] if failed_kind == 'case_start' else list(BASELINE[:3]))
    assert app.status('run')['storage_failure']['required_record_kind'] == failed_kind
    diagnostic = capsys.readouterr().err
    for exact in ('BYTEFAULT REQUIRED RECORDING STOP', 'raw', 'marker-X', 'run',
                  'available_materializations', 'controlled Raw required save failure'):
        assert exact in diagnostic
    if failed_kind == 'case_start':
        assert not any(v[0] == 'open' for v in traces[0][0])
    else:
        assert traces[0][1].closed
        records = app.read_records('run').records
        assert tuple(r.identity['action_id'] for r in records if r.kind == 'action_result') == ('a0', 'a1', 'a2a')


@pytest.mark.parametrize('send_failure', [False, True])
def test_raw_cleanup_uncertainty_does_not_rewrite_traffic(raw_data, tmp_path, application_factory, send_failure):
    app, traces = application_factory(stream_options={
        'close_error': OSError('controlled uncertain Raw close'),
        'sends': (OSError('controlled Raw send failure'),) if send_failure else ()})
    plan = raw_data[2](app, one_action(b'ABC'))
    result = app.submit(bind(app, raw_data, tmp_path, plan))
    assert offered(traces) == [b'ABC']
    assert result.outcome == ('transport_failed' if send_failure else 'cleanup_failed')
    assert result.execution_outcome == ('transport_failed' if send_failure else 'completed')
    assert result.cleanup.outcome == 'uncertain'
    assert result.cleanup.error == 'controlled uncertain Raw close'
    assert result.actions[0].transport.acceptance == ('uncertain' if send_failure else 'accepted')
    assert sum(v[0] == 'close' for v in traces[0][0]) == 1
    cleanup = next(r.data['cleanup'] for r in app.read_records('run').records if r.kind == 'transport_cleanup')
    assert cleanup['outcome'] == 'uncertain'
    assert app.close()['outcome'] == 'failed'


def test_raw_multiple_selected_collections_each_govern_the_hold(raw_data, tmp_path, application_factory):
    """Raw attachment also traverses the corrected per-action wait boundary."""
    from bytefault.management import Management, CollectionOutcome
    entered, release = threading.Event(), threading.Event()
    def collection(action):
        if action.action_id == 'collect-two':
            entered.set()
            assert release.wait(5)
        return CollectionOutcome('succeeded')
    store = LocalRecordStore(tmp_path / 'management.bfr')
    management = Management(store, collection=collection)
    class Policy:
        def evaluate(self, observation):
            if observation.correlation.action_id != 'a0':
                return MonitoringDecision(str(uuid4()), observation.observation_id,
                                          observation.correlation, 'continue')
            actions = tuple(MonitoringAction(identity, 'event', observation.observation_id,
                observation.correlation, 'followup', {'collect': True})
                for identity in ('collect-one', 'collect-two'))
            return MonitoringDecision('wait-both', observation.observation_id, observation.correlation,
                'hold', 'awaited', ('collection',), actions=actions)
    app, traces = application_factory(monitoring=Monitoring(Policy()), management=management,
                                     stream_options={'reads': (b'\x01',)})
    plan = raw_data[2](app, seven_actions(), tuple(f'S{i}' for i in range(6)))
    request = bind(app, raw_data, tmp_path, plan, selected=('a5',))
    results = []
    thread = threading.Thread(target=lambda: results.append(app.submit(request)))
    thread.start()
    try:
        assert entered.wait(3)
        engine = app._run('run').engine
        assert engine.status().monitoring_hold == 'wait-both'
        assert engine.continuation.satisfied == {('collection', 'collect-one')}
        assert offered(traces) == [b'\x10']
        assert len(management.status()['pending']) == 1
        release.set()
        thread.join(3)
        assert not thread.is_alive() and results[0].outcome == 'completed'
        assert offered(traces) == list(BASELINE)
        completions = [record.data['completion'] for record in app.read_records('run').records
                       if record.kind == 'monitoring_completion' and
                       record.data['completion']['condition'] == 'collection']
        assert tuple(v['followup_action_id'] for v in completions) == ('collect-one', 'collect-two')
        assert all(v['status'] == 'succeeded' for v in completions)
    finally:
        release.set()
        app.control('run', 'stop')
        thread.join(3)
        management.close(); management._worker.join(5); store.close()
