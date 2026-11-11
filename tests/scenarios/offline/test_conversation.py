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
import json
import pytest


def request(failure=False):
    from bytefault.core.contracts import (PassivePlan, ConversationAction, ReceiveRequest,
        ResponseEdge, ConversationRequest, PreparedRow)
    return ConversationRequest(PassivePlan('neutral', 1, (
        ConversationAction('setup', b'\x10', 'S0', receive=ReceiveRequest(cap=4, deadline=10),
            edges=(ResponseEdge(b'\x01', 'selected', 'positive'),
                   ResponseEdge(b'\x00', 'failure' if failure else None, 'negative'))),
        ConversationAction('selected', b'ABC', 'S1', next_action=None),
        ConversationAction('failure', b'\xff', 'S2')),
        ('S0', 'S1', 'S2')), PreparedRow('row', 1),
        ('failure' if failure else 'selected',), 'run', 'case', 'conversation')


def test_passive_plan_and_unreached(engine_factory):
    engine, trace, _, _ = engine_factory(reads=(b'\x01',))
    result = engine.execute_conversation(request())
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'ABC']
    assert result.outcome == 'completed' and not result.unreached
    assert result.actions[0].response_meaning == 'positive'
    assert result.actions[0].iteration_id is None
    assert result.actions[1].iteration_id == 'conversation:selected'

    engine, trace, _, _ = engine_factory(reads=(b'\x00',))
    result = engine.execute_conversation(request())
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10']
    assert result.outcome == 'unreached' and result.unreached[0][0] == 'selected'
    assert result.actions[0].response_meaning == 'negative'

    engine, trace, _, _ = engine_factory(reads=(b'\x00',))
    result = engine.execute_conversation(request(True))
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10', b'\xff']
    assert result.outcome == 'completed' and not result.unreached

    engine, trace, _, _ = engine_factory(reads=(b'\x02',))
    result = engine.execute_conversation(request())
    assert result.outcome == 'unknown' and result.unreached
    assert result.actions[0].response_meaning == 'unknown'
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10']

    engine, trace, _, _ = engine_factory(open_error=OSError('refused'))
    result = engine.execute_conversation(request())
    assert result.outcome == 'transport_failed' and result.unreached
    assert not any(t[0] == 'offer' for t in trace)

    from bytefault.core.contracts import Capability, ContractError
    bad = replace(request(), plan=replace(request().plan,
        required_capabilities=(Capability('unregistered'),)))
    engine, trace, _, _ = engine_factory()
    with pytest.raises(ContractError, match='unsupported_capability'):
        engine.execute_conversation(bad)
    assert not trace

    # Declared control state is extracted from this attempt's actual response;
    # varying remainder bytes do not become an implicit whole-reply condition.
    from bytefault.core.contracts import ResponseField, ResponseEdge, ConversationAction, ReceiveRequest
    first = request().plan.actions[0]
    control = replace(first, response_fields=(ResponseField('flag', 0, 1),
        ResponseField('remainder', 1, 2), ResponseField('unknown')),
        edges=(ResponseEdge(b'\x01', 'p1', 'positive', 'flag'),
               ResponseEdge(b'\x00', 'failure', 'negative', 'flag')))
    preparation = tuple(ConversationAction('p' + str(i), bytes([0x10 + i]), 'P' + str(i))
                        for i in range(1, 6))
    value = replace(request(), plan=replace(request().plan,
        actions=(control, *preparation, *request().plan.actions[1:]),
        stages=(*request().plan.stages, *(a.stage_id for a in preparation))))
    positive_path = (b'\x10', *(a.seed for a in preparation), b'ABC')
    for reply, meaning, path in ((b'\x01B', 'positive', positive_path),
                                (b'\x01C', 'positive', positive_path),
                                (b'\x00D', 'negative', (b'\x10', b'\xff')),
                                (b'\x02E', 'unknown', (b'\x10',)),
                                (b'', 'unknown', (b'\x10',))):
        engine, trace, _, _ = engine_factory(reads=(reply,))
        actual = engine.execute_conversation(value)
        result = actual.actions[0]
        assert tuple(t[1] for t in trace if t[0] == 'offer') == path
        assert result.transport.received == reply and result.transport.response_boundary == 'unknown'
        state = result.response_interpretation
        assert state.meaning == result.response_meaning == meaning
        assert state.fields[0].data == reply[:1]
        assert state.fields[0].outcome == ('available' if reply else 'short')
        assert state.fields[1].data == reply[1:3] and state.fields[1].outcome == 'short'
        assert state.fields[2].outcome == 'unknown_location'
        assert state.target == ('p1' if meaning == 'positive' else 'failure' if meaning == 'negative' else None)
        history = engine.record_store.snapshot().records
        saved = next(r.data.result for r in history if r.kind == 'action_result')
        observed = next(r.data.observation for r in history if r.kind == 'observation')
        assert saved.response_interpretation == observed.parameters.response_interpretation
        assert observed.correlation.attempt_id == result.attempt_id
        assert actual.unreached == (() if meaning == 'positive' else (('selected',
            'unknown response at setup' if meaning == 'unknown' else 'declared path did not reach selected action'),))

    # Unknown declared spans cannot obtain a value merely from a matching reply.
    unknown = replace(control, edges=(ResponseEdge(b'\x01', 'p1', 'positive', 'unknown'),))
    engine, trace, _, _ = engine_factory(reads=(b'\x01B',))
    actual = engine.execute_conversation(replace(value, plan=replace(value.plan,
        actions=(unknown, *value.plan.actions[1:]))))
    assert actual.outcome == 'unknown' and len(actual.actions) == 1
    assert actual.actions[0].response_interpretation.matched is False

    unrequested = replace(control, receive=ReceiveRequest(requested=False), edges=())
    engine, trace, _, _ = engine_factory(reads=(b'SENTINEL',))
    actual = engine.execute_conversation(replace(value, plan=replace(value.plan,
        actions=(unrequested, *value.plan.actions[1:]))))
    assert all(f.outcome == 'unrequested' for f in actual.actions[0].response_interpretation.fields)
    assert not any(t[0] == 'read' for t in trace)
    engine, trace, _, _ = engine_factory(open_error=OSError('controlled refusal'))
    actual = engine.execute_conversation(value)
    assert actual.actions[0].response_interpretation.fields[0].outcome == 'not_observed'
    assert actual.actions[0].response_interpretation.target is None

    reset = replace(control, receive=ReceiveRequest(cap=4, deadline=10, length_offset=0,
        length_size=1, length_counts='full'), response_fields=(ResponseField('flag', 1, 1),))
    engine, trace, _, _ = engine_factory(reads=(b'\x04\x01', ConnectionResetError('controlled reset')))
    actual = engine.execute_conversation(replace(value, plan=replace(value.plan,
        actions=(reset, *value.plan.actions[1:]))))
    state = actual.actions[0].response_interpretation
    assert actual.outcome == 'transport_failed' and len(actual.actions) == 1
    assert actual.actions[0].transport.received == b'\x04\x01'
    assert state.fields[0].data == b'\x01' and state.fields[0].outcome == 'available'
    assert state.meaning == 'uninterpreted' and state.target is None and state.matched is None

    for invalid in (replace(control, response_fields=(ResponseField('flag', -1, 1),)),
                    replace(control, edges=(ResponseEdge(b'\x01', None, 'positive', 'absent'),)),
                    replace(control, edges=(ResponseEdge(b'\x01', None, 'positive'), *control.edges)),
                    replace(control, response_fields=(ResponseField('flag', 0, 1), ResponseField('flag', 1, 1))),
                    replace(control, edges=(control.edges[0], control.edges[0])),
                    replace(control, edges=(ResponseEdge(b'12', None, 'positive', 'flag'),))):
        engine, trace, _, _ = engine_factory()
        with pytest.raises(ContractError):
            engine.execute_conversation(replace(value, plan=replace(value.plan,
                actions=(invalid, *value.plan.actions[1:]))))
        assert trace == []
    with pytest.raises(ContractError, match='executable_value'):
        engine.execute_conversation({'callback': lambda: pytest.fail('must not run')})
    assert not trace


def test_directory_admission(tmp_path, engine_factory):
    from bytefault.fuzzers.declarations import discover, admit_plan
    from bytefault.core.contracts import ContractError
    root = tmp_path / 'passive'
    assert discover(root).issues[0].code == 'absent'
    root.mkdir()
    assert discover(root).plans == ()
    neutral = {'version': 1, 'declaration_id': 'neutral',
               'actions': [{'action_id': 'send', 'seed_hex': '414243'}]}
    path = root / 'neutral.json'
    path.write_text(json.dumps(neutral), encoding='utf-8')
    assert discover(root).select('neutral').actions[0].seed == b'ABC'
    (root / 'never_import.py').write_text('raise AssertionError("executed")', encoding='utf-8')
    assert len(discover(root).plans) == 1
    path.unlink()
    with pytest.raises(ContractError, match='absent'):
        discover(root).select('neutral')
    for field, value, code in [('version', 2, 'unsupported_version'),
            ('required_capabilities', [{'name': 'unregistered'}], 'unsupported_capability'),
            ('stages', 'ab', 'malformed'),
            ('client', 'execute.py', 'unsupported_field')]:
        path.write_text(json.dumps(dict(neutral, **{field: value})), encoding='utf-8')
        result = discover(root)
        assert result.issues[0].code == code
        with pytest.raises(ContractError):
            result.select('neutral')
    path.write_text(json.dumps(neutral), encoding='utf-8')
    (root / 'duplicate.json').write_text(json.dumps(neutral), encoding='utf-8')
    with pytest.raises(ContractError, match='duplicate_identity'):
        discover(root).select('neutral')
    (root / 'duplicate.json').unlink()
    path.write_text('{"version":1,"version":1}', encoding='utf-8')
    assert discover(root).issues[0].code == 'duplicate_field'
    for bad in ({'callback': lambda: None}, {'reader': object()}, {'client': type('Client', (), {})}):
        with pytest.raises(ContractError):
            admit_plan(bad)
    engine, trace, _, _ = engine_factory()
    assert not trace


@pytest.mark.parametrize('field,nested', (
    ('actions', False), ('stages', False), ('required_capabilities', False),
    ('edges', True), ('fields', True), ('response_fields', True),
))
@pytest.mark.parametrize('invalid', (
    pytest.param('ab', id='string'), pytest.param({}, id='object'),
    pytest.param(None, id='null'),
))
def test_declaration_sequence_container_types(field, nested, invalid):
    from bytefault.core.contracts import ContractError
    from bytefault.fuzzers.declarations import admit_plan
    declaration = {'declaration_id': 'neutral', 'version': 1,
                   'actions': [{'action_id': 'send', 'seed_hex': '41'}]}
    target = declaration['actions'][0] if nested else declaration
    target[field] = invalid
    with pytest.raises(ContractError) as caught:
        admit_plan(declaration)
    assert caught.value.path == 'declaration.' + field
    assert caught.value.code == 'malformed'


def test_declaration_sequence_api_refusal(application_factory):
    from bytefault.core.contracts import ContractError
    app, traces = application_factory()
    declaration = {'declaration_id': 'neutral', 'version': 1, 'stages': 'ab',
                   'actions': [{'action_id': 'send', 'seed_hex': '41'}]}
    inspection = app.inspect_declaration(declaration)
    assert inspection['status'] == 'unavailable'
    assert inspection['supplied']['stages'] == 'ab'
    assert inspection['error']['path'] == 'declaration.stages'
    assert inspection['error']['code'] == 'malformed'
    for operation in (app.admit, app.export_declaration):
        with pytest.raises(ContractError) as caught:
            operation(declaration)
        assert caught.value.path == 'declaration.stages'
        assert caught.value.code == 'malformed'
    assert not traces


def test_declaration_sequence_compatibility(application_factory):
    from bytefault.core.contracts import Capability, FieldLocation, ResponseField
    from bytefault.fuzzers.declarations import admit_plan
    app, traces = application_factory()
    plan = request().plan
    first = replace(plan.actions[0], fields=(FieldLocation('prefix', 0, 1),),
                    response_fields=(ResponseField('reply', 0, 1),))
    plan = replace(plan, actions=(first, *plan.actions[1:]),
                   required_capabilities=(Capability('send'),))
    assert admit_plan(plan) is plan
    exported = json.loads(json.dumps(app.export_declaration(plan)))
    assert admit_plan(exported) == plan
    for field in ('actions', 'stages', 'required_capabilities'):
        exported[field] = tuple(exported[field])
    for action in exported['actions']:
        for field in ('edges', 'fields', 'response_fields'):
            action[field] = tuple(action[field])
    assert admit_plan(exported) == plan
    assert not traces


def test_legacy_execution_refuses(engine_factory):
    from bytefault.core.contracts import ContractError
    from bytefault.fuzzers.session_mixin import build_session_factory
    engine, trace, _, _ = engine_factory()
    for name in ('connect', 'open_session', 'send_packet', 'send_raw_packet',
                 'fuzz_with_generators', 'fuzz_raw_mutations', 'fuzz_field'):
        with pytest.raises(ContractError, match='unavailable'):
            getattr(engine, name)()
    with pytest.raises(ContractError, match='unavailable'):
        build_session_factory(object())
    engine.session_factory = lambda: pytest.fail('must not run')
    with pytest.raises(ContractError, match='executable_value'):
        engine.execute_conversation(request())
    assert not trace


def test_stop_between_preparation_and_offer(engine_factory):
    from bytefault.core.contracts import ConversationRequest, PassivePlan, ConversationAction, PreparedRow, ReceiveRequest
    # A prior setup result must never be borrowed for the cancelled selected send.
    plan = PassivePlan('stop-fixture', 1, (ConversationAction('setup', b'\x10'),
        ConversationAction('selected', b'ABC', receive=ReceiveRequest(cap=4, deadline=10))))
    value = ConversationRequest(plan, PreparedRow('row', 1), ('selected',), 'run', 'case', 'conversation')
    engine, trace, _, _ = engine_factory()
    real_pre_offer = engine._action_pre_offer
    def before_offer(request, action, materialized, attempt_id):
        real_pre_offer(request, action, materialized, attempt_id)
        if action.action_id == 'selected':
            engine.control('stop')
    engine._action_pre_offer = before_offer
    result = engine.execute_conversation(value)
    assert result.outcome == 'stopped' and result.unreached[0][0] == 'selected'
    assert [t[1] for t in trace if t[0] == 'offer'] == [b'\x10']
    fact = result.actions[-1].transport
    assert fact.prepared == b'ABC' and fact.offered == b''
    assert fact.acceptance == 'not_offered' and fact.receive_outcome == 'not_reached'
    assert fact.received == b'' and fact.error == 'stopped before offer'
    assert result.actions[-1].attempt_id.endswith('selected:attempt-1')
    assert not engine.status().connected
