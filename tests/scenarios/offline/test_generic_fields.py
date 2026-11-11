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

"""CC-01 neutral vectors through the ordinary application/engine and stores."""
from dataclasses import replace, FrozenInstanceError
import hashlib
import binascii
import json
from pathlib import Path
import shutil

import pytest

from bytefault.application import ApplicationRequest
from bytefault.core.contracts import (Calculation, ContractError, FieldLocation, FinalFieldLocation,
    MaterializedAction, Placement, PreparedContribution, PreparedRow, SourceInvocation, TransportRequest, freeze)
from bytefault.fuzzers.inputs import (raw_request, request_to_data, value_from_data,
    contract_from_record)
from bytefault.fuzzers.cli import execute_arguments
from bytefault.core.storage import LocalRecordStore, reopen_records


def request(seed=b'\0\3ABC', *, fields=None, calculations=(), repair=False, operations=(), final=()):
    value = raw_request(seed)
    action = replace(value.plan.actions[0], fields=fields if fields is not None else (
        FieldLocation('length', 0, 2), FieldLocation('body', 2, 3, variable=True)))
    contributions, placements = [], []
    for index, (data, operation, offset, end, name) in enumerate((*operations, *final)):
        key = str(index)
        contributions.append(PreparedContribution(key, data, SourceInvocation(key, 'literal')))
        placements.append(Placement(key, key, '1', operation, offset, end, field_id=name))
    return replace(value, plan=replace(value.plan, actions=(action,)),
        row=PreparedRow('row', 1, tuple(contributions), tuple(placements[:len(operations)]),
                        final_overrides=tuple(placements[len(operations):])),
        repair=repair, calculations=calculations)


def submit(app, value, tmp_path, *, cli=False):
    path = str(tmp_path / (value.run_id + '.bfr'))
    if cli:
        result = execute_arguments(['offline.invalid', '--port', '1234', '--no-ui',
            '--health-check-mode', 'disabled', '--records', path,
            '--request-json', json.dumps(request_to_data(value))], app).last_conversation
    else:
        result = app.submit(ApplicationRequest(value, TransportRequest('offline.invalid', 1234, 3), path))
    assert result.outcome == 'completed'
    return result.actions[0]


@pytest.mark.parametrize('repair,body,final,expected', [
    (False, b'Z', (), b'\0\3Z'),
    (True, b'Z', (), b'\0\1Z'),
    (True, b'WXYZ', (), b'\0\4WXYZ'),
    (True, b'WXYZ', ((b'\xff\xff', 'overwrite', None, None, 'length'),), b'\xff\xffWXYZ')])
def test_named_absolute_and_cli_exact_parity(application_factory, tmp_path, repair, body, final, expected):
    app, traces = application_factory()
    calculation = Calculation('length', '1', 'payload_length', size=2, payload_offset=2,
                              field_id='length', destination='field')
    named = request(operations=((body, 'replace', None, None, 'body'),),
                    final=final, repair=repair, calculations=(calculation,))
    absolute_final = tuple((data, op, 0, None, None) for data, op, _, _, _ in final)
    absolute = request(operations=((body, 'replace', 2, 5, None),), final=absolute_final,
                       repair=repair, calculations=(replace(calculation, field_id=None, destination='fixed', offset=0),))
    assert app.import_request(app.export_request(named)) == named
    assert app.admit(app.export_declaration(named.plan)) == named.plan
    for value, cli in ((named, False), (absolute, True)):
        action = submit(app, value, tmp_path, cli=cli)
        assert action.transport.offered == expected
        assert action.materialized.placements[0].span == (2, 5)
        assert action.materialized.final_fields == (
            FinalFieldLocation('1', 'outbound', 'length', 0, 2),
            FinalFieldLocation('1', 'outbound', 'body', 2, len(body), True))
        assert value_from_data(json.loads(json.dumps(request_to_data(action.materialized)))) == action.materialized
    assert len({named.run_id, absolute.run_id}) == 2
    assert all(stream.closed for _, stream, _ in traces)
    records = app.read_records(named.run_id).records
    retained = next(record for record in records if record.kind == 'case_start')
    assert retained.data['request']['plan']['actions'][0]['fields'][1]['field_id'] == 'body'
    assert retained.data['materialized'][0]['final_bytes'] == expected
    materialization = next(record for record in records if record.kind == 'materialization')
    observed = next(record for record in records if record.kind == 'action_result')
    terminal = next(record for record in records if record.kind == 'case_terminal')
    for stored in (retained.data['materialized'][0], materialization.data['materialized'],
                   observed.data['result']['materialized'], terminal.data['result']['actions'][0]['materialized']):
        restored = contract_from_record(MaterializedAction, stored)
        assert restored.final_fields == action.materialized.final_fields
    with pytest.raises(FrozenInstanceError):
        restored.final_fields[0].offset = 99
    with pytest.raises(TypeError):
        freeze(restored).final_fields[0].offset = 99
    old = {key: item for key, item in stored.items() if key != 'final_fields'}
    legacy_path = tmp_path / 'legacy.bfr'
    legacy_store = LocalRecordStore(legacy_path)
    try:
        legacy_store.append('materialization', retained.identity, {'materialized': old})
    finally:
        legacy_store.close()
    legacy_readback = reopen_records(legacy_path).records[0].data['materialized']
    assert contract_from_record(MaterializedAction, legacy_readback).final_fields is None
    tagged = request_to_data(restored)
    del tagged['fields']['final_fields']
    assert value_from_data(tagged).final_fields is None
    assert 'final_fields' not in old  # Legacy readback does not synthesize locations.


def test_ordered_multiple_contributions_cli_and_named_shift(application_factory, tmp_path):
    app, _ = application_factory()
    operations = ((b'x', 'overwrite', 1, None, None), (b'yz', 'insert', 3, None, None),
                  (b'!', 'append', None, None, None))
    for cli in (False, True):
        value = request(b'ABCDE', fields=(), operations=operations)
        action = submit(app, value, tmp_path, cli=cli)
        assert action.transport.offered == b'AxCyzDE!'
        assert [p.data for p in action.materialized.placements] == [b'x', b'yz', b'!']
        assert action.materialized.final_fields == ()
    # A named destination follows a larger absolute replacement of a prior field.
    value = request(b'AB\0\0C', fields=(FieldLocation('head', 0, 2, variable=True),
        FieldLocation('count', 2, 2), FieldLocation('tail', 4, 1)), repair=True,
        operations=((b'WXYZ', 'replace', 0, 2, None),), calculations=(
            Calculation('count', '1', 'length', field_id='count', counts='field', counts_field='head'),))
    action = submit(app, value, tmp_path)
    assert action.transport.offered == b'WXYZ\0\4C'
    assert action.materialized.final_fields == (
        FinalFieldLocation('1', 'outbound', 'head', 0, 4, True),
        FinalFieldLocation('1', 'outbound', 'count', 4, 2),
        FinalFieldLocation('1', 'outbound', 'tail', 6, 1))

    # Explicit membership differs from the default before-field insertion, and
    # only the selected span gains the prefix (same-start aliases keep defaults).
    for include in (False, True):
        value = request(b'\0ABC.', fields=(FieldLocation('count',0,1),
            FieldLocation('payload',1,3,variable=True), FieldLocation('alias',1,3),
            FieldLocation('inner',2,1), FieldLocation('tail',4,1)),
            operations=((b'P','insert',None,None,'payload'), (b'Z','overwrite',2,None,None)),
            final=((b'?','append',None,None,None),),
            calculations=(Calculation('count','1','length',field_id='count',counts='field',counts_field='payload'),),
            repair=True)
        value = replace(value,row=replace(value.row,placements=(
            replace(value.row.placements[0],include_in_field=include),value.row.placements[1])))
        actual = submit(app,value,tmp_path,cli=include)
        assert actual.transport.offered == (b'\x04PZBC.?' if include else b'\x03PZBC.?')
        spans = {f.field_id:(f.offset,f.size) for f in actual.materialized.final_fields}
        assert spans == {'count':(0,1),'payload':(1,4) if include else (2,3),
            'alias':(2,3),'inner':(3,1),'tail':(5,1)}
        restored = value_from_data(request_to_data(value))
        assert restored == value and restored.row.placements[0].include_in_field is include
        old = request_to_data(value.row.placements[0]); old['fields'].pop('include_in_field')
        assert value_from_data(old).include_in_field is False
        assert contract_from_record(Placement,{k:v for k,v in freeze(value.row.placements[0]).items()
            if k != 'include_in_field'}).include_in_field is False

    for change in ({'include_in_field':1}, {'include_in_field':None},
            {'include_in_field':True,'field_id':None,'offset':1},
            {'include_in_field':True,'operation':'overwrite'},
            {'include_in_field':True,'operation':'replace'},
            {'include_in_field':True,'operation':'append'}):
        malformed = replace(value,row=replace(value.row,placements=(replace(value.row.placements[0],**change),)))
        before = len(app.record_refs(value.run_id))
        with pytest.raises(ContractError,match='include_in_field'):
            app.validate(ApplicationRequest(malformed,TransportRequest('offline.invalid',1234,1),str(tmp_path/'bad.bfr')))
        assert len(app.record_refs(value.run_id)) == before
    unknown = request(b'ABC',fields=(FieldLocation('payload',0,None),),
        operations=((b'P','insert',None,None,'payload'),))
    unknown = replace(unknown,row=replace(unknown.row,placements=(
        replace(unknown.row.placements[0],include_in_field=True),)))
    actual = submit(app,unknown,tmp_path)
    assert actual.transport.offered == b'PABC'
    assert actual.materialized.final_fields[0].offset == 0 and actual.materialized.final_fields[0].size is None
    bad_count = replace(unknown,calculations=(Calculation('unknown-count','1','length',offset=0,size=1,
        counts='field',counts_field='payload',required=True),))
    with pytest.raises(ContractError,match='unsupported_capability'):
        app.validate(ApplicationRequest(bad_count,TransportRequest('offline.invalid',1234,1),str(tmp_path/'unknown.bfr')))


@pytest.mark.parametrize('calculation', [
    Calculation('missing', '1', 'future'),
    Calculation('missing', '1', 'length', field_id='absent'),
    Calculation('missing', '1', 'checksum', 0, 2, algorithm='future')])
def test_unknown_optional_raw_and_required_pretraffic(application_factory, tmp_path, calculation):
    app, traces = application_factory()
    value = request(calculations=(calculation,), repair=True)
    action = submit(app, value, tmp_path)
    assert action.transport.offered == b'\0\3ABC'
    assert action.materialized.calculations == (('missing', 'unavailable_rule_or_location'),)
    before = sum(len(trace) for trace, _, _ in traces)
    with pytest.raises(ContractError, match='unsupported_capability'):
        submit(app, replace(request(), repair=False,
                            calculations=(replace(calculation, required=True),)), tmp_path)
    assert sum(len(trace) for trace, _, _ in traces) == before


@pytest.mark.parametrize('fields,name,code', [
    ((), 'body', 'unknown_field'),
    ((FieldLocation('body'),), 'body', 'unknown_field_location'),
    ((FieldLocation('body', 0, 1), FieldLocation('body', 1, 1)), 'body', 'duplicate_identity')])
def test_named_mapping_never_guesses(application_factory, tmp_path, fields, name, code):
    app, traces = application_factory()
    with pytest.raises(ContractError, match=code):
        submit(app, request(fields=fields, operations=((b'Z', 'replace', None, None, name),)), tmp_path)
    assert not any(trace for trace, _, _ in traces)
    # The same incomplete metadata does not gate explicit raw edits.
    if code != 'duplicate_identity':
        value = request(fields=fields, operations=((b'Z', 'replace', 2, 5, None),))
        assert submit(app, value, tmp_path).transport.offered == b'\0\3Z'


def test_field_scope_unknown_required_count_and_preserved_variant(application_factory, tmp_path):
    app, traces = application_factory()
    value = request(fields=(), operations=((b'Z', 'replace', None, None, 'body'),))
    other = replace(value.plan.actions[0], action_id='other', fields=(FieldLocation('body', 0, 1),))
    with pytest.raises(ContractError, match='unknown_field'):
        submit(app, replace(value, plan=replace(value.plan, actions=(*value.plan.actions, other))), tmp_path)
    # A raw crossing replacement invalidates this counted field; a required
    # computation cannot manufacture a span even with optional repair disabled.
    value = request(b'\0\0ABCDE', fields=(FieldLocation('body', 3, 2),),
        operations=((b'X', 'replace', 2, 4, None),), calculations=(
            Calculation('count', '1', 'length', 0, 2, counts='field', counts_field='body', required=True),))
    with pytest.raises(ContractError, match='counted field no longer'):
        submit(app, value, tmp_path)
    # Existing length-mismatch variants require a known seed length destination.
    value = request(b'ABC', fields=(), calculations=(Calculation('length', '1', 'payload_length',
        9, 2, payload_offset=11, override_value=4),))
    with pytest.raises(ContractError, match='variant_unavailable'):
        submit(app, value, tmp_path)
    assert not any(trace for trace, _, _ in traces)
    # Metadata for an unavailable buffer survives but cannot supply an outbound
    # name. The raw outbound path still works, and same names in distinct buffers
    # resolve only within their explicit scope.
    hidden = FieldLocation('body', 0, 1, buffer_id='logical')
    value = request(fields=(hidden,), operations=((b'Z', 'replace', None, None, 'body'),))
    with pytest.raises(ContractError, match='unknown_field'):
        submit(app, value, tmp_path)
    value = request(fields=(hidden,), operations=((b'Z', 'replace', 2, 5, None),))
    assert submit(app, value, tmp_path).transport.offered == b'\0\3Z'
    value = request(fields=(hidden, FieldLocation('body', 2, 3)),
                    operations=((b'Z', 'replace', None, None, 'body'),))
    assert submit(app, value, tmp_path).transport.offered == b'\0\3Z'


@pytest.mark.parametrize('name,size,expected', [
    ('crc16', 2, bytes.fromhex('29b1')), ('crc32', 4, bytes.fromhex('cbf43926')),
    ('md5', 16, hashlib.md5(b'123456789').digest()),
    ('sha1', 20, hashlib.sha1(b'123456789').digest()),
    ('sha1', None, hashlib.sha1(b'123456789').digest()),
    ('sha256', 32, hashlib.sha256(b'123456789').digest()),
    ('sha256', 7, hashlib.sha256(b'123456789').digest()[:7])])
def test_generic_checksum_engine_vectors(application_factory, tmp_path, name, size, expected):
    app, _ = application_factory()
    # Numeric fixed destination, named field and append share the ordinary path.
    for destination in ('fixed', 'field', 'append'):
        seed = b'123456789' + (b'\0' * len(expected) if destination != 'append' else b'')
        fields = (FieldLocation('digest', 9, len(expected)),) if destination != 'append' else ()
        calculation = Calculation(name, '1', 'checksum', 9 if destination == 'fixed' else None,
            size, field_id='digest' if destination == 'field' else None,
            destination=destination, range_start=0, range_end=9, algorithm=name, required=True)
        value = request(seed, fields=fields, calculations=(calculation,))
        assert submit(app, value, tmp_path, cli=destination == 'field').transport.offered == b'123456789' + expected


def test_range_length_counts_and_shifted_checksum_override(application_factory, tmp_path):
    app, _ = application_factory()
    for counts, end, expected in (('body', None, 9), ('tail', None, 9), ('full', None, 11),
                                  ('packet', None, 11), ('range', -2, 7), ('range', 7, 5)):
        calculation = Calculation('count', '1', 'length', 0, 2, counts=counts,
                                  range_start=2, range_end=end, required=True)
        value = request(b'\0\0' + b'123456789', fields=(), calculations=(calculation,))
        assert submit(app, value, tmp_path).transport.offered == expected.to_bytes(2, 'big') + b'123456789'
    # The output extent is included in full length even when added beyond EOF.
    for destination, offset, expected in (('fixed', 5, b'ABC\0\0\0\7'), ('append', None, b'ABC\0\5')):
        value = request(b'ABC', fields=(), calculations=(Calculation('full', '1', 'length', offset, 2,
            destination=destination, counts='full', required=True),))
        action = submit(app, value, tmp_path)
        assert action.transport.offered == expected
        assert action.materialized.final_fields == ()
    value = request(b'\0\0ABC', fields=(), calculations=(Calculation('little', '1', 'length',
        0, 2, endian='little', counts='full', required=True),))
    assert submit(app, value, tmp_path).transport.offered == b'\5\0ABC'
    calculation = Calculation('crc', '1', 'crc16', field_id='crc', range_start=1,
                              range_end=-2, required=True)
    fields = (FieldLocation('crc', 9, 2),)
    for final, expected in (((), b'Q123456789\x29\xb1'),
                           (((b'XX', 'overwrite', None, None, 'crc'),), b'Q123456789XX')):
        value = request(b'123456789\0\0', fields=fields, repair=True, calculations=(calculation,),
            operations=((b'Q', 'insert', 0, None, None),), final=final)
        action = submit(app, value, tmp_path)
        assert action.transport.offered == expected
        assert action.materialized.final_fields == (FinalFieldLocation('1', 'outbound', 'crc', 10, 2),)
    value = request(b'123456789\0\0', fields=fields, repair=True, calculations=(calculation,),
        operations=((b'XX', 'overwrite', 9, None, None), (b'Q', 'insert', 0, None, None)))
    action = submit(app, value, tmp_path)
    assert action.transport.offered == b'Q123456789XX'
    assert action.materialized.calculations == (('crc', 'explicit_edit'),)


def test_named_source_cli_admission_and_raw_short_baseline(application_factory, tmp_path):
    app, _ = application_factory()
    root = tmp_path / 'protocols'
    directory = root / 'neutral'
    source = Path(__file__).resolve().parents[3] / 'src/bytefault/protocols/raw'
    shutil.copytree(source, directory, ignore=shutil.ignore_patterns('__pycache__'))
    plan = request().plan
    (directory / 'declaration.json').write_text(json.dumps(app.export_declaration(plan)), encoding='utf-8')
    result = execute_arguments(['raw', 'offline.invalid', '--declaration-dir', str(root),
        '--port', '1234', '--no-ui', '--health-check-mode', 'disabled', '--records', str(tmp_path/'named.bfr'),
        '--gen-field', 'body:list:5758595a,mode:replace'], app)
    assert result.last_conversation.actions[0].transport.offered == b'\0\3WXYZ'
    result = execute_arguments(['raw', 'offline.invalid', '--declaration-dir', str(root),
        '--port', '1234', '--no-ui', '--health-check-mode', 'disabled', '--records', str(tmp_path/'raw.bfr'),
        '--seed-hex', '41', '--gen-field', '@append:list:5a'], app)
    assert result.last_conversation.actions[0].transport.offered == b'AZ'


def test_final_fields_after_calculation_final_overrides_and_scoped_unknowns(application_factory, tmp_path):
    app, _ = application_factory()
    fields = (FieldLocation('body', 2, 2, variable=True), FieldLocation('crossed', 1, 2),
        FieldLocation('open', 4, None, variable=True), FieldLocation('empty', 5, 0),
        FieldLocation('unknown'), FieldLocation('body', 0, 1, buffer_id='logical'))
    value = request(b'ABCDE', fields=fields,
        operations=((b'WXYZ', 'replace', None, None, 'body'),),
        calculations=(Calculation('crc', '1', 'crc16', destination='append', required=True),),
        final=((b'Q', 'replace', None, None, 'body'), (b'!', 'insert', 0, None, None)))
    other = replace(value.plan.actions[0], action_id='other', seed=b'PQR',
                    fields=(FieldLocation('body', 0, 3),))
    value = replace(value, plan=replace(value.plan, actions=(*value.plan.actions, other)))
    result = app.submit(ApplicationRequest(value, TransportRequest('offline.invalid', 1234, 3),
                                          str(tmp_path / 'final-fields.bfr')))
    assert result.outcome == 'completed'
    first, second = (action.materialized for action in result.actions)
    checksum = binascii.crc_hqx(b'ABWXYZE', 0xffff).to_bytes(2, 'big')
    assert first.final_bytes == b'!ABQE' + checksum
    assert first.final_fields == (
        FinalFieldLocation('1', 'outbound', 'body', 3, 1, True),
        FinalFieldLocation('1', 'outbound', 'crossed', None, None),
        FinalFieldLocation('1', 'outbound', 'open', 4, None, True),
        # Existing tracking assigns a calculation's insertion at this exact empty
        # span to the field; the snapshot reports that final checksum span.
        FinalFieldLocation('1', 'outbound', 'empty', 5, 2),
        FinalFieldLocation('1', 'outbound', 'unknown', None, None),
        FinalFieldLocation('1', 'logical', 'body', None, None))
    assert second.final_bytes == b'PQR'
    assert second.final_fields == (FinalFieldLocation('other', 'outbound', 'body', 0, 3),)
    stored = next(record for record in app.read_records(value.run_id).records
                  if record.kind == 'action_result').data['result']['materialized']
    assert contract_from_record(MaterializedAction, stored) == first
    # Seed-invalid identities stay unknown when raw padding creates their nominal
    # byte ranges. Available empty boundaries and known-start unknown extents differ.
    value = request(b'ABC', fields=(FieldLocation('outside', 5, 0),
        FieldLocation('overrun', 2, 4, variable=True), FieldLocation('unknown-start', None, 2),
        FieldLocation('boundary', 3, 0), FieldLocation('open-boundary', 3, None)),
        final=((b'Z', 'overwrite', 6, None, None),))
    action = submit(app, value, tmp_path)
    assert action.transport.offered == b'ABC\0\0\0Z'
    assert action.materialized.final_fields == (
        FinalFieldLocation('1', 'outbound', 'outside', None, None),
        FinalFieldLocation('1', 'outbound', 'overrun', None, None, True),
        FinalFieldLocation('1', 'outbound', 'unknown-start', None, None),
        FinalFieldLocation('1', 'outbound', 'boundary', 3, 0),
        FinalFieldLocation('1', 'outbound', 'open-boundary', 3, None))
    assert MaterializedAction('direct-probe', b'X', b'X').final_fields is None
