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

"""Explicit current consumed files remain distinct from literal source recipes."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from bytefault.application import ApplicationRequest, SavedCaseIntent
from bytefault.core.contracts import (ContractError, Placement, PreparedContribution,
    PreparedRow, SourceInvocation, TransportRequest)
from bytefault.fuzzers.inputs import raw_request, request_from_record


def test_current_files_codec_literal_recipe_and_saved_lifetime(tmp_path, application_factory):
    consumed = tmp_path / 'consumed.txt'
    consumed.write_bytes(b'# consumed provenance, exact bytes already prepared\n')
    source = SourceInvocation('opaque', 'literal', options={'data': b'Z'},
                              input_reference='dataset:neutral/subset:9')
    original = replace(raw_request(b'A'), row=PreparedRow('row', 1,
        (PreparedContribution('part', b'Z', source),), (Placement('edit', 'part', '1', 'append'),)),
        input_files=(str(consumed),))
    app, traces = application_factory()
    assert app.import_request(app.export_request(original)) == original
    old = app.export_request(original)
    old['fields'].pop('input_files')
    assert app.import_request(old).input_files == ()
    for malformed in (str(consumed), [str(consumed)], ('',)):
        with pytest.raises(ContractError, match='input_files'):
            app.import_request(app.export_request(replace(original, input_files=malformed)))
    request = ApplicationRequest(original, TransportRequest('offline.invalid', 1234, 1),
                                 str(tmp_path / 'original.bfr'))
    assert app.submit(request).outcome == 'completed'
    start = next(r for r in app.read_records(original.run_id).records if r.kind == 'case_start')
    assert request_from_record(start.data['request']).input_files == (str(consumed),)
    portable = app.export_case(request.record_path, start.record_id)
    copied = tmp_path / 'copy.json'
    copied.write_text(json.dumps(portable), encoding='utf-8')
    consumed.unlink()
    # Both recorded and fresh literal recipes are self-contained; the label is
    # never guessed to be a filesystem prerequisite.
    for mode in ('literal', 'fresh_dynamic'):
        prepared = app.import_case(portable, mode=mode, record_path=str(tmp_path / (mode + '.bfr')))
        assert prepared.conversation.input_files == ()
        result = app.submit(prepared)
        assert result.outcome == 'completed' and result.actions[0].transport.offered == b'AZ'
        if mode == 'fresh_dynamic':
            assert prepared.conversation.row.contributions[0].source.options == {'kind': 'literal', 'data': b'Z'}
        assert prepared.conversation.original_request['saved_case']['original_request']['input_files'] == (str(consumed),)
    loaded = app.saved_case(SavedCaseIntent(str(copied)), record_path=str(tmp_path / 'loaded.bfr'))
    assert loaded.conversation.input_files == (str(copied.resolve()),)
    before = copied.read_bytes()
    with pytest.raises(ContractError, match='source_collision'):
        app.saved_case(SavedCaseIntent(str(copied)), record_path=str(copied))
    assert copied.read_bytes() == before
    assert all(stream.closed for _, stream, _ in traces)


@pytest.mark.parametrize('destination', ('record', 'log_hardlink', 'repeated_record'))
def test_explicit_files_refuse_record_alias_before_adapter_or_writer(tmp_path, application_factory, monkeypatch, destination):
    from bytefault.core.storage import LocalRecordStore
    from bytefault.logging import ActionLog
    consumed = tmp_path / 'consumed.txt'
    consumed.write_bytes(b'')
    caller = LocalRecordStore(tmp_path / 'caller.bfr') if destination == 'repeated_record' else None
    app, traces = application_factory(action_logs=(ActionLog(caller),) if caller is not None else ())
    opened = []
    ordinary_store, ordinary_log = LocalRecordStore.__init__, ActionLog.open
    def store(self, *args, **options):
        opened.append('store')
        return ordinary_store(self, *args, **options)
    def log(*args, **options):
        opened.append('log')
        return ordinary_log(*args, **options)
    monkeypatch.setattr(LocalRecordStore, '__init__', store)
    monkeypatch.setattr(ActionLog, 'open', log)
    value = replace(raw_request(b'A'), input_files=(str(consumed),))
    record_path = str(tmp_path / '.' / consumed.name)
    log_path = None
    if destination == 'log_hardlink':
        alias = tmp_path / 'aliased.actions.bfr'
        alias.hardlink_to(consumed)
        record_path, log_path = str(tmp_path / 'independent.bfr'), str(alias)
    elif destination == 'repeated_record':
        record_path = str(tmp_path / 'independent.bfr')
    request = ApplicationRequest(value, TransportRequest('offline.invalid', 1234, 1),
        record_path, log_path)
    try:
        run = None
        if caller is not None:
            run = app._reserve(request)
            # Controlled alias change between the two existing admission
            # boundaries: unwind must not append a failure to the aliased sink.
            consumed.unlink()
            consumed.hardlink_to(caller.path)
            Path(record_path).hardlink_to(caller.path)
        with pytest.raises(ContractError, match='source_collision'):
            app._submit(request, run) if run is not None else app.submit(request)
        assert opened == [] and traces == [] and consumed.read_bytes() == b''
        if caller is not None:
            assert caller.snapshot().records == () and not caller.closed
    finally:
        if caller is not None:caller.close()


@pytest.mark.parametrize('mode,options,expected', (
    ('whole_file', {}, b'AZ'), ('line_file', {}, b'AZ'),
    ('file', {}, b'AZ'), ('literal', {'kind':'file'}, b'AZ'),
    ('literal', {'data':b'L'}, b'AL')))
def test_selected_fresh_source_inventory_matches_file_mode_recipe(tmp_path, application_factory, mode, options, expected):
    from bytefault.application import ResumeIntent, ResumeChoice, SavedStepIntent
    from bytefault.core.storage import reopen_records
    source = tmp_path / 'source.bin'
    source.write_bytes(b'Z')
    contribution = PreparedContribution('part', b'old', SourceInvocation('source', mode,
        options=options, input_reference=str(source)))
    conversation = replace(raw_request(b'A'), row=PreparedRow('row', 1, (contribution,),
        (Placement('edit', 'part', '1', 'append'),)))
    app, traces = application_factory()
    original = ApplicationRequest(conversation, TransportRequest('offline.invalid',1234,1),
        str(tmp_path/'original.bfr'))
    assert app.submit(original).outcome == 'completed'
    history = reopen_records(original.record_path)
    reference = next(ref for record,ref in zip(history.records,history.refs) if record.kind=='materialization')
    prefix = tmp_path/'prefix.bfr'
    prefix.write_bytes(Path(original.record_path).read_bytes()[:reference.offset+reference.length])
    resumed = app.resume(ResumeIntent(str(prefix), (ResumeChoice(conversation.conversation_id,'rerun',(
        SavedStepIntent('1','fresh_dynamic'),)),)), record_path=str(tmp_path/'resumed.bfr'))
    paths, directories = app._current_input_inventory(resumed)
    is_file = mode != 'literal' or options.get('kind') == 'file'
    assert paths == ({prefix.resolve(),source.resolve()} if is_file else {prefix.resolve()})
    assert directories == set()
    result = app.submit(resumed)
    assert result.outcome == 'completed' and result.last_conversation.actions[0].transport.offered == expected
    assert source.read_bytes() == b'Z'
