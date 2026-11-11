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

"""Preparation and cleanup behavior through ordinary guarded consumers."""
from dataclasses import replace
import json

import pytest

from bytefault.application import ApplicationRequest
from bytefault.core.contracts import TransportRequest
from bytefault.core.records import decode_value
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.fuzzers.inputs import raw_request
from bytefault.fuzzers import cli
from bytefault.generators.sources import SourceStream


def argv(tmp_path, *, generated=False):
    arguments = ['offline.invalid', '--port', '1234', '--seed-hex', '414243',
                 '--no-ui', '--no-recv', '--health-check-mode','disabled','--retries','0','--records', str(tmp_path / 'required.bfr')]
    return arguments + (['--gen-field', '@1:list:5a,59,mode:overwrite'] if generated else [])


def input_request(tmp_path):
    conversation = replace(raw_request(b'ABC'), run_id='review', case_id='case', conversation_id='conversation')
    request = ApplicationRequest(conversation, TransportRequest('offline.invalid', 1234, 10),
                                 str(tmp_path / 'case.bfr'))
    configuration = {'sources': ({'source_id': 'source', 'kind': 'list', 'options': {'payloads': (b'Z', b'Y')}},),
        'sets': ({'set_id': 'S', 'source_id': 'source'},),
        'positions': ({'position_id': 'P', 'set_id': 'S', 'operation': 'overwrite', 'offset': 1},)}
    return request, configuration


@pytest.mark.parametrize('generated', [False, True])
def test_prepare_dispatcher_never_constructs_adapter_and_submit_remains_available(
        tmp_path, application_factory, generated):
    app, traces = application_factory()
    prepared = cli.execute_arguments(['prepare', *argv(tmp_path, generated=generated)], app)
    requests = list(prepared)
    assert len(requests)==(2 if generated else 1) and prepared.summary['outcome']=='completed'
    assert requests[0]['application_request']['transport']['port']==1234
    assert requests[0]['requests'][0]['plan']['actions'][0]['seed']==b'ABC'
    assert not traces
    assert not (tmp_path / 'required.bfr').exists()
    execution = cli.execute_arguments(['submit', *argv(tmp_path / 'submitted', generated=generated)], app)
    assert execution.outcome=='completed' and execution.fuzz_tests==(2 if generated else 1)
    assert [step[1] for trace, _, _ in traces for step in trace if step[0] == 'offer'] == (
        [b'AZC', b'AYC'] if generated else [b'ABC'])


@pytest.mark.parametrize('generated', [False, True])
def test_prepare_main_emits_request_without_adapter_execution(
        tmp_path, application_factory, monkeypatch, capsys, generated):
    app, traces = application_factory()
    monkeypatch.setattr(cli, 'Application', lambda: app)
    assert cli.main(['prepare', *argv(tmp_path, generated=generated)]) == 0
    output = [decode_value(json.loads(line)) for line in capsys.readouterr().out.splitlines()]
    requests = output[:-1]
    assert len(requests) == (2 if generated else 1)
    assert all('requests' in request and 'application_request' in request for request in requests)
    assert all(request['application_request']['transport']['port']==1234 for request in requests)
    assert not traces
    assert output[-1]['outcome']=='completed' and output[-1]['prepared_cases']==(2 if generated else 1)


def fail_source_close_after_actual_close(monkeypatch):
    closed = []
    original = SourceStream.close
    def close(source):
        original(source)
        closed.append(source.source.source_id)
        raise OSError('secondary controlled source-close failure')
    monkeypatch.setattr(SourceStream, 'close', close)
    return closed


def assert_refusal_history(app, result, preparation_path):
    assert result.outcome == 'transport_failed'
    assert result.cleanup.outcome == 'completed'
    assert result.actions[0].transport.error == 'primary controlled refusal'
    case = app.read_records(result.run_id).records
    assert case[-1].kind == 'case_terminal'
    assert case[-1].data['result']['outcome'] == result.outcome
    assert case[-1].data['result']['reason'] == result.reason
    preparation = reopen_records(preparation_path).records
    assert sum(record.kind == 'prepared_row' for record in preparation) == 1
    terminal = preparation[-1]
    assert terminal.kind == 'preparation_terminal'
    assert terminal.data['summary']['status'] == 'failed'
    source_id = case[0].data['request']['row']['contributions'][0]['source']['source_id']
    assert terminal.data['summary']['cleanup_errors'][0]['owner'] == source_id
    assert terminal.data['summary']['cleanup_errors'][0]['error'] == 'secondary controlled source-close failure'


def test_noncompleted_result_survives_first_source_cleanup_failure(tmp_path, application_factory, monkeypatch):
    app, traces = application_factory(stream_options={'open_error': OSError('primary controlled refusal')})
    request, configuration = input_request(tmp_path)
    closed = fail_source_close_after_actual_close(monkeypatch)
    operation = app.submit_generated(request, configuration)
    result = next(operation)
    assert list(operation) == [] and closed == ['source']
    summary = operation.summary
    assert summary['status'] == result.outcome and summary['reason'] == result.reason
    assert summary['preparation_status'] == 'failed'
    assert summary['preparation_reason'] == 'source preparation cleanup failed'
    failure, = summary['operation_cleanup_errors']
    assert failure['path'] == 'generation.cleanup' and failure['code'] == 'cleanup_failed'
    assert failure['preparation_summary']['cleanup_errors'][0]['owner'] == 'source'
    assert summary['prepared_rows'] == summary['processed_rows'] == 1
    assert summary['fuzz_sends'] == 0
    assert len(traces) == 1 and traces[0][1].closed
    assert_refusal_history(app, result, operation.prepared.path)


def test_noncompleted_cli_emits_original_result_and_separate_cleanup_summary(
        tmp_path, application_factory, monkeypatch, capsys):
    app, traces = application_factory(stream_options={'open_error': OSError('primary controlled refusal')})
    monkeypatch.setattr(cli, 'Application', lambda: app)
    closed = fail_source_close_after_actual_close(monkeypatch)
    assert cli.main(['submit', *argv(tmp_path, generated=True)]) == 1
    output = [decode_value(json.loads(line)) for line in capsys.readouterr().out.splitlines()]
    assert len(output)==2
    result,cleanup_output=output
    assert set(cleanup_output)=={'application_cleanup'}
    cleanup=cleanup_output['application_cleanup']
    assert cleanup['outcome']=='failed' and cleanup['pending_runs']==()
    assert cleanup['cleanup_failures']==({'run_id':result['run_id'],
        'engine_cleanup_errors':result['cleanup_errors']},)
    assert result['outcome']==result['execution_outcome']=='transport_failed'
    assert 'primary controlled refusal' in result['reason']
    assert result['preparation_summary']['status']=='failed'
    assert result['cleanup_errors'][0]['owner']=='preparation'
    assert 'secondary controlled source-close failure' in result['cleanup_errors'][0]['error']
    assert len(traces)==len(closed)==1 and traces[0][1].closed
    actual=app._run(result['run_id']).result
    assert actual.fuzz_tests==actual.attempts==2
    records=app.read_records(actual.run_id).records
    assert records[-1].kind=='campaign_terminal' and records[-1].data['result']['outcome']=='transport_failed'
    assert all(r.data['result']['transport']['error']=='primary controlled refusal' for r in records if r.kind=='action_result')
    preparation=reopen_records(str(tmp_path/'required.bfr.preparation.bfr')).records
    assert preparation[-1].data['summary']['cleanup_errors'][0]['error']=='secondary controlled source-close failure'



def test_noncompleted_result_retains_preparation_terminal_save_diagnostic(
        tmp_path, application_factory, monkeypatch):
    app, _ = application_factory(stream_options={'open_error': OSError('primary controlled refusal')})
    request, configuration = input_request(tmp_path)
    original = LocalRecordStore.append
    def save(store, kind, identity, data):
        if kind == 'preparation_terminal':
            raise OSError('secondary required preparation terminal failure')
        return original(store, kind, identity, data)
    monkeypatch.setattr(LocalRecordStore, 'append', save)
    operation = app.submit_generated(request, configuration)
    result = next(operation)
    assert list(operation) == []
    assert operation.summary['status'] == result.outcome == 'transport_failed'
    assert operation.summary['reason'] == result.reason
    assert operation.summary['preparation_status'] == 'recording_failed'
    failure, = operation.summary['operation_cleanup_errors']
    assert failure['diagnostic']['required_record_kind'] == 'preparation_terminal'
    assert failure['diagnostic']['reason'] == 'secondary required preparation terminal failure'


def test_empty_ordinary_reason_never_falls_back_to_cleanup_reason(
        tmp_path, application_factory, monkeypatch):
    app, _ = application_factory(stream_options={'open_error': OSError('primary controlled refusal')})
    request, configuration = input_request(tmp_path)
    original = app.submit
    monkeypatch.setattr(app, 'submit', lambda value: replace(original(value), reason=''))
    fail_source_close_after_actual_close(monkeypatch)
    operation = app.submit_generated(request, configuration)
    result = next(operation)
    assert result.reason == operation.summary['reason'] == ''
    assert operation.summary['preparation_reason'] == 'source preparation cleanup failed'
