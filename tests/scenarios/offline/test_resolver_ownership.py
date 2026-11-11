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

"""The public resolver owns only the Applications it creates itself."""
import pytest

import bytefault.application as application_module
import bytefault.cli as root
import bytefault.fuzzers.cli as shared
from bytefault.application import Application
from bytefault.core.contracts import ContractError, freeze


@pytest.fixture
def tracked(monkeypatch):
    instances = []

    class TrackedApplication(Application):
        transport_override = None
        cleanup_failure = False

        def __init__(self, *args, **kwargs):
            if type(self).transport_override is not None:
                kwargs.setdefault('transport_factory', type(self).transport_override)
            super().__init__(*args, **kwargs)
            self.close_calls = 0
            instances.append(self)

        def close(self):
            self.close_calls += 1
            result = super().close()
            return freeze({**dict(result), 'outcome': 'failed'}) if self.cleanup_failure else result

    monkeypatch.setattr(shared, 'Application', TrackedApplication)
    monkeypatch.setattr(application_module, 'Application', TrackedApplication)
    return TrackedApplication, instances


def test_implicit_passive_owner_closes_on_success_and_error(tracked):
    _, instances = tracked
    assert root.resolve_arguments(['schema'])['version'] == 1
    assert instances[-1].close_calls == 1
    with pytest.raises(ContractError, match='unsupported_field'):
        root.resolve_arguments(['admit', '{"declaration_id":"x","version":1,"actions":[],"extra":1}'])
    assert instances[-1].close_calls == 1


def test_replay_preparation_closes_only_implicit_owner(tracked):
    App, instances = tracked
    args = ['replay', 'raw', 'offline.invalid', '41', '--port', '1234', '--prepare']
    prepared = root.resolve_arguments(args)
    assert prepared.request.transport.port == 1234
    assert instances[-1].close_calls == 1
    supplied = App()
    root.resolve_arguments(args, supplied)
    assert supplied.close_calls == 0
    supplied.close()
    count = len(instances)
    request = root.resolve_arguments(['maintenance', '--local-only'])
    assert request.local and not request.remote
    assert len(instances) == count


def test_replay_preparation_failure_closes_implicit_owner(tracked):
    App, instances = tracked
    args = ['replay', 'raw', 'offline.invalid', 'not-hex', '--port', '1234', '--prepare']
    with pytest.raises(ValueError, match='Invalid hex'):
        root.resolve_arguments(args)
    assert instances[-1].close_calls == 1
    supplied = App()
    with pytest.raises(ValueError, match='Invalid hex'):
        root.resolve_arguments(args, supplied)
    assert supplied.close_calls == 0
    supplied.close()


def test_generic_supplied_owner_remains_caller_owned(tracked):
    App, _ = tracked
    supplied = App()
    try:
        assert root.resolve_arguments(['schema'], supplied)['version'] == 1
        assert supplied.close_calls == 0
    finally:
        supplied.close()


def test_direct_configuration_and_argument_helpers_close_implicit_owner(tracked, capsys):
    App, instances = tracked
    args = ['raw', 'offline.invalid', '--port', '1234', '--seed-hex', '41']
    config = shared.resolve_configuration(args)
    assert config.request.transport.port == 1234
    assert instances[-1].close_calls == 1
    request = shared.argument_request(args)
    assert request.transport.port == 1234
    assert instances[-1].close_calls == 1

    with pytest.raises(ContractError):
        shared.resolve_configuration(['raw', 'offline.invalid', '--port', '1234',
                                      '--seed-hex', 'not-hex'])
    assert instances[-1].close_calls == 1

    supplied = App()
    shared.resolve_configuration(args, supplied)
    assert supplied.close_calls == 0
    supplied.close()

    App.cleanup_failure = True
    assert shared.resolve_configuration(args).request.transport.port == 1234
    assert instances[-1].close_calls == 1
    assert 'BYTEFAULT STANDALONE CLEANUP/FOLLOWUP FAILURE' in capsys.readouterr().err


def test_root_configure_closes_implicit_owner(tracked):
    _, instances = tracked
    result = root.resolve_arguments(['configure', 'raw', 'offline.invalid',
                                     '--port', '1234', '--seed-hex', '41'])
    assert result.request.transport.port == 1234
    assert instances[-1].close_calls == 1


def test_implicit_owner_drains_pending_followup(tracked, monkeypatch):
    _, instances = tracked

    class PendingManagement:
        def __init__(self):
            self.wait_calls = 0

        def status(self):
            return freeze({'pending': () if self.wait_calls else ('followup',),
                           'outcome': 'completed' if self.wait_calls else 'pending',
                           'finalized': bool(self.wait_calls)})

        def wait(self):
            self.wait_calls += 1
            return freeze({'outcome': 'completed'})

    def dispatch(argv, application, **kwargs):
        application.management = PendingManagement()
        return freeze({'version': 1})

    monkeypatch.setattr(shared, 'execute_arguments', dispatch)
    assert root.resolve_arguments(['schema'])['version'] == 1
    owner = instances[-1]
    assert owner.management.wait_calls == 1
    assert owner.close_calls == 2


def _generated_args(tmp_path):
    return ['prepare', 'raw', 'offline.invalid', '--port', '1234',
            '--records', str(tmp_path / 'generated.bfr'),
            '--gen-field', 'payload:list:41,42', '--health-check-mode', 'disabled']


def test_implicit_lazy_owner_survives_consumption_and_closes(tracked, tmp_path):
    _, instances = tracked
    result = root.resolve_arguments(_generated_args(tmp_path))
    owner = instances[-1]
    assert owner.close_calls == 0
    rows = list(result)
    assert [row['materialized'][0][0].final_bytes for row in rows] == [b'A', b'B']
    assert result.summary['outcome'] == 'completed'
    assert owner.close_calls == 1
    result.close()
    assert owner.close_calls == 1


def test_implicit_lazy_early_close_and_failure(tracked, tmp_path):
    _, instances = tracked
    early = root.resolve_arguments(_generated_args(tmp_path / 'early'))
    first = next(early)
    assert first['materialized'][0][0].final_bytes == b'A'
    early.close()
    assert early.summary['outcome'] == 'cancelled'
    assert instances[-1].close_calls == 1

    missing = tmp_path / 'missing.bin'
    failed = root.resolve_arguments(['prepare', 'raw', 'offline.invalid', '--port', '1234',
        '--records', str(tmp_path / 'failed.bfr'), '--gen-field', f'payload:file:{missing}'])
    with pytest.raises((ContractError, OSError)):
        next(failed)
    assert instances[-1].close_calls == 1


def test_lazy_cleanup_failure_is_visible(tracked, tmp_path, capsys):
    App, instances = tracked
    App.cleanup_failure = True
    result = root.resolve_arguments(_generated_args(tmp_path))
    assert len(list(result)) == 2
    assert instances[-1].close_calls == 1
    assert result.summary['outcome'] == 'cleanup_failed'
    assert result.summary['execution_outcome'] == 'completed'
    assert result.summary['application_cleanup_errors']
    assert 'BYTEFAULT STANDALONE CLEANUP/FOLLOWUP FAILURE' in capsys.readouterr().err


def test_status_shaped_generated_summary_keeps_owner_cleanup_facts(tracked, tmp_path,
                                                                    monkeypatch, capsys):
    App, instances = tracked
    App.cleanup_failure = True
    args = _generated_args(tmp_path)

    def generated_stream(argv, application, **kwargs):
        config = shared.resolve_configuration(args[1:], application)
        return application.generate(config.request, config.generation,
                                    limit=config.generation_limit)

    monkeypatch.setattr(shared, 'execute_arguments', generated_stream)
    stream = root.resolve_arguments(args)
    assert len(list(stream)) == 2
    assert instances[-1].close_calls == 1
    summary = stream.summary
    assert summary['status'] == 'exhausted'
    assert summary['operation'] == 'prepare' and summary['prepared_rows'] == 2
    assert 'outcome' not in summary
    assert summary['application_cleanup_errors']
    assert 'BYTEFAULT STANDALONE CLEANUP/FOLLOWUP FAILURE' in capsys.readouterr().err


def test_implicit_fuzz_execution_uses_fake_transport_and_closes(tracked, tmp_path, capsys):
    from bytefault.fuzzers.transport import EngineTransport
    from conftest import Clock, Stream
    App, instances = tracked
    traces = []

    def transport(request):
        trace = []
        clock = Clock(trace)
        stream = Stream(trace, clock, reads=())
        traces.append(trace)
        return EngineTransport(request, socket_factory=lambda *args: stream,
            sleep=clock.sleep, clock=clock)

    App.transport_override = transport
    result = root.resolve_arguments(['fuzz', 'raw', 'offline.invalid', '--port', '1234',
        '--records', str(tmp_path / 'fuzz.bfr'), '--seed-hex', '41', '--no-recv',
        '--health-check-mode', 'disabled'])
    assert result.outcome == 'completed'
    assert any(('offer', b'A') in trace for trace in traces)
    assert instances[-1].close_calls == 2
    assert instances[-1].management.status()['finalized']

    App.cleanup_failure = True
    late = root.resolve_arguments(['fuzz', 'raw', 'offline.invalid', '--port', '1234',
        '--records', str(tmp_path / 'cleanup.bfr'), '--seed-hex', '41', '--no-recv',
        '--health-check-mode', 'disabled'])
    assert late.outcome == 'cleanup_failed'
    assert late.execution_outcome == 'completed'
    assert late.application_cleanup_errors
    assert 'BYTEFAULT STANDALONE CLEANUP/FOLLOWUP FAILURE' in capsys.readouterr().err
