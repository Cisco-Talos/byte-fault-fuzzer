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

"""Composed ordinary application path; external ports alone are fake."""
import ast
import importlib.abc
import json
from pathlib import Path
import sys

from test_ui_boundary import imports_at_load, NoUi


def test_composed_application_and_headless_boundary(tmp_path, application_factory, monkeypatch, capsys):
    # UI test intentionally reloads product modules; use current contract classes.
    from bytefault.application import ApplicationRequest
    from bytefault.core.contracts import (TransportRequest, MonitoringDecision,
        PassivePlan, ConversationAction, ReceiveRequest, ResponseEdge, PreparedRow,
        PreparedContribution, SourceInvocation, Placement, ConversationRequest)
    from bytefault.monitoring import Monitoring
    from bytefault.core.storage import reopen_records
    isolated = {name: module for name, module in sys.modules.items()
                if name == 'rich' or name.startswith(('rich.', 'bytefault.ui'))}
    for name in isolated:
        del sys.modules[name]
    blocker = NoUi()
    sys.meta_path.insert(0, blocker)
    try:
        plan = PassivePlan('neutral', 1, (
            ConversationAction('setup', b'\x10', receive=ReceiveRequest(cap=4, deadline=10),
                edges=(ResponseEdge(b'\x01', 'selected', 'positive'),)),
            ConversationAction('selected', b'U=aa;P=bb', next_action=None)))
        row = PreparedRow('row', 1, tuple(PreparedContribution(f'C{i}', data,
            SourceInvocation(f'S{i}', 'literal')) for i, data in enumerate((b'XXX', b'Y', b'ZZ'))),
            (Placement('P0', 'C0', 'selected', 'replace', 2, 4),
             Placement('P1', 'C1', 'selected', 'replace', 8, 10),
             Placement('P2', 'C2', 'selected', 'append')))
        conversation = ConversationRequest(plan, row, ('selected',), 'integrated', 'case', 'conversation',
                                           original_request={'password': 'marker-X'})
        app, traces = application_factory(monitoring=Monitoring(),
                                         stream_options={'reads': (b'\x01',)})
        request = ApplicationRequest(conversation, TransportRequest('offline.invalid', 1234, 10),
            str(tmp_path / 'evidence.bfr'), str(tmp_path / 'actions.bfr'))
        assert app.submit(request).outcome == 'completed'
        assert [t[1] for t in traces[0][0] if t[0] == 'offer'] == [b'\x10', b'U=XXX;P=YZZ']
        records, logs = reopen_records(request.record_path), reopen_records(request.log_path)
        assert [r.kind for r in records.records] == [r.kind for r in logs.records]
        assert sum(r.kind == 'materialization' for r in records.records) == 2
        assert sum(r.kind == 'observation' for r in logs.records) == 2
        assert all('recorded_at_utc' in r.data for r in logs.records)
        assert records.records[0].data['request']['original_request']['password'] == 'marker-X'
        assert app.observe('integrated')['events'][-1]['kind'] == 'application_terminal'
        assert 'bytefault.ui' not in sys.modules
        root = Path(__file__).resolve().parents[3]
        for folder in ('core', 'fuzzers'):
            for path in (root / 'src/bytefault' / folder).glob('*.py'):
                if path.name in ('rich_listener.py', 'rich_renderables.py',
                                 'keypress.py', 'theme.py'):
                    continue
                tree = ast.parse(path.read_text(encoding='utf-8-sig'))
                assert not any(name.startswith(('bytefault.ui','rich'))
                               for name in imports_at_load(tree.body)), path
                parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
                for node in ast.walk(tree):
                    names = ([node.module or ''] if isinstance(node, ast.ImportFrom) else
                        [item.name for item in node.names] if isinstance(node, ast.Import) else [])
                    if path.name == 'cli.py' and names == ['bytefault.ui.controller']:
                        # Explicit terminal dispatch may use the shared prepared
                        # helper; module load and headless dispatch stay UI-free.
                        assert isinstance(node, ast.ImportFrom)
                        assert [item.name for item in node.names] == ['run_terminal']
                        ancestors = []
                        current = node
                        while current in parents:
                            current = parents[current]
                            ancestors.append(current)
                        assert any(isinstance(item, ast.FunctionDef) and item.name in (
                            'execute_arguments', 'execute_prepared_request')
                                   for item in ancestors)
                        assert any(isinstance(item, ast.If) and (
                            (isinstance(item.test, ast.Name) and item.test.id == 'terminal') or
                            (isinstance(item.test, ast.BoolOp) and any(isinstance(value, ast.Name) and value.id == 'terminal'
                                for value in item.test.values))) for item in ancestors)
                        continue
                    assert not any(n.startswith(('bytefault.ui', 'rich', 'bytefault.protocols')) for n in names), path
        from bytefault.fuzzers import cli
        configuration = cli.execute_arguments(
            ['configure','neutral','offline.invalid','--gen-field','@0:list:00,ff','--gen-strategy','zip'], app)
        assert configuration.status == 'pending' and configuration.pending
        assert not configuration.resolved['ui']['requested']
        configured = cli.execute_arguments(
            ['configure','offline.invalid','--port','1234','--seed-hex','00ff','--ui'], app)
        assert not configured.pending and configured.resolved['ui']['requested']
        alias = cli.execute_arguments(
            ['configure','offline.invalid','--port','1234','--seed-hex','00ff','--tui'], app)
        assert alias.resolved['ui']['requested'] and alias.options['ui']
        # An ordinary machine invocation, even with --ui requested, cannot import
        # presentation code. Keep the real dispatcher, result encoder and executor.
        headless, headless_traces = application_factory()
        monkeypatch.setattr(cli, 'Application', lambda: headless)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
        assert cli.main(['offline.invalid','--port','1234','--seed-hex','00ff','--ui','--no-recv',
                         '--records',str(tmp_path / 'headless.bfr')]) == 0
        machine = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        from bytefault.core.records import decode_value
        result = decode_value(machine[0])
        assert result['outcome'] == 'completed'
        assert [item[1] for item in headless_traces[0][0] if item[0] == 'offer'] == [b'\x00\xff']
        assert not any(name == 'rich' or name.startswith(('rich.', 'bytefault.ui')) for name in sys.modules)
        # Even on an interactive terminal, the default entry does not attach UI.
        interactive, interactive_traces = application_factory()
        monkeypatch.setattr(cli, 'Application', lambda: interactive)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr(sys.stderr, 'isatty', lambda: True)
        assert cli.main(['offline.invalid','--port','1234','--seed-hex','41','--no-recv',
                         '--records',str(tmp_path / 'interactive-headless.bfr')]) == 0
        result = decode_value(json.loads(capsys.readouterr().out.splitlines()[0]))
        assert result['outcome'] == 'completed'
        assert [item[1] for item in interactive_traces[0][0] if item[0] == 'offer'] == [b'A']
        assert not any(name == 'rich' or name.startswith(('rich.', 'bytefault.ui')) for name in sys.modules)
        assert 'inspect_resume' in app.inspect()['operations']
        assert app.inspect()['service_attachments']['reporting']['owner'] == 'Reporting'
        assert 'report_layout' not in app.inspect()['unavailable']
        assert app.unavailable('schema_to_dissector').owner == 'Passive authoring'
    finally:
        sys.meta_path.remove(blocker)
        for name in list(sys.modules):
            if name == 'rich' or name.startswith(('rich.', 'bytefault.ui')):
                del sys.modules[name]
        sys.modules.update(isolated)
