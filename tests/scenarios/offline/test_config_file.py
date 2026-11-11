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

"""Selected config files use the same command parsers as physical CLI input."""

import pytest
from pathlib import Path

from bytefault import cli
from bytefault.config_file import ConfigError, command_parser, expand, read_file


COMMANDS = (*cli.OPERATIONS, 'fuzz', 'replay', 'maintenance')


def selected(tmp_path, body, argv=()):
    path = tmp_path / 'arbitrary name.cfg'
    path.write_text('format-version 1\n' + body, encoding='utf-8')
    return expand([*argv, '--config', str(path)], commands=COMMANDS), path


def test_file_only_fuzz_replay_maintenance_and_generic_positionals(tmp_path):
    fuzz, _ = selected(tmp_path, '[run]\ncommand fuzz\nprotocol raw\nhost offline.invalid\n'
        '[fuzz]\nport 1234\nverbose 2\nauto-length false\n')
    assert fuzz == ['fuzz', 'raw', 'offline.invalid', '--port', '1234',
                    '--verbose', '--verbose', '--no-auto-length']
    command_parser('fuzz').parse_args(fuzz[1:])
    replay, _ = selected(tmp_path, '[run]\ncommand replay\nprotocol raw\nhost offline.invalid\n'
        'packet 00\npacket ff\n[replay]\nport 1234\nprepare true\n')
    assert replay == ['replay', 'raw', 'offline.invalid', '00', 'ff', '--port', '1234', '--prepare']
    command_parser('replay').parse_args(replay[1:])
    maintenance, _ = selected(tmp_path, '[run]\ncommand maintenance\n[maintenance]\n'
        'local-only true\nlocal-entry first\nlocal-entry second\n')
    assert maintenance == ['maintenance', '--local-only', '--local-entry', 'first',
                           '--local-entry', 'second']
    command_parser('maintenance').parse_args(maintenance[1:])
    generic, _ = selected(tmp_path, '[run]\ncommand control\nrun-id run-1\ncontrol stop\n')
    assert generic == ['control', 'run-1', 'stop']
    command_parser('control').parse_args(generic[1:])


def test_merge_conflicts_report_both_sources_even_for_false_zero_aliases_and_repeats(tmp_path):
    cases = [
        ('[fuzz]\nauto-length false\n', ['fuzz', 'offline.invalid', '--no-auto-length'], 'auto-length'),
        ('[fuzz]\nverbose 0\n', ['fuzz', 'offline.invalid', '-vvv'], '-v'),
        ('[fuzz]\ngen-field @0:list:00\n', ['fuzz', 'offline.invalid', '--gen-field=@1:list:ff'], 'gen-field'),
        ('[output]\nlog-file local.log\n', ['fuzz', 'offline.invalid', '-llocal2.log'], '-l'),
        ('[timing]\ntcp-spacing 1\n', ['fuzz', 'offline.invalid', '--tcp-pre-delay', '2'], 'tcp-pre-delay'),
    ]
    for body, argv, spelling in cases:
        with pytest.raises(ConfigError) as error:
            selected(tmp_path, body, argv)
        message = str(error.value)
        assert 'arbitrary name.cfg:' in message and spelling in message
    with pytest.raises(ConfigError, match='positional group'):
        selected(tmp_path, '[run]\ncommand replay\nprotocol raw\nhost offline.invalid\n'
                 'packet 00\n', ['replay', 'raw', 'offline.invalid', 'ff'])
    with pytest.raises(ConfigError, match='command.*CLI command'):
        selected(tmp_path, '[run]\ncommand fuzz\n', ['replay'])


def test_full_values_comments_quotes_and_dash_leading_data(tmp_path):
    tokens, path = selected(tmp_path, """[run]
command fuzz
host offline.invalid
[fuzz]
port 1234
gen-field '@1:random:10-100,exclude:0x00-0x1f,count:100 # literal'
request-json {"path":"C:\\tmp\\case","text":"a # b","quote":"\\\""} # trailing
""")
    assert tokens[-4:] == ['--gen-field', '@1:random:10-100,exclude:0x00-0x1f,count:100 # literal',
                           '--request-json', '{"path":"C:\\tmp\\case","text":"a # b","quote":"\\\""}']
    dash, path = selected(tmp_path, '[run]\ncommand fuzz\nhost offline.invalid\n'
                          '[fuzz]\nseed-hex -ff\n')
    assert dash[-1] == '--seed-hex=-ff'
    assert read_file(path)[-1].value == '-ff'
    _, path = selected(tmp_path, '[run]\ncommand maintenance\n[maintenance]\n'
        'local-cache "C:\\temp\\" # trailing\n'
        "remote-dir 'a|b''c#d'\n")
    values = {entry.key: entry.value for entry in read_file(path)}
    assert values['local-cache'] == 'C:\\temp\\'
    assert values['remote-dir'] == "a|b'c#d"


def test_malformed_file_and_cross_source_credential_conflict(tmp_path):
    for body, marker in (
        ('[run]\ncommand fuzz\n[fuzz]\nport\n', 'expected key and value'),
        ('[run]\ncommand fuzz\n[fuzz]\nport "123\n', 'unmatched quote'),
        ('[run]\ncommand fuzz\n[replay]\nwait 1\n', 'not available'),
    ):
        with pytest.raises(ConfigError, match=marker):
            selected(tmp_path, body)
    with pytest.raises(ConfigError) as error:
        selected(tmp_path, '[run]\ncommand maintenance\nhost offline.invalid\n'
                 '[collection]\nssh-pass secret\n', ['maintenance', '--ssh-key', 'key.pem'])
    assert 'ssh-pass' in str(error.value) and 'CLI --ssh-key' in str(error.value)
    with pytest.raises(ConfigError) as error:
        selected(tmp_path, '[fuzz]\nseed-hex 00\n',
                 ['configure', 'offline.invalid', '--request-json', '{"case":1}'])
    assert 'arbitrary name.cfg:3 seed-hex' in str(error.value)
    assert 'CLI --request-json' in str(error.value) and '{"case":1}' in str(error.value)
    with pytest.raises(ConfigError) as error:
        selected(tmp_path, '[fuzz]\ngeneration-json {}\n',
                 ['configure', 'offline.invalid', '--gen-field', '@0:list:00'])
    assert 'arbitrary name.cfg:3 generation-json' in str(error.value)
    assert "CLI --gen-field='@0:list:00'" in str(error.value)


def test_boolean_modes_count_lines_and_actual_cli_abbreviation(tmp_path):
    tokens, _ = selected(tmp_path, '[run] # trailing comment\ncommand configure\nhost offline.invalid\n'
        '[fuzz]\npersistent false\nverbose 1\nverbose 2\nno-test-banner true\n'
        'auto-length false\n')
    assert tokens == ['configure', 'offline.invalid', '--non-persistent', '--verbose',
                      '--verbose', '--verbose', '--no-test-banner', '--no-auto-length']
    with pytest.raises(ConfigError, match='--gen-strat') as error:
        selected(tmp_path, '[fuzz]\ngen-strategy single\n',
                 ['fuzz', 'offline.invalid', '--gen-strat=zip'])
    assert 'zip' in str(error.value)
    plain, _ = selected(tmp_path, '[run]\ncommand fuzz\nhost offline.invalid\n'
        '[output]\nui false\nno-ui true\n')
    assert plain[-1] == '--no-ui' and '--ui' not in plain
    with pytest.raises(ConfigError, match='verbose'):
        selected(tmp_path, '[fuzz]\nverbose 0\nverbose 1\n', ['fuzz', 'offline.invalid', '-v'])
    with pytest.raises(ConfigError, match='--port'):
        selected(tmp_path, '[fuzz]\nport 1234\n',
                 ['fuzz', 'raw', 'offline.invalid', '--', '--port', '4321'])
    with pytest.raises(ConfigError, match='--offset'):
        selected(tmp_path, '[run]\ncommand fuzz\nprotocol raw\nhost offline.invalid\n'
                 '[fuzz]\noffset 1\n', ['fuzz', '--', '--offset', '2'])
    with pytest.raises(ConfigError) as error:
        selected(tmp_path, '[fuzz]\naction setup\naction outbound\n',
                 ['fuzz', 'offline.invalid', '--action', 'one', '--action', 'two'])
    message = str(error.value)
    assert 'arbitrary name.cfg:3 action=\'setup\'' in message
    assert 'arbitrary name.cfg:4 action=\'outbound\'' in message
    assert "CLI --action='one'" in message and "CLI --action='two'" in message


def test_template_covers_every_public_canonical_action_and_starts_inert():
    template = Path(__file__).parents[3] / 'docs' / 'CONFIG_TEMPLATE.conf'
    lines = template.read_text(encoding='utf-8').splitlines()
    assert 'format-version 1' in lines
    assert read_file(template) == []
    commented = {line[2:].split(None, 1)[0] for line in lines if line.startswith('# ') and
                 len(line[2:].split(None, 1)) > 1}
    for command in COMMANDS:
        for action in command_parser(command)._actions:
            long_names = [name[2:] for name in action.option_strings if name.startswith('--')]
            if long_names and long_names[0] != 'help':
                assert long_names[0] in commented, (command, action.option_strings)


def test_required_generic_group_and_missing_file_diagnostics(tmp_path, capsys):
    with pytest.raises(ConfigError, match='missing'):
        selected(tmp_path, '[run]\ncommand service\nrequest-json {}\n')
    absent = tmp_path / 'missing.cfg'
    assert cli.main(['--config', str(absent)]) == 2
    assert str(absent) in capsys.readouterr().err
    with pytest.raises(SystemExit, match='0'):
        cli.main(['--config', str(absent), '--help'])
    assert '--config PATH' in capsys.readouterr().out
    for command in ('fuzz', 'replay', 'maintenance', 'inspect', 'saved-case'):
        with pytest.raises(SystemExit, match='0'):
            cli.main([command, '--config', str(absent), '--help'])
        assert '--config PATH' in capsys.readouterr().out


def test_root_resolvers_keep_parser_and_request_parity(tmp_path):
    fuzz_body = '[run]\ncommand configure\nprotocol raw\nhost offline.invalid\n'
    fuzz_body += '[fuzz]\nport 1234\nseed-hex 00\nno-auto-length true\n'
    path = tmp_path / 'fuzz.txt'
    path.write_text('format-version 1\n' + fuzz_body, encoding='utf-8')
    from_file = cli.resolve_arguments(['--config', str(path)])
    from_cli = cli.resolve_arguments(['configure', 'raw', 'offline.invalid', '--port', '1234',
                                      '--seed-hex', '00', '--no-auto-length'])
    assert from_file.options['port'] == from_cli.options['port'] == 1234
    assert from_file.options['auto_length'] == from_cli.options['auto_length'] is False
    assert from_file.original_argv == ('--config', str(path))
    assert from_file.request.conversation.plan == from_cli.request.conversation.plan
    assert from_file.request.conversation.repair == from_cli.request.conversation.repair
    path.write_text('format-version 1\n[run]\ncommand replay\nprotocol raw\n'
        'host offline.invalid\npacket 00\npacket ff\n[replay]\nport 1234\nprepare true\n',
        encoding='utf-8')
    replay_file = cli.resolve_arguments(['--config', str(path)])
    replay_cli = cli.resolve_arguments(['replay', 'raw', 'offline.invalid', '00', 'ff',
                                        '--port', '1234', '--prepare'])
    assert replay_file.options['port'] == replay_cli.options['port'] == 1234
    assert replay_file.request.conversation.plan == replay_cli.request.conversation.plan
    path.write_text('format-version 1\n[run]\ncommand maintenance\n'
        '[maintenance]\nlocal-only true\nlocal-entry first\nlocal-entry second\n', encoding='utf-8')
    maintenance_file = cli.resolve_arguments(['--config', str(path)])
    maintenance_cli = cli.resolve_arguments(['maintenance', '--local-only',
                                             '--local-entry', 'first', '--local-entry', 'second'])
    assert maintenance_file.local_entries == maintenance_cli.local_entries == ('first', 'second')
    assert maintenance_file.remote is maintenance_cli.remote is False
    assert maintenance_file.original_request['argv'] == ('--config', str(path))
    assert maintenance_cli.original_request['argv'] == ('--local-only', '--local-entry',
        'first', '--local-entry', 'second')


@pytest.mark.parametrize(('command', 'positionals', 'options'), [
    ('inspect', '', '[generic]\ndirectory any-root\n'),
    ('schema', '', ''),
    ('inspect-declaration', 'declaration-json {}\n', ''),
    ('admit', 'declaration-json {}\n', ''),
    ('export-declaration', 'declaration-json {}\n', ''),
    ('status', 'run-id r1\n', ''),
    ('control', 'run-id r1\ncontrol stop\n', ''),
    ('observe', 'run-id r1\n', '[generic]\nafter 2\n'),
    ('record-refs', 'run-id r1\n', ''),
    ('records', 'run-id r1\n', ''),
    ('inspect-resume', 'path retained.bfr\n', ''),
    ('resume-run', 'intent-json {}\n', '[prepared]\nexecute false\n'),
    ('export-case', 'path retained.bfr\nrecord-id case-1\n', ''),
    ('saved-case', 'intent-json {}\n', '[options]\nno-recv true\n'),
    ('saved-intent', 'intent-json {}\n', '[prepared]\nexecute false\n'),
    ('service', 'owner monitoring\nrequest-json {}\n', ''),
])
def test_generic_public_argument_shapes_share_runtime_parser(tmp_path, command, positionals, options):
    tokens, _ = selected(tmp_path, '[run]\ncommand ' + command + '\n' + positionals + options)
    cli_only = {
        'inspect': ['--directory', 'any-root'], 'schema': [],
        'inspect-declaration': ['{}'], 'admit': ['{}'], 'export-declaration': ['{}'],
        'status': ['r1'], 'control': ['r1', 'stop'], 'observe': ['r1', '--after', '2'],
        'record-refs': ['r1'], 'records': ['r1'], 'inspect-resume': ['retained.bfr'],
        'resume-run': ['{}'], 'export-case': ['retained.bfr', 'case-1'],
        'saved-case': ['{}', '--no-recv'], 'saved-intent': ['{}'],
        'service': ['monitoring', '{}'],
    }[command]
    parser = command_parser(command)
    assert vars(parser.parse_args(tokens[1:])) == vars(parser.parse_args(cli_only))
    matching, _ = selected(tmp_path, '[run]\ncommand ' + command + '\n' + positionals + options,
                           [command])
    assert matching == tokens


def test_schema_rejects_directory_while_inspect_keeps_it(tmp_path, capsys):
    assert '--directory' not in command_parser('schema').format_help()
    assert '--directory' in command_parser('inspect').format_help()
    absent = tmp_path / 'absent'
    with pytest.raises(SystemExit) as refused:
        cli.main(['schema', '--directory', str(absent)])
    assert refused.value.code == 2
    output = capsys.readouterr()
    assert output.out == ''
    assert 'unrecognized arguments: --directory' in output.err
    assert str(absent) in output.err
    with pytest.raises(ConfigError, match="option 'directory' is not available for schema"):
        selected(tmp_path, '[run]\ncommand schema\n[generic]\ndirectory any-root\n')


@pytest.mark.parametrize(('cluster', 'verbose'), [
    ('-vlcli.log', 1), ('-vvlcli.log', 2), ('-vl=cli.log', 1)])
def test_mixed_short_cluster_reports_every_consumed_option(tmp_path, cluster, verbose):
    parser = command_parser('configure')
    direct = parser.parse_args(['offline.invalid', cluster])
    assert direct.verbose == verbose and direct.log_file == 'cli.log'
    with pytest.raises(ConfigError) as error:
        selected(tmp_path, '[output]\nlog-file from-file.log\n',
                 ['configure', 'offline.invalid', cluster])
    message = str(error.value)
    assert "arbitrary name.cfg:3 log-file='from-file.log'" in message
    assert "CLI -l='cli.log'" in message
    # A value-taking short consumes the remainder; -lv does not select verbose.
    tokens, _ = selected(tmp_path, '[fuzz]\nverbose 1\n',
                         ['configure', 'offline.invalid', '-lv'])
    parsed = parser.parse_args(tokens[1:])
    assert parsed.verbose == 1 and parsed.log_file == 'v'


def test_dash_leading_file_positionals_and_literal_cli_boundary(tmp_path):
    from types import SimpleNamespace
    path = tmp_path / 'leading.cfg'
    path.write_text('format-version 1\n[run]\ncommand inspect-resume\n'
        'path --selected-case.bfr\n', encoding='utf-8')
    assert cli.execute_arguments(['--config', str(path)],
        SimpleNamespace(inspect_resume=lambda selected_path: selected_path)) == '--selected-case.bfr'
    path.write_text('format-version 1\n[run]\ncommand maintenance\nhost -host\n'
        '[maintenance]\nlocal-only true\n', encoding='utf-8')
    request = cli.resolve_arguments(['--config', str(path)])
    assert request.host == '-host' and request.local and not request.remote
    path.write_text('format-version 1\n[run]\ncommand replay\nprotocol raw\n'
        'host -host\npacket 41\n[replay]\nport 1234\nprepare true\n', encoding='utf-8')
    replay = cli.resolve_arguments(['--config', str(path)])
    assert replay.request.transport.host == '-host'
    assert replay.options['port'] == 1234
    path.write_text('format-version 1\n[run]\ncommand configure\nhost -host\n'
        '[fuzz]\nport 1234\nseed-hex 41\n', encoding='utf-8')
    configured = cli.resolve_arguments(['--config', str(path)])
    assert configured.request.transport.host == '-host'
    assert configured.options['port'] == 1234
    # CLI owns the complete positional group; file options stay before its --.
    path.write_text('format-version 1\n[fuzz]\nport 1234\nseed-hex 41\n', encoding='utf-8')
    mixed = cli.resolve_arguments(['configure', '--config', str(path), '--', '-host'])
    assert mixed.request.transport.host == '-host' and mixed.options['port'] == 1234
    assert expand(['inspect-resume', '--', '--config'], commands=COMMANDS) == [
        'inspect-resume', '--', '--config']
    assert cli.execute_arguments(['inspect-resume', '--', '--help'],
        SimpleNamespace(inspect_resume=lambda selected_path: selected_path)) == '--help'


def test_root_fuzz_and_replay_keep_file_positional_boundary_with_options(tmp_path):
    path = tmp_path / 'leading.cfg'
    path.write_text('format-version 1\n[run]\ncommand fuzz\nprotocol raw\n'
        'host -host\n[fuzz]\nport 1234\nseed-hex 41\n', encoding='utf-8')
    expanded, inputs, boundary = expand(['--config', str(path)], commands=COMMANDS,
        with_inputs=True)
    assert inputs == (str(path.resolve()),) and boundary
    forwarded, replay = cli._arguments(expanded, file_boundary=boundary)
    assert not replay and forwarded[0] == 'submit'
    selected = command_parser('fuzz').parse_args(forwarded[1:])
    assert selected.host == '-host' and selected.port == 1234 and selected.seed_hex == '41'

    path.write_text('format-version 1\n[run]\ncommand replay\nprotocol raw\n'
        'host -host\npacket -ff\n[replay]\nport 1234\nprepare true\n', encoding='utf-8')
    expanded, _, boundary = expand(['--config', str(path)], commands=COMMANDS,
        with_inputs=True)
    forwarded, replay = cli._arguments(expanded, file_boundary=boundary)
    assert replay and forwarded.index('--protocol') < forwarded.index('--')
    from bytefault.replay.replay_packet import build_parser as replay_parser
    selected = replay_parser(root=True).parse_args(forwarded[1:])
    assert selected.host == '-host' and selected.packets == ['-ff']
    assert selected.port == 1234 and selected.prepare
    # The public route reaches packet validation instead of losing a packet
    # or the injected protocol at the parser boundary.
    with pytest.raises(ValueError, match='Invalid hex string: -ff'):
        cli.resolve_arguments(['--config', str(path)])
