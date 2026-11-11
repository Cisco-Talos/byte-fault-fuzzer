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

"""Opt-in text selections for the public Raw command grammar."""

import argparse
from dataclasses import dataclass, replace
from pathlib import Path


FUZZ_COMMANDS = frozenset(('fuzz', 'submit', 'configure', 'prepare', 'validate'))
PREPARED_COMMANDS = frozenset(('resume-run', 'saved-case', 'saved-intent'))
COLLECTION_KEYS = frozenset(('collect-cores', 'ssh-key', 'ssh-user', 'ssh-pass',
    'core-dir', 'core-cache', 'core-max-size', 'core-timeout', 'core-dump-wait'))
OUTPUT_KEYS = frozenset(('records', 'results', 'log-file', 'ui', 'tui', 'no-ui',
    'verbose', 'debug', 'hide-field', 'no-test-banner'))
TIMING_KEYS = frozenset(('timeout', 'connection-delay', 'tcp-pre-delay',
    'tcp-post-delay', 'tcp-spacing', 'heartbeat', 'heartbeat-interval'))
SEMANTIC_GROUPS = {'tcp-spacing': 'tcp_pre_delay',
    'non-persistent': 'persistent'}
# Existing resolver exclusions that can be decided from explicit selections.
# Value-dependent combinations remain with their owning resolver.
GENERATION_SOURCE_ONLY = ('mutate-count', 'mutate-raw', 'mutate-max-len',
    'mutate-rng-seed', 'mutate-seed-format', 'mutate-scope', 'random-iter',
    'random-seed', 'random-length-scope', 'random-content-scope',
    'random-range-scope', 'random-byte-range', 'random-range-choices',
    'prefix', 'offset', 'offset-range', 'offset-scope', 'offset-seed',
    'fuzz-length', 'mask', 'mask2', 'exclude', 'exclude2', 'start', 'start2',
    'field-same', 'target2')
INLINE_SCOPE_CONFLICTS = ('random-length-scope', 'random-content-scope',
    'random-range-scope', 'random-byte-range', 'random-range-choices',
    'offset-range', 'offset-scope', 'offset-seed', 'mutate-scope')
CROSS_CONFLICTS = (('ssh-key', 'ssh-pass'), ('local-only', 'remote-only'),
    ('seed-hex', 'request-json'), ('gen-field', 'target'),
    ('gen-field', 'mutate-seed'), ('gen-field', 'mutate-seed-file'),
    ('gen-field', 'mutate-seed-dir'), ('gen-field', 'random-len'),
    ('mutate-seed', 'random-len'), ('mutate-seed-file', 'random-len'),
    ('mutate-seed-dir', 'random-len')) + tuple(
    ('campaign-json', other) for other in ('request-json', 'generation-json',
        'seed-hex', 'gen-field', 'target', 'random-len', 'mutate-seed',
        'mutate-seed-file', 'mutate-seed-dir')) + tuple(
    ('generation-json', other) for other in ('gen-field', 'target',
        'random-len', 'mutate-seed', 'mutate-seed-file', 'mutate-seed-dir',
        *GENERATION_SOURCE_ONLY)) + tuple(
    ('gen-field', other) for other in INLINE_SCOPE_CONFLICTS) + tuple(
    ('target2', other) for other in ('random-len', 'mutate-seed',
        'mutate-seed-file', 'mutate-seed-dir'))


class ConfigError(ValueError):
    """A file selection or source merge failed before application execution."""


@dataclass(frozen=True)
class Entry:
    key: str
    value: str
    section: str
    line: int


def attach_inputs(request, input_files):
    """Keep selected run files in the ordinary consumed-input request value."""
    if request is None or not input_files:
        return request
    conversation = request.conversation
    files = tuple(dict.fromkeys((*conversation.input_files, *input_files)))
    return replace(request, conversation=replace(conversation, input_files=files))


def command_parser(command):
    """Use each existing runtime parser, never a second option declaration."""
    if command in FUZZ_COMMANDS:
        from bytefault.fuzzers.cli import build_parser
        return build_parser()
    if command == 'replay':
        from bytefault.replay.replay_packet import add_arguments
        return add_arguments(argparse.ArgumentParser(prog='bytefault replay'), root=True)
    if command == 'maintenance':
        from bytefault.management.maintenance import build_parser
        return build_parser()
    from bytefault.fuzzers.cli import command_parser as generic_parser
    return generic_parser(command)


def _error(path, line, message):
    raise ConfigError(f'{path}:{line}: {message}')


def _value(raw, path, line):
    """Remove comments and one optional whole-value quote; keep backslashes."""
    raw = raw.strip()
    if not raw:
        _error(path, line, 'missing value')
    if raw[0] in ('\"', "'"):
        mark = raw[0]
        result = []
        index = 1
        while index < len(raw):
            char = raw[index]
            if char == mark:
                if index + 1 < len(raw) and raw[index + 1] == mark:
                    result.append(mark)
                    index += 2
                    continue
                rest = raw[index + 1:].strip()
                if rest and not rest.startswith('#'):
                    _error(path, line, 'unexpected text after quoted value')
                return ''.join(result)
            result.append(char)
            index += 1
        _error(path, line, 'unmatched quote in value')
    quote = None
    result = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char in ('\"', "'") and (not quote or char == quote):
            # In an unquoted JSON/text value, preserve a backslash-escaped
            # quote as data while scanning for a trailing comment.
            prior = len(result) - 1
            slashes = 0
            while prior >= 0 and result[prior] == '\\':
                slashes += 1
                prior -= 1
            if slashes % 2 == 0:
                quote = None if quote else char
        if char == '#' and quote is None:
            break
        result.append(char)
        index += 1
    if quote:
        _error(path, line, 'unmatched quote in value')
    value = ''.join(result).strip()
    if not value:
        _error(path, line, 'missing value')
    return value


def read_file(path):
    location = Path(path)
    try:
        lines = location.read_text(encoding='utf-8').splitlines()
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f'{location}: {exc}') from exc
    entries = []
    section = None
    version = None
    for number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('['):
            heading = stripped.split('#', 1)[0].strip()
            if not heading.endswith(']') or heading.count('[') != 1:
                _error(location, number, 'malformed section heading')
            section = heading[1:-1]
            if section not in ('run', 'fuzz', 'replay', 'maintenance', 'prepared',
                    'generic', 'collection', 'output', 'timing', 'options'):
                _error(location, number, f'unknown section [{section}]')
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            _error(location, number, 'expected key and value separated by whitespace')
        key = parts[0]
        if key == 'format-version':
            if section is not None or version is not None or _value(parts[1], location, number) != '1':
                _error(location, number, 'expected one format-version 1 before sections')
            version = number
            continue
        if version is None:
            _error(location, number, 'format-version 1 required before selections')
        if section is None:
            _error(location, number, 'selection must be in a section')
        if key.startswith('-'):
            _error(location, number, 'use canonical long-option keys without --')
        entries.append(Entry(key, _value(parts[1], location, number), section, number))
    if version is None:
        _error(location, 1, 'format-version 1 required')
    return entries


def _canonical(action):
    return next((name[2:] for name in action.option_strings if name.startswith('--')), None)


def _group(action):
    key = _canonical(action) or action.dest
    return SEMANTIC_GROUPS.get(key, action.dest)


def _section_accepts(section, command, key):
    if section == 'options':
        return True
    if section == 'fuzz':
        return command in FUZZ_COMMANDS
    if section == 'replay':
        return command == 'replay'
    if section == 'maintenance':
        return command == 'maintenance'
    if section == 'prepared':
        return command in PREPARED_COMMANDS
    if section == 'generic':
        return command not in FUZZ_COMMANDS | PREPARED_COMMANDS | {'replay', 'maintenance'}
    return key in {'collection': COLLECTION_KEYS, 'output': OUTPUT_KEYS,
                   'timing': TIMING_KEYS}[section]


def _cli_options(parser, tokens):
    """Recover actual CLI spellings while respecting argparse option forms."""
    found = []
    positionals = []
    index = 0
    after_boundary = False
    while index < len(tokens):
        token = tokens[index]
        if token == '--' and not after_boundary:
            after_boundary = True
            index += 1
            continue
        optional = None if after_boundary else parser._parse_optional(token)
        if optional is None:
            positionals.append(token)
            index += 1
            continue
        # argparse returns a list of four-part candidates on supported Python
        # runtimes; some older releases returned one three-part candidate.
        if isinstance(optional, list):
            if len(optional) != 1:
                parser.error(f'ambiguous option: {token}')
            candidate = optional[0]
        else:
            candidate = optional
        if len(candidate) == 4:
            action, spelling, separator, attached = candidate
        else:
            action, spelling, attached = candidate
        typed = token.partition('=')[0] if token.startswith('--') else token
        if action is None:
            # The authoritative parser will produce its ordinary unknown-option error.
            index += 1
            continue
        if action.nargs == 0:
            found.append((action, spelling, token))
            if attached and spelling.startswith('-') and not spelling.startswith('--'):
                # Match argparse's short cluster: zero-argument actions consume
                # one letter; the first value-taking action consumes the tail.
                rest = attached
                while rest:
                    short = '-' + rest[0]
                    clustered = parser._option_string_actions.get(short)
                    if clustered is None:
                        break  # The real parser reports the unknown short option.
                    rest = rest[1:]
                    if clustered.nargs == 0:
                        found.append((clustered, short, token))
                        continue
                    if rest.startswith('='):
                        rest = rest[1:]
                    if rest:
                        found.append((clustered, short, rest))
                    elif index + 1 < len(tokens):
                        found.append((clustered, short, tokens[index + 1]))
                        index += 1
                    else:
                        found.append((clustered, short, '<missing>'))
                    break
        elif attached is not None:
            found.append((action, typed, attached))
        elif index + 1 < len(tokens):
            found.append((action, typed, tokens[index + 1]))
            index += 1
        else:
            found.append((action, typed, '<missing>'))
        index += 1
    return found, positionals


def _file_tokens(action, value, path, line):
    key = _canonical(action)
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
        if value.lower() not in ('true', 'false'):
            _error(path, line, f'{key} expects true or false, got {value!r}')
        selected = value.lower() == 'true'
        if not selected:
            if key == 'persistent':
                return ['--non-persistent']
            if key == 'non-persistent':
                return ['--persistent']
            inverse = next((name for name in ('--no-' + key, '--' + key.removeprefix('no-'))
                if name in action.container._option_string_actions and
                action.container._option_string_actions[name].dest == action.dest and name != '--' + key), None)
            return [inverse] if inverse else []
        return ['--' + key]
    if isinstance(action, argparse._CountAction):
        try:
            count = int(value)
        except ValueError as exc:
            _error(path, line, f'{key} expects a nonnegative integer, got {value!r}')
        if count < 0:
            _error(path, line, f'{key} expects a nonnegative integer, got {value!r}')
        return ['--' + key] * count
    return ['--' + key + '=' + value] if value.startswith('-') else ['--' + key, value]


def _positionals(command, entries, path):
    values = [entry for entry in entries if entry.section == 'run' and entry.key != 'command']
    if not values:
        return []
    if command in FUZZ_COMMANDS:
        allowed = {'protocol', 'host'}
        protocol = [entry for entry in values if entry.key == 'protocol']
        host = [entry for entry in values if entry.key == 'host']
        if len(protocol) > 1 or len(host) > 1 or (protocol and not host):
            _error(path, values[0].line, 'fuzz positionals require host and at most one protocol')
        result = [entry.value for entry in protocol + host]
    elif command == 'replay':
        allowed = {'protocol', 'host', 'packet'}
        protocol = [entry for entry in values if entry.key == 'protocol']
        host = [entry for entry in values if entry.key == 'host']
        packets = [entry for entry in values if entry.key == 'packet']
        if len(protocol) != 1 or len(host) != 1 or not packets:
            _error(path, values[0].line, 'replay requires protocol, host and ordered packet lines')
        result = [protocol[0].value, host[0].value, *(entry.value for entry in packets)]
    else:
        parser = command_parser(command)
        positional_actions = [action for action in parser._actions if not action.option_strings]
        ordered = [action.dest for action in positional_actions]
        allowed = set(ordered)
        grouped = {name: [entry for entry in values if entry.key == name.replace('_', '-')]
                   for name in ordered}
        if any(len(group) > 1 for group in grouped.values()):
            _error(path, values[0].line, 'positional value repeated')
        missing = [action.dest for action in positional_actions if action.nargs not in ('?', '*')
                   and not grouped[action.dest]]
        if missing:
            _error(path, values[0].line, f'{command} positional group is missing {missing!r}')
        result = [group[0].value for name in ordered if (group := grouped[name])]
        allowed = {name.replace('_', '-') for name in allowed}
    for entry in values:
        if entry.key not in allowed:
            _error(path, entry.line, f'{entry.key} is not a positional for {command}: {entry.value!r}')
    return result


def expand(argv, *, commands, with_inputs=False):
    """Merge one selected file with physical root argv before command dispatch."""
    def finish(tokens, inputs=(), file_boundary=False):
        return (tokens, inputs, file_boundary) if with_inputs else tokens

    physical = list(argv)
    selected = []
    cli = []
    index = 0
    after_boundary = False
    while index < len(physical):
        token = physical[index]
        if token == '--':
            cli.append(token)
            # Root fuzz's documented separator after its positional pair is
            # removed before the fuzz parser; other separators end loader flags.
            if not (cli and cli[0] == 'fuzz'):
                after_boundary = True
            index += 1
            continue
        if not after_boundary and token == '--config':
            if index + 1 == len(physical):
                raise ConfigError('--config requires a path')
            selected.append(physical[index + 1])
            index += 2
            continue
        if not after_boundary and token.startswith('--config='):
            selected.append(token.partition('=')[2])
            index += 1
            continue
        cli.append(token)
        index += 1
    if not selected:
        return finish(physical)
    help_tokens = cli[:cli.index('--')] if '--' in cli and cli[0] != 'fuzz' else cli
    if any(token in ('--help', '-h') for token in help_tokens):
        # Help is a loader control. It must work even if the selected file is
        # absent, malformed, or names a different command.
        return finish(cli)
    if len(selected) != 1 or not selected[0]:
        raise ConfigError('supply exactly one nonempty --config path')
    path = Path(selected[0])
    entries = read_file(path)
    file_commands = [entry for entry in entries if entry.section == 'run' and entry.key == 'command']
    if len(file_commands) > 1:
        _error(path, file_commands[1].line, 'command repeated')
    file_command = file_commands[0].value if file_commands else None
    cli_command = cli[0] if cli else None
    if file_command and file_command not in commands:
        _error(path, file_commands[0].line, f'unknown command {file_command!r}')
    if cli_command and cli_command not in commands:
        raise ConfigError(f'unknown CLI command {cli_command!r}')
    if file_command and cli_command and file_command != cli_command:
        _error(path, file_commands[0].line,
            f'command {file_command!r} conflicts with CLI command {cli_command!r}')
    command = cli_command or file_command
    if command is None:
        raise ConfigError(f'{path}: select command in [run] or on CLI')
    parser = command_parser(command)
    actions = {_canonical(action): action for action in parser._actions if _canonical(action)}
    cli_tail = cli[1:] if cli_command else cli
    file_pos = _positionals(command, entries, path)
    scan_tail = list(cli_tail)
    if command == 'fuzz':
        boundary = next((index for index, token in enumerate(scan_tail)
                         if token == '--' and index + len(file_pos) >= 2), None)
        if boundary is not None:
            del scan_tail[boundary]
    cli_found, cli_pos = _cli_options(parser, scan_tail)
    cli_by_group = {}
    for action, spelling, value in cli_found:
        cli_by_group.setdefault(_group(action), []).append((spelling, value))
    if file_pos and cli_pos:
        lines = ','.join(str(entry.line) for entry in entries
                         if entry.section == 'run' and entry.key != 'command')
        raise ConfigError(f'{path}:lines {lines}: positional group {file_pos!r} '
                          f'conflicts with CLI positionals {cli_pos!r}')
    file_options = []
    seen = {}
    file_by_group = {}
    for entry in entries:
        if entry.section == 'run':
            continue
        action = actions.get(entry.key)
        if action is None or entry.key in ('help', 'config'):
            _error(path, entry.line, f'option {entry.key!r} is not available for {command}: {entry.value!r}')
        if not _section_accepts(entry.section, command, entry.key):
            _error(path, entry.line, f'option {entry.key!r} is not applicable in [{entry.section}] for {command}: {entry.value!r}')
        group = _group(action)
        if group in seen and not isinstance(action, (argparse._AppendAction, argparse._CountAction)):
            other = seen[group]
            _error(path, entry.line,
                f'{entry.key}={entry.value!r} conflicts with file line {other.line} {other.key}={other.value!r}')
        seen[group] = entry
        file_by_group.setdefault(group, []).append(entry)
        file_options.extend(_file_tokens(action, entry.value, path, entry.line))
    for group, file_entries in file_by_group.items():
        if group in cli_by_group:
            file_values = ', '.join(f'{path}:{entry.line} {entry.key}={entry.value!r}'
                                    for entry in file_entries)
            cli_values = ', '.join(f'CLI {spelling}={value!r}'
                                   for spelling, value in cli_by_group[group])
            raise ConfigError(f'{group} conflict: {file_values}; {cli_values}')
    for left, right in CROSS_CONFLICTS:
        left_action, right_action = actions.get(left), actions.get(right)
        if left_action and right_action:
            a = seen.get(_group(left_action)) or (cli_by_group.get(_group(left_action)) or [None])[0]
            b = seen.get(_group(right_action)) or (cli_by_group.get(_group(right_action)) or [None])[0]
            if isinstance(a, Entry) and isinstance(left_action,
                    (argparse._StoreTrueAction, argparse._StoreFalseAction)) and a.value.lower() == 'false':
                a = None
            if isinstance(b, Entry) and isinstance(right_action,
                    (argparse._StoreTrueAction, argparse._StoreFalseAction)) and b.value.lower() == 'false':
                b = None
            for name, item in ((left, a), (right, b)):
                if name in ('target', 'target2') and item is not None and (
                        item.value if isinstance(item, Entry) else item[1]) == '':
                    if name == left:
                        a = None
                    else:
                        b = None
            if a and b and (isinstance(a, Entry) or isinstance(b, Entry)):
                def describe(item):
                    return f'{path}:{item.line} {item.key}={item.value!r}' if isinstance(item, Entry) else f'CLI {item[0]}={item[1]!r}'
                raise ConfigError(f'{left}/{right} conflict: {describe(a)}; {describe(b)}')
    if not file_pos and '--' in cli_tail and file_options:
        boundary = cli_tail.index('--')
        fuzz_separator = (command == 'fuzz' and boundary >= 2 and
            all(not value.startswith('-') for value in cli_tail[:2]))
        if not fuzz_separator:
            cli_tail = [*cli_tail[:boundary], *file_options, *cli_tail[boundary:]]
            file_options = []
    if file_pos and any(value.startswith('-') for value in file_pos):
        if cli_tail and cli_tail[-1] == '--':
            cli_tail = cli_tail[:-1]
        if command == 'replay':
            tokens = [command, file_pos[0], *cli_tail, *file_options, '--', *file_pos[1:]]
        else:
            tokens = [command, *cli_tail, *file_options, '--', *file_pos]
        return finish(tokens, (str(path.resolve()),), True)
    return finish([command, *(file_pos if file_pos else ()), *cli_tail, *file_options],
                  (str(path.resolve()),))
