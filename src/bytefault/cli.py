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

"""Public source and module grammar over the shared Application dispatcher."""
import argparse
import sys
from collections.abc import Iterator
from dataclasses import replace

from bytefault.fuzzers import cli as application_cli


class _OwnedIterator:
    """Keep an implicit resolver Application alive for its lazy result."""

    def __init__(self, value, application):
        self._value = value
        self._application = application
        self._closed = False
        self.application_cleanup_errors = ()

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._value)
        except StopIteration:
            self.close()
            raise
        except BaseException as error:
            self._finish(error)
            raise

    def _finish(self, primary_error=None):
        if self._closed:
            return
        self._closed = True
        close_error = None
        try:
            self._value.close()
        except BaseException as error:
            close_error = error
            if primary_error is not None:
                primary_error.add_note('Resolver preparation cleanup: ' + str(error))
        from bytefault.management.lifecycle import finish_owned_application
        self.application_cleanup_errors = finish_owned_application(
            self._application, primary_error=primary_error or close_error)
        if close_error is not None and primary_error is None:
            raise close_error

    def close(self):
        self._finish()

    @property
    def summary(self):
        summary = self._value.summary
        return _with_owned_cleanup(summary, self.application_cleanup_errors)

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        self._finish(error)

    def __getattr__(self, name):
        return getattr(self._value, name)


def _with_owned_cleanup(value, facts):
    if not facts:
        return value
    from bytefault.core.contracts import CampaignResult, ConversationResult, freeze
    if isinstance(value, (CampaignResult, ConversationResult)):
        changes = {'application_cleanup_errors': (*value.application_cleanup_errors, *facts)}
        if value.outcome == 'completed':
            changes.update(outcome='cleanup_failed',
                           execution_outcome=value.execution_outcome or value.outcome,
                           reason='resolver owner cleanup or accepted follow-up failed')
        return replace(value, **changes)
    if hasattr(value, 'get') and ('outcome' in value or 'status' in value):
        changes = {'application_cleanup_errors':
                   (*value.get('application_cleanup_errors', ()), *facts)}
        if 'outcome' in value:
            changes['execution_outcome'] = value.get('execution_outcome') or value['outcome']
            changes['outcome'] = 'cleanup_failed' if value['outcome'] == 'completed' else value['outcome']
        elif value['status'] == 'completed':
            changes.update(execution_status=value['status'], status='cleanup_failed')
        return freeze({**dict(value), **changes})
    return value


OPERATIONS = {
    'submit': 'Submit ordinary prepared input', 'configure': 'Inspect resolved fuzz configuration',
    'prepare': 'Prepare without target traffic', 'validate': 'Validate prepared input',
    'inspect': 'Inspect available application capabilities and protocols', 'schema': 'Export passive schema',
    'inspect-declaration': 'Inspect supplied passive declaration', 'admit': 'Admit passive declaration',
    'export-declaration': 'Export an admitted declaration', 'status': 'Query a retained run',
    'control': 'Control an application run', 'observe': 'Read optional run events',
    'record-refs': 'Read run record references', 'records': 'Read required run history',
    'inspect-resume': 'Inspect retained interrupted history', 'resume-run': 'Prepare or execute continuation',
    'export-case': 'Export a portable case', 'saved-case': 'Prepare or execute a saved case',
    'saved-intent': 'Alias for saved-case', 'service': 'Call an independent application owner',
}


def build_parser():
    # Each command imports its owner's parser rather than redefining shared options here.
    parser = argparse.ArgumentParser(prog='bytefault', description='One application: fuzzing, saved inputs and independent services')
    parser.add_argument('--config', metavar='PATH', help='Read optional run selections from a text config file')
    sub = parser.add_subparsers(dest='command', required=True)
    fuzz = sub.add_parser('fuzz', parents=[application_cli.build_parser()], add_help=False,
        help='Run an ordinary fuzz campaign')
    fuzz.add_argument('--config', metavar='PATH', help='Read optional run selections from a text config file')
    from bytefault.replay.replay_packet import add_arguments
    replay = add_arguments(sub.add_parser('replay', help='Run ordered literal packets'), root=True)
    replay.add_argument('--config', metavar='PATH', help='Read optional run selections from a text config file')
    from bytefault.management.maintenance import build_parser as maintenance_parser
    maintenance = sub.add_parser('maintenance', parents=[maintenance_parser()], add_help=False,
        help='Selected Management maintenance')
    maintenance.add_argument('--config', metavar='PATH', help='Read optional run selections from a text config file')
    for command, description in OPERATIONS.items():
        generic = sub.add_parser(command, parents=[application_cli.command_parser(command)],
            add_help=False, help=description)
        generic.add_argument('--config', metavar='PATH', help='Read optional run selections from a text config file')
    return parser


def _arguments(argv, *, file_boundary=False):
    args = list(argv)
    def help_requested(tokens):
        for token in tokens:
            if token == '--':
                return False
            if token in ('--help', '-h'):
                return True
        return False
    if not args or args[0] in ('--help', '-h'):
        build_parser().parse_args(args)
    command = args[0]
    if command == 'fuzz':
        if (help_requested(args[1:]) if file_boundary else
                any(value in ('--help', '-h') for value in args[1:])):
            build_parser().parse_args(args)
        forwarded = args[1:]
        if not file_boundary and '--' in forwarded[2:]:
            del forwarded[forwarded.index('--', 2)]
        return ['submit', *forwarded], False
    if command == 'replay':
        if len(args) < 3 or help_requested(args[1:]):
            build_parser().parse_args(args)
        tail = args[2:]
        protocol = ['--protocol=' + args[1]] if args[1].startswith('-') else ['--protocol', args[1]]
        if '--' in tail:
            boundary = tail.index('--')
            return ['replay', *tail[:boundary], *protocol, *tail[boundary:]], True
        return ['replay', *tail, *protocol], True
    if command in (*OPERATIONS, 'maintenance') and help_requested(args[1:]):
        build_parser().parse_args(args)
    if command not in (*OPERATIONS, 'maintenance'):
        build_parser().error('unknown command: ' + command)
    return args, False


def execute_arguments(argv, application, *, terminal=False):
    from bytefault.config_file import expand
    expanded, inputs, file_boundary = expand(argv,
        commands=(*OPERATIONS, 'fuzz', 'replay', 'maintenance'), with_inputs=True)
    forwarded, replay = _arguments(expanded, file_boundary=file_boundary)
    return application_cli.execute_arguments(forwarded, application, original_argv=tuple(argv),
        terminal=terminal, replay_root=replay, input_files=inputs)


def resolve_arguments(argv, application=None):
    """Retain root replay preparation and the established callable dispatcher."""
    from bytefault.config_file import expand
    physical = tuple(argv)
    argv, inputs, file_boundary = expand(argv,
        commands=(*OPERATIONS, 'fuzz', 'replay', 'maintenance'), with_inputs=True)
    if argv and argv[0] == 'maintenance':
        from bytefault.management.maintenance import resolve_arguments as prepare_maintenance
        selected = bool(inputs)
        return prepare_maintenance(argv[1:], original_argv=physical if selected else None,
                                   input_files=inputs)
    if argv and argv[0] == 'replay':
        forwarded, _ = _arguments(argv, file_boundary=file_boundary)
        from bytefault.replay.replay_packet import resolve_arguments as prepare_replay
        return prepare_replay(forwarded[1:], application, original_argv=physical, root=True,
                              input_files=inputs)
    forwarded, replay = _arguments(argv, file_boundary=file_boundary)
    if application is not None:
        return application_cli.execute_arguments(forwarded, application,
            original_argv=physical, replay_root=replay, input_files=inputs)
    from bytefault.management.lifecycle import finish_owned_application
    owned = application_cli.Application()
    try:
        value = application_cli.execute_arguments(forwarded, owned,
            original_argv=physical, replay_root=replay, input_files=inputs)
    except BaseException as error:
        finish_owned_application(owned, primary_error=error)
        raise
    if isinstance(value, Iterator):
        return _OwnedIterator(value, owned)
    return _with_owned_cleanup(value, finish_owned_application(owned))


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    from bytefault.config_file import ConfigError, expand
    try:
        expanded, inputs, file_boundary = expand(args,
            commands=(*OPERATIONS, 'fuzz', 'replay', 'maintenance'), with_inputs=True)
        forwarded, replay = _arguments(expanded, file_boundary=file_boundary)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return application_cli.main(forwarded, original_argv=tuple(args), replay_root=replay,
                                input_files=inputs)
