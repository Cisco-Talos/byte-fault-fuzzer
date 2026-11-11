#!/usr/bin/env python3
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

"""
Literal/list argument and callable clients of the ordinary campaign engine.

Usage:
    python src/bytefault/replay/replay_packet.py <device_ip> <packet_hex> [options]
"""
from __future__ import annotations

import sys
import argparse
import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

if __name__ == '__main__' and not __package__:
    # Retained source-script entry, independent of later installed launchers.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logger = logging.getLogger(__name__)

def parse_packet_hex(hex_string: str) -> bytes:
    """
    Parse hex string to bytes, handling various formats.
    
    Args:
        hex_string: Hex string (with or without spaces, 0x prefix, etc.)
        
    Returns:
        Packet bytes
        
    Examples:
        "0006082a10000000" -> b'\x00\x06\x08*\x10\x00\x00\x00'
        "00 06 08 2a 10 00 00 00" -> same
        "0x00 0x06 0x08 0x2a..." -> same
    """
    # Remove common separators and prefixes
    cleaned = hex_string.replace(" ", "").replace("0x", "").replace("\\x", "")
    
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {hex_string}") from e


def parse_value_literal(value: str):
    """Parse a value literal like 0x1f or decimal; fall back to raw string."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if value.startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return value
    try:
        return int(value, 10)
    except ValueError:
        return value


def read_packets_from_file(filepath: str) -> list[bytes]:
    """
    Read packet hex strings from file (one per line).
    
    Lines starting with # are ignored as comments.
    Empty lines are ignored.
    
    Args:
        filepath: Path to file containing hex strings
        
    Returns:
        List of packet bytes
    """
    packets = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            try:
                packet = parse_packet_hex(line)
                packets.append(packet)
            except ValueError as e:
                logger.warning(f"{filepath}:{line_num}: skipping invalid hex line: {e}")
    
    return packets


def add_arguments(parser, *, root=False):
    if root:
        parser.add_argument('protocol', help='Passive protocol directory selection')
    else:
        parser.add_argument('--protocol', default='raw', help='Passive protocol directory selection')
    parser.add_argument("host", help="Device IP address")
    parser.add_argument(
        "packets",
        nargs="+",
        help="Packet hex strings or @filename to read from file",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None if root else 1234,
        help=("TCP port; root Raw replay requires --port because Raw declares none"
              if root else "TCP port; direct replay module defaults to 1234"),
    )
    parser.add_argument("--wait", type=float, default=0.0,
        help="Pre-connection delay in seconds, including enabled service-check and recovery connections")
    parser.add_argument("--connection-delay", type=float, default=0.0,
        help="Additional wait after each connection closes and before the next connection's pre-delay")
    parser.add_argument(
        "--recovery-wait",
        type=float,
        default=5.0,
        help="Seconds between recovery checks after a crash (default: 5.0)",
    )
    parser.add_argument(
        "--recovery-attempts",
        type=int,
        default=10,
        help="Recovery attempts after a crash (default: 10)",
    )
    parser.add_argument(
        "--core-dump-wait",
        type=float,
        default=5.0,
        help="Seconds to wait before selected core acquisition (default: 5.0)",
    )
    parser.add_argument("--ssh-key", "-k", help="SSH key for explicitly selected core collection")
    parser.add_argument('--ssh-pass', help='Cleartext SSH password for selected core collection; requires --ssh-user')
    parser.add_argument('--collect-cores', action='store_true',
        help='Collect cores after a failed campaign service check; requires SSH credentials')
    parser.add_argument(
        "--enable-crash-handling",
        action="store_true",
        help="Enable recovery retries after service observations; ordinary service checks run by default",
    )
    parser.add_argument('--health-check-mode', choices=('new_connection', 'disabled'),
        help='Campaign service checks; defaults to new_connection')
    parser.add_argument("--no-recv", action="store_true", help="Send without reading responses")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity (repeatable)")
    parser.add_argument("--offset", type=int, help="Crash metadata: byte offset (no effect on send)")
    parser.add_argument("--fuzz-length", type=int, help="Crash metadata: length of fuzzed bytes")
    parser.add_argument("--value", help="Crash metadata: value (hex like 0x1f or decimal)")
    parser.add_argument("--fuzz-target", help="Crash metadata: fuzz target label")
    parser.add_argument('--prepare', action='store_true', help='Prepare the literal campaign without executing')
    parser.add_argument('--records', help='Required campaign journal destination')
    parser.add_argument('--results', help='Exact result bin path, including an existing bin; default is YYYYMMDD_HHMMSS_<protocol>')
    parser.add_argument('--log-file', '-l', help='Required action log destination')
    parser.add_argument('--timeout', type=float, default=3.0)
    parser.add_argument('--receive-cap', type=int, help='Override the declared receive cap')
    parser.add_argument('--receive-deadline', type=float, help='Override the declared receive deadline')
    parser.add_argument('--declaration-dir')
    parser.add_argument('--ssh-user')
    parser.add_argument('--core-dir', default='/root/cores')
    parser.add_argument('--core-cache')
    parser.add_argument('--core-max-size', type=int, default=0,
        help='Per-file collection cap in MiB; 0 means unlimited')
    parser.add_argument('--core-timeout', type=int, default=30,
        help='Rsync stalled-I/O timeout in seconds; 0 disables it, not a total transfer deadline')
    parser.add_argument('--heartbeat', action='store_true')
    parser.add_argument('--heartbeat-interval', type=float, default=2.0)
    parser.add_argument('--ui', '--tui', action='store_true')
    parser.add_argument('--no-ui', action='store_true')
    parser.add_argument('--debug', action='store_true')
    return parser


def build_parser(*, root=False):
    from bytefault.fuzzers.cli import _IntentArgumentParser
    parser = add_arguments(_IntentArgumentParser(description='Replay literal TCP packets'))
    if root:
        parser.set_defaults(port=None)
    return parser


@dataclass(frozen=True)
class ReplayConfiguration:
    original_argv: tuple
    options: object
    resolved: object
    request: object = None
    pending: tuple = ()
    status: str = 'available'


def _expand(values):
    """Keep file expansion at its argument position, retaining every diagnostic."""
    items, diagnostics, inputs = [], [], []
    for index, value in enumerate(values):
        if isinstance(value, bytes):
            items.append({'data': value, 'argument_index': index, 'source': 'literal'})
            continue
        if not value.startswith('@'):
            items.append({'data': parse_packet_hex(value), 'argument_index': index, 'source': 'literal'})
            continue
        path = str(Path(value[1:]).resolve())
        inputs.append({'path': path, 'encoding': 'hex_lines'})
        with open(path, encoding='utf-8') as stream:
            for line_number, text in enumerate(stream, 1):
                text = text.strip()
                if not text or text.startswith('#'):
                    continue
                try:
                    data = parse_packet_hex(text)
                except ValueError as exc:
                    diagnostic = {'path': path, 'line': line_number, 'text': text, 'error': str(exc)}
                    diagnostics.append(diagnostic)
                    logger.warning('%s:%s: skipping invalid hex line: %s', path, line_number, exc)
                else:
                    items.append({'data': data, 'argument_index': index, 'source': path, 'line': line_number})
    if not items:
        from bytefault.core.contracts import ContractError
        raise ContractError('replay.packets', 'empty', 'no valid packet literals; ' + repr(diagnostics))
    return items, diagnostics, inputs


def _configuration(application, options, values, *, original_argv=(), explicit_options=(),
                   pending=(), metadata=None, command_line=False):
    from bytefault.application import CampaignRequest
    from bytefault.core.contracts import (freeze, PreparedRow, PreparedContribution,
        SourceInvocation, Placement)
    from bytefault.monitoring.configuration import MonitoringConfig
    from bytefault.core.contracts import ContractError
    if options.get('ssh_pass') is not None and 'ssh_user' not in explicit_options:
        raise ContractError('replay.ssh_user', 'required', '--ssh-pass requires explicit --ssh-user')
    if options.get('ssh_pass') is not None and options.get('ssh_key') is not None:
        raise ContractError('replay.ssh_pass', 'conflicting_input', '--ssh-key and --ssh-pass conflict')
    log_path = options.get('log_file')
    if command_line:
        from bytefault.core.logging_utils import resolve_log_path
        from bytefault.paths import artifacts_root
        log_path = resolve_log_path(log_path, artifacts_root())
    items, diagnostics, inputs = _expand(values)
    intent = {'original_argv': tuple(original_argv), 'options': options, 'items': items,
              'diagnostics': diagnostics, 'source_inputs': inputs, 'metadata': metadata or {},
              'timing': {'wait': 'one transport pre_delay per packet connection'}}
    resolved = freeze({'packets': tuple(item['data'] for item in items), 'items': items,
        'diagnostics': diagnostics, 'source_inputs': inputs, 'value': parse_value_literal(options.get('value')),
        'explicit_options': tuple(explicit_options)})
    if not pending:
        from bytefault.core.contracts import ContractError
        try:
            resolution = application.resolve_protocol(options.get('protocol') or 'raw', options.get('declaration_dir'))
        except ContractError as exc:
            pending = ({'path': 'replay.protocol', 'owner': 'Protocol', 'reason': str(exc)},)
    if pending:
        return ReplayConfiguration(tuple(original_argv), freeze(options), resolved,
                                   pending=freeze(pending), status='pending')
    receive = resolution.entry.plan.actions[0].receive
    overrides = {key: options[option] for key, option in (('cap', 'receive_cap'), ('deadline', 'receive_deadline'))
                 if options.get(option) is not None}
    if options['no_recv']:
        overrides['requested'] = False
    base = application.protocol_request(options.get('protocol') or 'raw', options['host'],
        directory=options.get('declaration_dir'), seed=b'', port=options['port'],
        timeout=options['timeout'], pre_delay=options['wait'], post_delay=options.get('post_delay', 0),
        connection_delay=options.get('connection_delay', 0),
        receive=replace(receive, **overrides),
        record_path=options.get('records'), log_path=log_path, original_request={'replay': intent})
    action = base.conversation.plan.actions[0]
    cases = tuple(replace(base.conversation, case_id='case-' + str(i), conversation_id='conversation-' + str(i),
        input_files=tuple(item['path'] for item in inputs),
        row=PreparedRow('row-' + str(i), i, (PreparedContribution('packet', item['data'],
            SourceInvocation('packet', 'literal', options={'data': item['data']},
                             input_reference=item['source'] if 'line' in item else None)),),
            final_overrides=(Placement('packet', 'packet', action.action_id, 'replace', 0, len(action.seed)),)))
        for i, item in enumerate(items, 1))
    policy = None
    if application.monitoring is None:
        if options.get('enable_crash_handling'):
            delays = (options['recovery_wait'],) * options['recovery_attempts']
            policy = MonitoringConfig(recovery_delays=delays, recovery_budget=sum(delays),
                health_check_mode=options.get('health_check_mode') or 'new_connection',
                collect_cores=bool(options.get('collect_cores')))
        else:
            policy = MonitoringConfig(health_check_mode=options.get('health_check_mode') or 'new_connection',
                collect_cores=bool(options.get('collect_cores')), retry_rules=(), retries=0,
                reconnect_attempts=0, crash_throttle=0, delayed_check=0)
    elif set(explicit_options) & {'recovery_wait', 'recovery_attempts', 'health_check_mode', 'collect_cores'}:
        # Preserve caller ports/rules; a selected different retry policy cannot be silently ignored.
        from bytefault.core.contracts import ContractError
        config = getattr(getattr(application.monitoring, 'policy', None), 'configuration', None)
        if (config is None or
                ('recovery_wait' in explicit_options and any(delay != options['recovery_wait'] for delay in config.recovery_delays)) or
                ('recovery_attempts' in explicit_options and len(config.recovery_delays) != options['recovery_attempts']) or
                ('health_check_mode' in explicit_options and config.health_check_mode != options['health_check_mode']) or
                ('collect_cores' in explicit_options and config.collect_cores != options['collect_cores'])):
            raise ContractError('replay.monitoring', 'conflict', 'explicit recovery settings differ from caller Monitoring')
    request = CampaignRequest(cases[0], base.transport, base.record_path, base.log_path,
                              cases=cases, monitoring_configuration=policy)
    return ReplayConfiguration(tuple(original_argv), freeze(options), resolved, request)


def resolve_arguments(argv, application=None, *, original_argv=None, root=False, input_files=()):
    from bytefault.application import Application
    parser = build_parser(root=root)
    args = parser.parse_args(argv)
    if application is not None:
        resolved = _configuration(application, vars(args), args.packets,
            original_argv=argv if original_argv is None else original_argv,
            explicit_options=parser.explicit_destinations, command_line=True)
        from bytefault.config_file import attach_inputs
        return replace(resolved, request=attach_inputs(resolved.request, input_files))
    from bytefault.management.lifecycle import finish_owned_application
    owned = Application()
    try:
        resolved = _configuration(owned, vars(args), args.packets,
            original_argv=argv if original_argv is None else original_argv,
            explicit_options=parser.explicit_destinations, command_line=True)
        from bytefault.config_file import attach_inputs
        result = replace(resolved, request=attach_inputs(resolved.request, input_files))
    except BaseException as error:
        finish_owned_application(owned, primary_error=error)
        raise
    finish_owned_application(owned)
    return result


def execute_arguments(argv, application, *, original_argv=None, terminal=False, root=False,
                      input_files=()):
    from bytefault.fuzzers.cli import execute_prepared_request
    config = resolve_arguments(argv, application, original_argv=original_argv, root=root,
                               input_files=input_files)
    if config.pending:
        return config
    if config.options['prepare']:
        return config.request
    return execute_prepared_request(application, config.request, options={**dict(config.options),
        'argv': config.original_argv}, explicit_options=config.resolved['explicit_options'], terminal=terminal)


def replay_packets(host, port, packets,
        wait_between=0.5, tcp_spacing_s=None, tcp_pre_delay_s=None, tcp_post_delay_s=0.0,
        recovery_wait_s=None, recovery_attempts=None, core_dump_wait_s=None, ssh_key=None,
        crash_reporter=None, skip_recv=False, enable_crash_handling=False, session_factory=None,
        crash_hint=None, replay_metadata=None, protocol=None, health_check_mode=None, *,
        application=None, record_path=None, log_path=None, prepare=False,
        connection_delay_s=0.0, ssh_user=None, ssh_pass=None, collect_cores=False):
    """Prepare or submit literal cases through the ordinary Application."""
    from bytefault.application import Application
    from bytefault.core.contracts import ContractError
    from bytefault.fuzzers.cli import execute_prepared_request
    owned = application is None
    pending = []
    from bytefault.reporting import Reporting
    if crash_reporter is not None and not isinstance(crash_reporter, Reporting):
        pending.append({'path': 'replay.crash_reporter', 'owner': 'Reporting', 'reason': 'current Reporting owner required'})
    if application is not None and crash_reporter is not None and application.reporting is not crash_reporter:
        raise ContractError('replay.crash_reporter', 'conflict', 'use the Reporting owner attached to supplied Application')
    app = application or Application(reporting=crash_reporter if isinstance(crash_reporter, Reporting) else None)
    if session_factory is not None:
        pending.append({'path': 'replay.session_factory', 'owner': 'Protocol', 'reason': 'executable session attachment pending'})
    if protocol is not None and not isinstance(protocol, str):
        pending.append({'path': 'replay.protocol', 'owner': 'Protocol', 'reason': 'executable protocol attachment pending'})
    if health_check_mode not in (None, 'new_connection', 'disabled'):
        pending.append({'path': 'replay.health_check_mode', 'owner': 'Protocol', 'reason': 'in-band health conversation required'})
    options = vars(build_parser().parse_args([host, '00', '--port', str(port)]))
    packets = tuple(packets)
    options.update(protocol=protocol if isinstance(protocol, str) else 'raw',
        wait=(tcp_pre_delay_s if tcp_pre_delay_s is not None else
            tcp_spacing_s if tcp_spacing_s is not None else wait_between),
        post_delay=tcp_post_delay_s, recovery_wait=5.0 if recovery_wait_s is None else recovery_wait_s,
        recovery_attempts=10 if recovery_attempts is None else recovery_attempts,
        core_dump_wait=5.0 if core_dump_wait_s is None else core_dump_wait_s, ssh_key=ssh_key,
        ssh_user=ssh_user, ssh_pass=ssh_pass, collect_cores=collect_cores, no_recv=skip_recv,
        health_check_mode=health_check_mode, connection_delay=connection_delay_s,
        enable_crash_handling=enable_crash_handling, records=record_path, log_file=log_path, packets=packets)
    explicit = tuple(key for key, value in (('ssh_key', ssh_key), ('ssh_user', ssh_user),
        ('ssh_pass', ssh_pass), ('collect_cores', True if collect_cores else None),
        ('core_dump_wait', core_dump_wait_s),
        ('recovery_wait', recovery_wait_s), ('recovery_attempts', recovery_attempts),
        ('health_check_mode', health_check_mode)) if value is not None)
    result, cleanup_facts, primary_error = None, [], None
    try:
        config = _configuration(app, options, packets, pending=pending, explicit_options=explicit,
            metadata={'crash_hint': crash_hint, 'replay_metadata': replay_metadata,
                      'health_check_mode': health_check_mode, 'wait_between': wait_between,
                      'tcp_spacing_s': tcp_spacing_s, 'tcp_pre_delay_s': tcp_pre_delay_s})
        if config.pending:
            result = config
        elif prepare:
            result = config.request
        else:
            result = execute_prepared_request(app, config.request, options=options,
                explicit_options=explicit)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if owned:
            try:
                cleanup = app.close()
                if app.management is not None:
                    app.management.wait()
                    cleanup = app.close()
                    services = app.management.status()
                    if services['outcome'] == 'failed':
                        cleanup_facts.append({'owner': 'management', 'status': services})
                    else:
                        pending = tuple(entry for entry in services['outcomes']
                            if isinstance(entry, Mapping) and
                            entry['outcome']['collection']['status'] == 'pending')
                        if pending:
                            cleanup_facts.append({'owner': 'management', 'state': 'backend_pending',
                                'run_id': getattr(result, 'run_id', None), 'outcomes': pending})
                if cleanup['outcome'] != 'completed':
                    cleanup_facts.append({'owner': 'application', 'status': cleanup})
            except Exception as exc:
                cleanup_facts.append({'owner': 'application', 'exception': type(exc).__name__, 'error': str(exc)})
            if cleanup_facts:
                try:
                    only_pending = all(fact.get('state') == 'backend_pending' for fact in cleanup_facts)
                    label = ('BYTEFAULT REPLAY FOLLOWUP PENDING ' if only_pending else
                        'BYTEFAULT REPLAY CLEANUP/FOLLOWUP FAILURE ')
                    sys.stderr.write(label + repr(cleanup_facts) + '\n')
                    sys.stderr.flush()
                except Exception as exc:
                    cleanup_facts.append({'owner': 'replay_diagnostic', 'exception': type(exc).__name__, 'error': str(exc)})
                if primary_error is not None:
                    primary_error.add_note('Replay owner cleanup: ' + repr(cleanup_facts))
    if cleanup_facts:
        from bytefault.core.contracts import CampaignResult, freeze
        if isinstance(result, CampaignResult):
            only_pending = all(fact.get('state') == 'backend_pending' for fact in cleanup_facts)
            result = replace(result, application_cleanup_errors=(*result.application_cleanup_errors, *freeze(cleanup_facts)),
                execution_outcome=result.execution_outcome or result.outcome,
                outcome=('followup_pending' if only_pending else 'cleanup_failed')
                    if result.outcome == 'completed' else result.outcome,
                reason=('selected collection backend pending' if only_pending else
                    'replay owner cleanup or accepted follow-up failed')
                    if result.outcome == 'completed' else result.reason)
    return result


def main(argv=None):
    from bytefault.fuzzers.cli import main as application_main
    return application_main(['replay', *(sys.argv[1:] if argv is None else argv)])


if __name__ == '__main__':
    raise SystemExit(main())
