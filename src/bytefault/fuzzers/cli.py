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

"""CLI argument resolution and shared Application routes.

Options retain their resolved configuration when an owning capability is unavailable.
"""
import argparse
from dataclasses import dataclass, replace
import json
from pathlib import Path
import sys
from collections.abc import Iterator, Mapping
from uuid import uuid4

from bytefault.application import Application, ApplicationRequest, CampaignRequest
from bytefault.core.contracts import ContractError, TransportRequest, ReceiveRequest, freeze
from bytefault.core.records import encode_value, decode_value
from bytefault.core.json_values import load_json
from bytefault.fuzzers.inputs import raw_request, request_from_data
from bytefault.fuzzers.helpers import parse_hex_bytes, parse_hex_byte, _parse_length_range, _parse_recovery_delays
from bytefault.fuzzers.byte_mask import ByteMask
from bytefault.paths import artifacts_root, run_path
from bytefault.core.logging_utils import resolve_log_path


class _IntentArgumentParser(argparse.ArgumentParser):
    """Record destinations consumed by argparse, including admitted aliases.

    _get_values is called by argparse's take_action for recognized arguments;
    default conversion uses _get_value instead and must not imply explicit input.
    """
    def __init__(self, *args, **kwargs):
        self.explicit_destinations = set()
        super().__init__(*args, **kwargs)

    def parse_known_args(self, args=None, namespace=None):
        self.explicit_destinations.clear()
        return super().parse_known_args(args, namespace)

    def _get_values(self, action, arg_strings):
        value = super()._get_values(action, arg_strings)
        if action.option_strings:
            self.explicit_destinations.add(action.dest)
        return value

def build_parser():
    parser = _IntentArgumentParser(description="Bytefault Raw and passive TCP fuzzer")
    parser.add_argument('--cases', help='Original one-based case numbers, e.g. 1,3-6,10')
    parser.add_argument('--case-limit', type=int, help='Explicit maximum source case ordinal to prepare')
    parser.add_argument('--campaign-json', help='Tagged passive object with literal cases, generation and options')
    parser.add_argument('--connection-json', help='Tagged CampaignConnection, including explicit retry/reuse meanings')
    parser.add_argument('--monitoring-json', help='Tagged MonitoringConfig; rule objects become typed ObservationRule values')
    parser.add_argument('--retries', type=int, default=3, help='Retries after the initial attempt (default 3)')
    parser.add_argument("selection_or_host", help="Passive protocol/declaration selection, or host for schema-free input")
    parser.add_argument("host", nargs="?", help="Device IP address when a passive protocol selection precedes it")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override protocol default port (required if protocol has no default)",
    )
    parser.add_argument(
        "--target",
        required=False,
        help="Declared named field, 'offset', or 'byte:N'; raw/normal/payload are whole-input aliases when not declared fields",
    )
    parser.add_argument(
        "--target2",
        required=False,
        help="Second field to fuzz simultaneously (cartesian with --target)",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List valid --target values for the selected protocol and exit",
    )
    parser.add_argument(
        "--field-same",
        action="store_true",
        help="Fill each selected named top-level iterator field with its value (fixed declared width or variable base extent)",
    )
    parser.add_argument(
        "--base-payload",
        help="Base payload bytes (hex) to fuzz around",
    )
    parser.add_argument(
        "--mutate-seed",
        action="append",
        help="Seed payload for mutation mode (hex). Repeatable.",
    )
    parser.add_argument(
        "--mutate-seed-file",
        action="append",
        help="Exact binary seed file (use --mutate-seed-format hex for explicit hex decoding). Repeatable.",
    )
    parser.add_argument(
        "--mutate-seed-dir",
        help="Seed files in sorted filename order; binary default, explicit --mutate-seed-format hex.",
    )
    parser.add_argument(
        "--mutate-count",
        type=int,
        default=100,
        help="Number of mutations to generate per seed (default: 100)",
    )
    parser.add_argument(
        "--mutate-raw",
        action="store_true",
        help="Treat mutate seeds as full packet bytes (skip schema framing)",
    )
    parser.add_argument(
        "--random-len",
        default=None,
        help="Generate random bytes of this length per iteration (N or N-M range)",
    )
    parser.add_argument(
        "--random-iter",
        type=int,
        default=100,
        help="Number of random iterations (0 = run until stopped)",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=None,
        help="Deterministic RNG seed for random mode",
    )
    parser.add_argument(
        "--mutate-max-len",
        type=int,
        default=None,
        help="Maximum mutated payload length (default: no limit)",
    )
    parser.add_argument(
        "--mutate-rng-seed",
        type=int,
        default=None,
        help="Deterministic RNG seed for mutation mode",
    )
    parser.add_argument(
        "--base",
        action="append",
        help="Override base field bytes (field=hex). Repeatable.",
    )
    parser.add_argument(
        "--gen-field",
        action="append",
        dest="gen_field",
        metavar="FIELD:TYPE:PARAMS",
        help=(
            "Composable generator spec. Repeatable. "
            "FIELD is a schema field name or @N for byte-offset injection. "
            "Types: "
            "iter (e.g. route:iter:0-255), "
            "random (e.g. payload:random:10-100,exclude:0x00-0x1F), "
            "sweep (e.g. payload:sweep:500-4100,step:100,seed:42), "
            "mutate (e.g. payload:mutate:AABB,count:200), "
            "list (e.g. op:list:00,01,FF), "
            "edge (e.g. route:edge or route:edge:width:2), "
            "file (exact whole bytes; source_mode:lines explicitly splits binary records), "
            "dataset (e.g. cmd:dataset:commands.standard). "
            "Offset injection: use @N as field name to target byte offset N "
            "(e.g. @6:random:10-200). Default mode is insert; use "
            "mode:overwrite to replace bytes in-place. "
            "Modifiers: exclude:N-M, width:N, count:N, seed:N, fill, "
            "start:0xNN, max_len:N, endian:big|little, step:N, "
            "mode:insert|overwrite|replace|append; @START-END replaces a working range; @append appends. "
            "Line delimiter defaults LF; delimiter_hex:0d0a selects CRLF. "
            "Random scopes: length_scope/content_scope/range_scope:sample_once|per_test; "
            "offset_range:MIN-MAX,offset_scope:SCOPE,offset_seed:N. "
            "Use --generation-json for exact paths/bytes, transforms and shared-set bindings."
        ),
    )
    parser.add_argument(
        "--gen-strategy",
        choices=["single", "cartesian", "zip", "one-position", "broadcast", "hybrid-cartesian"],
        default="single",
        help="Candidate strategy (default single); broadcast/one-position need one explicitly shared set via --generation-json",
    )
    parser.add_argument(
        "--skip",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Omit original cases 1 through N; later case numbers remain original. "
            "Use inspect-resume/resume-run for journal-based interrupted recovery "
            "and explicit uncertain rerun/skip choices. Repeated generation needs "
            "unchanged inputs and matching random seeds; skip cannot restore unseeded choices."
        ),
    )
    parser.add_argument(
        "--base-packet",
        help="Full baseline packet bytes for offset/byte fuzzing (hex).",
    )
    parser.add_argument(
        "--prefix",
        help="Prefix bytes to prepend to the schema-built payload (hex).",
    )
    parser.add_argument(
        "--pad-byte",
        default="00",
        help="Hex byte used to left-pad fixed-size fields (default: 00).",
    )
    parser.add_argument(
        "--offset",
        type=int,
        help="Starting byte offset for offset-based fuzzing (0-indexed)",
    )
    parser.add_argument(
        "--fuzz-length",
        type=int,
        default=2,
        help="Number of bytes to fuzz at offset (default: 2)",
    )
    parser.add_argument(
        "--mask",
        help="Byte range to test (e.g., '0x00-0xFF', '0x20-0x7E')",
    )
    parser.add_argument(
        "--mask2",
        help="Byte range for --target2 (falls back to full 0x00-0xFF)",
    )
    parser.add_argument(
        "--exclude",
        help="Bytes to exclude (e.g., '0x11,0x12')",
    )
    parser.add_argument(
        "--exclude2",
        help="Bytes to exclude for --target2",
    )
    parser.add_argument(
        "--start",
        help="Resume from specific byte value (e.g., '0x50' to start at 0x50)",
    )
    parser.add_argument(
        "--start2",
        help="Resume from specific byte for --target2",
    )
    parser.add_argument(
        "--auto-length",
        dest="auto_length",
        action="store_true",
        default=True,
        help="Explicitly enable optional calculated-field repair; omission preserves the submitted setting (new requests default False)",
    )
    parser.add_argument(
        "--no-auto-length",
        dest="auto_length",
        action="store_false",
        help="Explicitly disable optional calculated-field repair; omission preserves the submitted setting",
    )
    parser.add_argument(
        "--test-length-mismatch",
        action="store_true",
        help="Also test with intentional length mismatches",
    )
    parser.add_argument(
        "--no-test-banner",
        dest="test_banner",
        action="store_false",
        help="Disable per-test delimiter lines",
    )
    parser.add_argument(
        "--ui", "--tui",
        action="store_true",
        default=False,
        help="Enable the optional terminal UI on a terminal; Plain if Rich is absent",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        default=False,
        help="Use the Plain terminal view (retained option); otherwise retain headless JSON output",
    )
    parser.add_argument(
        "--heartbeat",
        action="store_true",
        default=False,
        help="Enable independent ICMP reachability records/status (also shown by the optional UI)",
    )
    parser.add_argument(
        "--no-recv",
        action="store_true",
        dest="no_recv",
        help="Do not request a response to selected sends; required setup receives remain",
    )
    parser.add_argument(
        "--check-interval",
        type=int,
        default=1,
        help="Health check every N iterations (default: 1)",
    )
    parser.add_argument(
        "--crash-delay",
        type=int,
        default=50,
        help="Max seconds to wait for crash recovery (default: 50)",
    )
    parser.add_argument(
        "--crash-throttle",
        type=int,
        default=5,
        help="Stop current fuzz target after N consecutive crashes (default: 5; 0 disables)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Socket timeout in seconds (defaults to protocol setting or 3.0)",
    )
    parser.add_argument(
        "--tcp-pre-delay",
        type=float,
        default=None,
        help="Seconds to wait before each TCP connection (protocol default if omitted)",
    )
    parser.add_argument(
        "--tcp-spacing",
        type=float,
        default=None,
        help="Deprecated alias for --tcp-pre-delay",
    )
    parser.add_argument(
        "--tcp-post-delay",
        type=float,
        default=None,
        help="Seconds to wait after each TCP connection closes (protocol default if omitted)",
    )
    parser.add_argument(
        "--connection-delay", type=float, default=0.0,
        help="Additional delay before each connection after the first, including service checks and core collection",
    )
    parser.add_argument(
        "--health-check-mode",
        choices=["new_connection", "in_band", "disabled"],
        default=None,
        help="Campaign service-check mode (Raw default: new_connection; disabled turns checks off)",
    )
    parser.add_argument(
        "--core-dump-wait",
        type=float,
        default=5.0,
        help="Seconds to wait before selected core acquisition (default: 5.0)",
    )
    parser.add_argument(
        "--delayed-crash-check",
        type=float,
        default=0.0,
        help="Seconds to wait after a test before its scheduled health check (default: 0)",
    )
    parser.add_argument(
        "--recovery-delays",
        type=str,
        default=None,
        help="Comma-separated recovery delays in seconds (default: 3,5,10,15,17)",
    )
    parser.add_argument(
        "--reconnect-attempts",
        type=int,
        default=5,
        help="Reconnect attempts after crash (default: 5)",
    )
    parser.add_argument(
        "--reconnect-delay",
        type=float,
        default=1.0,
        help="Seconds between reconnect attempts (default: 1.0)",
    )
    persistent_group = parser.add_mutually_exclusive_group()
    persistent_group.add_argument(
        "--persistent",
        action="store_true",
        help="Keep connection alive between tests (overrides protocol default)",
    )
    persistent_group.add_argument(
        "--non-persistent",
        dest="non_persistent",
        action="store_true",
        help="Force a new TCP connection per test (overrides protocol default)",
    )
    parser.add_argument(
        "--fuzz-stage",
        dest="fuzz_stage",
        default=None,
        metavar="STAGE",
        help=(
            "Constrain explicit selected actions to a passive declaration stage. "
            "Use --list-stages to see available stages. "
            "A stage with several sends requires explicit action selection."
        ),
    )
    parser.add_argument(
        "--list-stages",
        action="store_true",
        default=False,
        help="List available stages for the selected protocol and exit",
    )
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity (repeat for more: -v, -vv, -vvv, -vvvv)")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Set log level to DEBUG (equivalent to -vvv)",
    )
    parser.add_argument(
        "--hide-field",
        action="append",
        default=[],
        help="Hide a named field from UI header value summaries (repeatable)",
    )
    parser.add_argument(
        "--log-file",
        "-l",
        help="Action log: bare names use artifacts/logs; explicit paths retain their location",
    )
    parser.add_argument(
        "--ssh-key",
        "-k",
        help="Key authentication for explicitly selected core collection",
    )
    parser.add_argument('--ssh-pass', help='Cleartext SSH password for selected core collection; requires --ssh-user')
    parser.add_argument('--collect-cores', action='store_true',
        help='Collect cores after a failed campaign service check; requires SSH credentials')
    
    parser.add_argument('--seed-hex', help='Exact whole bytes for one send (schema-free or selected declaration)')
    parser.add_argument('--request-json', help='Lossless Application.export_request conversation value')
    parser.add_argument('--records', help='Required local evidence destination')
    parser.add_argument('--results', help='Exact result bin path, including an existing bin; default is YYYYMMDD_HHMMSS_<protocol>')
    parser.add_argument('--ssh-user', help='Collection SSH user; key mode defaults to root')
    parser.add_argument('--core-dir', default='/root/cores', help='Remote collection directory')
    parser.add_argument('--core-cache', help='Local collection cache directory')
    parser.add_argument('--core-max-size', type=int, default=0, help='Collection per-file MiB limit; default 0 (unlimited)')
    parser.add_argument('--core-timeout', type=int, default=30, help='Rsync stalled-I/O timeout in seconds; 0 disables it')
    parser.add_argument('--heartbeat-interval', type=float, default=2.0, help='Independent ICMP cadence in seconds')
    parser.add_argument('--receive-cap', type=int)
    parser.add_argument('--receive-deadline', type=float)
    parser.add_argument('--declaration-dir', help='Authoritative root containing passive protocol directories')
    parser.add_argument('--action', action='append', dest='selected_actions',
                        help='Explicit selected action ID (repeatable; must match a prepared request)')
    parser.add_argument('--generation-json', help='Lossless tagged sources/sets/positions configuration')
    parser.add_argument('--generation-limit', type=int, help='Explicit preparation row bound (also bounds unbounded sources)')
    parser.add_argument('--datasets-json', help='Tagged passive dataset name/subset/ordered byte mapping')
    parser.add_argument('--mutate-seed-format', choices=('binary', 'hex'), default='binary',
                        help='Seed file encoding; binary preserves the exact entire file (default)')
    parser.add_argument('--mutate-scope', choices=('per_test', 'sample_once'), default='per_test')
    for name in ('length', 'content', 'range'):
        parser.add_argument('--random-' + name + '-scope', choices=('per_test', 'sample_once'), default='per_test')
    parser.add_argument('--random-byte-range', help='Explicit inclusive random byte range, e.g. 0x20-0x7e')
    parser.add_argument('--random-range-choices', help='Randomly choose among ranges separated by |')
    parser.add_argument('--offset-range', help='Random placement start bounds MIN-MAX')
    parser.add_argument('--offset-scope', choices=('per_test', 'sample_once'), default='per_test')
    parser.add_argument('--offset-seed', type=int)
    return parser


@dataclass(frozen=True)
class PendingAttachment:
    options: tuple[str, ...]
    owner: str
    due: str
    reason: str


@dataclass(frozen=True)
class CLIConfiguration:
    original_argv: tuple[str, ...]
    options: object
    resolved: object
    pending: tuple[PendingAttachment, ...]
    request: ApplicationRequest | None = None
    status: str = 'pending'
    generation: object = None
    generation_limit: int | None = None


def _tagged_json(text, path):
    try:
        return decode_value(load_json(text, path=path))
    except (ValueError, TypeError, KeyError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError(path, 'malformed', str(error)) from error


def _range(text):
    values = text.split('-', 1)
    pair = tuple(int(value, 0) for value in values)
    pair = pair if len(pair) == 2 else (pair[0], pair[0])
    if pair[0] < 0 or pair[0] > pair[1]:
        raise ValueError('ordered nonnegative bounds required')
    return pair


def _position(target, modifiers, set_id):
    position = {'position_id': target, 'set_id': set_id}
    if target in ('raw', 'normal', 'payload'):
        operation = modifiers.get('mode', 'replace')
        position['operation'] = operation
        if operation != 'append':
            position['offset'] = 0
        if operation == 'replace':
            position['end'] = 'seed'
    elif target == '@append':
        position['operation'] = 'append'
    elif target.startswith('@'):
        lo, hi = _range(target[1:])
        position.update(operation=modifiers.get('mode', 'replace' if '-' in target[1:] else 'insert'), offset=lo)
        if position['operation'] == 'replace':
            if '-' not in target[1:]:
                raise ValueError('range replacement requires @START-END')
            position['end'] = hi
        if position['operation'] == 'append':
            position.pop('offset', None)
    else:
        position.update(operation=modifiers.get('mode', 'replace'), field_id=target)
    for key in ('offset_range', 'offset_scope', 'offset_seed'):
        if key in modifiers:
            position[key] = modifiers[key]
    return position


def _generation(args, explicit, resolved):
    """Normalize current source workflows to the one shared passive mapping."""
    if args.generation_limit is not None and args.generation_limit < 0:
        raise ValueError('--generation-limit must be nonnegative')
    if args.generation_json is not None:
        if args.gen_field or args.target or args.random_len is not None or args.mutate_seed or args.mutate_seed_file or args.mutate_seed_dir:
            raise ValueError('--generation-json supplies sources and positions; do not combine source workflows')
        source_only = {'mutate_count', 'mutate_raw', 'mutate_max_len', 'mutate_rng_seed', 'mutate_seed_format',
            'mutate_scope', 'random_iter', 'random_seed', 'random_length_scope', 'random_content_scope',
            'random_range_scope', 'random_byte_range', 'random_range_choices', 'prefix', 'offset',
            'offset_range', 'offset_scope', 'offset_seed', 'fuzz_length', 'mask', 'mask2', 'exclude',
            'exclude2', 'start', 'start2', 'field_same', 'target2'}
        if explicit & source_only:
            raise ValueError('generation JSON owns source/transform/placement options: ' + repr(sorted(explicit & source_only)))
        value = _tagged_json(args.generation_json, 'cli.generation_json')
        if not isinstance(value, Mapping):
            raise ValueError('generation mapping required')
        value = dict(value)
        if 'gen_strategy' in explicit and value.get('strategy', 'single') != args.gen_strategy:
            raise ValueError('--gen-strategy disagrees with generation JSON')
        if args.datasets_json is not None:
            if 'datasets' in value:
                raise ValueError('choose datasets in generation JSON or --datasets-json')
            value['datasets'] = _tagged_json(args.datasets_json, 'cli.datasets_json')
        from bytefault.fuzzers.generated_inputs import configuration
        return configuration(value)
    sources, sets, positions = [], [], []
    specifications = []
    def add(target, source, modifiers=None, transforms=()):
        modifiers = modifiers or {}
        sid = source.source_id
        if any(s['source_id'] == sid for s in sources):
            raise ValueError(f'duplicate generator field {target!r}')
        sources.append({'source_id': sid, 'kind': source.kind, 'options': dict(source.options),
                        'reference': source.reference})
        sets.append({'set_id': sid, 'source_id': sid, 'transforms': tuple(transforms)})
        # Placement syntax resolves here; missing protocol declarations remain pending below.
        positions.append(_position(target, modifiers, sid))
    from bytefault.generators.sources import SourceSpec
    from bytefault.generators.cli_parser import parse_source_field, _split_params
    if args.gen_field:
        new_global_controls = {'random_length_scope', 'random_content_scope', 'random_range_scope',
            'random_byte_range', 'random_range_choices', 'offset_range', 'offset_scope', 'offset_seed', 'mutate_scope'}
        if explicit & new_global_controls:
            raise ValueError('--gen-field uses per-source inline scope/offset modifiers: ' + repr(sorted(explicit & new_global_controls)))
        for name in explicit & {'prefix', 'mutate_max_len', 'mutate_rng_seed', 'mutate_count', 'mask', 'mask2',
                                 'exclude', 'exclude2', 'start', 'start2'}:
            resolved['inactive_options'][name] = '--gen-field supplies each source options explicitly'
        for spec in args.gen_field:
            target = spec.split(':', 1)[0].strip()
            # The source parser owns source grammar. Adapt only the fuzzer's
            # named location to its existing positional modifier admission.
            if ':' in spec and target and not target.startswith('@'):
                _, source, placement = parse_source_field('@0-0:' + spec.split(':', 1)[1])
                source = replace(source, source_id=target)
            else:
                target, source, placement = parse_source_field(spec)
            raw = spec.split(':', 2)[2] if len(spec.split(':', 2)) == 3 else ''
            if source.kind == 'file':
                primary = source.options['path']
                _, modifiers = _split_params(','.join(raw.split(',')[1:])) if ',' in raw else ('', {})
            else:
                primary, modifiers = _split_params(raw)
            specifications.append({'field': target, 'type': source.kind, 'raw_parameters': raw,
                'primary': primary, 'modifiers': modifiers, 'original': spec})
            add(target, source, placement)
        resolved['generator_specs'] = tuple(specifications)
    else:
        mutate = bool(args.mutate_seed or args.mutate_seed_file or args.mutate_seed_dir)
        random_mode = args.random_len is not None
        if not (mutate or random_mode or args.target):
            if explicit & {'offset_range', 'offset_scope', 'offset_seed', 'random_length_scope',
                           'random_content_scope', 'random_range_scope', 'random_byte_range',
                           'random_range_choices', 'mutate_scope'}:
                raise ValueError('random source/placement controls require a source workflow')
            return None
        if not random_mode and explicit & {'random_length_scope', 'random_content_scope', 'random_range_scope',
                                           'random_byte_range', 'random_range_choices'}:
            raise ValueError('random source scope/range controls require --random-len')
        if not mutate and 'mutate_scope' in explicit:
            raise ValueError('--mutate-scope requires mutation seeds')
        target = 'raw' if args.mutate_raw else args.target or 'payload'
        transforms = []
        if mutate:
            options = {'seeds': resolved['mutation_seeds'], 'seed_files': tuple(args.mutate_seed_file or ()),
                'seed_encoding': args.mutate_seed_format, 'repeat_each': args.mutate_count}
            if args.mutate_seed_dir:
                options['seed_directory'] = args.mutate_seed_dir
            transforms.append({'mutator_id': 'mutation', 'kind': 'mutate', 'options': {
                'seed': args.mutate_rng_seed, 'max_len': args.mutate_max_len, 'scope': args.mutate_scope}})
            source = SourceSpec('payload-source', 'seed', options)
        elif random_mode:
            lo, hi = resolved['random_length']
            options = {'min_len': lo, 'max_len': hi, 'count': args.random_iter or None,
                'seed': args.random_seed, 'length_scope': args.random_length_scope,
                'content_scope': args.random_content_scope, 'range_scope': args.random_range_scope}
            if args.random_byte_range:
                options['byte_range'] = _range(args.random_byte_range)
            if args.random_range_choices:
                options['range_choices'] = tuple(_range(value) for value in args.random_range_choices.split('|'))
            if args.exclude:
                excluded = ByteMask.from_string(args.exclude)
                if any(lo < 0 or hi > 255 for lo, hi in excluded.ranges):
                    raise ValueError('random excluded values must be bytes')
                options['exclude_bytes'] = tuple(excluded.iter_values())
            source = SourceSpec('payload-source', 'random', options)
        else:
            if target == 'offset':
                if args.offset is None or args.offset < 0 or args.fuzz_length < 1:
                    raise ValueError('--target offset needs nonnegative --offset and positive --fuzz-length')
                width, target = args.fuzz_length, '@' + str(args.offset)
            elif target.startswith('byte:'):
                width, target = 1, '@' + str(int(target[5:]))
            else:
                width = 1
            mask = resolved.get('mask')
            options = {'ranges': mask['ranges'] if mask else ((0, (1 << (8 * width)) - 1),),
                'excludes': mask['excludes'] if mask else tuple(ByteMask.from_string(args.exclude).iter_values()) if args.exclude else (),
                'width': width, 'start_value': resolved.get('start')}
            source = SourceSpec('iterator-source', 'iter', options)
        if (mutate or random_mode) and target == 'offset':
            if args.offset is None:
                raise ValueError('--target offset requires --offset')
            target = '@' + str(args.offset)
        if (mutate or random_mode) and target.startswith('byte:'):
            target = '@' + str(int(target[5:]))
        modifiers = {'mode': 'overwrite'} if target.startswith('@') else {}
        if args.offset_range is not None:
            modifiers.update(offset_range=_range(args.offset_range), offset_scope=args.offset_scope,
                             offset_seed=args.offset_seed)
        elif 'offset_scope' in explicit or args.offset_seed is not None:
            raise ValueError('--offset-scope/--offset-seed requires --offset-range')
        if resolved['prefix'] is not None and target == 'payload' and not args.mutate_raw:
            transforms.append({'mutator_id': 'payload-prefix', 'kind': 'prepend',
                               'options': {'data': resolved['prefix']}})
        elif resolved['prefix'] is not None:
            if target.startswith('@') and not args.mutate_raw and resolved['base_packet'] is None:
                resolved['offset_prefix'] = True
            else:
                resolved['inactive_options']['prefix'] = 'complete base packet/raw mutation retains its own bytes'
        add(target, source, modifiers, transforms)
        if args.target2:
            mask = resolved['mask2']
            target2 = '@' + str(int(args.target2[5:])) if args.target2.startswith('byte:') else args.target2
            source = SourceSpec('iterator-source-2', 'iter', {'ranges': mask['ranges'], 'excludes': mask['excludes'],
                'width': max(1, (max(hi for _, hi in mask['ranges']).bit_length() + 7) // 8),
                'start_value': resolved.get('start2')})
            add(target2, source, {'mode': 'overwrite'} if target2.startswith('@') else {})
    if not sources:
        return None
    value = {'sources': tuple(sources), 'sets': tuple(sets), 'positions': tuple(positions),
        'strategy': 'cartesian' if args.target2 and 'gen_strategy' not in explicit else args.gen_strategy}
    if args.datasets_json is not None:
        value['datasets'] = _tagged_json(args.datasets_json, 'cli.datasets_json')
    return value


def _named_adapters(args, resolved, conversation, generation):
    """Bind source-owned encoding to explicit action context, retaining one set."""
    from bytefault.core.contracts import PreparedContribution, SourceInvocation, SourceResult, Placement
    from bytefault.generators.field_encoding import field_width, padded_base
    if generation is not None:
        from bytefault.fuzzers.generated_inputs import _baseline
        baseline = _baseline(conversation)
        if baseline is not conversation:
            conversation = replace(baseline, original_request={**dict(baseline.original_request),
                'cli_input': {**dict(baseline.original_request.get('cli_input', {})),
                    'seed_baseline_input': conversation}})
    actions = tuple(a for a in conversation.plan.actions if a.action_id in conversation.selected_actions)
    names = {f.field_id for a in actions for f in a.fields if f.buffer_id == a.buffer_id}
    bases = {k: v for k, v in resolved['base_values'].items() if k in names or k not in ('raw', 'normal', 'payload')}
    if 'payload' in names and resolved['base_payload'] is not None:
        bases = {'payload': resolved['base_payload'], **bases}
    missing = set(bases) - names
    if missing:
        raise ContractError('cli.baseline', 'unknown_field', ','.join(sorted(missing)))
    contributions, placements, contexts = [], [], {}
    for action in actions:
        for field in action.fields:
            if field.buffer_id != action.buffer_id:
                continue
            name = field.field_id
            if (field.offset is None or field.size is None or field.offset + field.size > len(action.seed)):
                if name in bases:
                    raise ContractError('cli.baseline', 'unknown_field_location', action.action_id + ':' + name)
                continue
            data = bases.get(name, action.seed[field.offset:field.offset + field.size])
            sizes = {name: 'var' if field.variable else field.size}
            data = padded_base(name, {name: data}, sizes, resolved['pad_byte'])
            if name in bases:
                identity = f'named-base:{len(action.action_id)}:{action.action_id}:{name}'
                contributions.append(PreparedContribution(identity, data,
                    SourceInvocation(identity, 'literal', options={'kind': 'literal', 'data': data}),
                    source_result=SourceResult(identity, data, 1)))
                placements.append(Placement(identity, identity, action.action_id, 'replace', field_id=name))
    if contributions:
        conversation = replace(conversation, row=replace(conversation.row,
            contributions=(*contributions, *conversation.row.contributions),
            placements=(*placements, *conversation.row.placements)))
    if resolved.get('offset_prefix'):
        prefixed, prefixes = [], []
        for action in actions:
            payload = next((f for f in action.fields
                if f.field_id == 'payload' and f.buffer_id == action.buffer_id), None)
            data = resolved['prefix']
            identity = 'offset-payload-prefix:' + action.action_id
            prefixed.append(PreparedContribution(identity, data,
                SourceInvocation(identity, 'literal', options={'data': data}),
                source_result=SourceResult(identity, data, 1)))
            prefixes.append(Placement(identity, identity, action.action_id, 'insert',
                **({'field_id': 'payload', 'include_in_field': True} if payload is not None else {'offset': 0})))
        conversation = replace(conversation, row=replace(conversation.row,
            contributions=(*conversation.row.contributions, *prefixed),
            placements=(*conversation.row.placements, *prefixes)))
    from bytefault.fuzzers.generated_inputs import _baseline_actions
    effective_actions = _baseline_actions(conversation)
    for action in actions:
        effective = effective_actions[action.action_id]
        for nominal in action.fields:
            if nominal.buffer_id != action.buffer_id:
                continue
            field = next(f for f in effective.fields if f.field_id == nominal.field_id and f.buffer_id == action.buffer_id)
            if field.offset is None or field.size is None:
                continue
            data = effective.seed[field.offset:field.offset + field.size]
            sizes = {field.field_id: 'var' if nominal.variable else nominal.size}
            data = padded_base(field.field_id, {field.field_id: data}, sizes, resolved['pad_byte'])
            contexts.setdefault(field.field_id, {})[action.action_id] = {
                'width': field_width(field.field_id, sizes, {field.field_id: nominal.size}, {field.field_id: data}),
                'base': data}
    if generation is None:
        return conversation, None
    if args.generation_json is not None or args.campaign_json is not None:
        return conversation, generation
    value = dict(generation)
    sources = {s['source_id']: dict(s) for s in value['sources']}
    sets = {s['set_id']: dict(s) for s in value['sets']}
    positions = []
    for supplied in value['positions']:
        position = dict(supplied)
        name = position.get('field_id', position['position_id'])
        if name in names and position['position_id'] == name:
            position.pop('offset', None)
            position.pop('end', None)
            position['field_id'] = name
        if position.get('field_id') is None:
            positions.append(position)
            continue
        name = position['field_id']
        applicable = position.get('action_ids', conversation.selected_actions)
        selected = {key: data for key, data in contexts.get(name, {}).items() if key in applicable}
        if set(selected) != set(applicable):
            raise ContractError('cli.generation', 'unknown_field_location', name)
        item = sets[position['set_id']]
        source = sources[item['source_id']]
        options = dict(source.get('options', {}))
        spec = next((s for s in resolved.get('generator_specs', ()) if s['field'] == name), None)
        mode, fill, endian = 'pad', False, options.get('endian', 'big')
        if source['kind'] == 'iter' and not args.gen_field and args.generation_json is None:
            mode, fill = 'leading', bool(args.field_same)
            options['width'] = max(1, (max(hi for _, hi in options['ranges']).bit_length() + 7) // 8)
        elif source['kind'] in ('iter', 'edge') and spec is not None and 'width' not in spec['modifiers']:
            mode = 'integer'
            if source['kind'] == 'edge':
                options['width'] = max(1, *(context['width'] for context in selected.values()))
            if options.get('fill', False):
                fill, options['fill'] = True, False
        if mode == 'pad':
            selected = {key: dict(data, width=0 if next(f for a in actions if a.action_id == key
                for f in a.fields if f.field_id == name and f.buffer_id == a.buffer_id).variable else data['width'])
                for key, data in selected.items()}
        transforms = item.get('transforms', ())
        after = tuple(t for t in transforms if t['mutator_id'] == 'payload-prefix') if source['kind'] == 'random' else ()
        if after:
            transforms = tuple(t for t in transforms if t['mutator_id'] != 'payload-prefix')
        item['transforms'] = (*transforms, {'mutator_id': 'field-encoding:' + name,
            'kind': 'field_encode', 'options': {'contexts': selected, 'mode': mode,
                'fill': fill, 'endian': endian, 'pad_byte': resolved['pad_byte']}}, *after)
        source['options'] = options
        positions.append(position)
    value.update(sources=tuple(sources.values()), sets=tuple(sets.values()), positions=tuple(positions))
    return conversation, value


def _resolve_configuration(argv, application, *, original_argv=None, input_files=(), owned_slot=None):
    """Parse and normalize current configuration with a live Application owner."""
    argv = list(argv)
    original_argv = tuple(argv) if original_argv is None else tuple(original_argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    explicit = set(parser.explicit_destinations)
    if args.ssh_pass is not None and 'ssh_user' not in explicit:
        raise ContractError('cli.ssh_user', 'required', '--ssh-pass requires explicit --ssh-user')
    if args.ssh_pass is not None and args.ssh_key is not None:
        raise ContractError('cli.ssh_pass', 'conflicting_input', '--ssh-key and --ssh-pass conflict')
    args.protocol = args.selection_or_host if args.host is not None else None
    args.host = args.host or args.selection_or_host
    values = vars(args).copy()
    resolved = {'base_values': {}, 'source_references': {
        'seed_files': tuple(args.mutate_seed_file or ()), 'seed_directory': args.mutate_seed_dir},
        'generator_specs': tuple(args.gen_field or ()),
        'ui': {'requested': args.ui or args.no_ui, 'attachment': 'optional ApplicationView client',
               'effective': ('Rich/Plain on an interactive terminal; structured results remain on stdout'
                             if args.ui or args.no_ui else 'headless; structured results remain on stdout')}}
    resolved['explicit_options'] = tuple(sorted(explicit))
    try:
        if args.seed_hex is not None and args.request_json is not None:
            raise ValueError('choose --seed-hex or --request-json')
        if (args.receive_cap is None) != (args.receive_deadline is None):
            raise ValueError('--receive-cap and --receive-deadline must be supplied together')
        for name in ('mask', 'mask2'):
            text = getattr(args, name)
            if text or (name == 'mask2' and args.target2):
                exclude = args.exclude2 if name == 'mask2' else args.exclude
                mask = ByteMask.from_string(text or '0x00-0xff', exclude)
                resolved[name] = {'ranges': tuple(mask.ranges), 'excludes': tuple(sorted(mask.excludes))}
        for name in ('start', 'start2'):
            resolved[name] = int(getattr(args, name), 16) if getattr(args, name) else None
        resolved['pad_byte'] = parse_hex_byte(args.pad_byte)
        for name in ('base_payload', 'base_packet', 'prefix'):
            raw = getattr(args, name)
            resolved[name] = parse_hex_bytes(raw) if raw is not None else None
        resolved['mutation_seeds'] = tuple(parse_hex_bytes(v) for v in args.mutate_seed or ())
        for override in args.base or ():
            if '=' not in override:
                raise ValueError('--base requires field=hex')
            name, value = override.split('=', 1)
            if not name.strip():
                raise ValueError('--base requires a nonempty field')
            resolved['base_values'][name.strip()] = parse_hex_bytes(value.strip())
        mutate_mode = bool(args.mutate_seed or args.mutate_seed_file or args.mutate_seed_dir)
        random_mode = args.random_len is not None
        if mutate_mode and args.mutate_count <= 0:
            raise ValueError('--mutate-count must be >= 1')
        if random_mode and args.random_iter < 0:
            raise ValueError('--random-iter must be >= 0')
        if mutate_mode and random_mode:
            raise ValueError('choose mutation mode or random mode')
        if args.gen_field and (args.target or mutate_mode or random_mode):
            raise ValueError('--gen-field cannot combine with --target, mutation seeds or --random-len')
        if random_mode:
            resolved['random_length'] = _range(str(args.random_len))
        resolved['recovery_delays'] = tuple(_parse_recovery_delays(args.recovery_delays))
        resolved['tcp_pre_delay'] = (args.tcp_pre_delay if args.tcp_pre_delay is not None else
            args.tcp_spacing if args.tcp_spacing is not None else 0.0)
        resolved['tcp_post_delay'] = args.tcp_post_delay if args.tcp_post_delay is not None else 0.0
        resolved['connection_delay'] = args.connection_delay
        resolved['timeout'] = args.timeout if args.timeout is not None else 3.0
        resolved['fuzz_stage'] = args.fuzz_stage
        resolved['effective_debug'] = args.debug or args.verbose >= 3
        resolved['selection'] = args.protocol
        resolved['target'] = ('raw' if args.mutate_raw else args.target or 'payload') if mutate_mode else args.target
        resolved['inactive_options'] = {}
        if mutate_mode and args.mutate_raw:
            for name in ('target','base_packet','prefix'):
                if name in explicit:
                    resolved['inactive_options'][name] = 'full-packet mutation takes precedence'
        if args.target2 and (random_mode or mutate_mode or args.target == 'offset' or args.target2 == 'offset'):
            raise ValueError('--target2 is incompatible with offset/random/mutation mode')
        generation = _generation(args, explicit, resolved)
        if generation is None and (args.generation_limit is not None or args.datasets_json is not None):
            raise ValueError('--generation-limit/--datasets-json requires a source workflow')
    except (ValueError, TypeError, OverflowError, MemoryError) as exc:
        raise ContractError('cli.configuration', 'invalid', str(exc)) from exc
    pending = []
    campaign_data = _tagged_json(args.campaign_json, 'cli.campaign_json') if args.campaign_json is not None else {}
    if not isinstance(campaign_data, Mapping) or set(campaign_data) - {'cases', 'generation', 'options', 'monitoring_configuration'}:
        raise ContractError('cli.campaign_json', 'invalid', 'cases/generation/options/monitoring_configuration object required')
    if args.campaign_json is not None and explicit & {'request_json', 'generation_json', 'seed_hex', 'gen_field', 'target', 'random_len', 'mutate_seed', 'mutate_seed_file', 'mutate_seed_dir'}:
        raise ContractError('cli.campaign_json', 'conflicting_input', 'campaign input and other source inputs are exclusive')
    literal_cases = tuple(request_from_data(case) for case in campaign_data.get('cases', ()))
    if campaign_data.get('generation') is not None:
        generation = campaign_data['generation']
    has_bytes = args.seed_hex is not None or args.request_json is not None or bool(literal_cases)
    has_generation = generation is not None
    has_baseline = bool(resolved['base_values']) or any(resolved[n] is not None for n in ('base_packet', 'base_payload'))
    if application is None:
        application = Application()
        owned_slot.append(application)
    resolution = None
    if args.declaration_dir is not None and args.protocol is None:
        raise ContractError('cli.protocol', 'required', '--declaration-dir requires a protocol selection')
    if args.protocol:
        try:
            resolution = application.resolve_protocol(args.protocol, args.declaration_dir)
        except ContractError as exc:
            # Deferred generator/campaign configuration retains unresolved names.
            # Execution and explicit roots always require actual admission.
            if (has_bytes or args.declaration_dir is not None or (not pending and not has_generation) or
                    args.list_targets or args.list_stages or exc.code != 'absent'):
                raise
            resolved['protocol_error'] = {'path': exc.path, 'code': exc.code, 'message': str(exc)}
            pending.append(PendingAttachment(('protocol',), 'Passive declarations', 'later protocol scope', str(exc)))
        if resolution is not None:
            resolved['protocol'] = resolution.provenance
            if not has_bytes and (args.fuzz_stage is not None or args.selected_actions is not None):
                from bytefault.fuzzers.protocol_directory import select_actions
                resolved['selected_actions'] = select_actions(resolution.entry.plan,
                    tuple(args.selected_actions) if args.selected_actions is not None else None, args.fuzz_stage)
    if resolution is None and not has_bytes and (args.fuzz_stage is not None or args.selected_actions is not None):
        pending.append(PendingAttachment(tuple(name for name in ('fuzz_stage','selected_actions')
            if getattr(args,name) is not None), 'Passive declarations', 'requires admitted plan',
            'stage/action selection needs supplied or discovered passive data'))
    if args.list_targets or args.list_stages:
        if resolution is None:
            raise ContractError('cli.protocol', 'required', 'inspection requires a discovered protocol')
        plan = resolution.entry.plan
        resolved['inspection'] = {'stages': tuple({'stage_id': stage,
            'actions': tuple(a.action_id for a in plan.actions if a.stage_id == stage)} for stage in plan.stages),
            'actions': tuple({'action_id': a.action_id, 'stage_id': a.stage_id,
                'buffer_id': a.buffer_id, 'seed': a.seed, 'receive': a.receive} for a in plan.actions),
            'named_fields': tuple({'action_id': a.action_id, 'buffer_id': a.buffer_id,
                'fields': a.fields} for a in plan.actions),
            'raw_placements': ('insert', 'overwrite', 'replace', 'append')}
        if has_bytes or has_generation:
            raise ContractError('cli.input', 'conflicting_input', 'inspection and execution inputs must be separate')
    request = None
    if has_bytes or ((has_generation or has_baseline) and (resolution is not None or args.protocol is None)):
        conversation = None
        seed = None
        if literal_cases:
            conversation = literal_cases[0]
        elif args.request_json is not None:
            try:
                conversation = request_from_data(load_json(args.request_json, path='cli.request_json'))
            except (ValueError, TypeError) as exc:
                if isinstance(exc, ContractError):
                    raise
                raise ContractError('cli.request_json', 'malformed', str(exc)) from exc
        elif args.seed_hex is not None:
            try:
                seed = bytes.fromhex(args.seed_hex)
            except ValueError as exc:
                raise ContractError('cli.seed_hex', 'malformed', str(exc)) from exc
        if has_generation or has_baseline:
            plan = conversation.plan if conversation is not None else resolution.entry.plan if resolution is not None else None
            if conversation is not None:
                selected_ids = conversation.selected_actions
            elif plan is not None:
                from bytefault.fuzzers.protocol_directory import select_actions
                selected_ids = select_actions(plan, tuple(args.selected_actions) if args.selected_actions is not None else None,
                                              args.fuzz_stage)
            else:
                selected_ids = ()
            named_fields = {f.field_id for a in plan.actions if a.action_id in selected_ids for f in a.fields
                            if f.buffer_id == a.buffer_id} if plan is not None else set()
            baseline_values = [resolved[name] for name in ('base_packet', 'base_payload')
                               if resolved[name] is not None and name not in resolved['inactive_options']]
            if 'payload' in named_fields and resolved['base_payload'] is not None:
                baseline_values.remove(resolved['base_payload'])
            baseline_values.extend(value for name, value in resolved['base_values'].items()
                                   if name in ('raw', 'normal', 'payload') and name not in named_fields)
            if baseline_values:
                if conversation is not None or seed is not None or any(value != baseline_values[0] for value in baseline_values):
                    raise ContractError('cli.baseline', 'conflicting_input', 'choose one exact whole baseline or prepared plan')
                seed = baseline_values[0]
            if resolution is not None and conversation is None and seed is None:
                from bytefault.core.contracts import ConversationRequest, PreparedRow
                from bytefault.fuzzers.protocol_directory import select_actions
                plan = resolution.entry.plan
                selected = select_actions(plan, tuple(args.selected_actions) if args.selected_actions is not None else None,
                                          args.fuzz_stage)
                conversation = ConversationRequest(plan, PreparedRow('baseline', 1), selected,
                    str(uuid4()), 'case-1', 'conversation-1')
            elif resolution is None and conversation is None and seed is None:
                seed = b''
        from bytefault.core.logging_utils import resolve_log_path
        log_path = resolve_log_path(args.log_file, artifacts_root())
        receive = (ReceiveRequest(cap=args.receive_cap, deadline=args.receive_deadline)
                   if args.receive_cap is not None and not args.no_recv else None)
        def bind(supplied, seed=None):
            # Every structured case uses the same admission and controls. Retain
            # the submitted value before protocol binding or CLI normalization.
            conversation = supplied
            if resolution is not None:
                bound = application.protocol_request(args.protocol, args.host, directory=args.declaration_dir,
                    seed=seed, conversation=conversation,
                    selected_actions=tuple(args.selected_actions) if args.selected_actions is not None else None,
                    stage=args.fuzz_stage, port=args.port, timeout=args.timeout,
                    pre_delay=args.tcp_pre_delay if args.tcp_pre_delay is not None else args.tcp_spacing,
                    post_delay=args.tcp_post_delay, connection_delay=args.connection_delay,
                    no_receive=bool(args.no_recv), receive=receive,
                    record_path=args.records, log_path=log_path)
                conversation = bound.conversation
            else:
                if conversation is None:
                    conversation = raw_request(seed, receive=receive or ReceiveRequest(requested=False))
                else:
                    if args.receive_cap is not None:
                        raise ContractError('cli.receive', 'invalid', 'structured actions carry receive settings')
                    if args.no_recv:
                        conversation = replace(conversation, plan=replace(conversation.plan,
                            actions=tuple(replace(a, receive=replace(a.receive, requested=False))
                                          if a.action_id in conversation.selected_actions else a
                                          for a in conversation.plan.actions)))
                if args.selected_actions is not None and tuple(args.selected_actions) != conversation.selected_actions:
                    raise ContractError('cli.action', 'conflicting_selection', 'actions disagree with the prepared request')
                if args.fuzz_stage is not None:
                    from bytefault.fuzzers.protocol_directory import select_actions
                    select_actions(conversation.plan, conversation.selected_actions, args.fuzz_stage)
                if args.port is None:
                    raise ContractError('cli.port', 'required', 'explicit port required without declaration defaults')
                record_path = args.records or str(run_path(conversation.run_id))
                bound = ApplicationRequest(conversation, TransportRequest(args.host, args.port,
                    resolved['timeout'], resolved['tcp_pre_delay'], resolved['tcp_post_delay'],
                    args.connection_delay), record_path, log_path)
            if 'auto_length' in explicit:
                conversation = replace(conversation, repair=args.auto_length)
            conversation = replace(conversation, original_request={**dict(conversation.original_request),
                'cli_input': {'supplied_conversation': supplied,
                              'no_receive': bool(args.no_recv), 'receive': receive,
                              'repair_override': args.auto_length if 'auto_length' in explicit else None}})
            return replace(bound, conversation=conversation)

        if literal_cases:
            bound_cases = tuple(bind(case) for case in literal_cases)
            request = bound_cases[0]
            literal_cases = tuple(bound.conversation for bound in bound_cases)
            if any(case.plan != request.conversation.plan for case in literal_cases):
                raise ContractError('campaign.cases', 'plan_mismatch', 'one declared campaign plan required')
        else:
            request = bind(conversation, seed)
        conversation = request.conversation
        if literal_cases:
            literal_cases = tuple(_named_adapters(args, resolved, case, None)[0] for case in literal_cases)
            conversation = literal_cases[0]
        else:
            conversation, generation = _named_adapters(args, resolved, conversation, generation)
        request = replace(request, conversation=conversation)
        named_targets = {p.get('field_id') for p in generation['positions']} if generation is not None else set()
        if 'field_same' in explicit and not (any(target in named_targets for target in (args.target, args.target2))
                                             and not args.gen_field):
            resolved['inactive_options']['field_same'] = 'fill applies to named top-level iterators; inline sources select fill explicitly'
        if 'pad_byte' in explicit and not named_targets and not any(
                name in {f.field_id for a in conversation.plan.actions for f in a.fields}
                for name in resolved['base_values']):
            resolved['inactive_options']['pad_byte'] = 'raw positions have no fixed field padding'
        if resolution is not None:
            resolved['protocol'] = conversation.original_request['protocol_input']['source']
            resolved.update(timeout=request.transport.timeout, tcp_pre_delay=request.transport.pre_delay,
                            tcp_post_delay=request.transport.post_delay,
                            connection_delay=request.transport.connection_delay)
        def provenance(conversation):
            return replace(conversation, original_request={**dict(conversation.original_request),
                'argv': original_argv, 'forwarded_argv': tuple(argv), 'options': values,
                'resolved_options': resolved})
        conversation = provenance(conversation)
        literal_cases = tuple(provenance(case) for case in literal_cases)
        request = replace(request, conversation=conversation)
    elif not pending and not (args.list_targets or args.list_stages):
        raise ContractError('cli.input', 'required', 'choose a current source/mutation workflow, --seed-hex or --request-json')
    if request is not None:
        from bytefault.core.contracts import CampaignOptions, CampaignConnection, CampaignSetupStep
        from bytefault.fuzzers.campaign import case_numbers, validate_campaign
        from bytefault.monitoring.configuration import configuration_from_data
        option_data = dict(campaign_data.get('options', {}))
        option_flags = {'skip': 'skip', 'cases': 'selected_cases', 'case_limit': 'case_limit',
                        'test_length_mismatch': 'variants'}
        for flag, key in option_flags.items():
            if flag in explicit and key in option_data:
                raise ContractError('cli.campaign.' + key, 'conflicting_input', 'JSON and explicit option both supplied')
        option_data.setdefault('skip', args.skip)
        option_data.setdefault('selected_cases', case_numbers(args.cases) if args.cases is not None else ())
        option_data.setdefault('case_limit', args.case_limit if args.case_limit is not None else args.generation_limit)
        option_data.setdefault('variants', ('normal', 'length4') if args.test_length_mismatch else ('normal',))
        if args.case_limit is not None and args.generation_limit is not None and args.case_limit != args.generation_limit:
            raise ContractError('cli.case_limit', 'conflicting_input', 'case and generation limits disagree')
        connection_data = option_data.pop('connection', None)
        if args.connection_json is not None:
            if connection_data is not None:
                raise ContractError('cli.connection', 'conflicting_input', 'connection supplied twice')
            connection_data = _tagged_json(args.connection_json, 'cli.connection_json')
        connection_data = dict(connection_data or {})
        if explicit & {'persistent', 'non_persistent'}:
            if 'mode' in connection_data:
                raise ContractError('cli.connection.mode', 'conflicting_input', 'JSON and explicit mode both supplied')
            connection_data['mode'] = 'persistent' if args.persistent else 'fresh'
        if 'retry_setup' in connection_data:
            connection_data['retry_setup'] = tuple(CampaignSetupStep(**dict(step)) for step in connection_data['retry_setup'])
        connection = CampaignConnection(**connection_data)
        for key in ('selected_cases', 'variants'):
            option_data[key] = tuple(option_data[key])
        options = CampaignOptions(**option_data, connection=connection)
        validate_campaign(options, request.conversation.plan)
        policy_data = campaign_data.get('monitoring_configuration')
        if args.monitoring_json is not None:
            if policy_data is not None:
                raise ContractError('cli.monitoring', 'conflicting_input', 'policy supplied twice')
            policy_data = _tagged_json(args.monitoring_json, 'cli.monitoring_json')
        policy_data = dict(policy_data or {})
        policy_flags = {'retries': 'retries', 'check_interval': 'check_interval', 'crash_delay': 'recovery_budget',
            'crash_throttle': 'crash_throttle', 'health_check_mode': 'health_check_mode',
            'delayed_crash_check': 'delayed_check', 'recovery_delays': 'recovery_delays',
            'reconnect_attempts': 'reconnect_attempts', 'reconnect_delay': 'reconnect_delay',
            'collect_cores': 'collect_cores'}
        for flag, key in policy_flags.items():
            if flag in explicit:
                if key in policy_data:
                    raise ContractError('cli.monitoring.' + key, 'conflicting_input', 'JSON and explicit option both supplied')
                policy_data[key] = (resolved['recovery_delays'] or (3,5,10,15,17)) if flag == 'recovery_delays' else getattr(args, flag)
        policy = configuration_from_data(policy_data)
        request = CampaignRequest(request.conversation, request.transport, request.record_path,
            request.log_path, options, generation, literal_cases, policy)
    from bytefault.config_file import attach_inputs
    request = attach_inputs(request, input_files)
    return CLIConfiguration(original_argv, freeze(values), freeze(resolved), tuple(pending), request,
                            'pending' if pending else 'available', freeze(generation), args.generation_limit)


def resolve_configuration(argv, application=None, *, original_argv=None, input_files=()):
    """Prepare detached configuration, closing an Application created here."""
    if application is not None:
        return _resolve_configuration(argv, application, original_argv=original_argv,
                                      input_files=input_files)
    from bytefault.management.lifecycle import finish_owned_application

    owned_slot = []
    try:
        result = _resolve_configuration(argv, None, original_argv=original_argv,
                                        input_files=input_files, owned_slot=owned_slot)
    except BaseException as error:
        if owned_slot:
            finish_owned_application(owned_slot[0], primary_error=error)
        raise
    if owned_slot:
        finish_owned_application(owned_slot[0])
    return result


def argument_request(argv):
    config = resolve_configuration(argv)
    if config.pending:
        raise ContractError('cli.attachment', 'unavailable', repr(config.pending))
    if config.generation is not None:
        raise ContractError('cli.input', 'generated_stream', 'use resolve_configuration and Application.generate or execute_arguments')
    return config.request


def _service_option_choices(options, explicit_options):
    if options.get('ssh_pass') is not None and 'ssh_user' not in explicit_options:
        raise ContractError('cli.ssh_user', 'required', '--ssh-pass requires explicit --ssh-user')
    if options.get('ssh_pass') is not None and options.get('ssh_key') is not None:
        raise ContractError('cli.ssh_pass', 'conflicting_input', '--ssh-key and --ssh-pass conflict')
    destinations = {'results': 'result_root', 'ssh_key': 'ssh_key', 'ssh_user': 'ssh_user',
        'ssh_pass': 'ssh_pass',
        'core_dir': 'remote_dir', 'core_cache': 'cache_dir', 'core_max_size': 'max_file_size_mb',
        'core_timeout': 'min_timeout', 'core_dump_wait': 'core_write_wait',
        'heartbeat': 'heartbeat', 'heartbeat_interval': 'heartbeat_interval'}
    return {field: options[option] for option, field in destinations.items() if option in explicit_options}


def execute_prepared_request(application, request, *, options, explicit_options=(), terminal=False):
    """Execute an already prepared input through the shared owner/client boundary."""
    application.configure_service_options(**_service_option_choices(options, explicit_options))
    if terminal:
        from importlib.util import find_spec
        if find_spec('bytefault.ui') is not None:
            from bytefault.ui.controller import run_terminal
            return run_terminal(application, request, options)
        if 'ui' in explicit_options:
            print('Optional Bytefault UI is unavailable; executing through the headless Application.', file=sys.stderr)
    return application.submit(request)


def _prepared_client_parser(command, *, saved=False):
    """Reuse actual owner/display options without parsing another input recipe."""
    from copy import copy
    parser = _IntentArgumentParser(prog='bytefault ' + command)
    parser.add_argument('intent_json')
    parser.add_argument('--execute', action='store_true', help='Execute the prepared request through the ordinary Application')
    destinations = {'records', 'log_file', 'results', 'ssh_key', 'ssh_user', 'ssh_pass',
        'collect_cores', 'core_dir',
        'core_cache', 'core_max_size', 'core_timeout', 'core_dump_wait', 'heartbeat',
        'heartbeat_interval', 'ui', 'no_ui', 'verbose', 'debug', 'hide_field', 'test_banner'}
    if saved:
        destinations.add('no_recv')
    for source in build_parser()._actions:
        if source.dest in destinations:
            action = copy(source)
            action.option_strings = list(source.option_strings)
            if action.dest == 'no_recv':
                action.option_strings.append('--no-receive')
            parser._add_action(action)
    return parser


def command_parser(command):
    """Return the parser used by a generic application command."""
    if command in ('submit', 'configure', 'prepare', 'validate'):
        return build_parser()
    if command in ('inspect', 'schema'):
        parser = argparse.ArgumentParser(prog='bytefault ' + command)
        if command == 'inspect':
            parser.add_argument('--directory')
    elif command in ('inspect-declaration', 'admit', 'export-declaration'):
        parser = argparse.ArgumentParser(prog='bytefault ' + command)
        parser.add_argument('declaration_json')
    elif command in ('status', 'control', 'observe', 'record-refs', 'records'):
        parser = argparse.ArgumentParser(prog='bytefault ' + command)
        parser.add_argument('run_id')
        if command == 'control':
            parser.add_argument('control')
        if command == 'observe':
            parser.add_argument('--after', type=int, default=0)
    elif command == 'inspect-resume':
        parser = argparse.ArgumentParser(prog='bytefault inspect-resume')
        parser.add_argument('path')
    elif command == 'resume-run':
        return _prepared_client_parser(command)
    elif command == 'export-case':
        parser = argparse.ArgumentParser(prog='bytefault export-case')
        parser.add_argument('path')
        parser.add_argument('record_id')
    elif command in ('saved-intent', 'saved-case'):
        return _prepared_client_parser(command, saved=True)
    elif command == 'service':
        parser = argparse.ArgumentParser(prog='bytefault service')
        parser.add_argument('owner', choices=('monitoring','management','reporting','maintenance'))
        parser.add_argument('request_json', help='exact tagged passive value')
    else:
        raise ValueError('unknown command: ' + command)
    return parser


def _prepared_client_intent(request, command, argv, options):
    if options.collect_cores:
        from bytefault.monitoring.configuration import MonitoringConfig
        if isinstance(request, CampaignRequest):
            request = replace(request, monitoring_configuration=replace(
                request.monitoring_configuration or MonitoringConfig(), collect_cores=True))
        else:
            # Saved cases are one ordinary execution. Adding campaign service
            # checks must not introduce a second target attempt on failure.
            single_case_policy = MonitoringConfig(collect_cores=True, retries=0,
                retry_rules=(), recovery_delays=(), recovery_budget=0,
                reconnect_attempts=0, crash_throttle=0)
            request = CampaignRequest(request.conversation, request.transport,
                request.record_path, request.log_path,
                monitoring_configuration=single_case_policy)
    conversation = replace(request.conversation, original_request={**dict(request.conversation.original_request),
        'prepared_client': {'command': command, 'argv': tuple(argv), 'options': vars(options)}})
    return replace(request, conversation=conversation)


def execute_arguments(argv, application, *, original_argv=None, terminal=False, replay_root=False,
                      input_files=()):
    """One dispatcher using the supplied in-process application for every owner."""
    args = list(argv)
    command = args[0] if args else ''
    if command == 'replay':
        from bytefault.replay.replay_packet import execute_arguments as replay_arguments
        return replay_arguments(args[1:], application, original_argv=original_argv or argv,
                                terminal=terminal, root=replay_root, input_files=input_files)
    if command in ('inspect', 'schema'):
        parser = command_parser(command)
        options = parser.parse_args(args[1:])
        return application.declaration_schema() if command == 'schema' else application.inspect(options.directory)
    if command in ('inspect-declaration','admit','export-declaration'):
        parser = command_parser(command)
        value = load_json(parser.parse_args(args[1:]).declaration_json, path='declaration')
        if command == 'inspect-declaration':
            return application.inspect_declaration(value)
        plan = application.admit(value)
        return plan if command == 'admit' else application.export_declaration(plan)
    if command in ('status','control','observe','record-refs','records'):
        parser = command_parser(command)
        options = parser.parse_args(args[1:])
        if command == 'control':
            return application.control(options.run_id, options.control)
        if command == 'observe':
            return application.observe(options.run_id, after=options.after)
        method = {'status':'status','record-refs':'record_refs','records':'read_records'}[command]
        return getattr(application, method)(options.run_id)
    if command == 'inspect-resume':
        parser = command_parser(command)
        return application.inspect_resume(parser.parse_args(args[1:]).path)
    if command == 'resume-run':
        from bytefault.application import ResumeIntent, ResumeChoice, SavedStepIntent
        parser = command_parser(command)
        options = parser.parse_args(args[1:])
        data = load_json(options.intent_json, path='cli.resume')
        try:
            choices = tuple(ResumeChoice(**{**dict(c),
                'steps': tuple(SavedStepIntent(**dict(s)) for s in c.get('steps', ()))})
                for c in data.get('choices', ()))
            intent = ResumeIntent(**{**dict(data), 'choices': choices})
        except (TypeError, ValueError, AttributeError) as exc:
            raise ContractError('cli.resume', 'malformed', str(exc)) from exc
        request = application.resume(intent, record_path=options.records,
            log_path=resolve_log_path(options.log_file, artifacts_root()))
        argv = original_argv if original_argv is not None else argv
        request = _prepared_client_intent(request, command, argv, options)
        from bytefault.config_file import attach_inputs
        request = attach_inputs(request, input_files)
        return execute_prepared_request(application, request, options={**vars(options), 'argv': tuple(argv)},
            explicit_options=parser.explicit_destinations, terminal=terminal) if options.execute else request
    if command == 'export-case':
        parser = command_parser(command)
        options = parser.parse_args(args[1:])
        return application.export_case(options.path, options.record_id)
    if command in ('saved-intent', 'saved-case'):
        from bytefault.application import SavedCaseIntent, SavedStepIntent
        parser = command_parser(command)
        options = parser.parse_args(args[1:])
        data = load_json(options.intent_json, path='cli.saved_intent')
        try:
            if not isinstance(data, Mapping):
                raise ValueError('saved intent object required')
            data['steps'] = tuple(SavedStepIntent(**s) for s in data.get('steps', ()))
            intent = SavedCaseIntent(**data)
        except (TypeError, ValueError, AttributeError) as exc:
            raise ContractError('cli.saved_intent', 'malformed', str(exc)) from exc
        request = application.saved_case(intent, record_path=options.records,
            log_path=resolve_log_path(options.log_file, artifacts_root()), no_receive=options.no_recv)
        argv = original_argv if original_argv is not None else argv
        request = _prepared_client_intent(request, command, argv, options)
        from bytefault.config_file import attach_inputs
        request = attach_inputs(request, input_files)
        return execute_prepared_request(application, request, options={**vars(options), 'argv': tuple(argv)},
            explicit_options=parser.explicit_destinations, terminal=terminal) if options.execute else request
    if command == 'service':
        # Same exact tagged value codec as retained records, no class imports.
        from bytefault.core.contracts import Correlation, Observation, TransportResult, MonitoringAction
        from bytefault.reporting import ReportRequest
        parser = command_parser(command)
        options = parser.parse_args(args[1:])
        try:
            data = decode_value(load_json(options.request_json, path='cli.service'))
        except ValueError as exc:
            if isinstance(exc, ContractError):
                raise
            raise ContractError('cli.service', 'malformed', str(exc)) from exc
        def action(value):
            return MonitoringAction(**{**dict(value), 'correlation': Correlation(**dict(value['correlation']))})
        if options.owner == 'maintenance':
            from bytefault.management.maintenance import MaintenanceRequest
            request = MaintenanceRequest(**{**dict(data), **{name: tuple(data.get(name, ()))
                for name in ('local_entries', 'remote_entries', 'protected_files', 'input_files')},
                'input_files': tuple(dict.fromkeys((*data.get('input_files', ()), *input_files)))})
        elif options.owner == 'management':
            request = action(data)
        elif options.owner == 'reporting':
            request = ReportRequest(**{**dict(data), 'action': action(data['action'])})
        else:
            request = Observation(**{**dict(data), 'correlation': Correlation(**dict(data['correlation'])),
                                      'transport': TransportResult(**dict(data['transport']))})
        return application.service(options.owner, request, input_files=input_files)
    if command == 'maintenance':
        from bytefault.management.maintenance import execute_arguments as maintenance_arguments
        selected = bool(input_files)
        return maintenance_arguments(args[1:], application,
            original_argv=original_argv if selected else None, input_files=input_files)
    if command in ('submit','validate','configure','prepare'):
        args.pop(0)
    config = resolve_configuration(args, application, original_argv=original_argv,
                                   input_files=input_files)
    if command == 'configure' or config.pending:
        return config
    if config.request is None:
        return config
    if command not in ('prepare', 'validate') and (isinstance(config.request, CampaignRequest) or config.generation is None):
        return execute_prepared_request(application, config.request,
            options={**dict(config.options), 'argv': config.original_argv},
            explicit_options=config.resolved['explicit_options'], terminal=terminal)
    if isinstance(config.request, CampaignRequest):
        # Campaign execution already returned through execute_prepared_request.
        # Only prepare/validate reach here; a second terminal/submit route would
        # bypass the shared service-option boundary and is not an extension point.
        return application.prepare(config.request, service_options=_service_option_choices(
            config.options, config.resolved['explicit_options']))
    if config.generation is not None:
        if command == 'prepare':
            return application.generate(config.request, config.generation, limit=config.generation_limit)
        method = application.validate_generated if command == 'validate' else application.submit_generated
        return method(config.request, config.generation, limit=config.generation_limit)
    if command == 'prepare':
        return config.request
    if terminal and command!='validate':
        from bytefault.ui.controller import run_terminal
        return run_terminal(application,config.request,{**dict(config.options),'argv':config.original_argv})
    return application.validate(config.request) if command == 'validate' else application.submit(config.request)


def operation_exit_code(value):
    status = getattr(value, 'status', None)
    outcome = getattr(value, 'outcome', 'completed')
    if hasattr(value, 'get'):
        status = value.get('status', status)
        outcome = value.get('outcome', outcome)
    if status in ('unavailable', 'failed', 'pending') or outcome == 'followup_pending':
        return 2
    if status in ('recording_failed', 'cleanup_failed', 'transport_failed', 'cancelled', 'stopped', 'unknown', 'unreached'):
        return 1
    if isinstance(value, Mapping) and 'outcomes' in value:
        for entry in value['outcomes']:
            followup = entry.get('outcome') if isinstance(entry, Mapping) else None
            collection = followup.get('collection') if isinstance(followup, Mapping) else None
            if isinstance(collection, Mapping) and collection.get('status') in ('failed', 'pending'):
                return 2
    if hasattr(value, 'collection'):
        report = value.report
        if value.collection.status in ('failed', 'pending') or (report is not None and
                report.status in ('failed', 'pending', 'unavailable')):
            return 2
    return 0 if outcome == 'completed' else 1


def main(argv=None, *, original_argv=None, replay_root=False, input_files=()):
    args = list(sys.argv[1:] if argv is None else argv)
    application = Application()
    value, code, primary_summary = None, 0, None
    try:
        terminal_requested = any(option in args for option in ('--ui', '--tui', '--no-ui'))
        value = execute_arguments(args, application, original_argv=original_argv,
            terminal=terminal_requested and sys.stdin.isatty() and sys.stderr.isatty(),
            replay_root=replay_root, input_files=input_files)
        if isinstance(value, Iterator):
            for item in value:
                print(json.dumps(encode_value(item), ensure_ascii=True))
                code = max(code, operation_exit_code(item))
            primary_summary = value.summary
            print(json.dumps(encode_value(primary_summary), ensure_ascii=True))
            code = max(code, operation_exit_code(primary_summary))
        else:
            # The portable format is already lossless JSON and can be copied
            # from this entry's stdout directly into the ordinary saved loader.
            encoded = value if isinstance(value, Mapping) and value.get('format') == 'bytefault.case' else encode_value(value)
            print(json.dumps(encoded, ensure_ascii=True))
            code = operation_exit_code(value)
    except (ContractError, OSError, ValueError, TypeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        code = 2
    finally:
        try:
            if isinstance(value, Iterator):
                value.close()
        except Exception as error:
            print(str(error), file=sys.stderr)
            code = max(code, 2)
        try:
            cleanup = application.close()
            if application.management is not None:
                # The process entry owns its lifetime: accepted service work is
                # drained before return, even though callable close is nonblocking.
                application.management.wait()
                cleanup = application.close()
            if application.management is not None:
                services = application.management.status()
                if services['outcomes'] or services['failures']:
                    print(json.dumps(encode_value({'followup': services}), ensure_ascii=True))
                    code = max(code, operation_exit_code(services))
            if cleanup['outcome'] != 'completed':
                print(json.dumps(encode_value({'application_cleanup': cleanup}), ensure_ascii=True))
                code = max(code, operation_exit_code(cleanup))
        except Exception as error:
            print(str(error), file=sys.stderr)
            code = max(code, 2)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
