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

"""Movable passive protocol directories. Discovery never imports their code."""
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import math

from bytefault.core.contracts import ContractError, PassivePlan, freeze
from bytefault.core.json_values import load_json
from bytefault.fuzzers.declarations import AdmissionIssue, admit_plan, object_keys


DEFAULT_ROOT = Path(__file__).resolve().parents[1] / 'protocols'


def selection_key(name):
    """Retain current named-selection handling, independently of protocol ID."""
    return name.strip().lower()


def select_actions(plan, selected_actions=None, stage=None):
    """Resolve a named stage only when it identifies one send or explicit actions."""
    plan = admit_plan(plan)
    if stage is not None and (not isinstance(stage, str) or stage not in plan.stages):
        raise ContractError('protocol.stage', 'unknown_stage', str(stage))
    candidates = tuple(a.action_id for a in plan.actions if stage is None or a.stage_id == stage)
    if selected_actions is None:
        if len(candidates) != 1:
            raise ContractError('protocol.selection', 'ambiguous_action', 'explicit selected action IDs required')
        return candidates
    if selected_actions == () and stage is not None:
        raise ContractError('protocol.selection', 'conflicting_selection', 'an empty prepared selection cannot select a stage')
    if (not isinstance(selected_actions, tuple) or any(not isinstance(a, str) or not a for a in selected_actions)
            or len(set(selected_actions)) != len(selected_actions)):
        raise ContractError('protocol.selection', 'invalid_identity', 'distinct action IDs in a tuple required')
    if any(a not in candidates for a in selected_actions):
        raise ContractError('protocol.selection', 'conflicting_selection', 'selected actions must belong to the plan/stage')
    return selected_actions


@dataclass(frozen=True)
class ProtocolDefaults:
    port: int | None = None
    timeout: float = 3.0
    pre_delay: float = 0.0
    post_delay: float = 0.0


@dataclass(frozen=True)
class ProtocolEntry:
    protocol_id: str
    aliases: tuple[str, ...]
    format_version: int
    transport: str
    defaults: ProtocolDefaults
    plan: PassivePlan
    root: str
    directory: str
    descriptor_path: str
    declaration_path: str
    descriptor: object


@dataclass(frozen=True)
class ProtocolResolution:
    requested_selection: str
    entry: ProtocolEntry

    @property
    def provenance(self):
        entry = self.entry
        return freeze({'requested_selection': self.requested_selection,
            'protocol_id': entry.protocol_id, 'format_version': entry.format_version,
            'declaration_id': entry.plan.declaration_id, 'declaration_version': entry.plan.version,
            'transport': entry.transport, 'root': entry.root, 'directory': entry.directory,
            'descriptor_path': entry.descriptor_path, 'declaration_path': entry.declaration_path,
            'descriptor': entry.descriptor})


@dataclass(frozen=True)
class ProtocolDiscovery:
    root: str
    entries: tuple[ProtocolEntry, ...]
    issues: tuple[AdmissionIssue, ...]
    pending_directories: tuple[str, ...]

    def select(self, selection):
        if not isinstance(selection, str) or not selection.strip():
            raise ContractError('protocol.selection', 'invalid_identity', 'nonempty name required')
        if self.issues:
            issue = self.issues[0]
            raise ContractError(issue.source, issue.code, issue.message)
        for entry in self.entries:
            if selection_key(selection) in tuple(selection_key(name) for name in (entry.protocol_id, *entry.aliases)):
                return ProtocolResolution(selection, entry)
        raise ContractError(self.root, 'absent', f'passive protocol {selection!r} not found')


def _entry(root, directory, path):
    value = load_json(path.read_text(encoding='utf-8'), path=str(path))
    object_keys(value, ('format_version', 'protocol_id', 'aliases', 'transport',
                        'declaration', 'defaults'), str(path))
    try:
        if type(value['format_version']) is not int or value['format_version'] != 1:
            raise ContractError(str(path) + '.format_version', 'unsupported_version', 'expected 1')
        identity, aliases = value['protocol_id'], value.get('aliases', [])
        if (not isinstance(identity, str) or not identity or identity.strip() != identity or
                not isinstance(aliases, list) or any(not isinstance(a, str) or not a or a.strip() != a for a in aliases)):
            raise ContractError(str(path), 'invalid_identity', 'exact nonempty IDs/aliases required')
        if len({selection_key(name) for name in (identity, *aliases)}) != 1 + len(aliases):
            raise ContractError(str(path), 'duplicate_identity', 'ID/aliases must be distinct')
        if value['transport'] != 'tcp':
            raise ContractError(str(path) + '.transport', 'unsupported_transport', str(value['transport']))
        reference = value['declaration']
        if (not isinstance(reference, str) or not reference or Path(reference).is_absolute() or
                PureWindowsPath(reference).drive or PureWindowsPath(reference).root):
            raise ContractError(str(path) + '.declaration', 'invalid_reference', 'relative declaration path required')
        declaration = (directory / reference).resolve()
        if not declaration.is_relative_to(directory):
            raise ContractError(str(path) + '.declaration', 'invalid_reference', 'reference leaves protocol directory')
        defaults = value.get('defaults', {})
        object_keys(defaults, ('port', 'timeout', 'pre_delay', 'post_delay'), str(path) + '.defaults')
        defaults = ProtocolDefaults(**defaults)
        if defaults.port is not None and (type(defaults.port) is not int or not 1 <= defaults.port <= 65535):
            raise ContractError(str(path) + '.defaults.port', 'invalid', 'TCP port required')
        for name in ('timeout', 'pre_delay', 'post_delay'):
            number = getattr(defaults, name)
            if (type(number) not in (int, float) or not math.isfinite(number) or
                    (number <= 0 if name == 'timeout' else number < 0)):
                raise ContractError(str(path) + '.defaults.' + name, 'invalid', 'finite valid timing required')
        plan = admit_plan(load_json(declaration.read_text(encoding='utf-8'), path=str(declaration)))
        return ProtocolEntry(identity, tuple(aliases), 1, 'tcp', defaults, plan,
            str(root), str(directory), str(path), str(declaration), freeze(value))
    except (KeyError, TypeError, AttributeError) as exc:
        raise ContractError(str(path), 'malformed', str(exc)) from exc


def discover_protocols(directory=None):
    """Inspect immediate descriptor-bearing children; an explicit root is final.

    Any malformed or colliding eligible entry refuses selection for the root.
    Directories without protocol.json are reported as pending, never imported.
    """
    try:
        root = (DEFAULT_ROOT if directory is None else Path(directory)).resolve()
    except (TypeError, OSError, ValueError) as exc:
        raise ContractError('protocol.root', 'malformed', str(exc)) from exc
    entries, issues, pending, names = [], [], [], {}
    try:
        if not root.is_dir():
            raise ContractError(str(root), 'absent', 'protocol root not found')
        for directory in sorted(root.iterdir()):
            if directory.name == '__pycache__' or not directory.is_dir():
                continue
            path = directory / 'protocol.json'
            if not path.exists():
                pending.append(str(directory))
                continue
            try:
                entry = _entry(root, directory.resolve(), path.resolve())
                for name in (entry.protocol_id, *entry.aliases):
                    if selection_key(name) in names:
                        raise ContractError(str(path), 'duplicate_identity', f'{name!r} also in {names[selection_key(name)]}')
                for name in (entry.protocol_id, *entry.aliases):
                    names[selection_key(name)] = str(path)
                entries.append(entry)
            except (ContractError, OSError, ValueError) as exc:
                issues.append(AdmissionIssue(str(path), getattr(exc, 'code', 'malformed'), str(exc)))
    except (ContractError, OSError, ValueError) as exc:
        issues.append(AdmissionIssue(str(root), getattr(exc, 'code', 'malformed'), str(exc)))
    return ProtocolDiscovery(str(root), tuple(entries), tuple(issues), tuple(pending))
