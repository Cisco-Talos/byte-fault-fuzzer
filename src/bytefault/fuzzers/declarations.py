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

"""Fuzzer-owned passive JSON admission. Never imports discovered Python code.

Version 1 schema: declaration_id, version=1, actions[], optional stages[],
required_capabilities[{name, parameters}], entry_action. Each action has action_id,
seed_hex, optional stage_id, buffer_id='outbound', receive (ReceiveRequest fields),
edges[{literal_hex,target,meaning}], unknown_target, kind='send' and optional
fields[{field_id,offset,size,buffer_id,variable}], response_fields[{field_id,offset,size}]
and optional edge.field_id selecting a declared inbound span. Unknown keys
are errors. Equality selects either the complete response or one declared field.
"""
from dataclasses import dataclass, fields
from pathlib import Path
from bytefault.core.json_values import load_json

from bytefault.core.contracts import (PassivePlan, ConversationAction, ResponseEdge,
    ReceiveRequest, Capability, ContractError, FieldLocation, ResponseField)
from bytefault.core.validation import validate_plan, passive, fail

SUPPORTED_CAPABILITIES = frozenset({'send', 'response_literal', 'raw_edits', 'payload_length',
    'sequence', 'named_fields', 'response_fields', 'length', 'checksum', 'crc32', 'crc16', 'md5', 'sha1', 'sha256'})


def object_keys(value, allowed, path):
    if not isinstance(value, dict):
        fail(path, 'malformed', 'JSON object required')
    unknown = set(value) - set(allowed)
    if unknown:
        fail(path, 'unsupported_field', ','.join(sorted(unknown)))


def array_items(value, path):
    if not isinstance(value, (list, tuple)):
        fail(path, 'malformed', 'array required')
    return value


def hex_bytes(value, path):
    if not isinstance(value, str):
        fail(path, 'malformed', 'hex string required')
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ContractError(path, 'malformed', 'invalid hexadecimal bytes') from exc


def admit_plan(value):
    passive(value, 'declaration')
    if isinstance(value, PassivePlan):
        return validate_plan(value, SUPPORTED_CAPABILITIES)
    object_keys(value, ('declaration_id', 'version', 'actions', 'stages',
                       'required_capabilities', 'entry_action'), 'declaration')
    try:
        actions = []
        for item in array_items(value['actions'], 'declaration.actions'):
            object_keys(item, ('action_id', 'seed_hex', 'stage_id', 'buffer_id', 'receive',
                              'edges', 'unknown_target', 'kind', 'next_action', 'fields', 'response_fields'), 'declaration.actions')
            receive = item.get('receive', {'requested': False})
            object_keys(receive, [f.name for f in fields(ReceiveRequest)], 'declaration.receive')
            edges = []
            for edge in array_items(item.get('edges', []), 'declaration.edges'):
                object_keys(edge, ('literal_hex', 'target', 'meaning', 'field_id'), 'declaration.edges')
                edges.append(ResponseEdge(hex_bytes(edge['literal_hex'], 'edge.literal_hex'),
                                          edge['target'], edge['meaning'], edge.get('field_id')))
            locations = []
            for location in array_items(item.get('fields', []), 'declaration.fields'):
                object_keys(location, [f.name for f in fields(FieldLocation)], 'declaration.fields')
                locations.append(FieldLocation(**location))
            response_fields = []
            for location in array_items(item.get('response_fields', []), 'declaration.response_fields'):
                object_keys(location, [f.name for f in fields(ResponseField)], 'declaration.response_fields')
                response_fields.append(ResponseField(**location))
            actions.append(ConversationAction(item['action_id'],
                hex_bytes(item['seed_hex'], 'action.seed_hex'), item.get('stage_id', ''),
                item.get('buffer_id', 'outbound'), ReceiveRequest(**receive), tuple(edges),
                item.get('unknown_target'), item.get('kind', 'send'), item.get('next_action', '__ordered__'),
                tuple(locations), tuple(response_fields)))
        caps = []
        for cap in array_items(value.get('required_capabilities', []), 'declaration.required_capabilities'):
            object_keys(cap, ('name', 'parameters'), 'declaration.required_capabilities')
            caps.append(Capability(cap['name'], cap.get('parameters', {})))
        plan = PassivePlan(value['declaration_id'], value['version'], tuple(actions),
            tuple(array_items(value.get('stages', []), 'declaration.stages')),
            tuple(caps), value.get('entry_action'))
        return validate_plan(plan, SUPPORTED_CAPABILITIES)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ContractError('declaration', 'malformed', str(exc)) from exc


@dataclass(frozen=True)
class AdmissionIssue:
    source: str
    code: str
    message: str


@dataclass(frozen=True)
class DiscoveryResult:
    plans: tuple[PassivePlan, ...]
    issues: tuple[AdmissionIssue, ...]
    sources: tuple[tuple[str, str], ...]

    def select(self, declaration_id):
        # Any malformed/duplicate installed data prevents ambiguous partial admission.
        if self.issues:
            issue = self.issues[0]
            raise ContractError(issue.source, issue.code, issue.message)
        for plan in self.plans:
            if plan.declaration_id == declaration_id:
                return plan
        raise ContractError('directory', 'absent', declaration_id)


def discover(directory):
    root = Path(directory)
    if not root.is_dir():
        return DiscoveryResult((), (AdmissionIssue(str(root), 'absent', 'directory not found'),), ())
    plans, issues, sources, by_id = [], [], [], {}
    for path in sorted(root.glob('*.json')):
        try:
            value = load_json(path.read_text(encoding='utf-8'), path='declaration')
            plan = admit_plan(value)
            if plan.declaration_id in by_id:
                raise ContractError(str(path), 'duplicate_identity',
                                    f'{plan.declaration_id} also in {by_id[plan.declaration_id]}')
            by_id[plan.declaration_id] = str(path)
            plans.append(plan)
            sources.append((plan.declaration_id, str(path)))
        except (ContractError, OSError, ValueError) as exc:
            issues.append(AdmissionIssue(str(path), getattr(exc, 'code', 'malformed'), str(exc)))
    return DiscoveryResult(tuple(plans), tuple(issues), tuple(sources))
