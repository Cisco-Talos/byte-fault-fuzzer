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

"""Prepared input boundary. This module never loads generators or selects rows."""
from dataclasses import fields, is_dataclass
from collections.abc import Mapping
from uuid import uuid4

from bytefault.core import contracts
from bytefault.core.contracts import (ConversationAction, PassivePlan, PreparedRow,
    ConversationRequest, ReceiveRequest, ContractError)
from bytefault.core.validation import validate_request
from bytefault.fuzzers.declarations import SUPPORTED_CAPABILITIES


def positional_plan(frames, *, declaration_id='operator', receive=None):
    return PassivePlan(declaration_id, 1, tuple(ConversationAction(str(i), data,
        receive=receive or ReceiveRequest(requested=False))
        for i, data in enumerate(frames, 1)))


def raw_request(data, *, receive=None, original_request=None):
    identity = str(uuid4())
    return ConversationRequest(positional_plan((data,), receive=receive),
        PreparedRow('row-1', 1), ('1',), identity, 'case-1', 'conversation-1',
        original_request=original_request or {})


def request_to_data(value):
    """Lossless JSON-compatible value encoding; no arbitrary class import tags."""
    from bytefault.core.provenance import is_view, export
    if is_view(value):
        return {'$provenance': export(value)}
    if is_dataclass(value):
        return {'$type': type(value).__name__, 'fields': {
            f.name: request_to_data(getattr(value, f.name)) for f in fields(value)}}
    if isinstance(value, bytes):
        return {'$bytes': value.hex()}
    if isinstance(value, Mapping):
        return {'$mapping': [[k, request_to_data(v)] for k, v in value.items()]}
    if isinstance(value, tuple):
        return {'$tuple': [request_to_data(v) for v in value]}
    if isinstance(value, list):
        return [request_to_data(v) for v in value]
    return value


_TYPES = {name: value for name, value in vars(contracts).items()
          if isinstance(value, type) and is_dataclass(value)}


def value_from_data(value):
    """Decode only the closed current contract vocabulary; never import a tag."""
    def decode(item):
        if isinstance(item, list):
            return [decode(v) for v in item]
        if not isinstance(item, dict):
            return item
        if set(item) == {'$provenance'}:
            from bytefault.core.provenance import load
            return load(item['$provenance'])
        if set(item) == {'$bytes'}:
            return bytes.fromhex(item['$bytes'])
        if set(item) == {'$tuple'}:
            return tuple(decode(v) for v in item['$tuple'])
        if set(item) == {'$mapping'}:
            pairs = item['$mapping']
            if len({k for k, _ in pairs}) != len(pairs):
                raise ValueError('duplicate mapping key')
            return {k: decode(v) for k, v in pairs}
        if set(item) == {'$type', 'fields'} and item['$type'] in _TYPES:
            return _TYPES[item['$type']](**{k: decode(v) for k, v in item['fields'].items()})
        raise ValueError('unsupported encoded value')
    try:
        return decode(value)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError('request', 'malformed', str(exc)) from exc


def request_from_data(value):
    try:
        return validate_request(value_from_data(value), SUPPORTED_CAPABILITIES)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError('request', 'malformed', str(exc)) from exc


def contract_from_record(contract, value, *, path='record'):
    """Restore a known contract from the journal's untyped passive mappings.

    Callers select the type, never journal data. Mapping/Any members remain
    passive provenance; only declared dataclass members are reconstructed.
    """
    from types import UnionType
    from typing import get_args, get_origin, get_type_hints, Union
    if contract not in _TYPES.values():
        raise ContractError(path, 'unsupported_contract', 'unknown current contract type')

    def restore(kind, item):
        origin, arguments = get_origin(kind), get_args(kind)
        if origin in (UnionType, Union):
            if item is None and type(None) in arguments:
                return None
            alternatives = [k for k in arguments if k is not type(None)]
            return restore(alternatives[0], item) if len(alternatives) == 1 else item
        if origin is tuple:
            if not isinstance(item, (tuple, list)):
                raise ValueError('expected ordered sequence')
            if len(arguments) == 2 and arguments[1] is Ellipsis:
                return tuple(restore(arguments[0], v) for v in item)
            if len(arguments) != len(item):
                raise ValueError('incorrect tuple length')
            return tuple(restore(k, v) for k, v in zip(arguments, item))
        if isinstance(kind, type) and kind in _TYPES.values():
            if isinstance(item, kind):
                return item
            if not isinstance(item, Mapping):
                raise ValueError('expected contract mapping')
            hints = get_type_hints(kind)
            if set(item) - set(hints):
                raise ValueError('unknown contract members: ' + repr(tuple(set(item) - set(hints))))
            return kind(**{k: restore(hints[k], v) for k, v in item.items()})
        return item
    try:
        return restore(contract, value)
    except (TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError(path, 'malformed', str(exc)) from exc


def request_from_record(value):
    try:
        return validate_request(contract_from_record(ConversationRequest, value,
            path='record.request'), SUPPORTED_CAPABILITIES)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError('record.request', 'malformed', str(exc)) from exc
