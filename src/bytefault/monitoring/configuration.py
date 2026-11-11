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

"""Passive, inspectable observation and continuation configuration."""
from dataclasses import dataclass, field, fields
from collections.abc import Mapping
import math

from bytefault.core.contracts import ContractError, freeze


@dataclass(frozen=True)
class ObservationRule:
    rule_id: str
    kind: str
    parameters: Mapping = field(default_factory=dict)
    classification: str = 'response_anomaly'
    uncertainty: str = 'criterion_observed_effect_unknown'
    disposition: str = 'continue'
    conditions: tuple[str, ...] = ()
    actions: tuple[Mapping, ...] = ()
    hold_timeout: float | None = None
    on_expiry: str = 'hold'
    on_failure: str = 'hold'

    def __post_init__(self):
        object.__setattr__(self, 'parameters', freeze(self.parameters))
        object.__setattr__(self, 'actions', freeze(self.actions))
        object.__setattr__(self, 'conditions', tuple(self.conditions))


@dataclass(frozen=True)
class MonitoringConfig:
    observations: tuple[str, ...] = ('action', 'probe', 'service_check', 'late_response', 'heartbeat')
    rules: tuple[ObservationRule, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    retries: int = 3
    recovery_delays: tuple[float, ...] = (3, 5, 10, 15, 17)
    recovery_budget: float = 50.0
    reconnect_attempts: int = 5
    reconnect_delay: float = 1.0
    crash_throttle: int = 5
    throttle_rules: tuple[str, ...] = ('service_failure',)
    healthy_rules: tuple[str, ...] = ('service_success', 'positive_response')
    retry_rules: tuple[str, ...] = ('missing_response', 'send_failure', 'connection_failure', 'service_failure')
    check_interval: int = 1
    delayed_check: float = 0.0
    health_check_mode: str = 'new_connection'
    collect_cores: bool = False
    in_band: Mapping = field(default_factory=dict)
    history_capacity: int = 128

    def __post_init__(self):
        for key in ('observations', 'rules', 'disabled_rules', 'recovery_delays', 'throttle_rules', 'healthy_rules', 'retry_rules'):
            object.__setattr__(self, key, tuple(getattr(self, key)))
        object.__setattr__(self, 'in_band', freeze(self.in_band))
        if type(self.collect_cores) is not bool:
            raise ContractError('monitoring.configuration.collect_cores', 'invalid', 'boolean required')
        for key in ('retries', 'reconnect_attempts', 'crash_throttle', 'check_interval', 'history_capacity'):
            value = getattr(self, key)
            if type(value) is not int or value < (1 if key == 'history_capacity' else 0):
                raise ContractError('monitoring.configuration.' + key, 'invalid', 'nonnegative integer required')
        for key in ('recovery_budget', 'reconnect_delay', 'delayed_check'):
            number(getattr(self, key), 'monitoring.configuration.' + key)
        for delay in self.recovery_delays:
            number(delay, 'monitoring.configuration.recovery_delays')
        if self.health_check_mode not in ('new_connection', 'in_band', 'disabled'):
            raise ContractError('monitoring.configuration.health_check_mode', 'invalid', self.health_check_mode)
        if self.health_check_mode == 'in_band' and (type(self.in_band.get('prepared')) is not bytes or not self.in_band.get('predicate')):
            raise ContractError('monitoring.configuration.in_band', 'unavailable', 'declared bytes and observable predicate required')
        if self.health_check_mode == 'in_band':
            from bytefault.core.contracts import ReceiveRequest, PassivePlan, ConversationAction
            from bytefault.core.validation import validate_plan
            predicate = dict(self.in_band['predicate'])
            kind = predicate.pop('kind', None)
            validate_predicate(kind, predicate)
            receive = ReceiveRequest(**dict(self.in_band.get('receive', {})))
            if not receive.requested:
                raise ContractError('monitoring.configuration.in_band.receive', 'unavailable', 'observable requested receive required')
            validate_plan(PassivePlan('monitoring-in-band', 1,
                (ConversationAction('health', self.in_band['prepared'], receive=receive),)))


def number(value, path):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ContractError(path, 'invalid', 'finite nonnegative number required')


def configuration_from_data(value):
    """Normalize tagged JSON/client data into the same immutable typed policy."""
    if not isinstance(value, Mapping):
        raise ContractError('monitoring.configuration', 'invalid', 'configuration mapping required')
    options = dict(value)
    unknown = set(options) - {f.name for f in fields(MonitoringConfig)}
    if unknown:
        raise ContractError('monitoring.configuration', 'unknown_fields', repr(sorted(unknown)))
    rules = options.get('rules', ())
    if not isinstance(rules, (tuple, list)):
        raise ContractError('monitoring.configuration.rules', 'invalid', 'ordered rule sequence required')
    built = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            raise ContractError(f'monitoring.configuration.rules.{index}', 'invalid', 'rule mapping required')
        try:
            built.append(ObservationRule(**dict(rule)))
        except (TypeError, ValueError) as error:
            raise ContractError(f'monitoring.configuration.rules.{index}', 'invalid', str(error)) from error
    options['rules'] = tuple(built)
    try:
        configuration = MonitoringConfig(**options)
        # The current policy owns rule admission; this does not loosen its
        # typed/passive guard for callers constructing configurations directly.
        from bytefault.monitoring.rules import RulePolicy
        RulePolicy(configuration)
        return configuration
    except (TypeError, ValueError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError('monitoring.configuration', 'invalid', str(error)) from error


def predicate_match(kind, parameters, transport):
    """None means insufficient boundary/bytes, never an invented invalid reply."""
    data = transport.received
    complete = transport.response_boundary == 'declared' and transport.receive_outcome == 'complete'
    if kind == 'exact':
        return data == parameters['value'] if complete else None
    if kind == 'prefix':
        expected = parameters['value']
        return data.startswith(expected) if len(data) >= len(expected) else (False if complete else None)
    if kind == 'length':
        minimum, maximum = parameters.get('min', 0), parameters.get('max')
        if not complete:
            return None
        return len(data) >= minimum and (maximum is None or len(data) <= maximum)
    raise ContractError('monitoring.predicate.kind', 'invalid', str(kind))


def validate_predicate(kind, parameters):
    if kind in ('exact', 'prefix'):
        if set(parameters) - {'value', 'expect'} or type(parameters.get('value')) is not bytes:
            raise ContractError('monitoring.predicate', 'invalid', 'exact expected bytes required')
    elif kind == 'length':
        if set(parameters) - {'min', 'max', 'expect'}:
            raise ContractError('monitoring.predicate', 'invalid', 'min/max expected')
        for key in ('min', 'max'):
            if key in parameters and (type(parameters[key]) is not int or parameters[key] < 0):
                raise ContractError('monitoring.predicate.' + key, 'invalid', 'nonnegative integer required')
        if parameters.get('max', float('inf')) < parameters.get('min', 0):
            raise ContractError('monitoring.predicate', 'invalid', 'ordered lengths required')
    else:
        raise ContractError('monitoring.predicate', 'invalid', str(kind))
    if parameters.get('expect', 'mismatch') not in ('match', 'mismatch'):
        raise ContractError('monitoring.predicate.expect', 'invalid', 'match or mismatch required')
