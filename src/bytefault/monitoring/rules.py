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

"""Observation interpretation and passive campaign decisions; no target I/O."""
from collections import OrderedDict
from dataclasses import replace
from uuid import uuid4
import threading

from bytefault.core.contracts import (Assessment, CampaignDirective, ContractError, Correlation,
    MonitoringAction, MonitoringDecision, ProbeRequest, ReceiveRequest, freeze)
from bytefault.monitoring.configuration import (MonitoringConfig, ObservationRule,
    number, predicate_match, validate_predicate)


def builtins():
    return tuple(ObservationRule(name, name, classification=classification, uncertainty=uncertainty)
        for name, classification, uncertainty in (
            ('missing_response', 'potential_crash', 'unresolved_response'),
            ('unrequested', 'unrequested', 'not_observed'),
            ('send_failure', 'local_send_failure', 'target_effect_unknown'),
            ('connection_failure', 'connection_failed', 'target_state_unknown'),
            ('service_failure', 'service_unavailable', 'process_and_cause_unknown'),
            ('service_success', 'service_responsive', 'process_history_unknown'),
            ('positive_response', 'declared_positive_response', 'declared_meaning_only'),
            ('reset', 'transport_reset', 'application_effect_unknown'),
            ('partial_response', 'partial_response', 'completeness_unknown'),
            ('heartbeat', 'device_reachability', 'service_state_independent')))


def service_failure_followup_rule(collect):
    """One default failed-service action shared by owned and supplied policies."""
    return ObservationRule('service_failure', 'service_failure',
        parameters={'delayed_followup': True}, classification='service_unavailable',
        uncertainty='process_and_cause_unknown',
        actions=({'report': True, 'collect': collect},))


def retry_window(config, used, elapsed):
    """One finite configured schedule; scopes supply their actual consumed state."""
    if type(used) is not int or used < 0:
        raise ContractError('monitoring.retry.used_retries', 'invalid', 'nonnegative consumed retry count required')
    number(elapsed, 'monitoring.retry.elapsed')
    facts = {'unused_retries': max(0, config.retries - used)}
    if used >= config.retries:
        facts['retry_exhausted'] = True
        return None, facts
    remaining = config.recovery_budget - elapsed
    if used >= len(config.recovery_delays) or remaining <= 0:
        facts.update(schedule_exhausted=used >= len(config.recovery_delays), budget_exhausted=remaining <= 0)
        return None, facts
    return min(config.recovery_delays[used], remaining), facts


class RulePolicy:
    def __init__(self, configuration=None):
        self._campaign_lock = threading.Lock()
        self.configuration = configuration or MonitoringConfig()
        if not isinstance(self.configuration, MonitoringConfig):
            raise ContractError('monitoring.configuration', 'invalid', 'MonitoringConfig required')
        from bytefault.core.validation import passive, unique, validate_followup_action
        passive(self.configuration, 'monitoring.configuration')
        for key in ('observations', 'disabled_rules', 'retry_rules', 'throttle_rules', 'healthy_rules'):
            unique(getattr(self.configuration, key), 'monitoring.configuration.' + key)
        rules = {rule.rule_id: rule for rule in builtins()}
        for supplied in self.configuration.rules:
            rule = ObservationRule(**dict(supplied)) if not isinstance(supplied, ObservationRule) else supplied
            if not isinstance(rule.rule_id, str) or not rule.rule_id:
                raise ContractError('monitoring.rules', 'invalid', 'nonempty identity required')
            if rule.kind in ('exact', 'prefix', 'length'):
                validate_predicate(rule.kind, rule.parameters)
            elif rule.kind == 'latency':
                if set(rule.parameters) != {'threshold'}:
                    raise ContractError('monitoring.rules.latency', 'invalid', 'explicit threshold required')
                number(rule.parameters['threshold'], 'monitoring.rules.latency.threshold')
            elif rule.kind not in {r.kind for r in builtins()} | {'late_correlated', 'late_unknown'}:
                raise ContractError('monitoring.rules.kind', 'invalid', rule.kind)
            if rule.disposition not in ('continue', 'hold', 'stop') or rule.on_expiry not in ('hold', 'stop', 'advance') or rule.on_failure not in ('hold', 'stop', 'advance'):
                raise ContractError('monitoring.rules.disposition', 'invalid', 'known continuation treatment required')
            if rule.disposition == 'hold' and not rule.conditions:
                raise ContractError('monitoring.rules.conditions', 'required', 'hold requires completion conditions')
            if rule.hold_timeout is not None:
                number(rule.hold_timeout, 'monitoring.rules.hold_timeout')
            unique(rule.conditions, 'monitoring.rules.conditions')
            for index, parameters in enumerate(rule.actions):
                validate_followup_action(MonitoringAction(str(index), rule.rule_id, 'configuration',
                    Correlation('configuration', 'configuration', 'configuration', 'configuration', 'configuration'),
                    'followup', parameters))
            rules[rule.rule_id] = rule
        if self.configuration.collect_cores and not any(
                rule.rule_id == 'service_failure' for rule in self.configuration.rules):
            rules['service_failure'] = service_failure_followup_rule(True)
        for key in ('disabled_rules', 'retry_rules', 'throttle_rules', 'healthy_rules'):
            if set(getattr(self.configuration, key)) - set(rules):
                raise ContractError('monitoring.configuration.' + key, 'unknown_rule', 'declared rule identities required')
        self.rules = tuple(r for key, r in rules.items() if key not in self.configuration.disabled_rules)
        self._history = OrderedDict()
        self._campaign = None
        self._last_summary = freeze({})

    def inspect(self):
        return freeze({'configuration': self.configuration, 'effective_rules': self.rules,
                       'statistical_baseline': 'unavailable'})

    def matches(self, rule, observation):
        t, kind = observation.transport, rule.kind
        if kind == 'missing_response':
            return observation.kind == 'action' and t.receive_requested and not t.received and t.receive_outcome in ('deadline', 'reset', 'eof', 'error')
        if kind == 'unrequested': return observation.kind == 'action' and not t.receive_requested
        if kind == 'send_failure': return observation.kind == 'action' and t.acceptance in ('partial', 'uncertain')
        if kind == 'connection_failure': return observation.kind == 'action' and t.acceptance == 'not_offered' and bool(t.error)
        if kind == 'service_failure': return observation.kind == 'service_check' and observation.service_readiness == 'unavailable'
        if kind == 'service_success': return observation.kind == 'service_check' and observation.service_readiness == 'available'
        if kind == 'positive_response': return observation.kind == 'action' and observation.response_meaning == 'positive'
        if kind == 'reset': return t.receive_outcome == 'reset' or t.error_type == 'ConnectionResetError'
        if kind == 'partial_response': return bool(t.received) and t.receive_outcome in ('reset', 'eof', 'deadline', 'error')
        if kind == 'heartbeat': return observation.kind == 'heartbeat'
        if kind == 'latency':
            return bool(t.received) and t.offer_completed_at is not None and t.first_response_at is not None and t.first_response_at - t.offer_completed_at > rule.parameters['threshold']
        if kind in ('exact', 'prefix', 'length'):
            result = predicate_match(kind, rule.parameters, t)
            return result is not None and result == (rule.parameters.get('expect', 'mismatch') == 'match')
        if kind in ('late_correlated', 'late_unknown'):
            return observation.kind == 'late_response' and self.correlated_late(observation) == (kind == 'late_correlated')
        return False

    def correlated_late(self, observation):
        prior = self._history.get(observation.prior_observation_id)
        return prior is not None and prior.correlation == observation.correlation

    def readiness_eligible(self, observation):
        return (observation.kind in self.configuration.observations and
                any(rule.kind == 'service_success' and self.matches(rule, observation) for rule in self.rules))

    def evaluate(self, observation):
        with self._campaign_lock:
            return self._evaluate_locked(observation)

    def _evaluate_locked(self, observation):
        assessments, actions, selected = [], [], []
        enabled = observation.kind in self.configuration.observations
        state = self._campaign
        repeated_recovery_failure = bool(state and state['recovering'] and
            observation.kind == 'service_check' and observation.parameters.get('purpose') == 'recovery' and
            observation.service_readiness == 'unavailable' and
            observation.correlation == state['recovery_origin'])
        if enabled and observation.kind == 'late_response':
            known = self.correlated_late(observation)
            prior = self._history.get(observation.prior_observation_id)
            missing = known and any(r.kind == 'missing_response' and self.matches(r, prior) for r in self.rules)
            assessments.append(Assessment(str(uuid4()), observation.observation_id, observation.correlation,
                'late_association', ('missing_response_resolved' if missing and observation.transport.received else
                    'correlated_additional_response' if known else 'late_response_unknown'),
                'original_attempt_only' if known else 'association_unknown',
                {'prior_observation_id': observation.prior_observation_id, 'does_not_undo_prior_actions': True}))
        if enabled:
            for rule in self.rules:
                if self.matches(rule, observation):
                    selected.append(rule)
                    assessments.append(Assessment(str(uuid4()), observation.observation_id, observation.correlation,
                        rule.rule_id, rule.classification, rule.uncertainty,
                        dict(rule.parameters, response_boundary=observation.transport.response_boundary,
                             supporting_observation=observation.observation_id)))
                    for index, parameters in enumerate(rule.actions):
                        # Recovery checks belong to the first failed check's
                        # episode. Retain their facts but do not dispatch its
                        # collection/report action a second time.
                        if repeated_recovery_failure and rule.kind == 'service_failure':
                            continue
                        if rule.parameters.get('delayed_followup') and observation.parameters.get('purpose') not in ('periodic', 'final', 'retry_check'):
                            continue
                        actions.append(MonitoringAction(f'{observation.observation_id}:{rule.rule_id}:{index}',
                            observation.observation_id, observation.observation_id, observation.correlation,
                            'followup', parameters))
        # Late reassessment cannot independently change a current execution gate.
        governed = ([r for r in selected if r.kind in ('late_correlated', 'late_unknown')]
                    if observation.kind == 'late_response' else selected)
        if repeated_recovery_failure:
            governed = [r for r in governed if r.kind != 'service_failure' or r.disposition == 'stop']
        chosen = next((r for r in governed if r.disposition == 'stop'),
            next((r for r in governed if r.disposition == 'hold'), None))
        conditions = tuple(dict.fromkeys(c for r in governed for c in r.conditions))
        disposition = chosen.disposition if chosen is not None else 'continue'
        self._history[observation.observation_id] = observation
        while len(self._history) > self.configuration.history_capacity:
            self._history.popitem(last=False)
        return MonitoringDecision(str(uuid4()), observation.observation_id, observation.correlation,
            disposition, 'awaited' if disposition == 'hold' else 'nonblocking', conditions,
            tuple(assessments), tuple(actions), reason=('configured observation rules: ' +
                ', '.join(rule.rule_id for rule in selected) +
                ('; repeated recovery check for ' + state['recovery_origin_observation']
                 if repeated_recovery_failure else '')) if selected else 'unmatched or disabled observation retained',
            hold_timeout=chosen.hold_timeout if chosen else None,
            on_expiry=chosen.on_expiry if chosen else 'hold', on_failure=chosen.on_failure if chosen else 'hold')

    def begin_campaign(self, identity):
        with self._campaign_lock:
            self._begin_campaign_locked(identity)

    def _begin_campaign_locked(self, identity):
        if self._campaign is not None:
            raise ContractError('monitoring.campaign', 'busy', 'one active campaign per policy')
        self._campaign = {'id': identity, 'test': None, 'counted': False, 'consecutive': 0,
            'last_crash_test': None, 'checked': 0, 'window_start': None, 'processed': set(),
            'recovering': False, 'recovery_index': 0, 'recovery_elapsed': 0.0,
            'recovery_origin': None, 'recovery_origin_observation': None,
            'unrecovered': False, 'throttled': False, 'failures': 0, 'service_checks': 0,
            'failed_tests': 0, 'failed_recorded': False, 'attempt': None,
            'service_retry_check': False, 'delayed_retry_rules': (), 'terminal_failure': {},
            'throttle_trigger': None}
        self._campaign['setup_failed_candidates'] = 0

    def end_campaign(self):
        with self._campaign_lock:
            self._last_summary = self.summary()
            self._campaign = None
            return self._last_summary

    def summary(self):
        if self._campaign is None: return self._last_summary
        return freeze({k: self._campaign[k] for k in ('id', 'consecutive', 'unrecovered', 'throttled', 'failures', 'service_checks', 'failed_tests', 'setup_failed_candidates')})

    def decide_setup(self, context, observations):
        from bytefault.core.contracts import CampaignSetupContext
        from bytefault.core.validation import passive, typed
        typed(context, CampaignSetupContext, 'monitoring.setup_context')
        passive(context, 'monitoring.setup_context')
        if context.correlation.iteration_id is not None:
            raise ContractError('monitoring.setup_context', 'invalid', 'setup does not invent a selected iteration')
        config, state = self.configuration, self._campaign
        if state is None or state['id'] != context.campaign_id:
            raise ContractError('monitoring.campaign', 'unavailable', 'campaign must be initialized')
        facts = {'governed_actions': context.governed_actions, 'declared_target': context.declared_target,
            'continuation_available': context.continuation_available,
            'used_retries': context.used_retries, 'recovery_elapsed': context.elapsed,
            'retry_count': config.retries, 'reconnect_attempts': config.reconnect_attempts,
            'reconnect_delay': config.reconnect_delay, 'advance_candidate': False, 'failed_setup': False}
        def directive(operation='advance', wait=0, reason=''):
            if facts['failed_setup'] and not context.failure_recorded:
                state['setup_failed_candidates'] += 1
            return CampaignDirective(str(uuid4()), context.campaign_id, None, context.correlation,
                operation, wait, reason, facts=facts, scope='setup', candidate_id=context.candidate_id)
        action = next((o for o in reversed(observations) if o.correlation == context.correlation), None)
        matched = {r.rule_id for r in self.rules if action is not None and
            action.kind in config.observations and self.matches(r, action)}
        triggered = bool(matched.intersection(config.retry_rules)) and context.response_meaning != 'negative'
        if context.reconnect_exhausted:
            facts.update(advance_candidate=True, failed_setup=True, reconnect_exhausted=True,
                unused_retries=max(0, config.retries - context.used_retries))
            return directive(reason='setup connection reopening exhausted; advance candidate')
        if not triggered:
            if not context.continuation_available:
                facts.update(advance_candidate=True, failed_setup=True)
            return directive(reason='declared setup path continuation' if context.continuation_available else
                'declared setup did not reach governed action; advance candidate')
        wait, window = retry_window(config, context.used_retries, context.elapsed)
        facts.update(window)
        if wait is None:
            facts.update(advance_candidate=True, failed_setup=True)
            return directive(reason='setup retry count/schedule/budget exhausted; advance candidate')
        return directive('retry', wait, 'same prepared candidate setup retry')

    def probe(self, context, observation, purpose, delay):
        config, state = self.configuration, self._campaign
        in_band = config.in_band
        receive = ReceiveRequest(**dict(in_band['receive'])) if 'receive' in in_band else ReceiveRequest(requested=False)
        return ProbeRequest(str(uuid4()), observation.observation_id, context.correlation,
            in_band.get('prepared', b''), receive,
            'same_connection' if config.health_check_mode == 'in_band' else 'service_connect',
            delay=delay, timeout=5.0 if purpose == 'recovery' else 3.0, purpose=purpose,
            window=tuple(dict.fromkeys(v for v in (state['window_start'], context.test_id) if v)),
            predicate=in_band.get('predicate', {}))

    def preview_attempt(self, context, observations):
        """Inspect a pending decision without advancing campaign policy state."""
        import copy
        state = copy.deepcopy(self._campaign)
        try:
            return self.decide_attempt(context, observations)
        finally:
            self._campaign = state

    def decide_attempt(self, context, observations):
        config, state = self.configuration, self._campaign
        if state is None or state['id'] != context.campaign_id:
            raise ContractError('monitoring.campaign', 'unavailable', 'campaign must be initialized')
        if state['test'] != context.test_id:
            state.update(test=context.test_id, counted=False, processed=set(), recovering=False,
                         recovery_index=0, recovery_elapsed=0.0, failed_recorded=False,
                         recovery_origin=None, recovery_origin_observation=None,
                         attempt=None, service_retry_check=False, delayed_retry_rules=(), terminal_failure={})
        if state['attempt'] != context.attempt_number:
            state.update(attempt=context.attempt_number, delayed_retry_rules=())
        if state['window_start'] is None and context.executed_test_number > state['checked']:
            state['window_start'] = context.test_id
        for observation in observations:
            if observation.observation_id in state['processed'] or observation.kind == 'late_response':
                continue
            state['processed'].add(observation.observation_id)
            matched_rules = tuple(r for r in self.rules
                if observation.kind in config.observations and self.matches(r, observation))
            rules = {r.rule_id for r in matched_rules}
            service_failure = any(r.kind == 'service_failure' for r in matched_rules)
            service_success = any(r.kind == 'service_success' for r in matched_rules)
            delayed = observation.kind == 'service_check' and observation.parameters.get('purpose') in ('periodic', 'final', 'retry_check')
            throttle = next((r for r in matched_rules if r.rule_id in config.throttle_rules and
                (delayed or r.kind != 'service_failure')), None)
            if throttle is not None and not state['counted']:
                state['consecutive'] += 1
                state['failures'] += 1
                state['counted'], state['last_crash_test'] = True, context.test_id
                state['throttle_trigger'] = (throttle.rule_id, throttle.kind)
            if rules.intersection(config.healthy_rules) and state['last_crash_test'] != context.test_id:
                state['consecutive'] = 0
            if observation.kind == 'service_check':
                state['service_checks'] += 1
                if observation.parameters.get('purpose') == 'recovery':
                    state['recovery_elapsed'] += observation.parameters.get('delay', 0.0)
                    state['recovery_index'] += 1
                    if service_success:
                        state['recovering'] = False
                elif delayed:
                    state['checked'] = context.executed_test_number
                    state['window_start'] = None
                    state['delayed_retry_rules'] = tuple(sorted(rules.intersection(config.retry_rules)))
                    if service_failure:
                        state.update(recovering=True, recovery_index=0, recovery_elapsed=0.0,
                                     recovery_origin=observation.correlation,
                                     recovery_origin_observation=observation.observation_id,
                                     service_retry_check=True)
                    else:
                        state['service_retry_check'] = False
        state['throttled'] = state['throttled'] or bool(config.crash_throttle and state['consecutive'] >= config.crash_throttle)
        facts = {'consecutive': state['consecutive'], 'retry_count': config.retries,
            'recovery_elapsed': context.recovery_elapsed, 'reconnect_attempts': config.reconnect_attempts,
            'reconnect_delay': config.reconnect_delay, 'failed_test': False}
        def directive(operation='advance', wait=0, reason='', probes=()):
            if facts.get('failed_test') and not state['failed_recorded']:
                state['failed_tests'] += 1
                state['failed_recorded'] = True
            return CampaignDirective(str(uuid4()), context.campaign_id, context.test_id, context.correlation,
                operation, wait, reason, state['throttled'], state['unrecovered'], facts, probes)
        if context.reconnect_exhausted:
            state['unrecovered'] = True
            facts.update(reconnect_exhausted=True, failed_test=True, unused_retries=max(0, config.retries - context.attempt_number + 1))
            state['terminal_failure'] = dict(facts)
            return directive(reason='connection reopening attempts exhausted; advance failed')
        if state['recovering']:
            index, remaining = state['recovery_index'], config.recovery_budget - state['recovery_elapsed']
            if index < len(config.recovery_delays) and remaining > 0:
                delay = min(config.recovery_delays[index], remaining)
                return directive(reason='recovery observation requested', probes=(self.probe(context, observations[-1], 'recovery', delay),))
            state['recovering'], state['unrecovered'] = False, True
            facts.update(failed_test=True, recovery_schedule_exhausted=index >= len(config.recovery_delays),
                         recovery_budget_exhausted=remaining <= 0)
        if state['throttled']:
            rule_id, kind = state['throttle_trigger']
            facts['throttle_trigger'] = {'rule_id': rule_id, 'kind': kind}
            return directive('stop', reason=f'consecutive tests matching throttle rule {rule_id} ({kind}) reached threshold')
        actual_offer = any(o.kind == 'action' and o.transport.acceptance != 'not_offered' for o in observations)
        delayed_done = any(o.kind == 'service_check' and o.parameters.get('purpose') in ('periodic', 'final', 'retry_check') for o in observations)
        retry_due = state['service_retry_check'] and context.attempt_number > 1 and actual_offer and not delayed_done
        due = (context.executed_test_number > state['checked'] and (
            context.final or context.executed_test_number % max(1, config.check_interval) == 0)) or retry_due
        if due and observations and (context.final or context.attempt_number == 1 or retry_due):
            if config.health_check_mode == 'disabled':
                state['checked'] = context.executed_test_number
                facts['service_check'] = 'disabled_unobserved'
            else:
                return directive(reason='scheduled service observation', probes=(self.probe(context, observations[0],
                    'retry_check' if retry_due else 'final' if context.final else 'periodic', config.delayed_check),))
        if state['terminal_failure']:
            facts.update(state['terminal_failure'])
            return directive(reason='previous retry exhaustion retained; advance failed')
        action = next((o for o in observations if o.kind == 'action'), None)
        matched = {r.rule_id for r in self.rules if action is not None and action.kind in config.observations and self.matches(r, action)}
        retry = bool(matched.intersection(config.retry_rules)) and context.response_meaning != 'negative'
        retry = retry or bool(state['delayed_retry_rules'])
        if not retry:
            return directive(reason='no configured retry trigger')
        wait, window = retry_window(config, context.attempt_number - 1, context.recovery_elapsed)
        facts.update(window)
        if wait is None:
            facts.update(failed_test=True)
            state['terminal_failure'] = dict(facts)
            return directive(reason='test retry count/schedule/budget exhausted; advance failed')
        return directive('retry', wait, 'same immutable test retry')
