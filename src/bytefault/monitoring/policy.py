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

"""Monitoring port with configured rule and fixed-disposition policies."""
from collections import deque
from dataclasses import replace
from uuid import uuid4
import threading

from bytefault.core.contracts import MonitoringDecision, Observation, ContractError
from bytefault.core.validation import typed, passive, unique, resolve_wait_obligations


class ConfiguredPolicy:
    """An explicit fixed contract policy, not a crash detector.

    It applies a caller-selected disposition without crash classification.
    All transport facts are retained regardless of the selected disposition.
    """
    def __init__(self, disposition='continue', *, mode='nonblocking', conditions=()):
        self.disposition, self.mode = disposition, mode
        self.conditions = tuple(conditions)

    def evaluate(self, observation):
        return MonitoringDecision(str(uuid4()), observation.observation_id,
            observation.correlation, self.disposition, self.mode, self.conditions,
            reason='explicit fixed-disposition policy; no crash classification')


class Monitoring:
    def __init__(self, policy=None, *, history_capacity=128, configuration=None):
        if not isinstance(history_capacity, int) or history_capacity < 1:
            raise ValueError('positive Monitoring history capacity required')
        if policy is not None and configuration is not None:
            raise ContractError('monitoring.configuration', 'conflict', 'choose explicit policy or configuration')
        from bytefault.monitoring.rules import RulePolicy
        self.policy = policy if policy is not None else RulePolicy(configuration)
        self.observations = deque(maxlen=history_capacity)
        self.decisions = deque(maxlen=history_capacity)
        self.history_dropped = 0
        self._continuations, self._continuation_lock = {}, threading.RLock()

    def attach_continuation(self, run_id, current_hold, completion):
        """Application attaches enforcement; Monitoring supplies actual readiness."""
        with self._continuation_lock:
            self._continuations[run_id] = (current_hold, completion)
        def detach():
            with self._continuation_lock:
                self._continuations.pop(run_id, None)
        return detach

    def inspect(self):
        inspect = getattr(self.policy, 'inspect', None)
        return inspect() if inspect else {'policy': type(self.policy).__name__, 'configuration': 'caller supplied'}

    def begin_campaign(self, identity):
        begin = getattr(self.policy, 'begin_campaign', None)
        if begin:
            begin(identity)

    def end_campaign(self):
        end = getattr(self.policy, 'end_campaign', None)
        return end() if end else {}

    def summary(self):
        summary = getattr(self.policy, 'summary', None)
        return summary() if summary else {}

    def service_readiness(self, probe, fact):
        from bytefault.monitoring.configuration import predicate_match, validate_predicate
        parameters = dict(probe.predicate)
        kind = parameters.pop('kind', None)
        validate_predicate(kind, parameters)
        result = predicate_match(kind, parameters, fact)
        if result is None:
            return 'unknown'
        expected = parameters.get('expect', 'match') == 'match'
        return 'available' if result == expected else 'unavailable'

    def decide_attempt(self, context, observations):
        decide = getattr(self.policy, 'decide_attempt', None)
        if decide:
            return decide(context, observations)
        from bytefault.core.contracts import CampaignDirective
        return CampaignDirective(str(uuid4()), context.campaign_id, context.test_id,
            context.correlation, 'advance', reason='explicit policy supplies no automatic retry')

    def decide_setup(self, context, observations):
        decide = getattr(self.policy, 'decide_setup', None)
        if decide:
            return decide(context, observations)
        from bytefault.core.contracts import CampaignDirective
        return CampaignDirective(str(uuid4()), context.campaign_id, None, context.correlation,
            'advance', reason='explicit policy supplies no automatic setup retry',
            facts={'advance_candidate': not context.continuation_available,
                   'failed_setup': not context.continuation_available},
            scope='setup', candidate_id=context.candidate_id)

    def observe(self, observation):
        typed(observation, Observation, 'monitoring.observation')
        passive(observation, 'monitoring.observation')
        if len(self.observations) == self.observations.maxlen:
            self.history_dropped += 1
        self.observations.append(observation)
        decision = self.policy.evaluate(observation)
        if not isinstance(decision, MonitoringDecision):
            raise ContractError('monitoring', 'invalid_decision', 'typed decision required')
        passive(decision, 'monitoring.decision')
        if not decision.decision_id:
            raise ContractError('monitoring', 'invalid_decision', 'nonempty decision identity required')
        unique(decision.required_conditions, 'monitoring.decision.conditions')
        if decision.correlation != observation.correlation or decision.observation_id != observation.observation_id:
            raise ContractError('monitoring', 'correlation', 'decision does not identify supplied facts')
        if decision.disposition not in ('continue', 'hold', 'stop') or decision.mode not in ('awaited', 'nonblocking'):
            raise ContractError('monitoring', 'invalid_decision', 'unsupported disposition/mode')
        if decision.disposition == 'hold' and (decision.mode != 'awaited' or not decision.required_conditions):
            raise ContractError('monitoring', 'invalid_decision', 'hold needs explicit awaited conditions')
        if decision.disposition == 'continue' and decision.mode == 'awaited' and decision.required_conditions:
            raise ContractError('monitoring', 'invalid_decision', 'pending awaited conditions require hold')
        for value in decision.assessments + decision.actions + decision.probes:
            if value.correlation != observation.correlation or value.observation_id != observation.observation_id:
                raise ContractError('monitoring', 'correlation', 'selected work does not identify supplied facts')
        obligations = resolve_wait_obligations(decision)
        if decision.obligations and decision.obligations != obligations:
            raise ContractError('monitoring.decision.obligations', 'inconsistent_wait',
                                'declared obligations do not cover selected required actions')
        decision = replace(decision, obligations=obligations)
        self.decisions.append(decision)
        eligible = getattr(self.policy, 'readiness_eligible', None)
        if eligible is not None and eligible(observation):
            with self._continuation_lock:
                attachment = self._continuations.get(observation.correlation.run_id)
            if attachment is not None:
                current, complete = attachment
                hold = current()
                if hold is not None and hold.correlation == observation.correlation:
                    from bytefault.core.contracts import MonitoringCompletion
                    for obligation in hold.obligations:
                        if obligation.condition == 'readiness' and obligation.followup_action_id is None:
                            complete(MonitoringCompletion(str(uuid4()), hold.decision_id,
                                hold.observation_id, hold.correlation, 'readiness', 'succeeded',
                                observation.observation_id))
        return decision
