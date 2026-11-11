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

"""Campaign ownership over the ordinary conversation engine and transport.

Preparation is a supplied local iterator. Selection follows complete construction,
so an omitted family advances exactly the same source decisions as a full run.
"""
from dataclasses import replace
import math

from bytefault.core.contracts import (CampaignOptions, CampaignResult, CampaignConnection,
    ContractError, TransportCleanup, CampaignPolicyContext, CampaignDirective, Correlation,
    PreparedRow, ActionResult, CampaignSetupContext, ConversationResult, freeze)
from bytefault.core.validation import passive
from bytefault.core.records import RequiredSaveFailure, RequiredServiceSaveFailure


def case_numbers(text):
    """Positive comma-separated numbers/inclusive ranges in source order."""
    if not isinstance(text, str) or not text.strip():
        raise ContractError('campaign.selected_cases', 'invalid', 'positive numbers/ranges required')
    numbers = set()
    try:
        for field in text.split(','):
            limits = field.strip().split('-')
            first = int(limits[0])
            last = int(limits[1]) if len(limits) == 2 else first
            if len(limits) > 2 or first < 1 or last < first:
                raise ValueError('ordered positive range required')
            numbers.update(range(first, last + 1))
    except ValueError as error:
        raise ContractError('campaign.selected_cases', 'invalid', str(error)) from error
    return tuple(sorted(numbers))


def selected_case(options, number):
    return number > options.skip and (not options.selected_cases or number in options.selected_cases)


def validate_campaign(options, plan):
    if not isinstance(options, CampaignOptions):
        raise ContractError('campaign', 'invalid', 'typed CampaignOptions required')
    passive(options, 'campaign')
    if (not isinstance(options.selected_cases, tuple) or
        any(type(n) is not int or n < 1 for n in options.selected_cases) or
        len(set(options.selected_cases)) != len(options.selected_cases)):
        raise ContractError('campaign.selected_cases', 'invalid', 'unique positive ordinals required')
    if type(options.skip) is not int or options.skip < 0 or (options.case_limit is not None and
        (type(options.case_limit) is not int or options.case_limit < 0)):
        raise ContractError('campaign', 'invalid', 'nonnegative skip and optional case limit required')
    if (not options.variants or not isinstance(options.variants, tuple) or
        len(set(options.variants)) != len(options.variants) or
        any(v not in ('normal', 'length4') for v in options.variants)):
        raise ContractError('campaign.variants', 'invalid', 'ordered distinct normal/length4 variants required')
    connection = options.connection
    if not isinstance(connection, CampaignConnection) or connection.mode not in ('fresh', 'persistent'):
        raise ContractError('campaign.connection', 'invalid', 'fresh or persistent contract required')
    ids = tuple(a.action_id for a in plan.actions)
    setup_ids = set()
    for index, step in enumerate(connection.retry_setup):
        path = f'campaign.connection.retry_setup.{index}'
        if step.action_id in setup_ids:
            raise ContractError(path + '.action_id', 'duplicate_identity',
                                'one explicit retry setup choice per action required')
        if step.action_id not in ids:
            raise ContractError(path + '.action_id', 'unknown_action',
                                'retry setup action must name a declared plan action')
        if step.choice not in ('recorded', 'declared_seed'):
            raise ContractError(path + '.choice', 'invalid_choice', 'recorded or declared_seed required')
        setup_ids.add(step.action_id)
    if connection.mode == 'persistent' and len(ids) > 1:
        if (connection.reuse_entry_action not in ids or not connection.reusable_after or
            any(a not in ids for a in connection.reusable_after) or not connection.reusable_meanings):
            raise ContractError('campaign.connection', 'unavailable',
                'multi-action reuse needs declared entry, allowed terminals and observed meanings')
    if any(m not in ('positive', 'negative', 'unknown', 'uninterpreted') for m in connection.reusable_meanings):
        raise ContractError('campaign.connection.reusable_meanings', 'invalid', 'declared response meanings required')
    return options


class CampaignMixin:
    def _preflight_required_collection_spacing(self, plan, *, entry_action=None):
        if not self.transport.request.connection_delay:
            return
        from bytefault.core.validation import collection_blocks_required_followup
        rules = getattr(getattr(self.monitoring, 'policy', None), 'rules', ())
        if not any(rule.kind == 'unrequested' and rule.disposition == 'hold' and
                collection_blocks_required_followup(rule.actions, rule.conditions)
                for rule in rules):
            return
        actions = plan.actions
        by_id = {action.action_id: (index, action) for index, action in enumerate(actions)}
        pending = [entry_action or plan.entry_action or actions[0].action_id]
        seen = set()
        while pending:
            identity = pending.pop()
            if identity in seen or identity not in by_id:
                continue
            seen.add(identity)
            index, action = by_id[identity]
            continuation = ((actions[index + 1].action_id if index + 1 < len(actions) else None)
                if action.next_action == '__ordered__' else action.next_action)
            targets = tuple(target for target in (
                continuation, action.unknown_target, *(edge.target for edge in action.edges)) if target)
            if targets and not action.receive.requested and not action.edges:
                self._required_save('monitoring_incompatibility', {
                    'reason': 'known unrequested-action collection hold conflicts with same-socket continuation and connection delay',
                    'action_id': action.action_id, 'next_action': targets[0],
                    'connection_delay': self.transport.request.connection_delay})
                raise ContractError('monitoring.collection', 'hold_conflict',
                    'required collection hold with nonzero connection delay conflicts with same-socket conversation continuation')
            pending.extend(targets)

    def _campaign_snapshot_setup(self):
        last = getattr(self, '_campaign_last_attempt', None)
        if last is not None and last[0].conversation_id == self._campaign_setup_state['candidate_id']:
            self._campaign_last_setup_state = dict(self._campaign_setup_state)

    def _campaign_after_setup(self, request, result, target, governed, *, reconnect_exhausted=False, path_available=None):
        state = self._campaign_setup_state
        self._campaign_setup_pending = result
        correlation = Correlation(request.run_id, request.case_id, request.conversation_id,
            result.action_id, result.attempt_id, None, result.stage_id)
        available = (result.transport.acceptance == 'accepted' and not result.transport.error and
                     (target is not None or not governed))
        if path_available is not None:
            available = path_available
        context = CampaignSetupContext(request.run_id,
            f'{self.transport.request.host}:{self.transport.request.port}', state['candidate_id'],
            correlation, tuple(governed), state['used'], state['elapsed'], result.response_meaning,
            target, available, reconnect_exhausted, state['failed'])
        decide = getattr(self.monitoring, 'decide_setup', None)
        directive = (decide(context, tuple(self._campaign_observations)) if decide else
            CampaignDirective('setup:' + result.attempt_id, request.run_id, None, correlation, 'advance',
                facts={'advance_candidate': not available, 'failed_setup': not available},
                scope='setup', candidate_id=state['candidate_id']))
        passive(directive, 'campaign.setup_directive')
        if (not isinstance(directive, CampaignDirective) or directive.scope != 'setup' or
                directive.test_id is not None or directive.candidate_id != state['candidate_id'] or
                directive.campaign_id != request.run_id or directive.correlation != correlation or
                directive.operation not in ('advance', 'retry', 'hold', 'stop') or directive.probes or
                type(directive.wait_seconds) not in (int, float) or not math.isfinite(directive.wait_seconds) or
                directive.wait_seconds < 0):
            raise ContractError('campaign.setup_directive', 'invalid', 'correlated passive setup continuation required')
        self._required_save('campaign_setup_directive', {'context': context, 'directive': directive})
        if directive.operation == 'stop':
            self.continuation.stop(directive, cause='setup_directive')
        if directive.operation == 'hold':
            if self.continuation.hold is None:
                raise ContractError('campaign.setup_directive', 'missing_obligation', 'hold requires an installed obligation')
            self._await_monitoring()
        if directive.facts.get('failed_setup'):
            state['failed'] = True
        if directive.operation == 'advance' and directive.facts.get('advance_candidate'):
            self._campaign_setup_failed = True
            self._campaign_setup_failure = result
            self._campaign_setup_last_directive = directive
            self._campaign_setup_reconnect_exhausted = reconnect_exhausted
            self._campaign_advance_failure = True
            self._campaign_failed_current = True
            self._campaign_failed_test = True
            state['failure'] = result
            state['failure_directive'] = directive
            state['reconnect_exhausted'] = reconnect_exhausted
        self._campaign_snapshot_setup()
        return directive

    def _campaign_after_attempt(self, request, result, attempt_number, *, final=False, reconnect_exhausted=False,
                                retained=True, path_results=None, defer_new_connection=False,
                                deferred_context=None, selected_directive=None):
        if result.iteration_id != self._campaign_current_test:
            self._campaign_current_test = result.iteration_id
            self._campaign_retry_elapsed = self._campaign_retry_elapsed_by_test.get(result.iteration_id, 0.0)
        if (deferred_context is None and result.transport.acceptance != 'not_offered'
                and result.iteration_id not in self._campaign_test_ordinals):
            self._campaign_executed_tests += 1
            self._campaign_test_ordinals[result.iteration_id] = self._campaign_executed_tests
        decide = getattr(self.monitoring, 'decide_attempt', None)
        if decide is None:
            return None
        correlation = Correlation(request.run_id, request.case_id, request.conversation_id,
            result.action_id, result.attempt_id, result.iteration_id, result.stage_id)
        context = (replace(deferred_context, recovery_elapsed=self._campaign_retry_elapsed)
            if deferred_context is not None else CampaignPolicyContext(request.run_id,
            f'{self.transport.request.host}:{self.transport.request.port}', result.iteration_id,
            correlation, attempt_number, result.response_meaning, self.transport.clock(),
            recovery_elapsed=self._campaign_retry_elapsed,
            executed_test_number=self._campaign_test_ordinals.get(result.iteration_id,
                self._campaign_executed_tests), final=final,
            reconnect_exhausted=reconnect_exhausted))
        with self._action_lock:
            if final and retained:
                self._campaign_observations = list(self._campaign_last_observations)
                self._record_context = dict(self._campaign_last_record_context)
                self._record_request = request
                self._available_materializations = self._campaign_last_materializations
                self._campaign_setup_state = dict(self._campaign_last_setup_state)
        expected_connection = (self._campaign_last_connection if final and retained else
                               getattr(self, '_connection_epoch', 0))
        if defer_new_connection:
            preview = getattr(getattr(self.monitoring, 'policy', None), 'preview_attempt', None)
            proposed = (preview(context, tuple(self._campaign_observations)) if preview is not None else
                decide(context, tuple(self._campaign_observations)))
            if preview is None:
                selected_directive = proposed
            if self._campaign_deferred_attempts and not proposed.probes:
                if proposed.operation == 'stop':
                    self._required_save('campaign_directive', {'context': context,
                        'directive': proposed, 'prior_assessment_pending': True})
                    self.continuation.stop(proposed, cause='campaign_directive')
                    return proposed
                if proposed.operation == 'retry':
                    raise ContractError('campaign.defer', 'unavailable',
                        'immediate action retry after an earlier deferred service check cannot be ordered faithfully')
            # An action-level hold without a new-connection probe is already
            # gated by its correlated observation obligation. Resolve it now;
            # replaying it after that obligation completes creates a second,
            # impossible hold on the same action.
            immediate_hold = proposed.operation == 'hold' and not proposed.probes
            if not immediate_hold and (self._campaign_deferred_attempts or any(
                    probe.kind == 'service_connect' for probe in proposed.probes)):
                deferred_at = self.transport.clock()
                self._campaign_deferred_attempts.append((request, result, attempt_number,
                    context, tuple(self._campaign_observations), dict(self._record_context),
                    tuple(path_results or ()), deferred_at, selected_directive))
                self._required_save('campaign_assessment_deferred', {'attempt_id': result.attempt_id,
                    'reason': 'new-connection policy follows conversation close',
                    'proposed_probes': proposed.probes,
                    'later_actions_may_precede_decision': True,
                    'deferred_at': deferred_at})
                return None
        new_probe_hold = False
        while True:
            directive = selected_directive or decide(context, tuple(self._campaign_observations))
            selected_directive = None
            if (not isinstance(directive, CampaignDirective) or directive.correlation != correlation or
                directive.campaign_id != request.run_id or directive.test_id != result.iteration_id or
                directive.scope != 'test' or directive.candidate_id not in (None, request.conversation_id) or
                directive.operation not in ('advance', 'retry', 'stop', 'hold') or
                type(directive.wait_seconds) not in (int, float) or not math.isfinite(directive.wait_seconds)
                or directive.wait_seconds < 0):
                raise ContractError('campaign.directive', 'invalid', 'correlated passive continuation decision required')
            passive(directive, 'campaign.directive')
            self._required_save('campaign_directive', {'context': context, 'directive': directive})
            if directive.operation == 'stop':
                self.continuation.stop(directive, cause='campaign_directive')
            if not directive.probes or directive.operation == 'stop':
                break
            for probe in directive.probes:
                if probe.correlation != correlation:
                    raise ContractError('campaign.probe', 'correlation', 'probe must identify the governed attempt')
                if probe.kind == 'service_connect' and self.socket is not None:
                    cleanup = self.disconnect(phase='new_connection_check')
                    self._required_save('transport_cleanup', {'cleanup': cleanup,
                        'purpose': 'release original socket before new-connection service check',
                        'probe_id': probe.probe_id})
                    if cleanup.outcome == 'uncertain' or cleanup.pacing_error:
                        raise ContractError('campaign.probe', 'cleanup_failed',
                            'original test connection could not be confirmed closed before service check')
                self._campaign_probe_permission = probe
                self._campaign_probe_connection = expected_connection
                prior_hold = self.continuation.hold
                try:
                    self.execute_probe(probe)
                finally:
                    self._campaign_probe_permission = None
                if (self.continuation.hold is not None and
                        self.continuation.hold is not prior_hold):
                    new_probe_hold = True
                if self._should_stop or self.storage_failure or self.continuation.stopped:
                    return replace(directive, operation='stop', probes=(), reason='engine stopped during service observation')
        if (directive.unrecovered and
                (directive.facts.get('recovery_schedule_exhausted') or
                 directive.facts.get('recovery_budget_exhausted'))):
            hold = self.continuation.hold
            if (hold is not None and hold.correlation == correlation and
                    any(item.condition == 'readiness' and item.followup_action_id is None
                        for item in hold.obligations) and
                    ('readiness', None) not in self.continuation.satisfied):
                from uuid import uuid4
                from bytefault.core.contracts import MonitoringCompletion
                self.complete_monitoring(MonitoringCompletion(str(uuid4()), hold.decision_id,
                    hold.observation_id, hold.correlation, 'readiness', 'failed', directive.decision_id))
        if new_probe_hold and self.continuation.hold is not None:
            self._await_monitoring()
            if self._should_stop or self.storage_failure or self.continuation.stopped:
                return replace(directive, operation='stop', probes=(), reason='engine stopped during required monitoring follow-up')
        if directive.operation == 'hold':
            if self.continuation.hold is None:
                raise ContractError('campaign.directive', 'missing_obligation',
                                    'Monitoring hold requires a correlated continuation obligation')
            self._await_monitoring()
        self._campaign_advance_failure = directive.operation == 'advance'
        self._campaign_failed_current = bool(directive.facts.get('failed_test'))
        if directive.operation == 'advance' and directive.facts.get('failed_test'):
            self._campaign_failed_test = True
        self._campaign_last_attempt = (request, result, attempt_number)
        self._campaign_last_connection = expected_connection
        if path_results is not None:
            self._campaign_last_path = tuple(path_results)
            self._campaign_last_record_context = dict(self._record_context)
            self._campaign_last_materializations = self._available_materializations
            self._campaign_last_setup_state = dict(self._campaign_setup_state)
        self._campaign_last_observations = tuple(self._campaign_observations)
        self._campaign_last_directive = directive
        return directive

    def _campaign_setup_failure_outcome(self):
        failure = self._campaign_setup_failure
        return ('transport_failed' if failure.transport.error or
            failure.transport.acceptance != 'accepted' or self._campaign_setup_reconnect_exhausted else
            'unknown' if failure.response_meaning == 'unknown' else 'monitoring_failed')

    def _campaign_interruption(self):
        if self.storage_failure:
            return 'recording_failed', str(self.storage_failure['reason'])
        if self._should_stop:
            return 'stopped', 'operator stop requested'
        if self.continuation.stopped:
            gate = self.continuation
            decision = gate.stop_decision
            reason = ('Monitoring ' + (gate.stop_cause or 'stop') + ': ' + decision.decision_id + ': ' +
                (gate.stop_reason or '') if decision is not None else
                'Monitoring ' + (gate.stop_cause or 'stop') + ': ' +
                (gate.stop_reason or 'no stopping decision was supplied'))
            return 'monitoring_stopped', reason
        return None

    def _campaign_retry_terminal(self, request, results, outcome, reason):
        with self._action_lock:
            cleanup = self.disconnect(phase='retry_setup_terminal')
            self._required_save('transport_cleanup', {'cleanup': cleanup, 'purpose': 'retry_setup_terminal',
                'actual_connection_context': getattr(self, '_connection_context', {})})
            reached = {a.action_id for a in results if a.transport.acceptance != 'not_offered'}
            terminal = ConversationResult(request.run_id, request.case_id, request.conversation_id,
                request.row.row_id, outcome, tuple(results), tuple(a.action_id for a in request.plan.actions),
                tuple((identity, reason) for identity in request.selected_actions if identity not in reached),
                reason, cleanup, outcome, reason)
            self._conversation_terminal(request, terminal)
            self.last_conversation_result = terminal
            return terminal

    def _campaign_retry_setup(self, request, current, materials, results, connection, directive,
                              *, failed_attempt=None):
        """One bounded acquisition/replay cycle, with setup failures fed to policy."""
        from bytefault.core.byte_edits import materialize
        self._campaign_reconnect_exhausted = False
        self._campaign_setup_failed = False
        prefix = []
        failed_attempt = failed_attempt or results[-1].attempt_id
        for previous in results:
            if previous.action_id == current:
                break
            if previous.action_id not in prefix:
                prefix.append(previous.action_id)
        governed = ((current,) if current in request.selected_actions else tuple(
            identity for identity in request.selected_actions if not any(
                item.action_id == identity and item.iteration_id is not None for item in results)))
        choices = {s.action_id: s for s in connection.retry_setup} if connection else {}
        for action_id in prefix:
            if action_id in request.selected_actions and action_id not in choices:
                raise ContractError('campaign.retry_setup.' + action_id, 'unavailable',
                    'earlier selected send requires an explicit recorded or declared_seed choice')
        if not self._case_recorded:
            self._record_request = request
            self._campaign_retry_reopen_ref = self._required_save('retry_case_resume', {'request': request, 'materialized': tuple(materials.values()),
                'directive': directive, 'purpose': 'final_delayed_check'})
            self._case_recorded = True
        actions = {a.action_id: a for a in request.plan.actions}
        setup_request = replace(request, selected_actions=())
        state = self._campaign_setup_state
        if state['failed']:
            self._campaign_setup_failed = True
            self._campaign_setup_failure = state['failure']
            self._campaign_setup_last_directive = state['failure_directive']
            self._campaign_setup_reconnect_exhausted = state['reconnect_exhausted']
            self._required_save('setup_advance_retained', {'candidate_id': state['candidate_id'],
                'setup_directive': state['failure_directive'], 'requested_directive': directive})
            return False
        while True:
            setup_scope = directive.scope == 'setup'
            kind = 'setup_retry_wait' if setup_scope else 'retry_wait'
            self._required_save(kind, {'directive': directive, 'next_attempt': failed_attempt,
                'prefix': tuple(prefix), 'choices': tuple(choices.values())})
            began = self.transport.clock()
            waited = self._policy_wait(directive.wait_seconds)
            elapsed = min(directive.wait_seconds, max(0, self.transport.clock() - began))
            if setup_scope:
                state['elapsed'] += elapsed
            else:
                self._campaign_retry_elapsed += elapsed
                self._campaign_retry_elapsed_by_test[self._campaign_current_test] = self._campaign_retry_elapsed
            if not waited:
                self._campaign_snapshot_setup()
                return False
            if setup_scope:
                state['used'] += 1
                self._campaign_setup_counts['setup_retries'] += 1
            state['cycle'] += 1
            cycle = state['cycle']
            self._campaign_snapshot_setup()
            with self._action_lock:
                cleanup = self.disconnect(phase='retry')
                self._required_save('transport_cleanup', {'cleanup': cleanup, 'purpose': 'retry',
                    'actual_connection_context': getattr(self, '_connection_context', {})})
                if cleanup.outcome == 'uncertain' or cleanup.pacing_error:
                    raise ContractError('campaign.retry', 'cleanup_failed', cleanup.error or cleanup.pacing_error)
                self._campaign_setup_counts['case_entry_attempts'] += 1
                self._record_context.update(action_id=current,
                    attempt_id=failed_attempt + ':replay-' + str(cycle) + ':connection')
                self._required_save('connection_attempt', {'entry_action': prefix[0] if prefix else current,
                    'purpose': 'retry', 'test_id': directive.test_id, 'candidate_id': state['candidate_id'],
                    'replay_cycle': cycle})
                self._connection_permission = True
            configured_reopens = directive.facts.get('reconnect_attempts')
            if not prefix and configured_reopens is None:
                return True
            opened = False
            for reopen in range(configured_reopens if configured_reopens is not None else 1):
                if reopen and not self._policy_wait(directive.facts.get('reconnect_delay', 1)):
                    return False
                if self._should_stop or self.storage_failure or self.continuation.stopped:
                    return False
                with self._action_lock:
                    self._required_save('reconnect_attempt', {'number': reopen + 1, 'test_id': directive.test_id,
                        'candidate_id': state['candidate_id'], 'replay_cycle': cycle,
                        'purpose': 'retry_connection', 'retry_attempt': failed_attempt})
                    self._connection_permission = True
                    opened = self._connect_conversation()
                    self._required_save('reconnect_result', {'number': reopen + 1, 'connected': opened,
                        'replay_cycle': cycle, 'error': self.transport.open_error})
                if opened:
                    break
            if not opened:
                if setup_scope:
                    failure = self._campaign_setup_pending
                    self._campaign_after_setup(request, failure,
                        directive.facts.get('declared_target'), governed, reconnect_exhausted=True)
                else:
                    self._campaign_reconnect_exhausted = True
                return False
            restart = False
            for index, action_id in enumerate(prefix):
                action, prepared = actions[action_id], materials[action_id]
                choice = choices.get(action_id)
                if choice is not None:
                    if choice.reapply_mutations or choice.dynamic_source_reference is not None:
                        raise ContractError('campaign.retry_setup.' + action_id, 'unavailable',
                                            'dynamic retry setup needs its declared regeneration attachment')
                    if choice.choice == 'declared_seed':
                        prepared = materialize(action, PreparedRow('retry-setup', request.row.ordinal),
                                               request.calculations, request.repair)
                attempt = failed_attempt + ':replay-' + str(cycle) + ':setup:' + action_id
                while True:
                    if not self._await_monitoring():
                        return False
                    with self._action_lock:
                        if self.continuation.hold is not None:
                            continue
                        if self._should_stop or self.storage_failure or self.continuation.stopped:
                            return False
                        self._campaign_observations = []
                        self._action_pre_offer(setup_request, action, prepared, attempt)
                        self._exchange_packet(prepared.final_bytes, action.receive)
                        fact = self.last_transport_result
                        target = prefix[index + 1] if index + 1 < len(prefix) else current
                        from bytefault.fuzzers.response import interpret_response
                        ids = tuple(actions)
                        following = ids[ids.index(action_id) + 1] if ids.index(action_id) + 1 < len(ids) else None
                        interpretation = interpret_response(action, fact, following)
                        actual_target = interpretation.target
                        replay = ActionResult(action_id, action.stage_id, None, attempt, prepared, fact,
                            interpretation.meaning, interpretation)
                        results.append(replay)
                        self._action_result(setup_request, replay)
                        break
                if self._should_stop or self.storage_failure or self.continuation.stopped:
                    return False
                setup = self._campaign_after_setup(request, replay, actual_target, governed,
                    path_available=fact.acceptance == 'accepted' and not fact.error and actual_target == target)
                if setup.operation == 'stop':
                    return False
                if setup.operation == 'retry':
                    directive, restart = setup, True
                    break
                if setup.facts.get('advance_candidate'):
                    return False
            if not restart:
                return True

    def execute_campaign(self, base, families, options, *, original_request=None):
        """One engine, required journal and adapter; families contain prepared variants."""
        validate_campaign(options, base.plan)
        with self._control_condition:
            if self._executing_conversation:
                raise ContractError('engine', 'busy', 'one campaign/conversation at a time')
            self._executing_conversation = True
            self._campaign_active = True
            self._accepting_observations = True
            self._probe_cleanup_total = 0
            self._probe_cleanup_failures.clear()
        counts = dict(prepared_cases=0, selected_cases=0, omitted_cases=0,
                      fuzz_tests=0, attempts=0, setup_sends=0,
                      prepared_variants=0, selected_variants=0, executed_variants=0)
        wanted = {n for n in options.selected_cases if n > options.skip}
        remaining = set(wanted)
        remaining.difference_update(getattr(families, 'retained_numbers', ()))
        last, outcome, reason, cleanup = None, 'completed', '', None
        failed_outcome, failed_reason = None, ''
        unexpected_error, cleanup_errors = None, ()
        cleanup_execution = None
        literal_items = {(item['case_number'], item['variant_id']): dict(item)
                         for item in getattr(families, 'literal_items', ())}
        preparing_literal = None
        active_literal = None
        active_literal_previous = None
        active_literal_retry_actions = None
        def retain_literal(request, result):
            key = (request.campaign.case_number, request.campaign.variant_id)
            if key in literal_items:
                literal_items[key].update(state=result.outcome, result=result,
                    case_id=request.case_id, conversation_id=request.conversation_id)
        def retain_active_failure(error):
            if active_literal is None:
                return
            result = self.last_conversation_result
            if (result is not None and result is not active_literal_previous and
                    result.conversation_id == active_literal.conversation_id):
                retain_literal(active_literal, result)
            else:
                key = (active_literal.campaign.case_number, active_literal.campaign.variant_id)
                if key in literal_items:
                    state = ('recording_failed' if self.storage_failure else
                             'cleanup_failed' if getattr(error, 'code', None) == 'cleanup_failed' else 'failed')
                    literal_items[key].update(state=state, result=None,
                        error={'message': str(error), 'last_transport': self.last_transport_result})
                    if active_literal_retry_actions is not None:
                        literal_items[key]['retry_progress'] = {
                            'reopen_reference': getattr(self, '_campaign_retry_reopen_ref', None),
                            'actions': tuple(active_literal_retry_actions),
                            'last_transport': self.last_transport_result,
                            'storage_failure': self.storage_failure,
                            'cleanup': self.last_cleanup_result,
                            'last_record': self.record_refs[-1] if self.record_refs else None,
                            'terminal_available': False}
        self._record_request = base
        self._campaign_current_test, self._campaign_retry_elapsed = None, 0.0
        self._campaign_executed_tests = 0
        self._campaign_test_ordinals, self._campaign_retry_elapsed_by_test = {}, {}
        self._campaign_advance_failure = False
        self._campaign_failed_test = False
        self._campaign_last_attempt = None
        self._campaign_setup_counts = {'case_entry_attempts': 0, 'setup_attempts': 0, 'setup_retries': 0}
        policy_started = False
        monitoring_summary = {}
        families.set_cancelled(lambda: self._should_stop or self.storage_failure is not None or
                               self.continuation.stopped)
        self._record_context = dict(run_id=base.run_id, campaign_id=base.run_id)
        try:
            self._required_save('campaign_start', {'request': base, 'options': options,
                'application_request': original_request,
                'monitoring': self.monitoring.inspect() if hasattr(self.monitoring, 'inspect') else
                    {'policy': type(self.monitoring).__name__, 'configuration': 'caller supplied'}})
            if hasattr(self.monitoring, 'begin_campaign'):
                self.monitoring.begin_campaign(base.run_id)
                policy_started = True
            if hasattr(families, 'items'):
                self._await_monitoring()
            for family in families:
                if self._should_stop or self.storage_failure:
                    outcome, reason = 'stopped', 'stop requested before case'
                    break
                # Resolve and preflight the whole family before its first offer.
                preparing_literal = family[0].campaign.case_number
                materials = tuple(self.validate_conversation(request) for request in family)
                preparing_literal = None
                number = family[0].campaign.case_number
                counts['prepared_cases'] += 1
                counts['prepared_variants'] += len(family)
                selected = selected_case(options, number)
                with self._action_lock:
                    self._record_context = dict(run_id=base.run_id, campaign_id=base.run_id,
                                                case_number=number, case_id=family[0].case_id)
                    self._required_save('campaign_case', {'case_number': number, 'selected': selected,
                        'requests': family, 'materialized': materials})
                if not selected:
                    counts['omitted_cases'] += 1
                    continue
                remaining.discard(number)
                counts['selected_cases'] += 1
                counts['selected_variants'] += len(family)
                for variant_index, (request, materialized) in enumerate(zip(family, materials), 1):
                    self._campaign_advance_failure = False
                    self._campaign_failed_current = False
                    self._campaign_setup_failed = False
                    self._campaign_setup_state = {'candidate_id': request.conversation_id,
                        'used': 0, 'elapsed': 0.0, 'cycle': 0, 'failed': False}
                    if self.socket is not None and (options.connection.mode == 'fresh' or
                            not getattr(self, '_campaign_connection_reusable', False)):
                        with self._action_lock:
                            prior_cleanup = self.disconnect(phase='fresh_case')
                            self._required_save('transport_cleanup', {'cleanup': prior_cleanup, 'purpose': 'fresh_case'})
                        if prior_cleanup.outcome == 'uncertain' or prior_cleanup.pacing_error:
                            cleanup_errors += ({'owner':'transport', 'phase':'fresh_case',
                                'cleanup':prior_cleanup, 'unreached_request':request},)
                            outcome, reason = 'cleanup_failed', prior_cleanup.error or prior_cleanup.pacing_error
                            cleanup_execution = ((failed_outcome,failed_reason) if failed_outcome is not None else
                                ('unreached', 'cleanup prevented the next prepared variant'))
                            break
                    reuse = self.socket is not None and options.connection.mode == 'persistent'
                    entry = (options.connection.reuse_entry_action if reuse else None)
                    self._campaign_setup_counts['case_entry_attempts'] += 1
                    active_literal = request
                    active_literal_previous = self.last_conversation_result
                    last = self._execute_validated_conversation(request, materialized,
                        entry_action=entry, reuse=reuse, connection=options.connection)
                    retain_literal(request, last)
                    active_literal = None
                    deferred_attempts = tuple(self._campaign_deferred_attempts)
                    if deferred_attempts and last.cleanup and (
                            last.cleanup.outcome == 'uncertain' or last.cleanup.pacing_error):
                        for pending in deferred_attempts:
                            self._required_save('campaign_assessment_not_started', {
                                'attempt_id': pending[1].attempt_id,
                                'reason': 'original conversation cleanup is uncertain; no new-connection check started',
                                'cleanup': last.cleanup})
                        deferred_attempts = ()
                    for index, (deferred_request, deferred_result, deferred_number,
                                deferred_context, deferred_observations, deferred_record_context,
                                deferred_path, deferred_at, deferred_selected) in enumerate(deferred_attempts):
                        if self._should_stop or self.storage_failure or self.continuation.stopped:
                            for pending in deferred_attempts[index:]:
                                self._required_save('campaign_assessment_not_started', {
                                    'attempt_id': pending[1].attempt_id,
                                    'reason': 'continuation stopped before deferred check'})
                            break
                        self._record_context = dict(deferred_record_context)
                        self._campaign_observations = list(deferred_observations)
                        resumed_at = self.transport.clock()
                        self._required_save('campaign_assessment_resumed', {
                            'attempt_id': deferred_result.attempt_id,
                            'deferred_at': deferred_at, 'resumed_at': resumed_at,
                            'elapsed': max(0.0, resumed_at - deferred_at),
                            'later_actions_before_assessment': tuple(a.attempt_id for a in last.actions
                                if a.attempt_id != deferred_result.attempt_id and
                                a not in deferred_path)})
                        directive = self._campaign_after_attempt(deferred_request, deferred_result,
                            deferred_number, retained=False, path_results=tuple(last.actions),
                            deferred_context=deferred_context, selected_directive=deferred_selected)
                        if directive is None:
                            continue
                        if directive.operation == 'retry':
                            history = list(last.actions)
                            resumed = self._campaign_retry_setup(deferred_request,
                                deferred_result.action_id,
                                {m.action_id: m for m in materialized}, history,
                                options.connection, directive,
                                failed_attempt=deferred_result.attempt_id)
                            if resumed:
                                last = self._execute_validated_conversation(deferred_request,
                                    materialized, entry_action=deferred_result.action_id,
                                    reuse=True, connection=options.connection,
                                    attempt_start=deferred_number, final_attempt=True,
                                    prior_results=tuple(history),
                                    prior_reached=tuple(a.action_id for a in history
                                        if a.transport.acceptance != 'not_offered'))
                                retain_literal(deferred_request, last)
                            else:
                                outcome, reason = (self._campaign_interruption() or
                                    ('monitoring_failed', 'deferred retry setup did not complete'))
                                for pending in deferred_attempts[index + 1:]:
                                    self._required_save('campaign_assessment_not_started', {
                                        'attempt_id': pending[1].attempt_id,
                                        'reason': 'earlier deferred retry setup did not complete'})
                                break
                        if directive.operation == 'stop' or self._campaign_interruption() is not None:
                            outcome, reason = (self._campaign_interruption() or
                                ('monitoring_stopped', directive.reason))
                            for pending in deferred_attempts[index + 1:]:
                                self._required_save('campaign_assessment_not_started', {
                                    'attempt_id': pending[1].attempt_id,
                                    'reason': 'earlier deferred decision stopped continuation'})
                            break
                    counts['fuzz_tests'] += len({a.iteration_id for a in last.actions
                        if a.iteration_id is not None})
                    counts['executed_variants'] += int(any(a.iteration_id is not None for a in last.actions))
                    counts['attempts'] += sum(a.iteration_id is not None for a in last.actions)
                    counts['setup_sends'] += sum(a.iteration_id is None and
                        a.transport.acceptance != 'not_offered' for a in last.actions)
                    if last.cleanup and (last.cleanup.outcome=='uncertain' or last.cleanup.pacing_error):
                        cleanup_errors += ({'owner':'transport','phase':'conversation',
                            'cleanup':last.cleanup,'request':request},)
                    if last.outcome != 'completed':
                        if (last.outcome == 'transport_failed' or self._campaign_failed_current) and self._campaign_advance_failure:
                            failed_outcome = last.outcome if last.outcome == 'transport_failed' else 'monitoring_failed'
                            failed_reason = last.reason or 'configured test policy exhausted'
                            continue
                        outcome, reason = last.outcome, last.reason
                        if last.outcome == 'cleanup_failed':
                            proven_bound = (variant_index == len(family) and
                                ((options.selected_cases and not remaining) or
                                 (options.case_limit is not None and number >= options.case_limit)))
                            cleanup_execution = ((last.execution_outcome or 'completed', last.execution_reason)
                                if proven_bound else
                                ('unreached', 'cleanup ended execution before campaign completion was established'))
                        break
                if outcome != 'completed' or (options.selected_cases and not remaining):
                    break
            if getattr(families, 'barrier', None) is not None and outcome == 'completed':
                outcome, reason = 'unresolved', 'uncertain interrupted attempt requires explicit rerun or skip'
            if (self._campaign_last_attempt is not None and outcome != 'unresolved' and not self._should_stop and
                    not self.storage_failure and not self.continuation.stopped and
                    outcome in ('completed', 'unknown', 'unreached')):
                directive = self._campaign_after_attempt(*self._campaign_last_attempt, final=True)
                if directive is not None and directive.operation == 'retry':
                    retry_request, retry_result, retry_number = self._campaign_last_attempt
                    materialized = self._campaign_last_materializations
                    prior_results = list(self._campaign_last_path)
                    prior_count = len(prior_results)
                    # A final delayed retry can reopen an already terminal case
                    # before _execute_validated_conversation is reached. Keep
                    # that old result as history, never as the new lifecycle's
                    # terminal when setup/wait/recording fails in between.
                    active_literal = retry_request
                    active_literal_previous = self.last_conversation_result
                    active_literal_retry_actions = prior_results
                    self._campaign_retry_reopen_ref = None
                    key = (retry_request.campaign.case_number, retry_request.campaign.variant_id)
                    if key in literal_items:
                        item = literal_items[key]
                        item.update(previous_result=item.get('result'), result=None, state='retry_pending')
                    resumed = self._campaign_retry_setup(retry_request, retry_result.action_id,
                            {m.action_id: m for m in materialized}, prior_results, options.connection, directive)
                    if resumed:
                        self._required_save('final_attempt_resume', {'test_id': retry_result.iteration_id,
                            'next_attempt_number': retry_number + 1, 'materialized': retry_result.materialized})
                        active_literal = retry_request
                        last = self._execute_validated_conversation(retry_request, materialized,
                            entry_action=retry_result.action_id, reuse=True, connection=options.connection,
                            attempt_start=retry_number, final_attempt=True, prior_results=tuple(prior_results),
                            prior_reached=tuple(a.action_id for a in prior_results if a.transport.acceptance != 'not_offered'))
                        added = last.actions[prior_count:]
                        counts['attempts'] += sum(a.iteration_id is not None for a in added)
                        counts['setup_sends'] += sum(a.iteration_id is None and a.transport.acceptance != 'not_offered' for a in added)
                        directive = self._campaign_last_directive
                        if outcome == 'completed' or last.outcome != 'completed':
                            outcome, reason = last.outcome, last.reason
                    elif self._campaign_interruption() is not None:
                        outcome, reason = self._campaign_interruption()
                    elif self._campaign_reconnect_exhausted:
                        directive = self._campaign_after_attempt(retry_request, retry_result, retry_number,
                            final=True, reconnect_exhausted=True)
                        outcome, reason = 'transport_failed', 'retry reconnect attempts exhausted'
                    elif self._campaign_setup_failed:
                        outcome, reason = self._campaign_setup_failure_outcome(), self._campaign_setup_last_directive.reason
                    else:
                        outcome, reason = 'stopped', 'stop requested during final retry setup'
                    if not resumed:
                        added = prior_results[prior_count:]
                        counts['setup_sends'] += sum(a.iteration_id is None and a.transport.acceptance != 'not_offered' for a in added)
                        if not self.storage_failure:
                            last = self._campaign_retry_terminal(retry_request, prior_results, outcome, reason)
                        else:
                            retain_active_failure(reason)
                    if (last is not None and last is not active_literal_previous and
                            last.conversation_id == retry_request.conversation_id):
                        retain_literal(retry_request, last)
                    active_literal = None
                    active_literal_retry_actions = None
                interruption = self._campaign_interruption()
                if interruption is not None:
                    outcome, reason = interruption
                elif directive is not None and directive.operation == 'stop':
                    outcome, reason = 'monitoring_stopped', directive.reason
            if self._should_stop and outcome == 'completed':
                outcome, reason = 'stopped', 'stop requested during preparation'
            elif failed_outcome is not None and outcome == 'completed':
                outcome, reason = failed_outcome, failed_reason
            elif self._campaign_failed_test and outcome == 'completed':
                outcome, reason = 'monitoring_failed', 'configured test policy exhausted or service unrecovered'
        except RequiredSaveFailure as error:
            retain_active_failure(error)
            outcome, reason = 'recording_failed', str(error)
        except BaseException as error:
            retain_active_failure(error)
            if preparing_literal is not None:
                for (number, _), item in literal_items.items():
                    if number == preparing_literal:
                        item.update(state='failed', error={'message': str(error),
                            'path': getattr(error, 'path', None), 'code': getattr(error, 'code', None)})
            prior_failure = failed_outcome or (outcome if outcome not in ('completed','cleanup_failed') else None)
            preparation_cleanup = ((isinstance(error,ContractError) and error.path=='generation.cleanup') or
                (isinstance(error,RequiredServiceSaveFailure) and
                 error.diagnostic.get('required_record_kind')=='preparation_terminal'))
            if preparation_cleanup and prior_failure is not None:
                cleanup_errors += ({'owner':'preparation','error':str(error),'error_type':type(error).__name__,
                    'diagnostic':getattr(error,'diagnostic',None)},)
                outcome,reason=prior_failure,failed_reason if failed_outcome is not None else reason
            else:
                unexpected_error = error
                outcome = 'recording_failed' if isinstance(error, RequiredServiceSaveFailure) else 'failed'
                reason = str(error)
            if not self.storage_failure:
                self._required_save('campaign_error', {'error': str(error),
                    'error_type': type(error).__name__, 'path': getattr(error, 'path', None),
                    'code': getattr(error, 'code', None), 'diagnostic': getattr(error, 'diagnostic', None)})
        finally:
            execution_outcome, execution_reason = cleanup_execution or (outcome, reason)
            try:
                try:
                    families.close()
                except BaseException as error:
                    cleanup_errors += ({'owner': 'preparation', 'error': str(error),
                        'error_type': type(error).__name__, 'diagnostic': getattr(error, 'diagnostic', None)},)
                    if unexpected_error is not None:
                        unexpected_error.add_note('Campaign preparation cleanup: ' + str(error))
                    elif outcome == 'completed' or last is None:
                        unexpected_error = error
                    if outcome == 'completed':
                        outcome, reason = 'cleanup_failed', str(error)
            finally:
                with self._action_lock:
                    self._accepting_observations = False
                    interruption = self._campaign_interruption()
                    if interruption is not None:
                        if execution_outcome in ('completed', 'monitoring_stopped'):
                            execution_outcome, execution_reason = interruption
                            if outcome in ('completed', 'monitoring_stopped', 'cleanup_failed'):
                                outcome, reason = interruption
                        elif outcome == 'monitoring_stopped':
                            outcome, reason = interruption
                    # Pending selection implies unavailable ordinals only after
                    # active interruption and actual execution failures are settled.
                    if remaining and execution_outcome == 'completed':
                        execution_outcome, execution_reason = 'unreached', 'requested case ordinals were not available'
                        if outcome == 'completed':
                            outcome, reason = execution_outcome, execution_reason
                    cleanup = self.disconnect(phase='campaign')
                    if policy_started:
                        monitoring_summary = self.monitoring.end_campaign()
                    if self.continuation.stopped:
                        gate = self.continuation
                        stopping = gate.stop_decision or gate.stop_reference
                        monitoring_summary = freeze({**monitoring_summary, 'continuation_stop': {
                            'decision_id': getattr(gate.stop_decision, 'decision_id', None),
                            'observation_id': getattr(stopping, 'observation_id', None),
                            'correlation': getattr(stopping, 'correlation', None),
                            'cause': gate.stop_cause, 'reason': gate.stop_reason}})
                    self._case_recorded = False
                    self._offer_permission = None
                    with self._control_condition:
                        self._executing_conversation = False
                        self._campaign_active = False
                    if cleanup.outcome == 'uncertain' or cleanup.pacing_error:
                        if outcome == 'completed':
                            outcome, reason = 'cleanup_failed', cleanup.error or cleanup.pacing_error
                    if self._probe_cleanup_total:
                        probe_cleanup = self.probe_cleanup_summary()
                        cleanup_errors += (probe_cleanup,)
                        if outcome == 'completed':
                            latest = probe_cleanup['failures'][-1]['cleanup']
                            outcome,reason = 'cleanup_failed',latest['error'] or latest['pacing_error']
                    result = CampaignResult(base.run_id, outcome, reason, **counts,
                        **self._campaign_setup_counts,
                        missing_cases=tuple(sorted(remaining)), last_conversation=last, cleanup=cleanup,
                        preparation_summary=families.preparation.summary if families.preparation is not None else {},
                        cleanup_errors=cleanup_errors, monitoring=monitoring_summary,
                        execution_outcome=execution_outcome, execution_reason=execution_reason)
                    result = replace(result, literal_items=tuple(literal_items.values()))
                    if hasattr(families, 'items'):
                        retained_counts = {}
                        for item in families.items.values():
                            retained_counts[item['state']] = retained_counts.get(item['state'], 0) + 1
                        result = replace(result, resume={'source_path': families.request.resume['source_path'],
                            'recovery_issue': families.request.resume['recovery_issue'],
                            'choices': families.request.resume['choices'],
                            'barrier': families.barrier,
                            'pending_hold': self.continuation.hold,
                            'retained_state_counts': retained_counts})
                    self._record_context = dict(run_id=base.run_id, campaign_id=base.run_id)
                    if not self.storage_failure:
                        try:
                            self._required_save('campaign_terminal', {'result': result})
                        except RequiredSaveFailure as error:
                            result = replace(result, outcome='recording_failed', reason=str(error))
                    self.last_campaign_result = result
        if unexpected_error is not None:
            raise unexpected_error.with_traceback(unexpected_error.__traceback__)
        return result
