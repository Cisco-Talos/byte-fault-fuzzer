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

"""The engine's passive conversation route. Transport ports carry facts unchanged."""
from bytefault.core.contracts import (ActionResult, ConversationResult, TransportResult, TransportCleanup,
                                     ContractError)
from bytefault.core.validation import validate_request
from bytefault.core.byte_edits import materialize
from bytefault.fuzzers.declarations import SUPPORTED_CAPABILITIES
from bytefault.core.records import RequiredSaveFailure
from bytefault.fuzzers.response import interpret_response


def validate_conversation(request):
        validate_request(request, SUPPORTED_CAPABILITIES)
        for owner in request.row.contributions + request.row.placements + request.row.final_overrides:
            for choice in owner.random_choices:
                if choice.resolved is None:
                    raise ContractError('row.random_choices', 'unsupported_sampling',
                                        'conversation execution requires resolved random choices')
        # All selected bytes/calculation failures resolve before even opening.
        return tuple(materialize(action, request.row, request.calculations, request.repair)
                     for action in request.plan.actions)


class ConversationMixin:
    def validate_conversation(self, request):
        return validate_conversation(request)

    def execute_conversation(self, request):
        materialized = self.validate_conversation(request)
        if self.session_factory is not None or self.handshake_checker is not None:
            raise ContractError('engine', 'executable_value',
                                'executable protocol factories and checkers are unsupported; use passive declarations')
        with self._control_condition:
            if self._executing_conversation:
                raise ContractError('engine', 'busy', 'one conversation at a time')
            self._executing_conversation = True
        try:
            return self._execute_validated_conversation(request, materialized)
        finally:
            self._case_recorded = False
            self._offer_permission = None
            with self._control_condition:
                self._executing_conversation = False

    def _execute_validated_conversation(self, request, materialized, *, entry_action=None,
                                        reuse=False, connection=None, attempt_start=0,
                                        final_attempt=False, prior_reached=(), prior_results=()):
        self.last_transport_result = None
        self.last_conversation_result = None
        self.last_cleanup_result = None
        self._execution_summary = None
        self._campaign_deferred_attempts = []
        actions = request.plan.actions
        by_id = {a.action_id: a for a in actions}
        materials = {m.action_id: m for m in materialized}
        ids = tuple(by_id)
        reached, results = list(prior_reached), list(prior_results)
        outcome, reason = 'completed', ''
        unexpected_error = None
        current = entry_action or request.plan.entry_action or ids[0]
        try:
            self._conversation_start(request, materialized, entry_action=current, reuse=reuse)
            self._preflight_required_collection_spacing(request.plan, entry_action=current)
            while current is not None:
                action, prepared = by_id[current], materials[current]
                attempt_number = attempt_start if current == entry_action else 0
                while True:
                    if self._check_ui_state():
                        outcome, reason = 'stopped', 'stop requested before action'
                        break
                    if not self._await_monitoring():
                        outcome = 'recording_failed' if self.storage_failure else (
                            'stopped' if self._should_stop else 'monitoring_stopped')
                        reason = 'required recording failed' if self.storage_failure else 'continuation stopped'
                        break
                    with self._action_lock:
                        # An assessment may install a hold while this executor
                        # waits for the lock. Re-enter the unlocked wait without
                        # consuming an unsent attempt or blocking completions.
                        if self.continuation.hold is not None or self.continuation.stopped or self._should_stop:
                            continue
                        attempt_number += 1
                        attempt = f'{request.conversation_id}:{current}:attempt-{attempt_number}'
                        self._campaign_observations = [] if self._campaign_active else None
                        connected = self.socket is not None or self._connect_conversation()
                        if connected:
                            self._action_pre_offer(request, action, prepared, attempt)
                            self._exchange_packet(prepared.final_bytes, action.receive)
                            fact = self.last_transport_result
                        else:
                            fact = TransportResult(prepared.final_bytes, receive_requested=action.receive.requested,
                                receive_outcome='not_reached' if action.receive.requested else 'unrequested',
                                error=self.transport.open_error or 'connection failed',
                                connection=getattr(self.transport, 'last_open', None))
                            self.last_transport_result = fact
                        if fact.acceptance != 'not_offered':
                            reached.append(current)
                        index = ids.index(current) + 1
                        interpretation = interpret_response(action, fact, ids[index] if index < len(ids) else None)
                        meaning, target = interpretation.meaning, interpretation.target
                        if self._should_stop:
                            outcome, reason = 'stopped', 'stop requested'
                        elif fact.error or fact.acceptance != 'accepted':
                            outcome, reason = 'transport_failed', fact.error or fact.acceptance
                        elif action.edges:
                            if not interpretation.matched:
                                outcome, reason = 'unknown', f'unknown response at {current}'
                        result = ActionResult(current, action.stage_id,
                            f'{request.conversation_id}:{current}' if current in request.selected_actions else None,
                            attempt, prepared, fact, meaning, interpretation)
                        results.append(result)
                        self._action_result(request, result)
                        if self.continuation.stopped:
                            outcome, reason = 'monitoring_stopped', 'Monitoring selected stop'
                    retry = False
                    if self._campaign_active and not (
                            self._should_stop or self.storage_failure or self.continuation.stopped):
                        if result.iteration_id is not None:
                            directive = self._campaign_after_attempt(request, result, attempt_number,
                                final=final_attempt, retained=False, path_results=tuple(results),
                                defer_new_connection=(target is not None or bool(self._campaign_deferred_attempts))
                                    and not final_attempt)
                        else:
                            governed = tuple(identity for identity in request.selected_actions if not any(
                                item.action_id == identity and item.iteration_id is not None for item in results))
                            directive = self._campaign_after_setup(request, result, target, governed)
                        if directive is not None:
                            interruption = self._campaign_interruption()
                            if interruption is not None:
                                outcome, reason = interruption
                            elif directive.operation == 'retry':
                                retry = self._campaign_retry_setup(request, current, materials, results, connection, directive)
                                if not retry:
                                    interruption = self._campaign_interruption()
                                    if interruption is not None:
                                        outcome, reason = interruption
                                    elif self._campaign_setup_failed:
                                        outcome = self._campaign_setup_failure_outcome()
                                        reason = self._campaign_setup_last_directive.reason
                                    elif getattr(self, '_campaign_reconnect_exhausted', False):
                                        self._campaign_after_attempt(request, result, attempt_number, reconnect_exhausted=True)
                                        outcome, reason = 'transport_failed', 'retry reconnect attempts exhausted'
                                    else:
                                        outcome, reason = 'stopped', 'stop requested during retry wait/setup'
                            elif directive.operation == 'stop':
                                outcome, reason = 'monitoring_stopped', directive.reason
                            elif directive.scope == 'setup' and directive.facts.get('advance_candidate'):
                                if outcome == 'completed':
                                    outcome = 'monitoring_failed'
                                reason = directive.reason
                    if retry:
                        outcome, reason = 'completed', ''
                        continue
                    break
                if outcome in ('transport_failed', 'stopped', 'monitoring_stopped', 'recording_failed', 'monitoring_failed') or (
                        self._campaign_active and self._campaign_setup_failed):
                    break
                if final_attempt:
                    break
                current = target
        except RequiredSaveFailure as exc:
            outcome, reason = 'recording_failed', str(exc)
        except ContractError as exc:
            outcome, reason = 'failed', str(exc)
        except (KeyboardInterrupt, SystemExit) as exc:
            self.control('stop')
            outcome, reason = 'incomplete', f'execution interrupted: {type(exc).__name__}'
        except Exception as exc:
            # Preserve the established exception behavior for the caller, while
            # still retaining teardown and terminal evidence before re-raising.
            unexpected_error = exc
            outcome, reason = 'failed', f'{type(exc).__name__}: {exc}'
        finally:
            with self._action_lock:
                keep = (connection is not None and connection.mode == 'persistent'
                    and outcome == 'completed' and bool(results) and self.socket is not None
                    and not self._should_stop and not self.storage_failure and not self.continuation.stopped
                    and results[-1].transport.acceptance == 'accepted' and not results[-1].transport.error
                    and results[-1].response_meaning in (connection.reusable_meanings or
                        (('uninterpreted', 'positive') if len(actions) == 1 else ()))
                    and (len(actions) == 1 or results[-1].action_id in connection.reusable_after))
                # Campaign owns the final cadence opportunity, including a same-
                # connection probe after preparation reaches EOF. Fresh mode closes
                # this connection before the next case's setup instead.
                self._campaign_connection_reusable = keep
                if (self._campaign_active and self.socket is not None and
                        not self._campaign_deferred_attempts and
                        outcome in ('completed', 'unknown', 'unreached') and not self._should_stop and
                        not self.storage_failure and not self.continuation.stopped):
                    keep = True
                cleanup = TransportCleanup('conversation', 'not_attempted') if keep else self.disconnect()
                if keep:
                    self._required_save('connection_retained', {'terminal_action': results[-1].action_id,
                        'terminal_meaning': results[-1].response_meaning, 'contract': connection})
                self._case_recorded = False
        unreached = tuple((key, reason or 'declared path did not reach selected action')
                          for key in request.selected_actions if key not in reached)
        if unreached and outcome == 'completed':
            outcome = 'unreached'
        execution_outcome, execution_reason = outcome, reason
        self._execution_summary = {'outcome': execution_outcome, 'reason': execution_reason}
        cleanup_failed = cleanup.outcome == 'uncertain' or cleanup.pacing_error is not None
        if cleanup_failed and outcome == 'completed':
            outcome = 'cleanup_failed'
            reason = cleanup.error or cleanup.pacing_error
        result = ConversationResult(request.run_id, request.case_id, request.conversation_id,
            request.row.row_id, outcome, tuple(results), ids, unreached, reason,
            cleanup, execution_outcome, execution_reason)
        if self.storage_failure is None:
            try:
                if cleanup.outcome != 'not_attempted':
                    self._required_save('transport_cleanup', {'cleanup': cleanup,
                        'execution_outcome': execution_outcome,
                        'execution_reason': execution_reason})
                self._conversation_terminal(request, result)
            except RequiredSaveFailure as exc:
                from dataclasses import replace
                result = replace(result, outcome='recording_failed', reason=str(exc))
        self.last_conversation_result = result
        if self.storage_failure:
            self._execution_state = 'recording_failed'
        elif result.outcome == 'monitoring_stopped':
            self._execution_state = 'monitoring_stopped'
        elif cleanup_failed:
            self._execution_state = result.outcome
        if unexpected_error is not None:
            raise unexpected_error.with_traceback(unexpected_error.__traceback__)
        return result
