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

"""Required evidence gates for the ordinary executor, independent of UI/log sinks."""
import sys
import threading
from collections import OrderedDict, deque
from datetime import datetime
from uuid import uuid4

from bytefault.core.contracts import (Correlation, Observation, MonitoringCompletion,
    ContractError, freeze)
from bytefault.core.records import RequiredSaveFailure, encode_value, emit_recording_diagnostic
from bytefault.core.validation import passive, validate_plan, validate_wait_obligations


class RecordingMixin:
    def _initialize_recording(self, record_store, monitoring):
        from bytefault.fuzzers.continuation import ContinuationGate
        from bytefault.monitoring import Monitoring
        self.record_store = record_store  # attachment owner closes it, not the engine
        self.monitoring = monitoring or Monitoring()
        self.continuation = ContinuationGate()
        self.record_refs = []
        self.storage_failure = None
        self.diagnostic_delivery_error = None
        self._required_sinks = []
        self._record_context = {}
        self._record_request = None
        self._current_materialization = None
        self._available_materializations = ()
        self._case_recorded = False
        self._connection_permission = False
        self._offer_permission = None
        self._action_lock = threading.RLock()
        self._last_transport_context = None
        self._transport_in_progress = False
        self._campaign_active = False
        self._observation_connections = OrderedDict()
        self._accepting_observations = True
        configuration = getattr(getattr(self.monitoring,'policy',None),'configuration',None)
        capacity = getattr(configuration,'history_capacity',None) or getattr(
            getattr(self.monitoring,'observations',None),'maxlen',128) or 128
        self._probe_cleanup_failures = deque(maxlen=capacity)
        self._probe_cleanup_total = 0

    def probe_cleanup_summary(self):
        return freeze({'owner':'probe','failure_total':self._probe_cleanup_total,
            'omitted_count':self._probe_cleanup_total-len(self._probe_cleanup_failures),
            'history_capacity':self._probe_cleanup_failures.maxlen,
            'failures':tuple(self._probe_cleanup_failures)})

    def _record_probe_cleanup(self, probe, cleanup, actual_connection):
        data = freeze({'probe_id':probe.probe_id,'probe':probe,'correlation':probe.correlation,
                       'actual_connection':actual_connection,'cleanup':cleanup})
        failed = cleanup.outcome=='uncertain' or cleanup.pacing_error is not None
        if failed:
            self._probe_cleanup_total += 1
            self._probe_cleanup_failures.append(freeze({**dict(data),'record_ref':None}))
        if self.storage_failure is None:
            ref = self._required_save('probe_cleanup',data)
            if failed:
                self._probe_cleanup_failures[-1] = freeze({**dict(data),'record_ref':ref})
        elif failed:
            # The original recording-stop remains primary. The cleanup happened
            # afterwards, so report its exact unacknowledged fact independently.
            self.storage_failure = freeze({**dict(self.storage_failure),
                'unacknowledged_probe_cleanup':data,'probe_cleanup_summary':self.probe_cleanup_summary()})
            delivery_error = emit_recording_diagnostic(self.storage_failure)
            if delivery_error is not None:
                self.diagnostic_delivery_error = delivery_error

    def add_required_sink(self, sink):
        """Attach a required action sink; it must not be a presentation callback.

        Called as sink(kind, identity, data, acknowledged_record_ref). Its failure
        joins the same independent storage-stop rule.
        """
        self._required_sinks.append(sink)

    def _recording_stop(self, kind, exc, *, failed_identity=None, failed_data=None):
        self._should_stop = True
        self._stop_event.set()
        self._offer_permission = None
        self._case_recorded = False
        self._connection_permission = False
        cleanup = self.disconnect(phase='recording_stop')
        target = self.transport.request
        self.storage_failure = freeze({
            'reason': str(exc), 'required_record_kind': kind,
            'identity': self._record_context, 'resolved_transport': target,
            'failed_record_identity': failed_identity,
            'failed_record_data': failed_data,
            'execution_identity': self._record_context,
            'original_request': self._record_request.original_request if self._record_request else {},
            'resolved_request': self._record_request,
            'available_materializations': self._available_materializations,
            'known_transport_progress': self.last_transport_result,
            'known_transport_identity': self._last_transport_context,
            'transport_progress_state': ('inflight_unknown' if self._transport_in_progress else
                                          'retained_result' if self.last_transport_result else 'not_observed'),
            'available_materialized_bytes': (self._current_materialization.final_bytes
                if self._current_materialization is not None else None),
            'last_retained_record': self.record_refs[-1] if self.record_refs else None,
            'missing_evidence': f'{kind} save not acknowledged; target effects unknown',
            'cleanup': cleanup,
            'execution': getattr(self, '_execution_summary', None),
        })
        self._execution_state = 'recording_failed'
        self.continuation.wake()
        # This direct terminal route never calls a file sink or optional renderer.
        self.diagnostic_delivery_error = emit_recording_diagnostic(self.storage_failure)
        self._emit('on_required_record_failure', diagnostic=self.storage_failure,
                   terminal_delivery_error=self.diagnostic_delivery_error)

    def _required_save(self, kind, data, *, identity=None):
        if self.storage_failure is not None:
            raise RequiredSaveFailure(str(self.storage_failure['reason']))
        context = freeze(identity if identity is not None else self._record_context)
        supplied = freeze(data)
        try:
            if self.record_store is None:
                raise OSError('required local record store is not attached')
            ref = self.record_store.append(kind, context, supplied)
            self.record_refs.append(ref)
            for sink in self._required_sinks:
                sink(kind, context, supplied, ref)
            projection = getattr(self, '_record_projection', None)
            if projection is not None:
                try:
                    projection(kind, context, supplied, ref)
                except Exception:
                    self._projection_failures = getattr(self, '_projection_failures', 0) + 1
            return ref
        except Exception as exc:
            self._recording_stop(kind, exc, failed_identity=context, failed_data=supplied)
            raise RequiredSaveFailure(str(exc)) from exc

    def _conversation_start(self, request, materialized, *, entry_action=None, reuse=False):
        with self._action_lock:
            return self._conversation_start_locked(request,materialized,entry_action=entry_action,reuse=reuse)

    def _conversation_start_locked(self, request, materialized, *, entry_action=None, reuse=False):
        self._record_request = request
        self._current_materialization = None
        self._available_materializations = materialized
        self._last_transport_context = None
        self._case_recorded = False
        self._connection_permission = False
        self._offer_permission = None
        self._record_context = dict(run_id=request.run_id, case_id=request.case_id,
            conversation_id=request.conversation_id, row_id=request.row.row_id,
            stage_id=None, action_id=None, attempt_id=None, iteration_id=None)
        if request.campaign is not None:
            self._record_context.update(campaign_id=request.campaign.campaign_id,
                case_number=request.campaign.case_number, variant_id=request.campaign.variant_id)
        self._required_save('case_start', {'request': request, 'materialized': materialized,
                                         'transport': self.transport.request})
        self._case_recorded = True
        first = entry_action or request.plan.entry_action or request.plan.actions[0].action_id
        action = next(action for action in request.plan.actions if action.action_id == first)
        self._record_context.update(stage_id=action.stage_id, action_id=first,
            attempt_id=f'{request.conversation_id}:{first}:attempt-1',
            iteration_id=f'{request.conversation_id}:{first}' if first in request.selected_actions else None)
        self._required_save('connection_reuse' if reuse else 'connection_attempt', {'entry_action': first})
        self._connection_permission = True

    def _action_pre_offer(self, request, action, materialized, attempt_id):
        self._record_context.update(stage_id=action.stage_id, action_id=action.action_id,
            attempt_id=attempt_id, iteration_id=(f'{request.conversation_id}:{action.action_id}'
                                               if action.action_id in request.selected_actions else None))
        self._current_materialization = materialized
        self._required_save('materialization', {'materialized': materialized,
            'receive': action.receive, 'attempt_state': 'prepared_not_offered'})
        self._offer_permission = materialized.final_bytes

    def _action_result(self, request, result):
        if self._campaign_active and result.iteration_id is None:
            self._campaign_setup_counts['setup_attempts'] += 1
        self._record_context.update(stage_id=result.stage_id, action_id=result.action_id,
            attempt_id=result.attempt_id, iteration_id=result.iteration_id)
        self._offer_permission = None
        self._required_save('action_result', {'result': result})
        self._observe_result(request, result)

    def _conversation_terminal(self, request, result):
        with self._action_lock:
            self._offer_permission = None
            self._case_recorded = False
            self._connection_permission = False
            self._required_save('case_terminal', {'result': result,
                'pending_monitoring_decision': self.continuation.hold})

    def _observe_result(self, request, result, *, kind='action'):
        correlation = Correlation(request.run_id, request.case_id, request.conversation_id,
            result.action_id, result.attempt_id, result.iteration_id, result.stage_id)
        observation = Observation(str(uuid4()), correlation, result.transport,
                                  kind=kind, observed_at=self.transport.clock(),
                                  response_meaning=result.response_meaning,
                                  parameters={'response_interpretation': result.response_interpretation,
                                      'observed_at_utc': datetime.now().astimezone().isoformat()})
        self._observation_connections[observation.observation_id] = (
            correlation, getattr(self, '_connection_epoch', 0), request, observation.observation_id)
        capacity = getattr(getattr(self.monitoring, 'observations', None), 'maxlen', 128) or 128
        while len(self._observation_connections) > capacity:
            self._observation_connections.popitem(last=False)
        return self._publish_observation(observation)

    def _publish_observation(self, observation, *, external=False):
        if external:
            prior = self._observation_connections.get(observation.prior_observation_id)
            if prior is not None and prior[0] == observation.correlation:
                self._observation_connections[observation.observation_id] = prior
                capacity = getattr(getattr(self.monitoring,'observations',None),'maxlen',128) or 128
                while len(self._observation_connections) > capacity:
                    self._observation_connections.popitem(last=False)
        if not external and getattr(self, '_campaign_observations', None) is not None:
            self._campaign_observations.append(observation)
        identity = dict(freeze(observation.correlation)) if external else None
        if external:
            identity.update(campaign_id=observation.correlation.run_id,
                            case_number=None, variant_id=None, row_id=None)
        self._required_save('observation', {'observation': observation}, identity=identity)
        try:
            decision = self.monitoring.observe(observation)
            validate_wait_obligations(decision)
            if decision.correlation != observation.correlation or decision.observation_id != observation.observation_id:
                raise ContractError('monitoring', 'correlation', 'decision does not identify supplied facts')
            self._required_save('monitoring_decision', {'decision': decision}, identity=identity)
            self.continuation.select(decision, now=self.transport.clock())
            self._required_save('monitoring_gate', {'decision_id': decision.decision_id,
                'deadline': self.continuation.deadline}, identity=identity)
            from bytefault.core.validation import collection_blocks_required_followup
            earlier_collection = (getattr(self, 'pending_collection', lambda _run_id: False)(
                observation.correlation.run_id) if decision.disposition == 'hold' else False)
            required_collection = (decision.disposition == 'hold' and
                collection_blocks_required_followup(decision.actions,
                    decision.required_conditions, earlier_collection=earlier_collection))
            if required_collection and self.socket is not None and self.transport.request.connection_delay:
                interpretation = observation.parameters.get('response_interpretation')
                next_action = getattr(interpretation, 'target', None)
                if next_action is not None:
                    self._required_save('monitoring_incompatibility', {
                        'decision_id': decision.decision_id,
                        'reason': 'required collection hold cannot pace a new connection while the conversation socket must continue',
                        'next_action': next_action,
                        'earlier_collection_pending': earlier_collection,
                        'connection_delay': self.transport.request.connection_delay}, identity=identity)
                    raise ContractError('monitoring.collection', 'hold_conflict',
                        'required collection hold with nonzero connection delay conflicts with same-socket conversation continuation')
                cleanup = self.disconnect(phase='required_collection')
                self._required_save('transport_cleanup', {'cleanup': cleanup,
                    'purpose': 'release terminal conversation socket before required collection'}, identity=identity)
                if cleanup.outcome == 'uncertain' or cleanup.pacing_error:
                    raise ContractError('monitoring.collection', 'cleanup_failed',
                        'terminal conversation socket could not be confirmed closed before required collection')
            if decision.actions:
                if getattr(self, 'followup', None) is None:
                    self._required_save('followup_unavailable', {'decision': decision,
                        'reason': 'Management attachment unavailable'}, identity=identity)
                else:
                    self.followup(decision)
            if decision.disposition == 'stop':
                self._execution_state = 'monitoring_stopped'
            self._emit('on_monitoring_decision', decision=decision)
            for probe in decision.probes:
                self.execute_probe(probe)
            return decision
        except RequiredSaveFailure:
            raise
        except Exception as exc:
            # A failed/unavailable Monitoring port never implies permission.
            self.continuation.stop(cause='monitoring_failure', reason=str(exc), reference=observation)
            self._required_save('monitoring_failure', {'observation': observation, 'error': str(exc),
                'path': getattr(exc, 'path', None), 'code': getattr(exc, 'code', None),
                'active_hold': self.continuation.hold}, identity=identity)
            if isinstance(exc, ContractError) and (exc.code == 'hold_conflict' or
                    (exc.path=='probe.connection' and exc.code=='unavailable')):
                raise
            raise ContractError('monitoring', 'failed', str(exc)) from exc

    def complete_monitoring(self, completion):
        if not isinstance(completion, MonitoringCompletion):
            raise ContractError('monitoring.completion', 'invalid', 'typed completion required')
        passive(completion, 'monitoring.completion')
        if completion.status not in ('succeeded', 'failed', 'pending', 'disabled'):
            raise ContractError('monitoring.completion', 'invalid', 'unsupported completion status')
        self._required_save('monitoring_completion', {'completion': completion}, identity={
            name: getattr(completion.correlation, name) for name in
            ('run_id', 'case_id', 'conversation_id', 'stage_id', 'action_id', 'attempt_id', 'iteration_id')})
        accepted = self.continuation.complete(completion)
        self._emit('on_monitoring_completion', completion=completion, accepted=accepted)
        return accepted

    def _await_monitoring(self):
        if self.continuation.hold is not None:
            self._execution_state = 'monitoring_held'
        gate = self.continuation
        while gate.hold is not None and not gate.stopped and not self._should_stop and not self.storage_failure:
            self._check_ui_state()
            with gate.condition:
                deadline, hold = gate.deadline, gate.hold
            if hold is None:
                continue
            if deadline is not None:
                if self.transport.clock() >= deadline:
                    self._required_save('monitoring_expiry', {'decision': hold, 'treatment': hold.on_expiry,
                        'phase': 'requested'})
                    applied = gate.expire(hold.decision_id)
                    self._required_save('monitoring_expiry_result', {'decision_id': hold.decision_id,
                        'treatment': hold.on_expiry, 'applied': applied})
                else:
                    self.transport.sleep(min(.05, deadline - self.transport.clock()))
            else:
                with gate.condition:
                    gate.condition.wait(.05)
        return not gate.stopped and not self._should_stop and not self.storage_failure

    def _policy_wait(self, seconds):
        deadline = self.transport.clock() + seconds
        while self.transport.clock() < deadline and not self._should_stop and not self.storage_failure and not self.continuation.stopped:
            self._check_ui_state()
            if not self._should_stop:
                self.transport.sleep(min(.1, deadline - self.transport.clock()))
        return not self._should_stop and not self.storage_failure and not self.continuation.stopped

    def execute_probe(self, probe):
        """Execute and record a configured probe under the engine action lock.

        Service probes require the saved campaign directive.
        """
        with self._action_lock:
            return self._execute_probe_locked(probe)

    def _execute_probe_locked(self, probe):
        from bytefault.core.contracts import ProbeRequest, MaterializedAction, ActionResult
        if not isinstance(probe, ProbeRequest) or probe.kind not in ('same_connection', 'service_connect'):
            raise ContractError('probe', 'unavailable', 'typed engine probe required')
        passive(probe, 'probe')
        if getattr(self, '_campaign_probe_permission', None) == probe:
            return self._execute_campaign_probe(probe)
        if probe.kind != 'same_connection':
            raise ContractError('probe', 'unavailable', 'service probe needs a saved campaign directive')
        association = self._observation_connections.get(probe.observation_id)
        if (association is None or association[0] != probe.correlation or self.socket is None or
                association[1] != getattr(self,'_connection_epoch',0)):
            self._required_save('probe_unavailable',{'probe':probe,
                'reason':'original observation connection is unknown or retired',
                'original_association':association,
                'actual_connection':{'epoch':getattr(self,'_connection_epoch',0),
                    **getattr(self,'_connection_context',{})}},identity=dict(freeze(probe.correlation)))
            raise ContractError('probe.connection','unavailable','original observation connection is unknown or retired')
        from bytefault.core.contracts import PassivePlan, ConversationAction
        validate_plan(PassivePlan('engine-probe', 1,
            (ConversationAction(probe.probe_id, probe.prepared, receive=probe.receive),)))
        hold = self.continuation.hold
        if (not self._executing_conversation or not self._accepting_observations or
                self.storage_failure or self._should_stop or self.continuation.stopped or self.socket is None):
            raise ContractError('probe', 'unavailable', 'no recorded active connection or engine stopped')
        if (hold is None or hold.decision_id != probe.decision_id or
                hold.observation_id != probe.observation_id or hold.correlation != probe.correlation):
            raise ContractError('probe', 'correlation', 'probe does not identify the active hold')
        correlation, epoch, request, original_id = association
        return self._execute_external_probe(probe, request, epoch, original_id)
    def _execute_external_probe(self, probe, request, epoch, original_id):
        """Use shared packet I/O with exact original association, no context swap."""
        from bytefault.core.contracts import MaterializedAction, ActionResult
        identity = dict(freeze(probe.correlation))
        identity.update(action_id=probe.probe_id, attempt_id=probe.probe_id, iteration_id=None)
        materialized = MaterializedAction(probe.probe_id,probe.prepared,probe.prepared)
        association={'original_observation_id':original_id,'original_correlation':probe.correlation,
            'original_request':request,'original_connection_epoch':epoch,
            'actual_connection':{'epoch':self._connection_epoch,**getattr(self,'_connection_context',{})}}
        prior_materialization, prior_result = self._current_materialization, self.last_transport_result
        prior_transport_context = self._last_transport_context
        self._current_materialization = materialized
        try:
            self._required_save('probe_materialization',{'probe':probe,'materialized':materialized,
                'association':association},identity=identity)
            self._offer_permission = probe.prepared
            self._exchange_packet(probe.prepared,probe.receive,probe=True,
                record_identity=identity,acknowledged_probe=True)
            result=ActionResult(probe.probe_id,'',None,probe.probe_id,materialized,self.last_transport_result)
            self._required_save('probe_result',{'probe':probe,'result':result,'association':association},identity=identity)
            observation=Observation(str(uuid4()),probe.correlation,result.transport,kind='probe',
                observed_at=self.transport.clock(),parameters={'probe_id':probe.probe_id,'original_request':request,
                    'observed_at_utc':datetime.now().astimezone().isoformat()})
            self._observation_connections[observation.observation_id]=(probe.correlation,epoch,request,observation.observation_id)
            capacity=getattr(getattr(self.monitoring,'observations',None),'maxlen',128) or 128
            while len(self._observation_connections)>capacity:
                self._observation_connections.popitem(last=False)
            self._publish_observation(observation,external=True)
            return result
        finally:
            self._current_materialization=prior_materialization
            self._offer_permission=None
            if not self.storage_failure:
                self.last_transport_result=prior_result
                self._last_transport_context=prior_transport_context

    def _execute_campaign_probe(self, probe):
        from dataclasses import replace
        from bytefault.core.contracts import TransportResult, MaterializedAction
        from bytefault.fuzzers.transport import EngineTransport
        from bytefault.monitoring.configuration import number
        number(probe.delay, 'probe.delay')
        number(probe.timeout, 'probe.timeout')
        if probe.timeout <= 0:
            raise ContractError('probe.timeout', 'invalid', 'positive timeout required')
        if self.storage_failure or self._should_stop or self.continuation.stopped:
            return None
        self._required_save('probe_wait', {'probe': probe})
        if not self._policy_wait(probe.delay):
            return None
        context = dict(self._record_context)
        previous_materialization = self._current_materialization
        previous_result = self.last_transport_result
        previous_transport_context = self._last_transport_context
        adapter, cleanup = None, None
        readiness = 'unknown'
        connection_context = ({'probe_connection_id': probe.probe_id,
            'host': self.transport.request.host, 'port': self.transport.request.port}
            if probe.kind == 'service_connect' else {
                'epoch': getattr(self, '_connection_epoch', 0),
                'setup': getattr(self, '_connection_context', {}),
                'governed_epoch': self._campaign_probe_connection})
        self._record_context.update(probe_id=probe.probe_id, attempt_id=probe.probe_id, iteration_id=None)
        self._current_materialization = MaterializedAction(probe.probe_id, probe.prepared, probe.prepared)
        try:
            self._required_save('probe_materialization', {'probe': probe,
                'materialized': self._current_materialization, 'actual_connection': connection_context})
            if self._should_stop or self.storage_failure or self.continuation.stopped:
                return None
            self._last_transport_context = dict(self._record_context)
            self.last_transport_result = None
            self._transport_in_progress = True
            if probe.kind == 'service_connect':
                adapter = EngineTransport(replace(self.transport.request, timeout=probe.timeout), socket_factory=self.transport.socket_factory,
                    sleep=self.transport.sleep if self.transport._injected_sleep else None,
                    clock=self.transport.clock)
                adapter.pacer = self.transport.pacer
                adapter.bind_stop_event(self._stop_event)
                opened = adapter.open()
                readiness = ('available' if opened else 'unavailable'
                    if adapter.last_open and adapter.last_open.get('connect_attempted') else 'unknown')
                fact = TransportResult(b'', receive_requested=False, receive_outcome='unrequested',
                    error=adapter.open_error, connection=adapter.last_open)
            else:
                from bytefault.core.contracts import PassivePlan, ConversationAction
                validate_plan(PassivePlan('engine-probe', 1,
                    (ConversationAction(probe.probe_id, probe.prepared, receive=probe.receive),)))
                if self._campaign_probe_connection != getattr(self, '_connection_epoch', 0):
                    raise ContractError('probe.connection', 'unavailable',
                        'original selected test connection was retired before this in-band observation')
                if self.socket is None:
                    fact = TransportResult(probe.prepared, receive_requested=probe.receive.requested,
                        error='same connection unavailable')
                else:
                    fact = self.transport.exchange(probe.prepared, probe.receive,
                        stopped=lambda: self._should_stop or self.storage_failure is not None or self.continuation.stopped)
                # The predicate is a declared interpretation; raw receive/connect facts survive.
                readiness = self.monitoring.service_readiness(probe, fact)
            self._transport_in_progress = False
            self.last_transport_result = fact
            self._required_save('probe_result', {'probe': probe, 'transport': fact,
                'service_readiness': readiness, 'actual_connection': connection_context})
            observation = Observation(str(uuid4()), probe.correlation, fact, kind='service_check',
                observed_at=self.transport.clock(), prior_observation_id=probe.observation_id,
                service_readiness=readiness, parameters={'probe_id': probe.probe_id,
                    'purpose': probe.purpose, 'delay': probe.delay, 'window': probe.window,
                    'predicate': probe.predicate, 'probe_kind': probe.kind,
                    'actual_connection': connection_context,
                    'observed_at_utc': datetime.now().astimezone().isoformat()})
            self._publish_observation(observation)
            return observation
        finally:
            self._transport_in_progress = False
            try:
                if adapter is not None:
                    cleanup = adapter.close(phase='service_probe')
                    self._record_probe_cleanup(probe,cleanup,connection_context)
            finally:
                self._record_context = context
                self._current_materialization = previous_materialization
                self.last_transport_result = previous_result
                self._last_transport_context = previous_transport_context
