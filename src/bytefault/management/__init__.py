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

"""Selected post-event routing. No classification, sender or resume owner."""
from dataclasses import dataclass
from collections import deque
from datetime import datetime
from queue import Queue, Full
import threading
from uuid import uuid4

from bytefault.core.contracts import MonitoringCompletion, MonitoringAction, Correlation, ContractError, freeze
from bytefault.reporting import ReportRequest, ReportOutcome
from bytefault.logging import ActionLog


@dataclass(frozen=True)
class CollectionOutcome:
    status: str
    artifacts: tuple = ()
    error: str = ''
    items: tuple = ()
    operations: tuple = ()
    inventory_status: str = 'unknown'


@dataclass(frozen=True)
class FollowupOutcome:
    followup_id: str
    action_id: str
    event_id: str
    observation_id: str
    collection: CollectionOutcome
    report: ReportOutcome | None


class Management:
    """Application/caller-lifetime port with independent required action history.

    A bounded worker queue allows nonblocking campaign continuation; late results
    remain correlated in this store even after a run detaches. Acquisition is
    optional; selected Reporting runs with disabled or failed collection too.
    """
    def __init__(self, store, *, reporting=None, collection=None, action_log=None, capacity=8):
        if type(capacity) is not int or capacity < 1:
            raise ValueError('positive follow-up capacity required')
        self.store, self.reporting, self.collection = store, reporting, collection
        self._owns_log = action_log is None
        self.action_log = action_log or ActionLog.open(str(store.path) + '.actions.bfr', owner='application')
        self._queue = Queue(maxsize=capacity)
        self._lock = threading.RLock()
        self._idle = threading.Condition(self._lock)
        self._finalized = False
        self._finalizing = False
        self._completed_total = self._failed_total = 0
        self.on_drained = None
        self._closed = False
        self._pending = set()
        self._pending_collection = {}
        self._settling = set()
        self._drained_callbacks = set()
        self._outcomes = deque(maxlen=capacity)
        self.failures = deque(maxlen=capacity)
        self._collection_boundary_loaded = False
        self._last_successful_collection = None
        self._worker = threading.Thread(target=self._work, daemon=False)
        try:
            self._worker.start()
        except BaseException as error:
            if self._owns_log:
                try:
                    self.action_log.end('application')
                except BaseException as cleanup_error:
                    error.add_note('Management initialization cleanup: ' + str(cleanup_error))
            raise

    def _save(self, kind, identity, data):
        ref = self.store.append(kind, identity, data)
        if self.action_log:
            self.action_log(kind, identity, data, ref)
        return ref

    @staticmethod
    def validate_action(action):
        from bytefault.core.validation import validate_followup_action
        return validate_followup_action(action)

    def _previous_collection(self):
        """Use acknowledged history so a reused result bin retains its boundary."""
        with self._lock:
            if not self._collection_boundary_loaded:
                recovered = self.store.snapshot()
                for record, ref in zip(recovered.records, recovered.refs):
                    if record.kind == 'collection_outcome' and record.data['collection']['status'] == 'succeeded':
                        boundary = record.data.get('boundary')
                        if boundary is None:
                            operations = record.data['collection'].get('operations', ())
                            completed = next((op['completed_at'] for op in reversed(operations)
                                if op.get('completed_at')), None)
                            if completed is not None:
                                boundary = {'run_id': record.identity.get('run_id'),
                                    'followup_action_id': record.identity.get('followup_action_id'),
                                    'completed_at_utc': completed,
                                    'inventory_status': record.data['collection'].get('inventory_status')}
                        if boundary is not None:
                            self._last_successful_collection = freeze({**dict(boundary), 'record_reference': ref})
                self._collection_boundary_loaded = True
            return self._last_successful_collection

    @staticmethod
    def _log_position(context):
        from bytefault.core.storage import reopen_records
        if not context or not context.get('log_path'):
            return None
        recovered = reopen_records(context['log_path'])
        return recovered.refs[-1] if recovered.issue is None and recovered.refs else None

    def _result_position(self):
        if self.reporting is None:
            return None
        recovered = self.reporting.root.store.snapshot()
        return recovered.refs[-1] if recovered.issue is None and recovered.refs else None

    def _intervening_tests(self, context, boundary, current_boundary):
        """Read every registered run log in the collection window.

        Within a boundary/current log, acknowledged frame offsets give exact
        ordering. Across distinct logs, UTC append times define candidates;
        this never attributes a core to an individual test.
        """
        from pathlib import Path
        from bytefault.core.storage import reopen_records
        current_run = context.get('decision', {}).get('correlation', {}).get('run_id') if context else None
        current_path = str(Path(context['log_path']).resolve()) if context and context.get('log_path') else None
        registry = self.reporting.root.store.snapshot() if self.reporting is not None else None
        entries = []
        registry_end = current_boundary.get('result_root_reference') if current_boundary else None
        if registry is not None:
            for record, ref in zip(registry.records, registry.refs):
                if registry_end is not None and ref.offset > registry_end.offset:
                    break
                if record.kind == 'run_action_log':
                    entries.append((record.identity['run_id'], str(Path(record.data['log_path']).resolve())))
        if boundary and boundary.get('action_log_path'):
            entries.append((boundary['run_id'], str(Path(boundary['action_log_path']).resolve())))
        if current_run and current_path:
            entries.append((current_run, current_path))
        entries = tuple(dict.fromkeys(entries))
        issues = []
        if registry is None or (registry.issue is not None and registry.issue.kind != 'not_found'):
            issues.append('run log registry unavailable')
        if boundary and not any(run == boundary['run_id'] for run, _ in entries):
            issues.append('boundary run log unavailable')
        if not current_path:
            issues.append('current run log unavailable')
        try:
            since = datetime.fromisoformat(boundary['completed_at_utc']) if boundary else None
            until = datetime.fromisoformat(current_boundary['completed_at_utc']) if current_boundary else None
        except (KeyError, TypeError, ValueError):
            return (), 'boundary time unavailable'
        start_ref = boundary.get('action_log_reference') if boundary else None
        end_ref = current_boundary.get('action_log_reference') if current_boundary else None
        candidates = []
        for registration_order, (run_id, path) in enumerate(entries):
            recovered = reopen_records(path)
            if recovered.issue is not None:
                issues.append(f'{run_id} log {recovered.issue.kind}')
            for record, ref in zip(recovered.records, recovered.refs):
                if record.kind != 'action_result' or record.identity.get('run_id') != run_id:
                    continue
                try:
                    when = datetime.fromisoformat(record.data['recorded_at_utc'])
                except (KeyError, TypeError, ValueError):
                    issues.append(f'{run_id} action time unavailable')
                    continue
                if (start_ref is not None and str(Path(start_ref.path).resolve()) == path):
                    if ref.offset <= start_ref.offset:
                        continue
                elif since is not None and when < since:
                    continue
                if (end_ref is not None and str(Path(end_ref.path).resolve()) == path):
                    if ref.offset > end_ref.offset:
                        continue
                elif until is not None and when > until:
                    continue
                candidates.append((when, registration_order, ref.offset, freeze({'identity': record.identity,
                    'evidence_reference': record.data.get('evidence_reference'),
                    'action_log_reference': ref})))
        candidates.sort(key=lambda item: (item[0], item[1], item[2]))
        scope = ('complete_registered_action_logs' if not issues else
                 'incomplete; ' + '; '.join(dict.fromkeys(issues)))
        return tuple(item[3] for item in candidates), scope

    @staticmethod
    def _stored_context(context):
        reference = context.get('report_context_ref') if context else None
        return (freeze({'projection': 'reference_only', 'record_reference': reference})
                if reference is not None else context)

    def route(self, action, *, context=None, _accepted=False, progress=None, required_failure=None):
        """Direct operations share the admitted-work lifetime with queued ones."""
        context = freeze(context) if context is not None else None
        token = None
        if not _accepted:
            self.validate_action(action)
            token = self._admit_direct()
        failed = False
        try:
            if token is not None:
                self._save('management_pending', dict(freeze(action.correlation)), {'action': action,
                    'followup_id': token, 'context': context, 'mode': 'standalone'})
            result = self._route(action, context=context, _accepted=True, progress=progress,
                                 required_failure=required_failure)
            failed = (result.collection.status == 'failed' or
                      (result.report is not None and result.report.status in ('failed', 'unavailable')))
            return result
        except Exception:
            failed = True
            raise
        finally:
            if token is not None:
                self._finish_direct(token, failed)

    def _admit_direct(self):
        with self._lock:
            if self._closed:
                raise OSError('Management attachment closed')
            token = str(uuid4())
            self._pending.add(token)
            return token

    def _finish_direct(self, token, failed):
        with self._lock:
            self._pending.discard(token)
            self._completed_total += 1
            self._failed_total += int(failed)
            finished = self._closed and not self._pending and not self._settling
            self._idle.notify_all()
            if finished:
                self._queue.put_nowait(None)
        if finished:
            self._finish_close()

    def maintain(self, request, *, process=None, stopped=None, pacer=None):
        """Explicit maintenance shares this owner's admission and required log."""
        from bytefault.management.maintenance import MaintenanceRequest, perform_maintenance
        from bytefault.core.input_files import selected_scope_aliases
        from pathlib import Path
        if not isinstance(request, MaintenanceRequest):
            raise ContractError('maintenance.request', 'invalid', 'typed MaintenanceRequest required')
        from dataclasses import replace
        from bytefault.paths import artifacts_root
        protected = [getattr(self.store, 'path', None), getattr(getattr(self.action_log, 'store', None), 'path', None)]
        if self.reporting is not None:
            protected.extend((self.reporting.root.store.path, self.reporting.root.action_log.store.path))
        request = replace(request, local_cache=request.local_cache or
            getattr(self.collection, 'core_cache_dir', None) or str(artifacts_root() / '_core_cache'),
            protected_files=tuple(dict.fromkeys((*request.protected_files, *request.input_files,
                *(str(p) for p in protected if p is not None)))))
        if request.local and request.input_files:
            root = Path(request.local_cache).absolute()
            selected = tuple(root / part for part in request.local_entries) if request.local_entries else (root,)
            try:
                collision = selected_scope_aliases(selected, request.input_files)
            except OSError as error:
                raise ContractError('maintenance.destinations', 'path_error', str(error)) from error
            if collision:
                raise ContractError('maintenance.destinations', 'source_collision',
                                    'selected scope includes a current input')
        token, failed = self._admit_direct(), True
        identity = {'service_id': token, 'host': request.host, 'operation': 'maintenance'}
        def save(kind, data):
            from bytefault.core.records import RequiredServiceSaveFailure, emit_recording_diagnostic
            try:
                return self._save(kind, identity, data)
            except Exception as error:
                diagnostic = freeze({'required_record_kind': kind, 'identity': identity,
                    'unacknowledged_action': data, 'reason': str(error)})
                raise RequiredServiceSaveFailure(diagnostic, emit_recording_diagnostic(diagnostic)) from error
        try:
            save('maintenance_request', {'request': request})
            outcome = perform_maintenance(request, save=save, process=process, stopped=stopped,
                pacer=pacer)
            failed = outcome['outcome'] != 'completed'
            save('maintenance_terminal', {'outcome': outcome})
            return outcome
        except Exception as error:
            try:
                save('maintenance_failure', {'request': request, 'error': str(error), 'error_type': type(error).__name__,
                    'diagnostic': getattr(error, 'diagnostic', None),
                    'diagnostic_delivery_error': getattr(error, 'diagnostic_delivery_error', None)})
            except Exception as failure_error:
                error.add_note('Maintenance failure history: ' + str(failure_error))
            raise
        finally:
            self._finish_direct(token, failed)

    def _route(self, action, *, context=None, _accepted=False, progress=None, required_failure=None):
        """Standalone owner operation; constructing an engine is unnecessary."""
        if self._closed and not _accepted:
            raise OSError('Management attachment closed')
        self.validate_action(action)
        context = freeze(context) if context is not None else None
        identity = dict(freeze(action.correlation))
        identity.update(followup_action_id=action.action_id, event_id=action.event_id,
                        observation_id=action.observation_id)
        history_errors = []
        def save(kind, data):
            try:
                return self._save(kind, identity, data)
            except Exception as exc:
                history_errors.append(exc)
        saved_context = self._stored_context(context)
        save('management_request', {'action': action, 'context': saved_context})
        if context is not None:
            save('report_context', {'context': saved_context})
        if history_errors and required_failure is not None:
            required_failure(history_errors[0])
        enabled = action.parameters.get('collect', False)
        if not enabled:
            collected = CollectionOutcome('disabled', inventory_status='not_requested')
        elif history_errors:
            collected = CollectionOutcome('failed', error='required Management request history unavailable; acquisition not started')
        elif self.collection is None:
            collected = CollectionOutcome('failed', error='collection port unavailable')
        else:
            try:
                from bytefault.management.collection import Collection
                collected = (self.collection(action, context=context) if isinstance(self.collection, Collection)
                             else self.collection(action))
                if (not isinstance(collected, CollectionOutcome) or
                        collected.status not in ('succeeded', 'failed', 'pending', 'disabled')):
                    raise ValueError('invalid collection outcome')
            except Exception as exc:
                collected = CollectionOutcome('failed', error=str(exc))
        previous = self._previous_collection() if enabled else None
        boundary = freeze({'run_id': action.correlation.run_id,
            'followup_action_id': action.action_id,
            'completed_at_utc': datetime.now().astimezone().isoformat(),
            'action_log_path': context.get('log_path') if context else None,
            'action_log_reference': self._log_position(context),
            'result_root_reference': self._result_position(),
            'inventory_status': collected.inventory_status}) if enabled and collected.status == 'succeeded' else None
        collection_ref = save('collection_outcome', {'collection': collected, 'boundary': boundary})
        if boundary is not None and collection_ref is not None and not history_errors:
            with self._lock:
                self._last_successful_collection = freeze({**dict(boundary), 'record_reference': collection_ref})
        if history_errors:
            from dataclasses import replace
            collected = replace(collected, status='failed', error='required Management history failed: ' +
                '; '.join(str(e) for e in history_errors) + '; ' + collected.error)
            if required_failure is not None:
                required_failure(history_errors[0])
        if progress is not None:
            progress('collection', collected.status, None)
        report = None
        if action.parameters.get('report', False):
            new_cores = tuple(item for item in collected.items if item.get('status') == 'cached')
            if len(new_cores) > 1:
                candidates, scope = self._intervening_tests(context, previous, boundary)
                context = freeze({**dict(context or {}), 'collection_boundary': previous,
                    'intervening_test_identities': candidates, 'intervening_test_scope': scope})
            report_id = str(uuid4())
            if self.reporting is None:
                report = ReportOutcome(report_id, action.event_id, action.action_id,
                                       'unavailable', error='Reporting not attached')
            else:
                report = self.reporting.report(ReportRequest(report_id, action,
                    collected.status, collected.artifacts, collected.error, context,
                    collected.items, collected.operations, collected.inventory_status))
            if progress is not None:
                progress('report', report.status, report.location)
        outcome = FollowupOutcome(str(uuid4()), action.action_id, action.event_id,
                                  action.observation_id, collected, report)
        save('management_outcome', {'outcome': outcome})
        if history_errors:
            raise OSError('required Management history failed: ' + '; '.join(str(e) for e in history_errors))
        return outcome

    def dispatch(self, decision, completion, required_failure=None, *, context=None, actions=None, settled=None):
        from bytefault.core.validation import validate_wait_obligations
        validate_wait_obligations(decision)
        selected = decision.actions if actions is None else tuple(actions)
        if any(action not in decision.actions for action in selected):
            raise ValueError('dispatch selection must belong to the supplied decision')
        context = freeze(context) if context is not None else None
        for action in selected:
            self.validate_action(action)
        for action in selected:
            with self._lock:
                if self._closed:
                    raise OSError('Management attachment closed')
            token = str(uuid4())
            # Required disk I/O must not hold the status/queue-state lock.
            self._save('management_pending', dict(freeze(action.correlation)),
                       {'decision': decision, 'action': action, 'followup_id': token,
                        'context': self._stored_context(context)})
            rejected = False
            with self._lock:
                if self._closed:
                    rejected = True
                else:
                    self._pending.add(token)
                    if action.parameters.get('collect'):
                        self._pending_collection[token] = action.correlation.run_id
                    try:
                        self._queue.put_nowait((token, decision, action, completion, required_failure, context, settled))
                    except Full:
                        self._pending.remove(token)
                        self._pending_collection.pop(token, None)
                        rejected = True
            if rejected:
                self._save('management_rejected', dict(freeze(action.correlation)),
                    {'action': action, 'reason': 'bounded queue full or attachment closed'})
                for condition, enabled in (('collection', action.parameters.get('collect', False)),
                                           ('report', action.parameters.get('report', False))):
                    if not enabled:
                        continue
                    completion(MonitoringCompletion(str(uuid4()), decision.decision_id,
                        decision.observation_id, decision.correlation, condition, 'failed',
                        followup_action_id=action.action_id))
                if settled is not None:
                    finalize, settlement_error = settled(action, None, 'bounded queue full or attachment closed')
                    if finalize is not None:
                        after_drained = finalize()
                        if after_drained is not None:
                            after_drained()
                    if settlement_error is not None:
                        raise settlement_error

    def _work(self):
        while True:
            task = self._queue.get()
            if task is None:
                self._queue.task_done()
                return
            token, decision, action, completion, required_failure, context, settled = task
            outcome, error = None, None
            failed = [False]
            failure_notified = [False]
            try:
                def notify_failure(exc):
                    failed[0] = True
                    if failure_notified[0] or required_failure is None:
                        return
                    failure_notified[0] = True
                    try:
                        required_failure(exc)
                    except Exception as callback_error:
                        from bytefault.core.records import emit_recording_diagnostic
                        emit_recording_diagnostic({'required_record_kind': 'management_required_failure_callback',
                            'reason': str(callback_error), 'action': action})
                def progress(condition, status, reference):
                    value = MonitoringCompletion(str(uuid4()), decision.decision_id,
                        decision.observation_id, decision.correlation, condition,
                        status if status in ('succeeded', 'failed', 'pending', 'disabled') else 'failed',
                        reference, followup_action_id=action.action_id)
                    try:
                        self._save('management_completion', dict(freeze(action.correlation)), {'completion': value})
                        completion(value)
                    except Exception as exc:
                        failed[0] = True
                        # Delivery to a stopped/broken run must not cancel the
                        # independently accepted selected report for this event.
                        fact = freeze({'followup_id': token, 'condition': condition,
                            'completion': value, 'error': str(exc), 'operation': 'completion_delivery'})
                        with self._lock:
                            self.failures.append(fact)
                        try:
                            self._save('management_completion_delivery_failed', dict(freeze(action.correlation)), fact)
                        except Exception as history_error:
                            from bytefault.core.records import emit_recording_diagnostic
                            emit_recording_diagnostic({'required_record_kind': 'management_completion_delivery_failed',
                                'reason': str(history_error), 'fact': fact})
                        notify_failure(exc)
                    finally:
                        if condition == 'collection':
                            with self._lock:
                                self._pending_collection.pop(token, None)
                outcome = self.route(action, context=context, _accepted=True, progress=progress,
                                     required_failure=notify_failure)
                failed[0] |= (outcome.collection.status == 'failed' or
                    (outcome.report is not None and outcome.report.status in ('failed', 'unavailable')))
                with self._lock:
                    self._outcomes.append(freeze({'followup_id': token, 'outcome': outcome}))
            except Exception as exc:
                error = str(exc)
                failed[0] = True
                # Owner-visible failure; never manufacture a successful completion.
                with self._lock:
                    self.failures.append(freeze({'followup_id': token, 'error': str(exc)}))
                try:
                    self._save('management_failure', dict(freeze(action.correlation)),
                        {'followup_id': token, 'action': action, 'error': str(exc),
                         'context': self._stored_context(context)})
                except Exception as history_error:
                    from bytefault.core.records import emit_recording_diagnostic
                    emit_recording_diagnostic({'required_record_kind': 'management_failure',
                        'reason': str(history_error), 'action': action, 'error': str(exc)})
                notify_failure(exc)
            finally:
                finalize = None
                if settled is not None:
                    try:
                        finalize, settlement_error = settled(action, outcome, error)
                        if settlement_error is not None:
                            raise settlement_error
                    except Exception as callback_error:
                        notify_failure(callback_error)
                        try:
                            self._save('management_settlement_failed', dict(freeze(action.correlation)),
                                {'action': action, 'error': str(callback_error),
                                 'diagnostic': getattr(callback_error, 'diagnostic', None)})
                        except Exception as history_error:
                            from bytefault.core.records import emit_recording_diagnostic
                            emit_recording_diagnostic({'required_record_kind': 'management_settlement_failed',
                                'reason': str(history_error), 'action': action})
                        from bytefault.core.records import emit_recording_diagnostic
                        emit_recording_diagnostic({'required_record_kind': 'management_settled_callback',
                            'reason': str(callback_error), 'action': action})
                with self._lock:
                    self._completed_total += 1
                    self._failed_total += int(failed[0])
                    self._settling.add(token)
                    self._pending.discard(token)
                    self._pending_collection.pop(token, None)
                self._queue.task_done()
                after_drained = None
                if finalize is not None:
                    try:
                        after_drained = finalize()
                    except Exception as callback_error:
                        with self._lock:
                            self._failed_total += 1
                            self.failures.append(freeze({'operation': 'management_finalization_callback',
                                'error': str(callback_error), 'action': action}))
                        from bytefault.core.records import emit_recording_diagnostic
                        emit_recording_diagnostic({'required_record_kind': 'management_finalization_callback',
                            'reason': str(callback_error), 'action': action})
                with self._idle:
                    if after_drained is not None:
                        self._drained_callbacks.add(token)
                    self._settling.discard(token)
                if after_drained is not None:
                    try:
                        after_drained()
                    except Exception as callback_error:
                        with self._lock:
                            self._failed_total += 1
                            self.failures.append(freeze({'operation': 'management_drained_callback',
                                'error': str(callback_error), 'action': action}))
                        from bytefault.core.records import emit_recording_diagnostic
                        emit_recording_diagnostic({'required_record_kind': 'management_drained_callback',
                            'reason': str(callback_error), 'action': action})
                with self._idle:
                    self._drained_callbacks.discard(token)
                    finished = self._closed and not self._pending and not self._settling and not self._drained_callbacks
                if finished:
                    self._finish_close()
                with self._idle:
                    self._idle.notify_all()
            if finished:
                return

    def _finish_close(self):
        with self._lock:
            if (self._finalized or self._finalizing or self._pending or self._settling or
                    (self._drained_callbacks and not self.draining_current_thread())):
                return
            self._finalizing = True
        try:
            if self._owns_log:
                self.action_log.end('application')
            if self.on_drained is not None:
                self.on_drained()
        except Exception as exc:
            from bytefault.core.records import emit_recording_diagnostic
            fact = freeze({'operation': 'management_finalize', 'error': str(exc)})
            with self._lock:
                self.failures.append(fact)
                self._failed_total += 1
            emit_recording_diagnostic({'required_record_kind': 'management_finalize', 'reason': str(exc)})
        finally:
            with self._idle:
                self._finalizing = False
                self._finalized = True
                self._idle.notify_all()

    def wait(self, timeout=None):
        """Drain admitted work without cancelling it; admission closes separately."""
        with self._idle:
            self._idle.wait_for(lambda: not self._pending and not self._settling and not self._drained_callbacks and
                               (not self._closed or self._finalized), timeout)
        if self._closed and threading.current_thread() is not self._worker:
            self._worker.join(timeout)
        return self.status()

    def status(self):
        with self._lock:
            return freeze({'pending': tuple(self._pending), 'outcomes': tuple(self._outcomes),
                           'settling': tuple(self._settling),
                           'drained_callbacks': tuple(self._drained_callbacks),
                           'failures': tuple(self.failures), 'closed': self._closed,
                           'finalized': self._finalized, 'completed_total': self._completed_total,
                           'failed_total': self._failed_total,
                           'outcome': 'pending' if self._pending or self._settling or self._drained_callbacks or (self._closed and not self._finalized) else
                                      'failed' if self._failed_total else 'completed'})

    def pending_collection(self, run_id):
        with self._lock:
            return run_id in self._pending_collection.values()

    def draining_current_thread(self):
        """Only the active owner-close callback may finalize its own writers."""
        with self._lock:
            return threading.current_thread() is self._worker and bool(self._drained_callbacks)

    def close(self):
        """No caller store close; return pending if an external port is running."""
        with self._lock:
            self._closed = True
            pending = tuple(self._pending | self._settling | self._drained_callbacks)
            can_finalize = not self._pending and not self._settling and (
                not self._drained_callbacks or self.draining_current_thread())
            if can_finalize:
                if self._worker.is_alive() and threading.current_thread() is not self._worker:
                    try:
                        self._queue.put_nowait(None)
                    except Full:
                        pass
        if can_finalize:
            self._finish_close()
        return freeze({'outcome': 'pending' if pending or not self._finalized else 'completed', 'pending': pending})
