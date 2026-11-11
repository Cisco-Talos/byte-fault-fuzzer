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

"""In-process application contract shared by argument and callable clients.

No transport protocol, model runtime or terminal dependency is required. Each
submit executes the ordinary engine; status/control queries never hold a global
application lock across execution or required I/O.
"""
from collections import deque
from dataclasses import dataclass, fields, replace
from datetime import datetime
from pathlib import Path
import threading
import math
import sys
from uuid import uuid4
from contextlib import contextmanager

from bytefault.core.contracts import (ConversationRequest, TransportRequest,
    ContractError, ControlOutcome, CampaignOptions, freeze)
from bytefault.core.storage import LocalRecordStore, reopen_records
from bytefault.core.records import emit_recording_diagnostic, RecordRef, RequiredServiceSaveFailure
from bytefault.fuzzers.declarations import discover, admit_plan, SUPPORTED_CAPABILITIES
from bytefault.fuzzers.protocol_directory import discover_protocols, select_actions
from bytefault.fuzzers.fuzzer import ProtocolFuzzer
from bytefault.fuzzers.inputs import request_to_data, request_from_data
from bytefault.fuzzers.transport import EngineTransport
from bytefault.logging import ActionLog
from bytefault.paths import run_path


@dataclass(frozen=True)
class ApplicationRequest:
    conversation: ConversationRequest
    transport: TransportRequest
    record_path: str
    log_path: str | None = None


@dataclass(frozen=True)
class IndependentOperation:
    operation_id: str
    stopped: object
    source_inventory: object


@dataclass(frozen=True)
class ServiceTarget:
    """Independent non-TCP owner context, including local-only operations."""
    host: str | None = None

    def __post_init__(self):
        if self.host is not None and (not isinstance(self.host, str) or not self.host):
            raise ContractError('services.host', 'invalid', 'nonempty host or explicit local-only None required')


@dataclass(frozen=True)
class CampaignRequest(ApplicationRequest):
    options: CampaignOptions = CampaignOptions()
    generation: object = None
    cases: tuple[ConversationRequest, ...] = ()
    monitoring_configuration: object = None

    def __post_init__(self):
        from bytefault.core.validation import passive
        if self.generation is not None:
            passive(self.generation, 'campaign.generation')
            object.__setattr__(self, 'generation', freeze(self.generation))
        if self.monitoring_configuration is not None:
            from bytefault.monitoring.configuration import MonitoringConfig
            if not isinstance(self.monitoring_configuration, MonitoringConfig):
                raise ContractError('campaign.monitoring_configuration', 'invalid', 'typed MonitoringConfig required')
        if not isinstance(self.cases, tuple):
            raise ContractError('campaign.cases', 'invalid', 'ordered literal conversation tuple required')


class _CampaignFamilies:
    """Own preparation even when execution fails before generator entry."""
    def __init__(self, iterator, preparation=None, literal_items=()):
        self.iterator, self.preparation = iterator, preparation
        self.literal_items = literal_items
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if getattr(self, '_cancelled', lambda: False)():
            raise StopIteration
        return next(self.iterator)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.iterator.close()
        finally:
            if self.preparation is not None:
                self.preparation.close()

    def set_cancelled(self, predicate):
        self._cancelled = predicate
        if self.preparation is not None:
            self.preparation._external_cancelled = predicate


@dataclass(frozen=True)
class SavedStepIntent:
    action_id: str
    choice: str = 'recorded'
    reapply_mutations: bool = False
    dynamic_source_reference: str | None = None


@dataclass(frozen=True)
class SavedCaseIntent:
    path: str
    record_id: str = ''
    mode: str = 'literal'
    steps: tuple[SavedStepIntent, ...] = ()


@dataclass(frozen=True)
class ResumeChoice:
    conversation_id: str
    disposition: str
    steps: tuple[SavedStepIntent, ...] = ()


@dataclass(frozen=True)
class ResumeIntent:
    path: str
    choices: tuple[ResumeChoice, ...] = ()


@dataclass(frozen=True)
class ResumeRequest(CampaignRequest):
    resume: object = None

    def __post_init__(self):
        super().__post_init__()
        from bytefault.core.validation import passive
        from collections.abc import Mapping
        if not isinstance(self.resume, Mapping) or set(self.resume) != {
                'root', 'history', 'source_path', 'references', 'recovery_issue', 'choices', 'continuation'}:
            raise ContractError('resume', 'malformed', 'complete retained restart contract required')
        passive(self.resume, 'resume')
        object.__setattr__(self, 'resume', freeze(self.resume))


@dataclass(frozen=True)
class Unavailable:
    operation: str
    owner: str
    due: str
    check: str
    status: str = 'unavailable'


@dataclass(frozen=True)
class ServiceHistory:
    """Complete selected valid history; refs align with records, issues name paths.

    A path generation changes on replacement or a changed recovered prefix, not
    on a verified append. Readers own their cursors; this value consumes nothing.
    """
    records: tuple
    refs: tuple
    issues: tuple
    generations: tuple


FUTURE = {
    'schema_to_dissector': ('Passive authoring', 'later converter', 'no converter implementation attached'),
    'dissector_to_schema': ('Passive authoring', 'later converter', 'recognized data may be authored as a versioned partial declaration'),
    'pi': ('Optional Pi client', 'UI-PI', 'separately commissioned application client'),
}


class _Run:
    def __init__(self, request, engine, capacity):
        self.request, self.engine = request, engine
        self.action_log = None
        self.state, self.result, self.error = 'initializing', None, None
        self.active = True
        self.closing = False
        self.finalized = threading.Event()
        self.stop_requested = threading.Event()
        self.storage_failure = None
        self.diagnostic_delivery_error = None
        self.lock = threading.RLock()
        self.history_lock = threading.RLock()
        self.projection_dropped = 0
        self.events = deque(maxlen=capacity)
        self.sequence = 0
        self.exception = None
        self.worker = None
        self.cleanup_errors = ()

    def event(self, kind, identity, data, ref=None):
        if not self.history_lock.acquire(blocking=False):
            self.projection_dropped += 1
            return
        try:
            self.sequence += 1
            self.events.append(freeze({'event_id': f'{self.request.conversation.run_id}:{self.sequence}',
                'sequence': self.sequence, 'kind': kind, 'identity': identity,
                'data': data, 'record_ref': ref}))
        finally:
            self.history_lock.release()


class _Attachment:
    """One construction result shared by all same-application waiters."""
    def __init__(self):
        self.done, self.error = threading.Event(), None


class RunHandle:
    """A consumer attachment; detaching this value never stops its run."""
    def __init__(self, application, run_id):
        self.application, self.run_id = application, run_id

    def status(self):
        return self.application.status(self.run_id)

    def control(self, command):
        return self.application.control(self.run_id, command)

    def observe(self, *, after=0):
        return self.application.observe(self.run_id, after=after)

    def wait(self, timeout=None):
        run = self.application._run(self.run_id)
        if run.worker is not None:
            run.worker.join(timeout)
        if run.active or (run.worker is not None and run.worker.is_alive()):
            return None
        if run.exception is not None:
            raise run.exception
        return run.result


class Application:
    def __init__(self, *, transport_factory=None, monitoring=None, management=None, reporting=None,
                 action_logs=(), event_capacity=128, service_configuration=None, heartbeat=None):
        if type(event_capacity) is not int or event_capacity < 1:
            raise ValueError('positive event capacity required')
        self.transport_factory = transport_factory or EngineTransport
        from bytefault.core.connection_pacing import ConnectionPacer
        self._connection_pacers = {}
        self._connection_pacer_type = ConnectionPacer
        self.monitoring, self.management = monitoring, management
        # Attached service resources remain caller-owned. Management's reporter
        # remains a convenient shared attachment when no independent one is given.
        self.reporting = reporting if reporting is not None else (
            management.reporting if management is not None else None)
        self.action_logs = tuple(action_logs)
        self.event_capacity = event_capacity
        self._runs, self._lock, self._closed = {}, threading.RLock(), False
        self._configuration_lock = threading.RLock()
        self._pending_monitoring = set()
        self._independent_operations = {}
        self._independent_targets = {}
        self._independent_cleanup_errors = []
        self._independent_log_path = str(run_path('services-' + str(uuid4())) ) + '.actions.bfr'
        self._preparations = {}
        self._preparation_failures = {}
        self._service_references = []
        self._service_history_lock = threading.RLock()
        self._service_snapshots = {}
        self._service_provider_histories = {}
        self._service_provider_generation = 0
        self._owned_services = None
        self._owned_services_drained = threading.Event()
        self._default_result_root = None
        self._attachments = {}
        self._heartbeats = {heartbeat.host: heartbeat} if heartbeat is not None else {}
        self._heartbeat_logs = {}
        self._heartbeat_failures = {}
        self.service_configuration = None
        if service_configuration is not None:
            self.configure_services(service_configuration)

    def connection_pacer(self, run_id):
        with self._lock:
            return self._connection_pacers.setdefault(run_id, self._connection_pacer_type())

    @staticmethod
    def _same_service_value(name, first, second):
        if name in ('result_root', 'ssh_key', 'cache_dir') and first is not None and second is not None:
            return Path(first).resolve() == Path(second).resolve()
        return first == second

    def _effective_service_configuration(self):
        """Read exposed owner settings; never infer an opaque collaborator's I/O."""
        from bytefault.management.configuration import ServiceConfiguration
        values = {}
        with self._lock:
            reporting = self.reporting or getattr(self.management, 'reporting', None)
            collection = getattr(self.management, 'collection', None)
        if reporting is not None:
            values['result_root'] = str(reporting.root.path)
        if collection is not None:
            for name in ('ssh_key', 'ssh_user', 'ssh_pass', 'remote_dir', 'max_file_size_mb', 'min_timeout', 'core_write_wait'):
                if hasattr(collection, name):
                    values[name] = getattr(collection, name)
            if isinstance(values.get('ssh_key'), Path):
                values['ssh_key'] = str(values['ssh_key'])
            if hasattr(collection, 'core_cache_dir'):
                values['cache_dir'] = str(collection.core_cache_dir)
        # A supplied per-host monitor does not enable automatic monitoring of
        # other hosts or set their cadence. Its own settings stay caller-owned.
        return ServiceConfiguration(**values)

    def configure_service_options(self, *, _apply=True, **choices):
        """Merge explicit argument intent, preserving omitted callable configuration."""
        with self._configuration_lock:
            if not choices and self.service_configuration is None and self.management is not None:
                return
            base = self.service_configuration or self._effective_service_configuration()
            configuration = replace(base, **choices)
            self.configure_services(configuration, _selected=tuple(choices), _apply=_apply)
            if not _apply:
                return configuration

    def configure_services(self, configuration, *, _selected=None, _apply=True):
        from bytefault.management.configuration import ServiceConfiguration
        if not isinstance(configuration, ServiceConfiguration):
            raise ContractError('services', 'invalid', 'typed ServiceConfiguration required')
        with self._configuration_lock:
            previous = self.service_configuration
            effective = self._effective_service_configuration() if previous is not None else None
            changed = previous is not None and any(
                    not self._same_service_value(f.name, getattr(configuration, f.name),
                        getattr(effective, f.name) if f.name in ('result_root', 'cache_dir') and
                        getattr(previous, f.name) is None else getattr(previous, f.name))
                    # Absence still means reuse the attached default destination.
                    for f in fields(configuration) if not (f.name in ('result_root', 'cache_dir') and
                        getattr(configuration, f.name) is None and getattr(effective, f.name) is not None))
            def admission():
                if self._closed:
                    raise ContractError('services', 'closed', 'application closed')
                if (previous is None or changed) and (
                        self._owned_services is not None or self._pending_attachments() or
                        any(r.active for r in self._runs.values())):
                    raise ContractError('services', 'busy', 'configured service owner already attached or initializing')
            with self._lock:
                admission()
                reporters = (self.reporting, getattr(self.management, 'reporting', None))
                management = self.management
                collection = getattr(management, 'collection', None)
                heartbeats = tuple(self._heartbeats.values())
            selected = set(_selected) if _selected is not None else {f.name for f in fields(configuration)}
            # Canonical path comparison may touch the filesystem. Only the
            # configuration serializer is held; stop/status/close remain free.
            for reporting in reporters:
                if (reporting is not None and configuration.result_root is not None and
                        not self._same_service_value('result_root', configuration.result_root, reporting.root.path)):
                    raise ContractError('services.result_root', 'conflicting_input',
                                        'configured root conflicts with the supplied Reporting owner')
            for name in selected & {'ssh_key', 'ssh_user', 'ssh_pass', 'remote_dir', 'cache_dir',
                                    'max_file_size_mb', 'min_timeout', 'core_write_wait'}:
                if management is None:
                    continue
                value = getattr(configuration, name)
                if name == 'cache_dir' and value is None:
                    continue
                actual = getattr(collection, 'core_cache_dir' if name == 'cache_dir' else name, None)
                default_key_user = name == 'ssh_user' and value is None and actual == 'root'
                if collection is None or not (default_key_user or self._same_service_value(name, value, actual)):
                    raise ContractError('services.' + name, 'conflicting_input',
                                        'configured option conflicts with the supplied Management owner')
            for monitor in heartbeats:
                if ('heartbeat_interval' in selected and (_selected is not None or configuration.heartbeat) and
                        configuration.heartbeat_interval != monitor.interval):
                    raise ContractError('services.heartbeat', 'conflicting_input',
                                        'configured option conflicts with an attached Heartbeat owner')
            with self._lock:
                admission()
                if _apply and (self.service_configuration is None or changed):
                    self.service_configuration = configuration
                    # Existing waiters retain their exact entry/exception.
                    self._attachments = {key: entry for key, entry in self._attachments.items()
                                         if not entry.done.is_set() or entry.error is None}

    def _begin_attachment(self, key, attached, *, admitted=False):
        with self._configuration_lock, self._lock:
            if attached():
                return None, False
            entry = self._attachments.get(key)
            if self._closed and not admitted and (entry is None or entry.done.is_set()):
                if entry is not None and entry.error is not None:
                    raise entry.error
                return entry, False
            if entry is None or (entry.done.is_set() and entry.error is not None):
                # Joined waiters already hold the old result. A new invocation
                # after failure may retry once the external cause has cleared.
                entry = self._attachments[key] = _Attachment()
                return entry, True
        # Filesystem/process construction and waiting never occupy control's lock.
        entry.done.wait()
        if entry.error is not None:
            raise entry.error
        return entry, False

    def _finish_attachment(self, entry, error=None):
        with self._lock:
            entry.error = error
            entry.done.set()

    def _pending_attachments(self):
        with self._lock:
            return tuple(key for key, entry in self._attachments.items() if not entry.done.is_set())

    def _result_root_path(self, record_path, conversation=None):
        """Bind one default result bin before writer/source admission."""
        configuration = self.service_configuration
        if configuration is not None and configuration.result_root is not None:
            return Path(configuration.result_root).resolve()
        if self.reporting is not None:
            return self.reporting.root.path
        if configuration is None:
            return (Path(record_path).parent / 'results').resolve()
        with self._configuration_lock:
            if self._default_result_root is None:
                from bytefault.reporting.layout import _name
                source = (conversation.original_request.get('protocol_input', {}).get('source', {})
                          if conversation is not None else {})
                protocol = source.get('protocol_id', 'raw')
                stamp = datetime.now().astimezone().strftime('%Y%m%d_%H%M%S')
                self._default_result_root = (Path(record_path).parent / f'{stamp}_{_name(protocol)}').resolve()
            return self._default_result_root

    def _attach_services(self, request):
        if self.service_configuration is None:
            return
        entry, construct = self._begin_attachment('services', lambda: self.management is not None)
        if not construct:
            return
        configuration = self.service_configuration
        owns_root = self.reporting is None
        try:
            from bytefault.management import Management
            from bytefault.management.collection import Collection
            from bytefault.reporting import ResultRoot, Reporting
            root = (ResultRoot(self._result_root_path(request.record_path, getattr(request, 'conversation', None)))
                    if owns_root else self.reporting.root)
            store = LocalRecordStore(root.path / 'management.bfr')
            reporting = Reporting(root) if owns_root else self.reporting
            collection = Collection(request.transport.host, ssh_key=configuration.ssh_key,
                ssh_user=configuration.ssh_user or 'root', ssh_pass=configuration.ssh_pass,
                remote_dir=configuration.remote_dir,
                cache_dir=configuration.cache_dir or root.path / 'collection',
                max_file_size_mb=configuration.max_file_size_mb, min_timeout=configuration.min_timeout,
                core_write_wait=configuration.core_write_wait,
                pacer_for_run=self.connection_pacer)
            management = Management(store, reporting=reporting, collection=collection)
        except BaseException as error:
            for cleanup in ((store.close,) if 'store' in locals() else ()) + (
                    (root.close,) if owns_root and 'root' in locals() else ()):
                try:
                    cleanup()
                except BaseException as cleanup_error:
                    error.add_note('Service initialization cleanup: ' + str(cleanup_error))
            self._finish_attachment(entry, error)
            raise
        def finalized():
            store.close()
            self._owned_services_drained.set()
            self._release_owned_result_root()
            if (self._closed and not any(run.active for run in self._runs.values()) and
                    not self._pending_monitoring and not self._independent_operations and
                    not self._preparations and not self._pending_attachments()):
                for log in self.action_logs:
                    log.end('application')
        management.on_drained = finalized
        with self._lock:
            self.management, self.reporting = management, reporting
            self._owned_services = (management, store, root if owns_root else None)
            self._finish_attachment(entry)
        if self._closed:
            self.close()

    def _release_owned_result_root(self):
        # Service drain and run/attachment completion can arrive in either order.
        # Publish drain before checking users so the last user's close can also
        # release the root while Management's final callback is still returning.
        if self._owned_services is None or not self._owned_services_drained.is_set():
            return
        root = self._owned_services[2]
        if root is None:
            return  # Supplied roots retain caller ownership.
        with self._lock:
            in_use = (any(run.active for run in self._runs.values()) or
                self._pending_monitoring or self._independent_operations or
                any(not preparation._done for preparation in self._preparations.values()) or
                self._pending_attachments() or
                any(self._heartbeats[host].status()['running'] for host in tuple(self._heartbeat_logs)))
        if not in_use:
            root.close()

    def _attach_heartbeat(self, request):
        configuration = self.service_configuration
        if configuration is None or not configuration.heartbeat:
            return
        host = request.transport.host
        if host is None:
            return
        if host in self._heartbeat_failures:
            self._stop_heartbeat_runs(host, OSError(self._heartbeat_failures[host]['error']))
            return
        entry, construct = self._begin_attachment('heartbeat:' + host, lambda: host in self._heartbeats)
        if not construct:
            return
        from bytefault.monitoring.heartbeat import HeartbeatMonitor
        from hashlib import sha256
        key = sha256(host.encode('utf-8')).hexdigest()[:16]
        root = self._result_root_path(request.record_path, getattr(request, 'conversation', None))
        try:
            log = ActionLog.open(root / ('heartbeat-' + key + '.bfr'), owner='application')
            def record(observation):
                try:
                    log('heartbeat_observation', dict(freeze(observation.correlation)), {'observation': observation})
                except Exception as exc:
                    self._heartbeat_failures[host] = freeze({'error': str(exc), 'observation': observation})
                    emit_recording_diagnostic({'required_record_kind': 'heartbeat_observation',
                        'reason': str(exc), 'observation': observation})
                    self._stop_heartbeat_runs(host, exc)
                    raise
            monitor = HeartbeatMonitor(host, interval=configuration.heartbeat_interval, record=record)
            def stopped():
                if monitor.closed:
                    log.end('application')
                if self._closed:
                    self.close()
            monitor.on_stopped = stopped
            monitor.start()
        except BaseException as error:
            for cleanup in ((monitor.close,) if 'monitor' in locals() else ()) + (
                    (lambda: log.end('application'),) if 'log' in locals() else ()):
                try:
                    cleanup()
                except BaseException as cleanup_error:
                    error.add_note('Heartbeat initialization cleanup: ' + str(cleanup_error))
            self._finish_attachment(entry, error)
            raise
        with self._lock:
            self._heartbeats[host], self._heartbeat_logs[host] = monitor, log
            self._finish_attachment(entry)
        if self._closed:
            self.close()

    def _stop_heartbeat_runs(self, host, error):
        with self._lock:
            affected = tuple(run for run in self._runs.values() if run.active and run.request.transport.host == host)
            for key, stopped in self._independent_operations.items():
                if self._independent_targets.get(key) == host:
                    stopped.set()
        for run in affected:
            with run.lock:
                run.stop_requested.set()
                if run.engine is not None and run.engine.storage_failure is None:
                    run.engine._recording_stop('heartbeat_required_history', error)
                elif run.engine is None and run.storage_failure is None:
                    self._initial_recording_stop(run, 'heartbeat_required_history', error)

    def heartbeat_status(self, host):
        monitor = self._heartbeats.get(host)
        return monitor.status() if monitor is not None else freeze({'enabled': False,
            'host': host, 'alive': None, 'latest_observation': None, 'observed_at': None,
            'running': False, 'closed': False, 'error': None})

    def _current_input_inventory(self, request):
        from bytefault.core.input_files import inventory, validate_files
        files, options = [], []
        if isinstance(request, ResumeRequest):
            from bytefault.fuzzers.resuming import current_input_options
            files.extend(validate_files(request.conversation.input_files))
            options.extend(current_input_options(request)[0])
        else:
            for conversation in (request.conversation, *getattr(request, 'cases', ())):
                files.extend(validate_files(conversation.input_files))
                for contribution in conversation.row.contributions:
                    options.append(contribution.source.options)
                    options.extend(m.options for m in contribution.mutators)
            options.append(getattr(request, 'generation', None))
        return inventory(files=tuple(files), options=tuple(options))

    def _validate_service_destinations(self, request):
        """Admit service writers before any service or run output can change inputs."""
        inputs, directories = self._current_input_inventory(request)
        reserved = (Path(request.record_path).resolve(),
                    Path(request.log_path or request.record_path + '.actions.bfr').resolve())
        return self._service_destinations(request.transport, request.record_path, reserved, inputs, directories,
                                          conversation=request.conversation)

    def _service_destinations(self, transport, record_path, reserved, inputs, directories,
                              reuse_reserved=(), conversation=None):
        """Common actual service-output inventory; no execution request required."""
        configuration = self.service_configuration
        root = self._result_root_path(record_path, conversation)
        roots = set()
        if self.reporting is not None:
            roots.add(self.reporting.root.path)
        if self.management is not None and self.management.reporting is not None:
            roots.add(self.management.reporting.root.path)
        if configuration is not None and self.management is None:
            roots.add(root)
        cache = (Path(configuration.cache_dir or root / 'collection').resolve() if configuration is not None else
                 Path(self.management.collection.core_cache_dir).resolve() if self.management is not None and
                 hasattr(self.management.collection, 'core_cache_dir') else None)
        outputs = tuple(directory / name for directory in roots for name in
                        ('results.bfr', 'reporting-actions.bfr', '.bytefault-owner.lock'))
        if configuration is not None and self.management is None:
            outputs += (root / 'management.bfr', root / 'management.bfr.actions.bfr')
        exposed_stores = [getattr(log, 'store', None) for log in self.action_logs]
        if self.management is not None:
            exposed_stores.extend((self.management.store, getattr(self.management.action_log, 'store', None)))
        for reporting in (self.reporting, getattr(self.management, 'reporting', None)):
            if reporting is not None:
                exposed_stores.extend((reporting.root.store, reporting.root.action_log.store))
        prospective = []
        if configuration is not None and self.management is None:
            prospective.extend((root / 'management.bfr', root / 'management.bfr.actions.bfr'))
            if self.reporting is None:
                prospective.extend((root / 'results.bfr', root / 'reporting-actions.bfr', root / '.bytefault-owner.lock'))
        outputs += tuple(Path(store.path).resolve() for store in exposed_stores
                         if isinstance(getattr(store, 'path', None), (str, Path)))
        with self._lock:
            attached_heartbeat_hosts = tuple(self._heartbeats)
            heartbeat_logs = tuple(self._heartbeat_logs.values())
            pending_heartbeat_hosts = tuple(key.removeprefix('heartbeat:') for key, entry in self._attachments.items()
                                            if key.startswith('heartbeat:') and not entry.done.is_set())
        if configuration is not None and configuration.heartbeat:
            from hashlib import sha256
            hosts = tuple(dict.fromkeys((*((transport.host,) if transport.host is not None else ()), *pending_heartbeat_hosts)))
            outputs += tuple(root / ('heartbeat-' + sha256(host.encode('utf-8')).hexdigest()[:16] + '.bfr')
                             for host in hosts)
            prospective.extend(root / ('heartbeat-' + sha256(host.encode('utf-8')).hexdigest()[:16] + '.bfr')
                               for host in hosts if host not in attached_heartbeat_hosts)
        outputs += tuple(log.store.path for log in heartbeat_logs)
        exposed_stores.extend(log.store for log in heartbeat_logs)
        from bytefault.core.input_files import aliases
        known_writers = {Path(store.path).resolve() for store in exposed_stores
                         if isinstance(getattr(store, 'path', None), (str, Path))}
        for index, output in enumerate(prospective):
            if aliases(output, known_writers | {path.resolve() for path in prospective[:index]}):
                raise ContractError('services.destinations', 'writer_conflict',
                                    'prospective journal aliases an attached or selected writer: ' + str(output))
        for output in reserved:
            if aliases(output, inputs, directories):
                raise ContractError('recording.destinations', 'source_collision', str(output))
        for output in (*roots, *((cache,) if cache is not None else ()), *outputs):
            if (output in inputs or (output in reserved and output not in reuse_reserved) or
                    (output in outputs and output.parent in directories) or
                    (output.exists() and any(p.exists() and output.samefile(p) for p in
                        (*inputs, *(p for p in reserved if p != output or output not in reuse_reserved))))):
                raise ContractError('services.destinations', 'source_collision', str(output))
        # Later concrete report destinations must also protect every known
        # append-only journal.
        journals = set(outputs)
        journals.update(Path(store.path).resolve() for store in exposed_stores
                        if isinstance(getattr(store, 'path', None), (str, Path)))
        return freeze({'paths': tuple(str(p) for p in (*inputs, *reserved, *journals)),
                       'directories': tuple(str(p) for p in directories)})

    def _identity(self, request):
        if (not isinstance(request, ApplicationRequest) or
                not isinstance(request.conversation, ConversationRequest)):
            raise ContractError('application.request', 'invalid', 'typed application/conversation request required')
        for name in ('run_id', 'case_id', 'conversation_id'):
            value = getattr(request.conversation, name)
            if not isinstance(value, str) or not value:
                raise ContractError('conversation.' + name, 'invalid_identity', 'nonempty string required')

    def inspect(self, directory=None):
        protocols = self.discover_protocols(directory)
        declarations = discover(directory) if directory is not None else None
        return freeze({'connection': 'in_process', 'passive_version': 1,
            'status': 'unavailable' if protocols.issues or (declarations is not None and declarations.issues) else 'available',
            'capabilities': tuple(sorted(SUPPORTED_CAPABILITIES)),
            'operations': ('inspect', 'declaration_schema', 'inspect_declaration', 'export_declaration', 'admit',
                           'export_request', 'import_request', 'discover_protocols', 'resolve_protocol', 'protocol_request',
                           'prepare', 'validate', 'submit', 'start', 'campaign', 'status', 'control', 'observe',
                           'record_refs', 'read_records', 'service_record_refs', 'read_service_records', 'read_service_history',
                           'assess', 'complete_monitoring', 'service',
                           'configure_services', 'configure_service_options', 'independent_operation', 'record_service',
                           'generate', 'export_case', 'import_case', 'saved_case', 'inspect_resume', 'resume',
                           'validate_generated', 'submit_generated'),
            'unavailable': {k: Unavailable(k, *v) for k, v in FUTURE.items()},
            'declarations': declarations,
            'protocols': protocols,
            'schema': self.declaration_schema(),
            'service_attachments': {
                'monitoring': {'owner': 'Monitoring', 'attached': self.monitoring is not None,
                    'required_logging_attached': bool(self.action_logs)},
                'management': {'owner': 'Management', 'attached': self.management is not None},
                'reporting': {'owner': 'Reporting', 'attached': self.reporting is not None}},
            'saved_intent': {'fields': ('path', 'record_id', 'mode'),
                'step_fields': ('action_id', 'choice', 'reapply_mutations', 'dynamic_source_reference'),
                'supported_modes': ('literal', 'fresh_dynamic'),
                'execution': 'prepare ApplicationRequest then ordinary submit/start',
                'format': 'bytefault.case', 'version': 1},
            'resume_intent': {'fields': ('path', 'choices'),
                'choice_fields': ('conversation_id', 'disposition', 'steps'),
                'dispositions': ('rerun', 'skip'), 'default': 'unresolved',
                'execution': 'prepare ResumeRequest then ordinary submit/start'}})

    def discover_protocols(self, directory=None):
        return discover_protocols(directory)

    def resolve_protocol(self, selection, directory=None):
        return self.discover_protocols(directory).select(selection)

    def protocol_request(self, selection, host, *, directory=None, seed=None, conversation=None,
                         selected_actions=None, stage=None, port=None, timeout=None,
                         pre_delay=None, post_delay=None, connection_delay=0.0, no_receive=False, receive=None,
                         record_path=None, log_path=None, original_request=None):
        """Bind passive directory data to one ordinary, exact prepared request.

        A prepared conversation must use the discovered plan unchanged; explicit
        receive overrides are applied afterwards and retained as input intent.
        A whole seed is represented by a final replacement in a one-send row.
        """
        from bytefault.core.contracts import (PreparedRow, PreparedContribution,
            SourceInvocation, Placement, ReceiveRequest)
        from bytefault.core.validation import validate_request, passive
        resolution = self.resolve_protocol(selection, directory)
        entry, supplied = resolution.entry, conversation
        if original_request is not None:
            from collections.abc import Mapping
            if not isinstance(original_request, Mapping):
                raise ContractError('protocol.original_request', 'malformed', 'passive mapping required')
            passive(original_request, 'protocol.original_request')
        if (seed is None) == (conversation is None):
            raise ContractError('protocol.input', 'conflicting_input', 'supply exact seed bytes or a prepared conversation')
        if type(no_receive) is not bool or (receive is not None and not isinstance(receive, ReceiveRequest)):
            raise ContractError('protocol.receive', 'malformed', 'typed receive policy/boolean required')
        if receive is not None and no_receive:
            raise ContractError('protocol.receive', 'conflicting_input', 'choose receive policy or no receive')
        if seed is not None:
            if type(seed) is not bytes:
                raise ContractError('protocol.seed', 'malformed', 'exact bytes required')
            if len(entry.plan.actions) != 1:
                raise ContractError('protocol.seed', 'ambiguous_action', 'whole seed requires a one-send declaration; use a prepared conversation')
            selected = select_actions(entry.plan, selected_actions, stage)
            action = entry.plan.actions[0]
            row = PreparedRow('row-1', 1,
                (PreparedContribution('whole-input', seed, SourceInvocation('whole-input', 'literal')),),
                final_overrides=(Placement('whole-input', 'whole-input', action.action_id,
                                          'replace', 0, len(action.seed)),))
            conversation = ConversationRequest(entry.plan, row, selected, str(uuid4()), 'case-1', 'conversation-1')
        else:
            if not isinstance(conversation, ConversationRequest):
                raise ContractError('protocol.conversation', 'malformed', 'typed ConversationRequest required')
            passive(conversation, 'protocol.conversation')
            if conversation.plan != entry.plan:
                raise ContractError('protocol.conversation.plan', 'conflicting_plan', 'prepared plan must equal the discovered declaration')
            if selected_actions is not None and selected_actions != conversation.selected_actions:
                raise ContractError('protocol.selection', 'conflicting_selection', 'explicit action IDs disagree with prepared request')
            selected = select_actions(entry.plan, conversation.selected_actions, stage)
            conversation = replace(conversation, selected_actions=selected)
        if receive is not None or no_receive:
            conversation = replace(conversation, plan=replace(conversation.plan, actions=tuple(
                replace(a, receive=receive if receive is not None else replace(a.receive, requested=False))
                if a.action_id in selected else a for a in conversation.plan.actions)))
        intent = {'source': resolution.provenance, 'stage': stage, 'selected_actions': selected,
            'seed': seed, 'supplied_conversation': supplied, 'no_receive': no_receive, 'receive': receive,
            'supplied_original_request': original_request,
            'transport_overrides': {'port': port, 'timeout': timeout, 'pre_delay': pre_delay, 'post_delay': post_delay}}
        conversation = replace(conversation, original_request={**dict(conversation.original_request),
            **dict(original_request or {}), 'protocol_input': intent})
        validate_request(conversation, SUPPORTED_CAPABILITIES)
        defaults = entry.defaults
        target = TransportRequest(host, defaults.port if port is None else port,
            defaults.timeout if timeout is None else timeout,
            defaults.pre_delay if pre_delay is None else pre_delay,
            defaults.post_delay if post_delay is None else post_delay, connection_delay)
        if target.port is None:
            raise ContractError('transport.port', 'required', 'selected protocol has no default port')
        self._validate_transport(target)
        destination = record_path if record_path is not None else str(run_path(conversation.run_id))
        return ApplicationRequest(conversation, target, destination, log_path)

    def declaration_schema(self):
        from bytefault.core.contracts import ReceiveRequest, FieldLocation, ResponseField, Calculation, Placement
        from bytefault.core.calculations import SUPPORTED_RULES, ALGORITHMS
        return freeze({'version': 1,
            'required': ('declaration_id', 'version', 'actions'),
            'optional': ('stages', 'entry_action', 'required_capabilities'),
            'unknown_fields': 'rejected',
            'action': {'required': ('action_id', 'seed_hex'),
                'optional': ('stage_id', 'buffer_id', 'kind', 'receive', 'edges', 'unknown_target', 'next_action', 'fields', 'response_fields'),
                'receive_fields': tuple(f.name for f in fields(ReceiveRequest)),
                'edge_fields': ('literal_hex', 'target', 'meaning', 'field_id'),
                'field_fields': tuple(f.name for f in fields(FieldLocation)),
                'response_field_fields': tuple(f.name for f in fields(ResponseField))},
            'placement_fields': tuple(f.name for f in fields(Placement)),
            'calculation_fields': tuple(f.name for f in fields(Calculation)),
            'calculation_rules': tuple(sorted(SUPPORTED_RULES)),
            'checksum_algorithms': tuple(ALGORITHMS),
            'capability_fields': ('name', 'parameters'),
            'supported_capabilities': tuple(sorted(SUPPORTED_CAPABILITIES)),
            'capability_parameters': 'no parameters supported in passive version 1',
            'example': {'declaration_id': 'operator', 'version': 1,
                        'actions': ({'action_id': '1', 'seed_hex': '00ff'},)}})

    def inspect_declaration(self, supplied):
        """Retain supplied version/unknown references even when admission refuses."""
        original = freeze(supplied)
        try:
            return freeze({'supplied': original, 'status': 'available', 'plan': admit_plan(supplied)})
        except ContractError as exc:
            return freeze({'supplied': original, 'status': 'unavailable',
                           'error': {'path': exc.path, 'code': exc.code, 'message': str(exc)}})

    def export_declaration(self, plan):
        plan = admit_plan(plan)
        return {'declaration_id': plan.declaration_id, 'version': plan.version,
            'stages': list(plan.stages), 'entry_action': plan.entry_action,
            'required_capabilities': [{'name': c.name, 'parameters': dict(c.parameters)}
                                      for c in plan.required_capabilities],
            'actions': [{'action_id': a.action_id, 'seed_hex': a.seed.hex(),
                'stage_id': a.stage_id, 'buffer_id': a.buffer_id, 'kind': a.kind,
                'receive': {f.name: getattr(a.receive, f.name) for f in fields(a.receive)},
                'edges': [{'literal_hex': e.literal.hex(), 'target': e.target, 'meaning': e.meaning,
                           'field_id': e.field_id}
                          for e in a.edges], 'unknown_target': a.unknown_target,
                'next_action': a.next_action,
                'fields': [{f.name: getattr(location, f.name) for f in fields(location)}
                           for location in a.fields],
                'response_fields': [{f.name: getattr(location, f.name) for f in fields(location)}
                                    for location in a.response_fields]} for a in plan.actions]}

    def admit(self, declaration):
        return admit_plan(declaration)

    def export_request(self, request):
        return request_to_data(request)

    def import_request(self, data):
        return request_from_data(data)

    def generate(self, base, configuration, *, limit=None, campaign=None):
        """Prepare lazy identified rows; yielded requests use ordinary submit.

        Preparation has its own required evidence store. An explicit limit is a
        caller-selected evaluation bound, never an implicit product cap.
        """
        from bytefault.fuzzers.generated_inputs import PreparedStream
        stream = PreparedStream(self, base, configuration, limit, campaign=campaign)
        with self._lock:
            if self._closed or stream.preparation_id in self._preparations:
                raise ContractError('generation', 'unavailable', 'application closed or preparation already active')
            self._preparations[stream.preparation_id] = stream
        return stream

    def campaign(self, base, *, options=None, generation=None, cases=()):
        """Execute a numbered campaign through one ordinary engine and journal."""
        return self.submit(CampaignRequest(base.conversation, base.transport, base.record_path,
            base.log_path, options or CampaignOptions(), generation, cases))

    def _campaign_families(self, request):
        if isinstance(request, ResumeRequest):
            from bytefault.fuzzers.resuming import ResumeFamilies
            return ResumeFamilies(self, request)
        from bytefault.fuzzers.campaign import validate_campaign, selected_case
        from bytefault.fuzzers.generated_inputs import campaign_conversation
        validate_campaign(request.options, request.conversation.plan)
        options = request.options
        if request.generation is not None and request.cases:
            raise ContractError('campaign.input', 'conflicting_input', 'choose generated or literal cases')
        bound = options.case_limit
        wanted = tuple(n for n in options.selected_cases if n > options.skip)
        if wanted:
            bound = min(bound, max(wanted)) if bound is not None else max(wanted)
        elif options.selected_cases:
            bound = 0
        if request.generation is not None:
            stream = self.generate(request, request.generation, limit=bound, campaign=options)
            # Check campaign destinations before consuming the generated stream.
            try:
                stream._check_destinations(request.record_path,
                    request.log_path or request.record_path + '.actions.bfr')
            except BaseException:
                stream.close()
                raise
            def generated():
                try:
                    while True:
                        family = []
                        for _ in options.variants:
                            try:
                                family.append(next(stream).conversation)
                            except StopIteration:
                                if stream.cancelled():
                                    return
                                if family:
                                    raise ContractError('campaign.variants', 'incomplete_family', 'variant preparation ended early')
                                return
                        yield tuple(family)
                finally:
                    stream.close()
            return _CampaignFamilies(generated(), stream)
        if not isinstance(request.cases, tuple):
            raise ContractError('campaign.cases', 'invalid', 'ordered literal conversation tuple required')
        def literal():
            for number, supplied in enumerate(request.cases or (request.conversation,), 1):
                if bound is not None and number > bound:
                    return
                if supplied.plan != request.conversation.plan:
                    raise ContractError('campaign.cases', 'plan_mismatch', 'one declared campaign plan required')
                family = []
                for variant_number, variant in enumerate(options.variants, 1):
                    conversation = replace(supplied, run_id=request.conversation.run_id,
                        case_id=f'{request.conversation.case_id}:row:{number}',
                        conversation_id=f'{request.conversation.conversation_id}:row:{number}:variant:{variant}')
                    family.append(campaign_conversation(conversation, request.conversation.run_id,
                        number, variant, variant_number, len(options.variants)))
                yield tuple(family)
        items = tuple({'case_number': n, 'case_id': f'{request.conversation.case_id}:row:{n}',
            'variant_id': variant,
            'conversation_id': f'{request.conversation.conversation_id}:row:{n}:variant:{variant}',
            'state': 'not_started' if selected_case(options, n) else 'omitted', 'result': None}
            for n, _ in enumerate(request.cases or (request.conversation,), 1)
            if bound is None or n <= bound for variant in options.variants)
        return _CampaignFamilies(literal(), literal_items=items)

    def validate_generated(self, base, configuration, *, limit=None):
        if isinstance(base, CampaignRequest):
            raise ContractError('generation.base', 'unsupported_request',
                'ordinary request required; use prepare for generated campaigns')
        from bytefault.fuzzers.generated_inputs import GeneratedOperation
        return GeneratedOperation(self, self.generate(base, configuration, limit=limit), 'validate')

    def submit_generated(self, base, configuration, *, limit=None):
        if isinstance(base, CampaignRequest):
            raise ContractError('generation.base', 'unsupported_request',
                'ordinary request required; use submit for generated campaigns')
        from bytefault.fuzzers.generated_inputs import GeneratedOperation
        return GeneratedOperation(self, self.generate(base, configuration, limit=limit), 'submit')

    def _validate_transport(self, target):
        def positive(value, zero=False):
            return (type(value) in (int, float) and math.isfinite(value) and
                    (value >= 0 if zero else value > 0))
        if (not isinstance(target, TransportRequest) or not isinstance(target.host, str) or
                not target.host or type(target.port) is not int or not 1 <= target.port <= 65535 or
                not positive(target.timeout) or not positive(target.pre_delay, True) or
                not positive(target.post_delay, True) or not positive(target.connection_delay, True)):
            raise ContractError('transport', 'invalid', 'valid host/port/timeout/pacing required')

    def _validate_destinations(self, request):
        """Validate destination values without constructing adapters or opening files."""
        if not isinstance(request.record_path, str) or not request.record_path:
            raise ContractError('record_path', 'required', 'local required evidence destination')
        if request.log_path is not None and (not isinstance(request.log_path, str) or not request.log_path):
            raise ContractError('log_path', 'invalid', 'nonempty path or explicit absence')
        resolved_log = request.log_path or request.record_path + '.actions.bfr'
        if Path(resolved_log).resolve() == Path(request.record_path).resolve():
            raise ContractError('log_path', 'invalid', 'action log and evidence paths must differ')
        from bytefault.core.input_files import aliases
        inputs, directories = self._current_input_inventory(request)
        for output in (request.record_path, resolved_log):
            if aliases(output, inputs, directories):
                raise ContractError('recording.destinations', 'source_collision', str(output))
        return resolved_log

    def _validate_collection_selection(self, request, configuration=None):
        """Reject an explicitly selected collection with no usable service port before target I/O."""
        from bytefault.management.collection import Collection
        policy = request.monitoring_configuration if isinstance(request, CampaignRequest) else None
        if policy is None:
            policy = getattr(getattr(self.monitoring, 'policy', None), 'configuration', None)
        if policy is None:
            return
        selected = policy.collect_cores or any(action.get('collect', False)
            for rule in policy.rules for action in rule.actions)
        if not selected:
            return
        collection = getattr(self.management, 'collection', None)
        if collection is not None and not isinstance(collection, Collection) and callable(collection):
            return
        configuration = configuration or self.service_configuration or self._effective_service_configuration()
        if configuration.ssh_key is None and configuration.ssh_pass is None:
            raise ContractError('campaign.collect_cores', 'required',
                'selected collection requires --ssh-key or explicit --ssh-user with --ssh-pass')

    def _engine(self, request):
        if not isinstance(request, ApplicationRequest):
            raise ContractError('application', 'invalid', 'typed ApplicationRequest required')
        target = request.transport
        self._validate_transport(target)
        self._validate_destinations(request)
        monitoring = self.monitoring
        configured_policy = request.monitoring_configuration if isinstance(request, CampaignRequest) else None
        if configured_policy is not None or (monitoring is None and self.service_configuration is not None):
            from bytefault.monitoring import Monitoring
            from bytefault.monitoring.configuration import MonitoringConfig
            configuration = configured_policy or MonitoringConfig()
            if (self.service_configuration is not None or configuration.collect_cores) and not any(
                    r.rule_id == 'service_failure' for r in configuration.rules):
                from bytefault.monitoring.rules import service_failure_followup_rule
                configuration = replace(configuration, rules=(*configuration.rules,
                    service_failure_followup_rule(configuration.collect_cores)))
            monitoring = Monitoring(configuration=configuration)
        transport = self.transport_factory(target)
        if isinstance(transport, EngineTransport) and target.connection_delay:
            transport.pacer = self.connection_pacer(request.conversation.run_id)
        return ProtocolFuzzer(target.host, target.port, timeout=target.timeout,
            transport=transport, monitoring=monitoring)

    def prepare(self, request, *, service_options=None):
        from bytefault.fuzzers.campaign_preparation import CampaignPreparation
        self._identity(request)
        if not isinstance(request, CampaignRequest):
            raise ContractError('campaign', 'invalid', 'typed CampaignRequest required')
        configuration = self.configure_service_options(_apply=False, **service_options) if service_options else None
        self._validate_collection_selection(request, configuration)
        return CampaignPreparation(self, request)

    def validate(self, request):
        if isinstance(request, CampaignRequest):
            return self.prepare(request)
        self._identity(request)
        engine = self._engine(request)
        try:
            return freeze({'request': request,
                           'materialized': engine.validate_conversation(request.conversation)})
        finally:
            engine.close_observers()

    def _initial_recording_stop(self, run, kind, exc, materialized=None):
        request = run.request
        conversation = request.conversation
        run.stop_requested.set()
        run.state = 'recording_failed'
        run.storage_failure = freeze({
            'reason': str(exc), 'required_record_kind': kind,
            'identity': {'run_id': conversation.run_id, 'case_id': conversation.case_id,
                'conversation_id': conversation.conversation_id,
                'row_id': getattr(conversation.row, 'row_id', None), 'action_id': None,
                'stage_id': None, 'attempt_id': None, 'iteration_id': None},
            'resolved_transport': request.transport,
            'transport_validation_state': 'resolved' if materialized is not None else 'unresolved',
            'original_request': conversation.original_request, 'resolved_request': conversation,
            'application_request': request,
            'materialization_state': 'materialized_not_offered' if materialized is not None else 'unresolved_not_materialized',
            'available_materializations': materialized if materialized is not None else (),
            'available_materialized_bytes': None, 'known_transport_progress': None,
            'known_transport_identity': None, 'transport_progress_state': 'not_observed',
            'last_retained_record': None, 'missing_evidence': f'{kind} initialization failed; no case evidence acknowledged',
        })
        if run.engine is not None:
            run.engine.control('stop')
            run.engine.storage_failure = run.storage_failure
            run.engine._execution_state = 'recording_failed'
        run.diagnostic_delivery_error = emit_recording_diagnostic(run.storage_failure)
        if run.engine is not None:
            run.engine.diagnostic_delivery_error = run.diagnostic_delivery_error

    def _reserve(self, request):
        self._identity(request)
        self._validate_collection_selection(request)
        self._validate_service_destinations(request)
        if isinstance(request, CampaignRequest):
            from bytefault.fuzzers.campaign import validate_campaign
            validate_campaign(request.options, request.conversation.plan)
        run_id = request.conversation.run_id
        with self._lock:
            if self._closed or run_id in self._runs:
                raise ContractError('run_id', 'unavailable', 'application closed or run identity already used')
            run = _Run(request, None, self.event_capacity)
            self._runs[run_id] = run
            return run

    def start(self, request):
        """Reserve synchronously, execute the ordinary submit path asynchronously."""
        run = self._reserve(request)
        def execute():
            try:
                self._submit(request, run)
            except BaseException as error:
                run.exception = error
            finally:
                run.finalized.set()
        try:
            run.worker = threading.Thread(target=execute, name='bytefault-' + request.conversation.run_id,
                                          daemon=True)
            run.worker.start()
        except BaseException as error:
            run.active, run.state, run.error, run.exception = False, 'failed', str(error), error
            try:
                self._finalize_run_application(run)
            except BaseException as cleanup_error:
                fact = freeze({'operation': 'application_finalize', 'error': str(cleanup_error),
                    'error_type': type(cleanup_error).__name__, 'result': run.result,
                    'application_finalization': getattr(run, 'application_finalization', None)})
                run.cleanup_errors = (fact,)
                error.add_note('Application cleanup: ' + str(dict(fact)))
                identity = {'run_id': request.conversation.run_id, 'case_id': request.conversation.case_id,
                            'conversation_id': request.conversation.conversation_id}
                retained, failures = [], []
                for log in self.action_logs:
                    if not getattr(log, 'closed', False):
                        try:
                            retained.append(log('application_cleanup_failure', identity, fact))
                        except BaseException as failure:
                            failures.append(str(failure))
                if failures or not retained:
                    run.diagnostic_delivery_error = emit_recording_diagnostic({
                        'required_record_kind': 'application_cleanup_failure', 'identity': identity,
                        'cleanup': fact, 'available_record_refs': tuple(retained), 'failures': tuple(failures),
                        'reason': 'cleanup history incomplete'})
            finally:
                run.finalized.set()
            raise
        return RunHandle(self, request.conversation.run_id)

    def _finalize_run_application(self, run):
        """Settle pending owner close after ordinary or failed-start admission."""
        if self._closed:
            run.application_finalization = self.close()
            if run.application_finalization['outcome'] == 'failed':
                raise OSError('application finalization failed: ' + repr(dict(run.application_finalization)))

    def submit(self, request):
        return self._submit(request, self._reserve(request))

    def _submit(self, request, run):
        engine, families, materialized = None, None, None
        run_id = request.conversation.run_id
        logs, store = list(self.action_logs), None
        try:
            resolved_log = self._validate_destinations(request)
            source_inventory = self._validate_service_destinations(request)
            self._attach_services(request)
            self._attach_heartbeat(request)
            families = self._campaign_families(request) if isinstance(request, CampaignRequest) else None
            # Exact action history remains mandatory when no extra path was chosen.
            log_path = resolved_log
            try:
                run.action_log=ActionLog.open(log_path, owner='run')
                logs.append(run.action_log)
            except Exception as exc:
                self._initial_recording_stop(run, 'action_log_open', exc)
                raise
            if self.reporting is not None:
                try:
                    self.reporting.root.register_run_log(run_id, log_path)
                except Exception as exc:
                    self._initial_recording_stop(run, 'run_action_log_registration', exc)
                    raise
            engine = self._engine(request)
            run.engine = engine
            if run.stop_requested.is_set():
                engine.control('stop')
            materialized = engine.validate_conversation(request.conversation)
            try:
                store = LocalRecordStore(request.record_path)
            except Exception as exc:
                self._initial_recording_stop(run, 'case_store_open', exc, materialized)
                raise
            engine.record_store = store
            for log in logs:
                engine.add_required_sink(log)
            engine._record_projection = run.event
            if run.storage_failure is not None:
                engine._recording_stop('heartbeat_required_history', OSError(run.storage_failure['reason']))
            def complete(completion):
                # Final detach/close shares this narrow lock; never app-wide.
                with run.lock:
                    if run.active and not run.closing and engine.storage_failure is None:
                        engine.complete_monitoring(completion)
            if self.management is not None:
                def dispatch(decision):
                    try:
                        if self.management.status()['closed']:
                            engine._required_save('followup_unavailable', {'decision': decision,
                                'reason': 'Management attachment is closed'})
                            from bytefault.core.contracts import MonitoringCompletion
                            for obligation in decision.obligations:
                                complete(MonitoringCompletion(str(uuid4()), decision.decision_id,
                                    decision.observation_id, decision.correlation, obligation.condition, 'failed',
                                    followup_action_id=obligation.followup_action_id))
                            return
                        def required_failure(exc):
                            with run.lock:
                                if run.active:
                                    if engine.storage_failure is None:
                                        engine._recording_stop('management_required_history', exc)
                                else:
                                    import sys
                                    sys.stderr.write(f'BYTEFAULT REQUIRED RECORDING STOP late service: {exc}; decision={decision!r}\n')
                        recovered = store.snapshot()
                        correlation = dict(freeze(decision.correlation))
                        names = ('run_id', 'case_id', 'conversation_id')
                        from bytefault.fuzzers.saved_cases import case_history
                        case_records, case_references = case_history(recovered, tuple(correlation[n] for n in names))
                        selected = next((r for r in reversed(case_records) if r.kind == 'action_result' and
                            all(r.identity.get(n) == correlation[n] for n in ('action_id', 'attempt_id'))), None)
                        if selected is None:
                            selected = next((r for r in reversed(case_records) if r.kind == 'case_start'), None)
                        portable = self.export_case(request.record_path, selected.record_id) if selected else None
                        observed = next((r.data['observation'] for r in reversed(case_records)
                            if r.kind == 'observation' and
                            r.data['observation']['observation_id'] == decision.observation_id), None)
                        source = request.conversation.original_request.get('protocol_input', {}).get('source', {})
                        context = freeze({'decision': decision, 'records': case_records,
                            'record_refs': case_references, 'history_projection': 'flat_case_v1',
                            'portable_case': portable, 'transport': request.transport,
                            'service_configuration': self.service_configuration,
                            'source_inventory': source_inventory,
                            'observation_time_utc': observed['parameters'].get('observed_at_utc') if observed else None,
                            'protocol_id': source.get('protocol_id', 'raw'),
                            'record_path': request.record_path, 'log_path': resolved_log})
                        # Acknowledge exact event context before queue acceptance.
                        context_ref = engine._required_save('report_context', {'decision_id': decision.decision_id,
                            'context': context}, identity=correlation)
                        self.management.dispatch(decision, complete, required_failure,
                            context=freeze({**dict(context), 'report_context_ref': context_ref}))
                    except OSError as exc:
                        # Required independent Management history is still required
                        # evidence; optional collection/report port errors are values.
                        engine._recording_stop('management_required_history', exc)
                        from bytefault.core.records import RequiredSaveFailure
                        raise RequiredSaveFailure(str(exc)) from exc
                engine.followup = dispatch
                engine.pending_collection = self.management.pending_collection
            attach_continuation = getattr(engine.monitoring, 'attach_continuation', None)
            if attach_continuation is not None:
                run.detach_monitoring = attach_continuation(run_id,
                    lambda: engine.continuation.hold, complete)
            run.state = 'running'
            if isinstance(request, ResumeRequest):
                from bytefault.fuzzers.resuming import restore_continuation
                restore_continuation(engine, request)
            run.result = (engine.execute_campaign(request.conversation, families, request.options, original_request=request)
                if families is not None else engine.execute_conversation(request.conversation))
            run.state = run.result.outcome
            if run.result.cleanup and (run.result.cleanup.outcome == 'uncertain' or
                                       run.result.cleanup.pacing_error is not None):
                run.error = run.result.reason or run.result.cleanup.error or run.result.cleanup.pacing_error
            elif getattr(run.result,'cleanup_errors',()):
                run.error = run.result.reason or 'engine cleanup did not complete cleanly'
        except BaseException as exc:
            if engine is not None and engine.storage_failure is not None:
                run.storage_failure = engine.storage_failure
            run.state, run.error = ('recording_failed' if run.storage_failure is not None else 'failed'), str(exc)
            if engine is not None:
                run.result = (getattr(engine, 'last_campaign_result', None) or
                              engine.last_conversation_result)
            # Validation/init errors are exact action history even without an engine case.
            try:
                # An engine recording-stop has already emitted its independent
                # diagnostic. Do not try failed required sinks again on unwind.
                source_refusal = isinstance(exc, ContractError) and exc.code == 'source_collision'
                for log in (() if run.storage_failure is not None or source_refusal else logs):
                    log('application_failure', {'run_id': run_id,
                        'case_id': request.conversation.case_id,
                        'conversation_id': request.conversation.conversation_id},
                        {'request': request, 'error': str(exc), 'result': run.result,
                         'cleanup': engine.last_cleanup_result if engine is not None else None})
            except Exception as logging_exc:
                if engine is not None and (engine._record_request is not None or engine.record_refs or
                        engine.last_transport_result is not None or engine._transport_in_progress):
                    engine._recording_stop('application_failure', logging_exc)
                    run.storage_failure = engine.storage_failure
                    run.state = 'recording_failed'
                else:
                    self._initial_recording_stop(run, 'application_failure', logging_exc, materialized)
            raise
        finally:
            run.closing = True
            errors = []
            def cleanup(operation, close):
                try:
                    close()
                except BaseException as error:
                    fact = freeze({'operation': operation, 'error': str(error),
                                   'error_type': type(error).__name__, 'result': run.result,
                                   'application_finalization': getattr(run, 'application_finalization', None)})
                    errors.append(fact)
                    retained, failures = [], []
                    identity = {'run_id': run_id, 'case_id': request.conversation.case_id,
                                'conversation_id': request.conversation.conversation_id}
                    # Cleanup has ended execution. Preserve its separate facts in
                    # each still-open sink; closed owners are never reopened.
                    storage_failed = run.storage_failure or (engine is not None and engine.storage_failure)
                    sinks = ([store] if not storage_failed and store is not None and not getattr(store, 'closed', False) else [])
                    for sink in sinks:
                        try:
                            retained.append(sink.append('application_cleanup_failure', identity, fact))
                        except Exception as failure:
                            failures.append(str(failure))
                    for log in (() if storage_failed else logs):
                        if not getattr(log, 'closed', False):
                            try:
                                retained.append(log('application_cleanup_failure', identity, fact))
                            except Exception as failure:
                                failures.append(str(failure))
                    if failures or not retained:
                        emit_recording_diagnostic({'required_record_kind': 'application_cleanup_failure',
                            'identity': identity, 'cleanup': fact, 'available_record_refs': tuple(retained),
                            'failures': tuple(failures), 'reason': 'cleanup history incomplete'})
            if families is not None:
                cleanup('campaign_preparation', families.close)
            with run.lock:
                detach_monitoring = getattr(run, 'detach_monitoring', None)
                if detach_monitoring is not None:
                    cleanup('monitoring_attachment', detach_monitoring)
                if engine is not None:
                    cleanup('observers', engine.close_observers)
                if store is not None:
                    cleanup('record_store', store.close)
                for index, log in enumerate(logs):
                    cleanup('action_log:' + str(index), lambda log=log: log.end('run'))
                run.cleanup_errors = tuple(errors)
                if errors and run.result is not None:
                    changes = {'application_cleanup_errors': tuple(errors)}
                    if run.result.outcome == 'completed':
                        changes.update(outcome='cleanup_failed', reason='application resource cleanup failed')
                    run.result = replace(run.result, **changes)
                    run.state = run.result.outcome
                try:
                    run.event('application_terminal', {'run_id': run_id,
                        'case_id': request.conversation.case_id,
                        'conversation_id': request.conversation.conversation_id},
                        {'state': run.state, 'error': run.error, 'result': run.result,
                         'cleanup_errors': tuple(errors)})
                except Exception:
                    run.projection_dropped += 1
                run.active = False
                if run.worker is None:
                    run.finalized.set()
            primary = sys.exc_info()[1]
            if self._closed:
                previous_errors = len(errors)
                cleanup('application_finalize', lambda: self._finalize_run_application(run))
                if len(errors) != previous_errors:
                    run.cleanup_errors = tuple(errors)
                    if run.result is not None:
                        changes = {'application_cleanup_errors': tuple(errors)}
                        if run.result.outcome == 'completed':
                            changes.update(outcome='cleanup_failed', reason='application finalization failed')
                        run.result = replace(run.result, **changes)
                        run.state = run.result.outcome
            if primary is not None:
                for error in errors:
                    primary.add_note('Application cleanup: ' + str(dict(error)))
        return run.result

    def _run(self, run_id):
        with self._lock:
            try:
                return self._runs[run_id]
            except KeyError as exc:
                raise ContractError('run_id', 'not_found', str(run_id)) from exc

    def action_log_progress(self, run_id, path):
        """Read the exact run-owned action writer's acknowledged append boundary."""
        with self._lock:
            run=self._runs.get(run_id)
        if run is None:
            return None
        log=run.action_log
        if log is None or Path(path).resolve()!=log.store.path:
            return None
        return log.append_progress()

    def status(self, run_id):
        run = self._run(run_id)
        cleanup_errors = tuple(getattr(run.result,'cleanup_errors',()))
        if (run.engine is not None and run.engine._probe_cleanup_total and
                not any(error.get('owner')=='probe' for error in cleanup_errors)):
            cleanup_errors += (run.engine.probe_cleanup_summary(),)
        # No required-I/O lock is needed for this immutable status copy.
        return freeze({'run_id': run_id, 'state': run.state, 'engine': run.engine.status() if run.engine else None,
            'result': run.result, 'error': run.error, 'active': run.active,
            'closing': run.closing, 'finalized': run.finalized.is_set(),
            'stop_requested': run.stop_requested.is_set(), 'cleanup_errors': cleanup_errors+run.cleanup_errors,
            'application_finalization': getattr(run, 'application_finalization', None),
            'storage_failure': run.engine.storage_failure if run.engine else run.storage_failure,
            'diagnostic_delivery_error': run.engine.diagnostic_delivery_error if run.engine else run.diagnostic_delivery_error,
            'heartbeat': self.heartbeat_status(run.request.transport.host),
            'followup': self.management.status() if self.management else None})

    def control(self, run_id, command):
        run = self._run(run_id)
        if not run.active or run.closing:
            return ControlOutcome(command, 'rejected', 'run has ended')
        if command == 'stop':
            run.stop_requested.set()
        if run.engine is None:
            return ControlOutcome(command, 'completed' if command == 'stop' else 'rejected',
                'stop retained during initialization' if command == 'stop' else 'run is initializing; control not yet applicable')
        return run.engine.control(command)

    def observe(self, run_id, *, after=0):
        run = self._run(run_id)
        with run.history_lock:
            first = run.events[0]['sequence'] if run.events else run.sequence + 1
            events = tuple(e for e in run.events if e['sequence'] > after)
            cursor, dropped = run.sequence, run.projection_dropped
        return freeze({'events': events, 'cursor': cursor,
            'resnapshot_required': after < first - 1 or dropped > 0,
            'dropped_before': first - 1, 'projection_dropped': dropped,
            'projection_failed': getattr(run.engine, '_projection_failures', 0),
            'status': self.status(run_id)})

    def record_refs(self, run_id):
        engine = self._run(run_id).engine
        return tuple(engine.record_refs) if engine else ()

    def read_records(self, run_id):
        return reopen_records(self._run(run_id).request.record_path)

    def _service_stores(self):
        with self._lock:
            stores = []
            if self.management is not None:
                stores.append(self.management.store)
            if self.reporting is not None:
                stores.append(self.reporting.root.store)
            stores.extend(log.store for log in self._heartbeat_logs.values())
        return tuple(stores)

    @staticmethod
    def _service_stamp(path):
        try:
            stat = path.stat()
            return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        except OSError as error:
            return (None, error.errno, str(error))

    def _service_snapshot(self, path, *, reader=None, refresh=False):
        """Reuse only a metadata-stable original-reader result, never parse frames.

        Metadata is an invalidation hint, not byte validation. Explicit fresh
        inspection recovers again, including deliberately metadata-preserving
        edits. A mutation across recovery leaves the result non-reusable.
        """
        path = Path(path).resolve()
        key = str(path)
        with self._service_history_lock:
            before = self._service_stamp(path)
            previous = self._service_snapshots.get(key)
            if not refresh and previous is not None and previous[0] == before:
                return previous[1], previous[2]
            recovered = reader() if reader is not None else reopen_records(path)
            after = self._service_stamp(path)
            generation = 1 if previous is None else previous[2]
            if previous is not None:
                old_stamp, old, _ = previous
                prefix = len(old.records)
                if (old_stamp is None or old_stamp[:2] != before[:2] or
                        (old_stamp[0] is not None and before[0] is not None and before[2] < old_stamp[2]) or
                        recovered.refs[:prefix] != old.refs or recovered.records[:prefix] != old.records):
                    generation += 1
            # Do not bless an append after EOF with its newer stat: the next
            # observation must recover it, even when this reader missed it.
            self._service_snapshots[key] = (before if before == after else None, recovered, generation)
            return recovered, generation

    def _opaque_service_recovery(self, store):
        """Always invoke the provider; retain its result only to compare epochs."""
        from bytefault.core.records import RecoveryResult
        with self._service_history_lock:
            recovered = store.snapshot()
            source = getattr(store, 'path', None)
            source = str(source) if isinstance(source, (str, Path)) else None
            paths = tuple(dict.fromkeys(((source,) if source is not None else ()) +
                                        tuple(ref.path for ref in recovered.refs)))
            previous = self._service_provider_histories.get(id(store))
            prefix = len(previous[2].records) if previous is not None else 0
            if (previous is None or previous[0] is not store or previous[1] != paths or
                    recovered.refs[:prefix] != previous[2].refs or recovered.records[:prefix] != previous[2].records):
                # Opaque epochs occupy negative integers, distinct from local
                # positive epochs when callers replace a provider at one path.
                self._service_provider_generation -= 1
                generation = self._service_provider_generation
            else:
                generation = previous[3]
            self._service_provider_histories[id(store)] = (store, paths, recovered, generation)
            snapshots = {}
            for path in paths:
                if all(ref.path == path for ref in recovered.refs) and (source is None or path == source):
                    selected = recovered
                else:
                    pairs = tuple((record, ref) for record, ref in zip(recovered.records, recovered.refs)
                                  if ref.path == path)
                    selected = RecoveryResult(tuple(record for record, ref in pairs),
                        tuple(ref for record, ref in pairs), recovered.issue if path == source else None)
                snapshots[path] = (selected, generation)
            return recovered, snapshots

    def _service_recoveries(self, run_id, *, refresh=False):
        with self._lock:
            references = tuple(ref for identity, ref in self._service_references
                               if run_id is None or identity.get('run_id') == run_id)
        snapshots = {}
        stores = self._service_stores()
        for store in stores:
            if type(store) is LocalRecordStore:
                path = str(store.path)
                if path in snapshots:
                    continue
                recovered, generation = self._service_snapshot(path, reader=store.snapshot, refresh=refresh)
                snapshots[path] = (recovered, generation)
            else:
                # An opaque provider's snapshot may change independently of a
                # filesystem path. Retain its actual admission semantics.
                recovered, supplied = self._opaque_service_recovery(store)
                snapshots.update(supplied)
            references += tuple(ref for record, ref in zip(recovered.records, recovered.refs)
                if run_id is None or record.identity.get('run_id') == run_id)
        references = tuple(dict.fromkeys(references))
        for path in dict.fromkeys(ref.path for ref in references):
            if path not in snapshots:
                snapshots[path] = self._service_snapshot(path, refresh=refresh)
        return references, snapshots

    def service_record_refs(self, run_id=None, *, refresh=True):
        """Fresh acknowledged selected refs, retaining direct inspection semantics."""
        return self._service_recoveries(run_id, refresh=refresh)[0]

    def read_service_history(self, run_id=None, *, refresh=False):
        """Paired full history with reader issues and non-append generations.

        Normal polling detects filesystem metadata changes. Use refresh=True
        for fresh byte inspection independent of those metadata hints. No store
        is opened for writing or closed by this reader, including caller stores.
        """
        references, snapshots = self._service_recoveries(run_id, refresh=refresh)
        wanted = {(ref.path, ref.record_id) for ref in references}
        pairs = tuple((record, ref) for path in dict.fromkeys(ref.path for ref in references)
                      for record, ref in zip(snapshots[path][0].records, snapshots[path][0].refs)
                      if (path, record.record_id) in wanted)
        return ServiceHistory(tuple(record for record, ref in pairs), tuple(ref for record, ref in pairs),
            tuple((path, recovered.issue) for path, (recovered, generation) in snapshots.items() if recovered.issue),
            tuple((path, generation) for path, (recovered, generation) in snapshots.items()))

    def read_service_records(self, run_id=None, *, refresh=True):
        return self.read_service_history(run_id, refresh=refresh).records

    def assess(self, observation, *, operation_id=None):
        """Assess correlated facts against the active run's actual policy and gate."""
        from bytefault.core.contracts import Observation
        from bytefault.core.validation import typed, passive
        typed(observation, Observation, 'monitoring.observation')
        passive(observation, 'monitoring.observation')
        run_id = observation.correlation.run_id
        with self._lock:
            run = self._runs.get(run_id)
        if (run is None or not run.active or run.closing or
                (run.engine is not None and not getattr(run.engine,'_accepting_observations',True))):
            monitoring = run.engine.monitoring if run is not None and run.engine is not None else self.monitoring
            if monitoring is None:
                return Unavailable('monitoring', 'Monitoring', 'current owner attachment',
                                   'ended or unknown run requires independent Monitoring attachment')
            return self._independent_monitoring(observation, monitoring=monitoring, operation_id=operation_id)
        engine = run.engine
        if engine is None:
            return Unavailable('monitoring', 'Application', 'current run initialization',
                               'run policy has not initialized')
        # Match the executor's action -> run lock order. Status/control never take it.
        with engine._action_lock, run.lock:
            if not run.active or run.closing or not getattr(engine,'_accepting_observations',True):
                return self.assess(observation)
            return engine._publish_observation(observation, external=True)

    def complete_monitoring(self, run_id, completion):
        run = self._run(run_id)
        with run.lock:
            if (not run.active or run.closing or run.engine is None or
                    not getattr(run.engine,'_accepting_observations',True)):
                return False
            return run.engine.complete_monitoring(completion)

    def unavailable(self, operation):
        if operation not in FUTURE:
            return Unavailable(operation, 'Application', 'not offered', 'operation is not in the supported catalogue')
        return Unavailable(operation, *FUTURE[operation])

    def service(self, operation, request, *, input_files=()):
        if self._closed:
            return Unavailable(operation, 'Application', 'current owner attachment', 'application is closed')
        source_inventory = None
        if input_files:
            from bytefault.core.input_files import inventory
            paths, directories = inventory(files=tuple(input_files))
            source_inventory = {'paths': tuple(str(path) for path in paths),
                                'directories': tuple(str(path) for path in directories)}
        if operation == 'management' and self.management is not None:
            if self.management.status()['closed']:
                return Unavailable(operation, 'Management', 'current owner attachment', 'open service attachment required')
            return self.management.route(request, context={'source_inventory': source_inventory}
                if source_inventory is not None else None)
        if operation == 'maintenance' and self.management is not None:
            from bytefault.management.maintenance import run_maintenance
            if input_files:
                request = replace(request, input_files=tuple(dict.fromkeys(
                    (*request.input_files, *input_files))))
            return run_maintenance(request, self)
        if operation == 'reporting' and self.reporting is not None:
            if self.reporting.root.closed:
                return Unavailable(operation, 'Reporting', 'current owner attachment', 'open result owner required')
            if source_inventory is not None:
                context = dict(request.context or {})
                prior = dict(context.get('source_inventory') or {})
                context['source_inventory'] = {**prior,
                    'paths': (*prior.get('paths', ()), *source_inventory['paths']),
                    'directories': (*prior.get('directories', ()), *source_inventory['directories'])}
                request = replace(request, context=context)
            return self.reporting.report(request)
        if operation == 'monitoring':
            return self.assess(request)
        if operation in ('monitoring', 'management', 'reporting', 'maintenance'):
            return Unavailable(operation, operation.capitalize(), 'current owner attachment',
                               'attach the configured owner')
        return self.unavailable(operation)

    @contextmanager
    def independent_operation(self, transport, *, log_path=None, services=False, service_options=None,
                              input_files=(), mutation_roots=()):
        """Admit standalone owner work before initialization or external I/O.

        The yielded operation's stopped Event is signalled by close. Existing owners and required
        sinks are reused; newly attached resources have application lifetime.
        No campaign, case, engine or transport adapter is constructed.
        """
        if not isinstance(transport, ServiceTarget):
            self._validate_transport(transport)
        operation_id, stopped = str(uuid4()), threading.Event()
        primary_error = None
        with self._lock:
            if self._closed:
                raise ContractError('services', 'closed', 'application closed')
            self._independent_operations[operation_id] = stopped
            self._independent_targets[operation_id] = transport.host
        try:
            if services or service_options:
                self.configure_service_options(**dict(service_options or {}))
            selected = str(Path(log_path or self._independent_log_path).resolve())
            from bytefault.core.input_files import inventory
            inputs, directories = inventory(files=input_files)
            selected_outputs = () if log_path is None and self.action_logs else (Path(selected),)
            reused = tuple(Path(log.store.path).resolve() for log in self.action_logs
                if isinstance(getattr(getattr(log, 'store', None), 'path', None), (str, Path)))
            source_inventory = self._service_destinations(transport, str(run_path(operation_id)),
                selected_outputs, inputs, directories, reused)
            # Selected maintenance scope cannot include its own active or
            # prospective required writers. This check precedes construction.
            if mutation_roots:
                roots = tuple(Path(path).resolve() for path in mutation_roots)
                from bytefault.core.input_files import selected_scope_aliases
                if selected_scope_aliases(roots, inputs):
                    raise ContractError('maintenance.destinations', 'source_collision',
                                        'selected scope includes a current input')
                configuration = self.service_configuration
                result_root = self._result_root_path(run_path(operation_id))
                from bytefault.reporting import ResultRoot
                protected = [*selected_outputs, result_root, result_root / ResultRoot.OWNER_FILE]
                protected.extend(Path(log.store.path).resolve() for log in self.action_logs
                    if isinstance(getattr(getattr(log, 'store', None), 'path', None), (str, Path)))
                if self.management is not None:
                    protected.extend(Path(store.path).resolve() for store in (self.management.store,
                        getattr(self.management.action_log, 'store', None)) if getattr(store, 'path', None) is not None)
                if any(path == root or path.is_relative_to(root) for root in roots for path in protected):
                    raise ContractError('maintenance.destinations', 'source_collision', 'selected scope includes an active service writer')
            # Claim the result namespace before a selected standalone log can
            # create files within it. This context constructs no execution owner.
            if services and not stopped.is_set():
                from types import SimpleNamespace
                context = SimpleNamespace(transport=transport, record_path=str(run_path(operation_id)))
                self._attach_services(context)
            def attached():
                return (bool(self.action_logs) if log_path is None else any(
                    getattr(getattr(log, 'store', None), 'path', None) is not None and
                    Path(log.store.path).resolve() == Path(selected) for log in self.action_logs))
            entry, construct = self._begin_attachment('independent-log:' + selected, attached, admitted=True)
            if construct:
                try:
                    log = ActionLog.open(selected, owner='application')
                except BaseException as error:
                    self._finish_attachment(entry, error)
                    raise
                with self._lock:
                    self.action_logs = (*self.action_logs, log)
                    self._finish_attachment(entry)
            with self._lock:
                if self.monitoring is None:
                    from bytefault.monitoring import Monitoring
                    self.monitoring = Monitoring()
            if services and not stopped.is_set():
                self._attach_heartbeat(context)
            yield IndependentOperation(operation_id, stopped, source_inventory)
        except BaseException as error:
            primary_error = error
            if self.action_logs and not (isinstance(error, ContractError) and error.code in ('source_collision', 'writer_conflict')):
                try:
                    self.record_service('independent_failure', {'service_id': operation_id},
                        {'transport': transport, 'error': str(error), 'error_type': type(error).__name__})
                except Exception as history_error:
                    error.add_note('Independent failure history: ' + str(history_error))
            raise
        finally:
            with self._lock:
                self._independent_operations.pop(operation_id, None)
                self._independent_targets.pop(operation_id, None)
                closed = self._closed
            if closed:
                try:
                    self.close()
                except Exception as error:
                    fact = freeze({'operation': 'independent_finalize', 'service_id': operation_id,
                        'error': str(error), 'error_type': type(error).__name__})
                    self._independent_cleanup_errors.append(fact)
                    emit_recording_diagnostic({'required_record_kind': 'independent_finalize', 'reason': str(error), 'fact': fact})
                    if primary_error is not None:
                        primary_error.add_note('Independent cleanup: ' + str(error))

    def record_service(self, kind, identity, data):
        """Acknowledge independent owner actions in every attached required sink."""
        from bytefault.core.validation import passive
        passive(identity, 'service.identity')
        passive(data, 'service.data')
        references = []
        try:
            if not self.action_logs:
                raise OSError('required independent action log unavailable')
            for log in self.action_logs:
                reference = log(kind, identity, data)
                if not isinstance(reference, RecordRef):
                    raise OSError('required action sink returned no RecordRef acknowledgement')
                references.append(reference)
                with self._lock:
                    self._service_references.append((freeze(identity), reference))
        except Exception as error:
            diagnostic = freeze({'reason': str(error), 'required_record_kind': kind,
                'identity': identity, 'unacknowledged_action': data,
                'available_record_refs': tuple(references)})
            raise RequiredServiceSaveFailure(diagnostic, emit_recording_diagnostic(diagnostic)) from error
        return tuple(references)

    def _independent_monitoring(self, observation, *, monitoring=None, operation_id=None):
        """Acknowledge independent owner actions; engine case logging is separate."""
        from bytefault.core.contracts import Observation
        from bytefault.core.validation import typed, passive, validate_wait_obligations
        with self._lock:
            if self._closed and operation_id not in self._independent_operations:
                return Unavailable('monitoring', 'Application', 'current owner attachment',
                                   'application is closed')
            if not self.action_logs:
                return Unavailable('monitoring', 'Logging', 'current required logging attachment',
                                   'attach a required action log before independent Monitoring')
            service_id = str(uuid4())
            self._pending_monitoring.add(service_id)
        retained = []
        decision, policy_failure = None, None
        evaluation_state = 'not_started'
        try:
            typed(observation, Observation, 'monitoring.observation')
            passive(observation, 'monitoring.observation')
            identity = dict(freeze(observation.correlation))
            identity.update(observation_id=observation.observation_id, service_id=service_id)

            def save(kind, data):
                try:
                    for sink_index, log in enumerate(self.action_logs, 1):
                        reference = log(kind, identity, data)
                        if not isinstance(reference, RecordRef):
                            raise OSError('required action sink returned no RecordRef acknowledgement')
                        retained.append(reference)
                        with self._lock:
                            self._service_references.append((freeze(identity), reference))
                except Exception as exc:
                    diagnostic = freeze({'reason': str(exc), 'required_record_kind': kind,
                        'service': 'monitoring', 'identity': identity,
                        'original_request': observation, 'available_decision': decision,
                        'policy_failure': policy_failure, 'evaluation_state': evaluation_state,
                        'required_sink_ordinal': sink_index,
                        'available_record_refs': tuple(retained), 'unacknowledged_action': data,
                        'engine_transport': 'not_constructed',
                        'missing_evidence': f'{kind} not acknowledged by every required action sink; service result withheld'})
                    delivery_error = emit_recording_diagnostic(diagnostic)
                    raise RequiredServiceSaveFailure(diagnostic, delivery_error) from exc

            save('monitoring_observation', {'observation': observation})
            try:
                supplied_decision = (monitoring or self.monitoring).observe(observation)
                validate_wait_obligations(supplied_decision)
                if (supplied_decision.correlation != observation.correlation or
                        supplied_decision.observation_id != observation.observation_id):
                    raise ContractError('monitoring', 'correlation', 'decision does not identify supplied facts')
                for selected in supplied_decision.assessments + supplied_decision.probes:
                    if (selected.correlation != observation.correlation or
                            selected.observation_id != observation.observation_id):
                        raise ContractError('monitoring', 'correlation', 'selected work does not identify supplied facts')
                decision = supplied_decision
            except Exception as exc:
                evaluation_state, policy_failure = 'failed', str(exc)
                save('monitoring_failure', {'observation': observation, 'error': str(exc),
                    'error_type': type(exc).__name__, 'error_path': getattr(exc, 'path', None),
                    'error_code': getattr(exc, 'code', None)})
                raise
            evaluation_state = 'produced_decision'
            save('monitoring_decision', {'decision': decision})
            return decision
        finally:
            with self._lock:
                self._pending_monitoring.remove(service_id)
            if self._closed:
                self.close()

    def export_case(self, path, record_id):
        """Prepare a standalone JSON-compatible case; no report or target I/O."""
        from bytefault.fuzzers.saved_cases import portable_case
        return portable_case(path, record_id)

    def inspect_resume(self, path):
        """Read acknowledged history without opening a writer or adapter."""
        from bytefault.fuzzers.resuming import inspect_resume
        return inspect_resume(path)

    def resume(self, intent, *, record_path=None, log_path=None, transport=None):
        """Prepare a linked ordinary campaign; submit/start performs execution."""
        from bytefault.fuzzers.resuming import prepare_resume
        request = prepare_resume(self, intent, record_path=record_path, log_path=log_path,
                                 transport=transport)
        self._validate_transport(request.transport)
        self._validate_destinations(request)
        return request

    def import_case(self, data, *, mode='literal', steps=(), record_path=None,
                    log_path=None, transport=None, no_receive=False):
        """Prepare a new ordinary request. Execution is an explicit submit/start."""
        from bytefault.fuzzers.saved_cases import prepare_case
        if not isinstance(steps, tuple) or any(not isinstance(s, SavedStepIntent) for s in steps):
            raise ContractError('saved_case.steps', 'invalid', 'ordered typed SavedStepIntent tuple required')
        conversation, retained_target = prepare_case(data, mode=mode, steps=steps, no_receive=no_receive)
        target = retained_target if transport is None else transport
        self._validate_transport(target)
        destination = record_path if record_path is not None else str(run_path(conversation.run_id))
        request = ApplicationRequest(conversation, target, destination, log_path)
        self._validate_destinations(request)
        return request

    def saved_case(self, intent, **options):
        if (not isinstance(intent, SavedCaseIntent) or not isinstance(intent.path, str) or not intent.path or
                not isinstance(intent.record_id, str) or intent.mode not in ('literal', 'fresh_dynamic')):
            raise ContractError('saved_case', 'invalid', 'path and literal/fresh_dynamic mode required')
        if not isinstance(intent.steps, tuple) or any(not isinstance(step, SavedStepIntent) or not step.action_id or
               step.choice not in ('recorded', 'fresh_dynamic') or
               type(step.reapply_mutations) is not bool for step in intent.steps):
            raise ContractError('saved_case.steps', 'invalid', 'per-action recorded/fresh choice and mutation intent required')
        if len({step.action_id for step in intent.steps}) != len(intent.steps):
            raise ContractError('saved_case.steps', 'duplicate', 'outbound action choices must be unique')
        from bytefault.fuzzers.saved_cases import load_case
        request = self.import_case(load_case(intent.path, intent.record_id), mode=intent.mode,
                                   steps=intent.steps, **options)
        request = replace(request, conversation=replace(request.conversation,
            input_files=(*request.conversation.input_files, str(Path(intent.path).resolve()))))
        self._validate_destinations(request)
        return request

    def close(self):
        with self._lock:
            self._closed = True
            runs = tuple(self._runs.values())
            for run in runs:
                if run.active:
                    run.stop_requested.set()
            for stopped in self._independent_operations.values():
                stopped.set()
            pending_monitoring = tuple(self._pending_monitoring)
            preparations = tuple(self._preparations.values())
        # Stop admission precedes every auxiliary close: a heartbeat, source
        # preparation or owned service may still be finishing blocking work.
        for run in runs:
            if run.active and run.engine is not None:
                run.engine.control('stop')
        preparation_failures = []
        for preparation in preparations:
            try:
                preparation.close()
            except Exception as error:
                failure = freeze({'preparation_id': preparation.preparation_id,
                    'error': str(error), 'summary': preparation.summary,
                    'diagnostic': getattr(error, 'diagnostic', None)})
                self._preparation_failures[preparation.preparation_id] = failure
        preparation_failures = tuple(self._preparation_failures.values())
        pending_preparations = tuple(p.preparation_id for p in preparations if not p._done)
        with self._lock:
            heartbeats = tuple(self._heartbeats[host] for host in self._heartbeat_logs)
        for monitor in heartbeats:
            monitor.close()
        with self._lock:
            pending_heartbeats = tuple(host for host in self._heartbeat_logs if self._heartbeats[host].status()['running'])
            pending_initializations = self._pending_attachments()
        pending = [run.request.conversation.run_id for run in runs if run.active]
        services = self.management.status() if self.management else None
        with self._lock:
            pending_independent = tuple(self._independent_operations)
        if self._owned_services is not None and not pending_independent:
            management, service_store, result_root = self._owned_services
            management.close()
            services = management.status()
            if services['finalized']:
                service_store.close()
            self._release_owned_result_root()
        service_pending = services is not None and (bool(services['pending']) or services.get('outcome') == 'pending')
        service_closure_pending = service_pending
        if (self.management is not None and
                getattr(self.management, 'draining_current_thread', lambda: False)()):
            # This callback itself is truthfully pending in the returned status.
            # Its already-settled service work must not make owner-close wait on
            # itself; other admitted route/settlement work still retains sinks.
            service_closure_pending = bool(services['pending'] or services.get('settling'))
        cleanup_failures = tuple(freeze({'run_id': run.request.conversation.run_id,
            'cleanup': run.engine.last_cleanup_result}) for run in runs
            if run.engine is not None and run.engine.last_cleanup_result is not None and
            (run.engine.last_cleanup_result.outcome == 'uncertain' or
             run.engine.last_cleanup_result.pacing_error is not None))
        if not pending and not service_closure_pending and not pending_monitoring and not pending_independent and not pending_preparations and not pending_heartbeats and not pending_initializations:
            for index, log in enumerate(self.action_logs):
                try:
                    log.end('application')
                except Exception as error:
                    fact = freeze({'operation': 'application_action_log:' + str(index),
                                   'error': str(error), 'error_type': type(error).__name__})
                    cleanup_failures += (fact,)
                    emit_recording_diagnostic({'required_record_kind': 'application_cleanup_failure',
                        'reason': str(error), 'cleanup': fact})
        cleanup_failures += tuple(freeze({'run_id': run.request.conversation.run_id,
            'application_cleanup_errors': run.cleanup_errors}) for run in runs if run.cleanup_errors)
        cleanup_failures += tuple(freeze({'run_id':run.request.conversation.run_id,
            'engine_cleanup_errors':run.result.cleanup_errors}) for run in runs
            if getattr(run.result,'cleanup_errors',()))
        cleanup_failures += tuple(self._independent_cleanup_errors)
        heartbeat_errors = tuple(self._heartbeats[host].status() for host in self._heartbeat_logs if self._heartbeats[host].error)
        service_errors = bool(services and services.get('outcome') == 'failed')
        return freeze({'outcome': 'pending' if pending or service_pending or pending_monitoring or pending_independent or pending_preparations or pending_heartbeats or pending_initializations else
                       'failed' if cleanup_failures or preparation_failures or heartbeat_errors or service_errors else 'completed',
                       'pending_runs': tuple(pending), 'services': services,
                       'pending_initializations': pending_initializations,
                       'pending_monitoring': pending_monitoring,
                       'pending_independent': pending_independent,
                       'pending_heartbeats': pending_heartbeats, 'heartbeat_errors': heartbeat_errors,
                       'pending_preparations': pending_preparations,
                       'preparation_failures': tuple(preparation_failures),
                       'cleanup_failures': cleanup_failures})
