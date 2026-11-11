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

"""Management-owned literal local/remote maintenance with per-item evidence."""
import argparse
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
import shlex

from bytefault.core.contracts import ContractError, freeze
from bytefault.monitoring.configuration import number


@dataclass(frozen=True)
class MaintenanceRequest:
    host: str | None = None
    ssh_key: str | None = None
    ssh_user: str | None = None
    remote_dir: str = '/root/cores'
    local_cache: str | None = None
    local: bool = True
    remote: bool = True
    local_entries: tuple[str, ...] = ()
    remote_entries: tuple[str, ...] = ()
    timeout: float = 30
    log_path: str | None = None
    result_root: str | None = None
    original_request: object = field(default_factory=dict)
    protected_files: tuple[str, ...] = ()
    connection_delay: float = 0.0
    ssh_pass: str | None = None
    input_files: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.local) is not bool or type(self.remote) is not bool or not (self.local or self.remote):
            raise ContractError('maintenance.selection', 'invalid', 'select local, remote or both')
        if self.ssh_key is not None and self.ssh_pass is not None:
            raise ContractError('maintenance.ssh_pass', 'conflicting_input', 'key and password authentication conflict')
        if self.ssh_pass is not None and (not isinstance(self.ssh_pass, str) or not self.ssh_pass):
            raise ContractError('maintenance.ssh_pass', 'invalid', 'nonempty SSH password required')
        if self.ssh_pass is not None and self.ssh_user is None:
            raise ContractError('maintenance.ssh_user', 'required', 'password authentication requires an explicit SSH user')
        if self.remote and (not isinstance(self.host, str) or not self.host or
                (not self.ssh_key and self.ssh_pass is None)):
            raise ContractError('maintenance.remote', 'required', 'remote host and SSH credentials required for selected remote work')
        if self.ssh_user is not None and (not isinstance(self.ssh_user, str) or not self.ssh_user):
            raise ContractError('maintenance.ssh_user', 'invalid', 'nonempty SSH user required')
        if not isinstance(self.remote_dir, str) or not self.remote_dir:
            raise ContractError('maintenance.remote', 'invalid', 'exact user and directory required')
        if self.ssh_user is None:
            object.__setattr__(self, 'ssh_user', 'root')
        if (not self.local and self.local_entries) or (not self.remote and self.remote_entries):
            raise ContractError('maintenance.selection', 'conflicting_input', 'entries supplied for an unselected side')
        for name in ('local_entries', 'remote_entries', 'protected_files', 'input_files'):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(not isinstance(p, str) or not p for p in value):
                raise ContractError('maintenance.' + name, 'invalid', 'ordered exact path tuple required')
            if len(set(value)) != len(value):
                raise ContractError('maintenance.' + name, 'ambiguous_selection', 'duplicate entries are ambiguous')
        number(self.timeout, 'maintenance.timeout')
        number(self.connection_delay, 'maintenance.connection_delay')
        if self.timeout == 0:
            raise ContractError('maintenance.timeout', 'invalid', 'positive operation timeout required')
        object.__setattr__(self, 'original_request', freeze(self.original_request))


def build_parser():
    parser = argparse.ArgumentParser(description='Maintain exactly selected local cache and/or remote core files')
    parser.add_argument('host', nargs='?', help='Remote device; unnecessary for --local-only')
    parser.add_argument('--ssh-key', help='SSH private key; unnecessary for --local-only')
    parser.add_argument('--ssh-user')
    parser.add_argument('--ssh-pass', help='Cleartext SSH password for selected remote work; requires --ssh-user')
    parser.add_argument('--remote-dir', default='/root/cores',
        help='Remote directory for selected SSH maintenance (default /root/cores)')
    parser.add_argument('--local-cache', help='Selected local root; defaults to the attached Collection cache')
    parser.add_argument('--local-only', action='store_true',
        help='Select local cache cleanup only; no host or SSH credential required')
    parser.add_argument('--remote-only', action='store_true',
        help='Select SSH remote cleanup only; requires host and key or user/password')
    parser.add_argument('--local-entry', action='append', default=[], help='Exact relative file/directory within local root; repeatable, no glob expansion')
    parser.add_argument('--remote-entry', action='append', default=[], help='Exact immediate remote basename; repeatable, no glob expansion')
    parser.add_argument('--timeout', type=float, default=30,
        help='Positive timeout in seconds for each selected SSH operation (default 30)')
    parser.add_argument('--connection-delay', type=float, default=0.0,
        help='Additional wait between remote inventory/stat/cleanup connections')
    parser.add_argument('--log-file')
    parser.add_argument('--results', help='Shared service owner root; action logs exist without a report')
    return parser


def resolve_arguments(argv, *, original_argv=None, input_files=()):
    from bytefault.paths import artifacts_root
    from bytefault.core.logging_utils import resolve_log_path
    args = build_parser().parse_args(argv)
    if args.local_only and args.remote_only:
        raise ContractError('maintenance.selection', 'conflicting_input', 'local-only and remote-only cannot be combined')
    return MaintenanceRequest(args.host, args.ssh_key, args.ssh_user, args.remote_dir,
        args.local_cache,
        not args.remote_only, not args.local_only, tuple(args.local_entry), tuple(args.remote_entry),
        args.timeout, resolve_log_path(args.log_file, artifacts_root()), args.results,
        {'argv': tuple(argv if original_argv is None else original_argv), 'options': vars(args)}, connection_delay=args.connection_delay,
        ssh_pass=args.ssh_pass, input_files=tuple(input_files))


def perform_maintenance(request, *, save, process=None, stopped=None, pacer=None):
    """Run under the admitted Management owner; exact argv and failures persist."""
    from bytefault.management.collection import Collection
    from bytefault.core.records import RequiredServiceSaveFailure
    stopped = stopped or (lambda: False)
    items, inventories, operations = [], {}, []
    def retain(item):
        items.append(freeze(item))
        save('maintenance_item', {'item': item})
    if request.local:
        root = Path(request.local_cache).resolve()
        protected = tuple(Path(p).resolve() for p in request.protected_files)
        def failed(path, reason):
            retain({'side': 'local', 'path': str(path), 'status': 'failed', 'error': reason})
        if not root.exists():
            inventories['local'] = 'absent'
        elif not root.is_dir():
            inventories['local'] = 'unavailable'
        else:
            inventories['local'] = 'empty'
            selected = request.local_entries or ('.',)
            # Reject overlapping selections rather than deleting an item twice.
            paths = []
            for entry in selected:
                part = Path(entry)
                candidate = root / part
                resolved = candidate.resolve()
                if (part.is_absolute() or PureWindowsPath(entry).drive or
                        any(piece == '..' for piece in part.parts) or not resolved.is_relative_to(root)):
                    failed(candidate, 'selection is outside the local root')
                    continue
                if candidate.is_symlink() or candidate.is_junction():
                    failed(candidate, 'linked entry is not traversed or deleted')
                    continue
                paths.append(resolved)
            conflicts = {i for i, path in enumerate(paths) for j, other in enumerate(paths) if i != j and
                (path == other or path.is_relative_to(other) or other.is_relative_to(path))}
            for i in sorted(conflicts):
                failed(paths[i], 'overlapping or aliased local selections are ambiguous')
            paths = [path for i, path in enumerate(paths) if i not in conflicts]
            pending = list(reversed(paths))
            while pending:
                path = pending.pop()
                operation = {'side': 'local', 'path': str(path), 'started_at': datetime.now(timezone.utc).isoformat()}
                if stopped():
                    retain(dict(operation, status='not_started', reason='stop requested'))
                    continue
                try:
                    if not path.resolve().is_relative_to(root):
                        raise ValueError('entry leaves selected root')
                    if path.is_symlink() or path.is_junction():
                        raise ValueError('linked entry is not traversed or deleted')
                    if not path.exists():
                        operation['status'] = 'absent'
                    elif path.is_dir():
                        pending.extend(reversed(sorted(path.iterdir())))
                        continue
                    elif not path.is_file():
                        raise ValueError('entry is not a regular file')
                    else:
                        inventories['local'] = 'available'
                        if any(path == target or (target.exists() and path.samefile(target)) for target in protected):
                            raise ValueError('entry is a protected input or active required service writer')
                        save('maintenance_operation', {'operation': dict(operation, requested='unlink')})
                        path.unlink()
                        operation['status'] = 'removed'
                except RequiredServiceSaveFailure:
                    raise
                except Exception as error:
                    operation.update(status='failed', error=str(error), error_type=type(error).__name__)
                operation['completed_at'] = datetime.now(timezone.utc).isoformat()
                retain(operation)
    if request.remote and stopped():
        inventories['remote'] = 'not_started'
        retain({'side': 'remote', 'status': 'not_started', 'reason': 'stop requested before inventory'})
    elif request.remote:
        collector = Collection(request.host, ssh_key=request.ssh_key, ssh_user=request.ssh_user,
            ssh_pass=request.ssh_pass,
            remote_dir=request.remote_dir, process=process, min_timeout=request.timeout, core_write_wait=0,
            record_operation=lambda operation: save('maintenance_external_operation', {'operation': operation}),
            pacer=pacer, connection_delay=request.connection_delay, cancelled=stopped)
        try:
            files = collector._list_remote_cores(request.remote_dir, operations=operations, timeout=request.timeout)
            inventories['remote'] = 'available' if files else 'empty'
            discovered = {name: (size, modified) for name, size, modified in files}
            for name in request.remote_entries or tuple(discovered):
                item = {'side': 'remote', 'name': name, 'host': request.host, 'user': request.ssh_user,
                    'remote_path': request.remote_dir.rstrip('/') + '/' + name}
                if stopped():
                    item.update(status='not_started', reason='stop requested')
                elif not name or name in ('.', '..') or '/' in name or '\0' in name:
                    item.update(status='failed', error='exact immediate remote basename required')
                elif name not in discovered:
                    item.update(status='absent')
                else:
                    size, modified = discovered[name]
                    item.update(size=size, remote_modified=modified)
                    save('maintenance_operation', {'operation': dict(item, requested='remote_unlink')})
                    try:
                        result = collector._ssh('rm -f -- ' + shlex.quote(item['remote_path']),
                            request.timeout, operations=operations)
                        item.update(status='removed' if result.returncode == 0 else 'failed', error=result.stderr or '')
                    except RequiredServiceSaveFailure:
                        raise
                    except Exception as error:
                        item.update(status='failed', error=str(error), error_type=type(error).__name__)
                retain(item)
        except RequiredServiceSaveFailure:
            raise
        except Exception as error:
            interrupted = stopped() and isinstance(error, InterruptedError)
            inventories['remote'] = ('not_started' if interrupted else
                getattr(error, 'inventory_status', 'unavailable'))
            retain({'side': 'remote', 'status': 'not_started' if interrupted else 'failed',
                'error': str(error), 'error_type': type(error).__name__})
    failed = any(i['status'] in ('failed', 'absent') for i in items) or any(
        state in ('absent', 'unavailable', 'failed') for state in inventories.values())
    return freeze({'outcome': 'stopped' if any(i['status'] == 'not_started' for i in items) else
        'failed' if failed else 'completed', 'items': tuple(items),
        'inventories': inventories, 'operations': tuple(operations)})


def run_maintenance(request, application=None, *, process=None):
    from bytefault.application import Application, ServiceTarget
    from bytefault.paths import artifacts_root
    if not isinstance(request, MaintenanceRequest):
        raise ContractError('maintenance.request', 'invalid', 'typed MaintenanceRequest required')
    app, owned = application or Application(), application is None
    result, primary_error = None, None
    choices = {'result_root': request.result_root} if request.result_root is not None else {}
    # A local-only operation does not require or initialize remote credentials.
    target = ServiceTarget(request.host)
    try:
        collection = getattr(app.management, 'collection', None)
        configuration = app.service_configuration
        service_root = Path(request.result_root or getattr(configuration, 'result_root', None) or
            (app.reporting.root.path if app.reporting is not None else artifacts_root() / 'runs' / 'results'))
        default_cache = (getattr(collection, 'core_cache_dir', None) or
            getattr(configuration, 'cache_dir', None) or service_root / 'collection')
        local_root = Path(request.local_cache or default_cache).absolute()
        selected_roots = tuple(str(local_root / part) for part in request.local_entries) if request.local_entries else (str(local_root),)
        with app.independent_operation(target, log_path=request.log_path, services=True, service_options=choices,
                input_files=request.input_files,
                mutation_roots=selected_roots if request.local else ()) as admitted:
            app.record_service('standalone_maintenance_request', {'service_id': admitted.operation_id}, {'request': request})
            protected = [getattr(getattr(log, 'store', None), 'path', None) for log in app.action_logs]
            management = app.management
            if management is None:
                if not admitted.stopped.is_set():
                    raise ContractError('maintenance.management', 'unavailable', 'Management initialization did not complete')
                result = freeze({'outcome': 'stopped', 'items': (), 'inventories': {}, 'operations': (),
                    'reason': 'stopped before Management initialization'})
            else:
                protected.extend((management.store.path, getattr(management.action_log.store, 'path', None)))
                if app.reporting is not None:
                    protected.extend((app.reporting.root.store.path, app.reporting.root.action_log.store.path))
                selected = replace(request, local_cache=str(local_root),
                    protected_files=(*request.protected_files, *request.input_files,
                        *(str(path) for path in protected if path is not None)))
                result = management.maintain(selected, process=process, stopped=admitted.stopped.is_set,
                    pacer=app.connection_pacer(admitted.operation_id) if request.connection_delay else None)
            app.record_service('standalone_maintenance_terminal', {'service_id': admitted.operation_id}, {'result': result})
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if owned:
            from bytefault.management.lifecycle import finish_owned_application, with_cleanup
            facts = finish_owned_application(app, primary_error=primary_error)
            if result is not None:
                result = with_cleanup(result, facts)
    return result


def execute_arguments(argv, application, *, original_argv=None, input_files=()):
    return run_maintenance(resolve_arguments(argv, original_argv=original_argv,
                                             input_files=input_files), application)


def main(argv=None):
    import sys
    from bytefault.cli import main as application_main
    return application_main(['maintenance', *(sys.argv[1:] if argv is None else argv)])


def remove_local_cache(cache_dir: Path) -> int:
    return 0 if run_maintenance(MaintenanceRequest(local_cache=str(cache_dir), remote=False))['outcome'] == 'completed' else 1


def remove_remote_cores(host: str, ssh_key: str, remote_dir: str) -> int:
    return 0 if run_maintenance(MaintenanceRequest(host, ssh_key, remote_dir=remote_dir, local=False))['outcome'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
