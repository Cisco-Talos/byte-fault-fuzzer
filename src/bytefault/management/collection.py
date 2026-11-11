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

"""Management-owned rsync batch acquisition, selected SSH cleanup and maintenance inventory."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import re
import threading
import shlex
import posixpath
import subprocess
from uuid import uuid4


class InventoryError(OSError):
    def __init__(self, status, message):
        self.inventory_status = status
        super().__init__(message)


def _rsync_name(value):
    # Rsync quotes controls/backslashes as octal escapes in its one-line
    # output. Decode once: a literal backslash followed by #012 is not a LF.
    return re.sub(r'\\#([0-7]{3})', lambda match: chr(int(match.group(1), 8)), value)


def _rsync_inventory(stdout):
    files, skipped, regular_count = {}, set(), None
    for line in stdout.splitlines():
        if line.startswith('BF|'):
            parts = line.split('|', 4)
            if len(parts) != 5:
                raise InventoryError('failed', 'malformed rsync itemized record')
            _, change, size, modified, encoded = parts
            if len(change) < 2 or change[1] != 'f':
                continue
            name = _rsync_name(encoded)
            if not name or name in ('.', '..') or '/' in name or '\0' in name:
                raise InventoryError('failed', 'rsync reported an invalid direct core filename')
            try:
                files[name] = (int(size), modified, change)
            except ValueError as error:
                raise InventoryError('failed', 'rsync reported invalid core size') from error
        elif line.endswith(' is over max-size'):
            skipped.add(_rsync_name(line[:-len(' is over max-size')]))
        elif line.startswith('Number of files:'):
            match = re.fullmatch(r'Number of files:\s*\d+\s*\(([^)]*)\)', line)
            if match is None:
                raise InventoryError('failed', 'malformed rsync file-list summary')
            regular = re.search(r'(?:^|,\s*)reg:\s*(\d+)(?:,|$)', match.group(1))
            regular_count = int(regular.group(1)) if regular else 0
    if regular_count is None:
        raise InventoryError('failed', 'rsync did not provide a complete file-list summary')
    if regular_count != len(files) + len(skipped - files.keys()):
        raise InventoryError('failed', 'rsync file count differs from decoded core inventory')
    return files, skipped


_cache_locks_guard = threading.Lock()
_cache_locks = {}


class Collection:
    def __init__(self, host, *, ssh_key=None, ssh_user=None, ssh_pass=None, cache_dir=None,
                 remote_dir='/root/cores', max_file_size_mb=0, min_timeout=30,
                 core_write_wait=5, process=None, sleep=None, record_operation=None,
                 pacer=None, connection_delay=0.0, cancelled=None, pacer_for_run=None):
        import time
        from bytefault.core.contracts import ContractError
        if ssh_key is not None and ssh_pass is not None:
            raise ContractError('collection.ssh_pass', 'conflicting_input', 'key and password authentication conflict')
        if ssh_pass is not None and (not isinstance(ssh_pass, str) or not ssh_pass):
            raise ContractError('collection.ssh_pass', 'invalid', 'nonempty SSH password required')
        if ssh_pass is not None and not ssh_user:
            raise ContractError('collection.ssh_user', 'required', 'password authentication requires an explicit SSH user')
        self.host, self.ssh_key, self.ssh_user, self.ssh_pass = host, ssh_key, ssh_user or 'root', ssh_pass
        from bytefault.paths import artifacts_root
        self.core_cache_dir = str(cache_dir or artifacts_root() / '_core_cache')
        self.remote_dir, self.max_file_size_mb = remote_dir, max_file_size_mb
        self.min_timeout, self.core_write_wait = min_timeout, core_write_wait
        self.process, self.sleep = process or subprocess.run, sleep or time.sleep
        self.record_operation = record_operation
        if connection_delay and pacer is None and pacer_for_run is None:
            from bytefault.core.connection_pacing import ConnectionPacer
            pacer = ConnectionPacer(sleep=self.sleep)
        self.pacer, self.connection_delay = pacer, connection_delay
        self.cancelled = cancelled or (lambda: False)
        self.pacer_for_run = pacer_for_run
        self.last_items = ()

    def _run(self, command, timeout, *, operations):
        operation = {'argv': tuple(command), 'timeout': timeout, 'capture_output': True,
                     'text': True, 'host': self.host, 'user': self.ssh_user,
                     'started_at': datetime.now(timezone.utc).isoformat()}
        try:
            if self.pacer is not None:
                operation['connection_throttle'], _ = self.pacer.before_start(
                    self.connection_delay, cancelled=self.cancelled, sleep=self.sleep)
                if operation['connection_throttle']['outcome'] == 'cancelled':
                    raise InterruptedError('stopped before collection connection')
            if self.cancelled():
                raise InterruptedError('stopped before collection connection')
            if self.ssh_pass is None:
                result = self.process(command, capture_output=True, text=True, timeout=timeout)
            else:
                from bytefault.management.ssh_auth import password_authenticated_run
                result = password_authenticated_run(self.process, command, timeout, self.ssh_pass)
            operation.update(returncode=result.returncode, stdout=getattr(result, 'stdout', ''),
                             stderr=getattr(result, 'stderr', ''))
            return result
        except Exception as exc:
            operation.update(error=str(exc), error_type=type(exc).__name__)
            raise
        finally:
            if self.pacer is not None and operation.get('connection_throttle', {}).get('outcome') == 'completed':
                self.pacer.finished()
            operation['completed_at'] = datetime.now(timezone.utc).isoformat()
            operations.append(operation)
            if self.record_operation is not None:
                self.record_operation(operation)

    def _ssh(self, command, timeout=15, *, operations):
        authentication = (['-i', str(self.ssh_key)] if self.ssh_pass is None else
            ['-o', 'BatchMode=no', '-o', 'PubkeyAuthentication=no', '-o',
             'PreferredAuthentications=password,keyboard-interactive', '-o',
             'NumberOfPasswordPrompts=1'])
        return self._run(['ssh', *authentication, '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=10', f'{self.ssh_user}@{self.host}', command],
            timeout, operations=operations)

    def _list_remote_cores(self, remote_dir, *, operations, timeout=15):
        literal = './' + remote_dir if remote_dir.startswith('-') else remote_dir
        directory = shlex.quote(literal)
        parent = posixpath.dirname(remote_dir.rstrip('/')) or ('/' if remote_dir.startswith('/') else '.')
        # The selected directory itself is tested separately from enumeration.
        # Fixed exit codes retain the remote test fact without parsing stderr.
        # BusyBox find supports -print0 but not GNU -printf. Stat each
        # discovered path separately: BusyBox find does not propagate every
        # failed -exec status, so a missing/raced file must fail inventory.
        result = self._ssh('find ' + directory +
            ' -maxdepth 1 -type f -print0; result=$?; ' +
            'if [ "$result" -ne 0 ]; then if [ ! -e ' + directory +
            ' ] && [ -x ' + shlex.quote(parent) +
            ' ]; then exit 44; else exit 45; fi; fi; ' +
            '[ -d ' + directory + ' ] || exit 45', timeout, operations=operations)
        operations[-1]['remote_dir'] = remote_dir
        if result.returncode:
            status = {44: 'absent', 45: 'unavailable', 255: 'unavailable'}.get(result.returncode, 'failed')
            raise InventoryError(status, result.stderr or f'listing failed: {result.returncode}')
        files = []
        for path in result.stdout.split('\0'):
            if not path:
                continue
            stat = self._ssh('stat -c ' + shlex.quote('%s %Y') + ' ' +
                shlex.quote(path), timeout, operations=operations)
            operations[-1]['remote_path'] = path
            if stat.returncode:
                raise InventoryError('failed', stat.stderr or
                    f'discovered core changed before stat: {path}')
            try:
                size, modified = stat.stdout.strip().split()
                files.append((posixpath.basename(path), int(size), modified))
            except (ValueError, TypeError) as error:
                raise InventoryError('failed', f'invalid remote stat for {path}') from error
        return files

    def _endpoint_root(self, remote_dir=None, local_dir=None):
        selected = remote_dir or self.remote_dir
        key = hashlib.sha256('\0'.join((self.ssh_user, self.host, selected)).encode()).hexdigest()[:24]
        return Path(local_dir or self.core_cache_dir) / key

    def acquire(self, *, remote_dir=None, local_dir=None, max_file_size_mb=None, min_timeout=None, cleanup=False):
        scope = (str(Path(local_dir or self.core_cache_dir).absolute()), self.ssh_user,
            self.host, remote_dir or self.remote_dir)
        with _cache_locks_guard:
            lock = _cache_locks.setdefault(scope, threading.RLock())
        with lock:
            return self._acquire_locked(remote_dir=remote_dir, local_dir=local_dir,
                max_file_size_mb=max_file_size_mb, min_timeout=min_timeout, cleanup=cleanup)

    def _acquire_locked(self, *, remote_dir=None, local_dir=None, max_file_size_mb=None, min_timeout=None, cleanup=False):
        from bytefault.management import CollectionOutcome
        operations = []
        if not self.ssh_key and self.ssh_pass is None:
            return CollectionOutcome('failed', error='SSH access not configured', inventory_status='unavailable')
        remote_dir = remote_dir or self.remote_dir
        limit = self.max_file_size_mb if max_file_size_mb is None else max_file_size_mb
        minimum = self.min_timeout if min_timeout is None else min_timeout
        discovered_at = datetime.now(timezone.utc).isoformat()
        # Keep the cache stable across Collection instances and separate remote
        # endpoints. Rsync checks contents when size and mtime happen to match;
        # changed same-name files replace the current copy, with the old one
        # retained in this acquisition's version directory.
        root = self._endpoint_root(remote_dir, local_dir)
        current = root / 'current'
        history = root / 'versions' / str(uuid4())
        pending = root / 'pending'
        current.mkdir(parents=True, exist_ok=True)
        before = {p.relative_to(current) for p in current.iterdir() if p.is_file() and not p.is_symlink()}
        source = f'{self.ssh_user}@{self.host}:' + remote_dir.rstrip('/') + '/'
        command = ['rsync', '-a', '--no-links', '--checksum', '--protect-args', '--backup',
            '--backup-dir=' + str(history), '--partial-dir=.rsync-partial',
            '--itemize-changes', '--itemize-changes', '--out-format=BF|%i|%l|%M|%n',
            '--info=skip2', '--stats',
            '--exclude=*/', '--timeout=' + str(minimum), '-e',
            ('ssh -i ' + shlex.quote(str(self.ssh_key)) + ' -o StrictHostKeyChecking=no'
             if self.ssh_pass is None else
             'ssh -o BatchMode=no -o PubkeyAuthentication=no'
             ' -o PreferredAuthentications=password,keyboard-interactive'
             ' -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no')]
        if limit:
            command.append('--max-size=' + str(limit * 1048576))
        command.extend((source, str(current) + '/'))
        def unverified_items():
            partial_dir = current / '.rsync-partial'
            partials = tuple(str(p) for p in partial_dir.iterdir()
                if p.is_file()) if partial_dir.is_dir() else ()
            replaced = {p.name for p in history.iterdir() if p.is_file()} if history.exists() else set()
            changed = tuple(str(p) for p in current.iterdir() if p.is_file() and
                not p.is_symlink() and (p.relative_to(current) not in before or p.name in replaced))
            if changed:
                pending.mkdir(exist_ok=True)
                for path in changed:
                    (pending / Path(path).name).touch(exist_ok=True)
            return tuple({'path': path, 'status': 'partial_or_unverified',
                'reason': 'rsync did not complete this acquisition'} for path in (*changed, *partials))
        try:
            # Rsync's --timeout bounds stalled I/O. A progressing large core
            # has no artificial total wall-clock deadline without a size list.
            result = self._run(command, None, operations=operations)
        except Exception as exc:
            return CollectionOutcome('failed', error=str(exc), items=unverified_items(),
                operations=tuple(operations),
                inventory_status='unavailable' if isinstance(exc, (OSError, subprocess.TimeoutExpired)) else 'failed')
        if result.returncode:
            error = result.stderr or f'rsync failed: {result.returncode}'
            absent = result.returncode == 23 and bool(re.search(
                r'change_dir[^\n]*No such file or directory', error))
            return CollectionOutcome('failed', error=error,
                items=unverified_items(),
                operations=tuple(operations),
                inventory_status='absent' if absent else 'unavailable' if result.returncode == 255 else 'failed')
        try:
            inventory, skipped = _rsync_inventory(result.stdout)
        except InventoryError as error:
            return CollectionOutcome('failed', error=str(error), items=unverified_items(),
                operations=tuple(operations), inventory_status=error.inventory_status)
        after = {p.relative_to(current): p for p in current.iterdir() if p.is_file() and not p.is_symlink()}
        local_ids = {}
        for name in inventory:
            path = current / name
            if not path.is_file() or path.is_symlink():
                return CollectionOutcome('failed', error='rsync-listed core is not representable in local cache: ' + name,
                    items=unverified_items(), operations=tuple(operations), inventory_status='failed')
            info = path.stat()
            local_id = (info.st_dev, info.st_ino)
            if local_id in local_ids and local_ids[local_id] != name:
                return CollectionOutcome('failed', error='distinct remote core names alias one local cache file',
                    items=unverified_items(), operations=tuple(operations), inventory_status='failed')
            local_ids[local_id] = name
        replaced = {p.relative_to(history) for p in history.iterdir() if p.is_file()} if history.exists() else set()
        unresolved = ({p.relative_to(pending) for p in pending.iterdir() if p.is_file()}
            if pending.exists() else set())
        new = sorted(((set(after) - before) | replaced | unresolved) & set(after),
            key=lambda path: (after[path].stat().st_mtime_ns, path.as_posix()))
        if new:
            pending.mkdir(exist_ok=True)
            for relative in new:
                (pending / relative).touch(exist_ok=True)
        items = []
        handoff = root / 'acquired' / str(uuid4())
        handoff.mkdir(parents=True, exist_ok=False)
        for relative in new:
            path = after[relative]
            stat = path.stat()
            source_fact = inventory.get(relative.name)
            if source_fact is None or source_fact[0] != stat.st_size:
                return CollectionOutcome('failed', error='new core is absent or differs from rsync inventory',
                    artifacts=tuple(item['path'] for item in items),
                    items=tuple(items), operations=tuple(operations), inventory_status='failed')
            stable = handoff / relative.name
            try:
                stable.hardlink_to(path)
            except OSError as exc:
                return CollectionOutcome('failed', error='stable acquired core link failed: ' + str(exc),
                    artifacts=tuple(item['path'] for item in items),
                    items=tuple(items), operations=tuple(operations), inventory_status='failed')
            items.append(dict(name=relative.name, size=stat.st_size,
                remote_modified=source_fact[1], rsync_change=source_fact[2], discovered_at=discovered_at,
                remote_path=remote_dir.rstrip('/') + '/' + relative.name,
                path=str(stable), cache_path=str(path), status='cached', selected=False,
                write_completion='unverified', association='unpaired_new_core'))
            (pending / relative).unlink()
        if items:
            items[-1].update(selected=True, association='provisional_newest_for_detected_crash')
            for item in items[:-1]:
                item['association'] = 'unpaired_new_core'
        for name in sorted(skipped):
            items.append(dict(name=name, size=None, remote_modified=None,
                discovered_at=discovered_at, remote_path=remote_dir.rstrip('/') + '/' + name,
                status='skipped', reason='size_limit', selected=False))
        if cleanup:
            for name, (size, modified, change) in sorted(inventory.items()):
                if name in {item['name'] for item in items}:
                    continue
                items.append(dict(name=name, size=size, remote_modified=modified,
                    rsync_change=change, discovered_at=discovered_at,
                    remote_path=remote_dir.rstrip('/') + '/' + name,
                    status='unchanged', selected=False))
            for item in items:
                try:
                    deletion = self._ssh('rm -f -- ' + shlex.quote(item['remote_path']), 20,
                        operations=operations)
                    item['cleanup'] = {'status': 'succeeded' if deletion.returncode == 0 else 'failed',
                        'error': deletion.stderr or ''}
                except Exception as exc:
                    item['cleanup'] = {'status': 'failed', 'error': str(exc)}
        self.last_items = tuple(items)
        failed = bool(skipped) or any(i.get('cleanup', {}).get('status') == 'failed' for i in items)
        return CollectionOutcome('failed' if failed else 'succeeded',
            tuple(item['path'] for item in items if item.get('status') == 'cached'),
            ('selected size cap skipped remote cores' if skipped else
             'selected remote cleanup failed' if failed else ''), tuple(items), tuple(operations),
            'skipped' if skipped else 'available' if new else 'no_new' if inventory else 'empty')

    def __call__(self, action, *, context=None):
        from bytefault.core.contracts import freeze
        from dataclasses import replace
        context = freeze(context) if context is not None else {}
        target = (context or {}).get('transport', {})
        host = target.get('host', self.host)
        if host != self.host:
            return Collection(host, ssh_key=self.ssh_key, ssh_user=self.ssh_user, ssh_pass=self.ssh_pass,
                cache_dir=self.core_cache_dir, remote_dir=self.remote_dir,
                max_file_size_mb=self.max_file_size_mb, min_timeout=self.min_timeout,
                core_write_wait=self.core_write_wait, process=self.process, sleep=self.sleep,
                record_operation=self.record_operation, pacer=self.pacer,
                connection_delay=self.connection_delay, cancelled=self.cancelled,
                pacer_for_run=self.pacer_for_run)(action, context=context)
        if self.pacer_for_run is not None and context is not None:
            correlation = (context or {}).get('decision')
            correlation = getattr(correlation, 'correlation', None)
            run_id = getattr(correlation, 'run_id', None)
            if run_id is None:
                run_id = getattr(getattr(action, 'correlation', None), 'run_id', None)
            transport = (context or {}).get('transport', {})
            delay = transport.get('connection_delay', 0.0)
            if run_id is not None and delay:
                selected = Collection(self.host, ssh_key=self.ssh_key, ssh_user=self.ssh_user, ssh_pass=self.ssh_pass,
                    cache_dir=self.core_cache_dir, remote_dir=self.remote_dir,
                    max_file_size_mb=self.max_file_size_mb, min_timeout=self.min_timeout,
                    core_write_wait=self.core_write_wait, process=self.process, sleep=self.sleep,
                    record_operation=self.record_operation, pacer=self.pacer_for_run(run_id),
                    connection_delay=delay, cancelled=self.cancelled)
                return selected(action, context=context)
        inventory = (context or {}).get('source_inventory') or {}
        if inventory.get('paths'):
            from bytefault.core.input_files import selected_scope_aliases
            from bytefault.management import CollectionOutcome
            try:
                root = self._endpoint_root()
                if selected_scope_aliases((root / 'current', root / 'pending'), inventory['paths']):
                    return CollectionOutcome('failed',
                        error='collection cache includes a current input', inventory_status='failed')
            except OSError as error:
                return CollectionOutcome('failed', error=str(error), inventory_status='failed')
        wait = {'operation': 'core_write_wait', 'seconds': self.core_write_wait,
                'host': self.host, 'started_at': datetime.now(timezone.utc).isoformat()}
        try:
            if self.core_write_wait:
                self.sleep(self.core_write_wait)
            wait['status'] = 'completed'
        except Exception as exc:
            from bytefault.management import CollectionOutcome
            wait.update(status='failed', error=str(exc), error_type=type(exc).__name__,
                        completed_at=datetime.now(timezone.utc).isoformat())
            return CollectionOutcome('failed', error=str(exc), operations=(wait,))
        wait['completed_at'] = datetime.now(timezone.utc).isoformat()
        outcome = self.acquire(cleanup=action.parameters.get('cleanup', False))
        return replace(outcome, operations=(wait, *outcome.operations))

    def retrieve_coredumps(self, remote_dir='/root/cores', local_dir=None, cleanup_threshold=20,
                          max_file_size_mb=0, min_timeout=30):
        # Retained callable settings; count thresholds never imply remote deletion.
        return list(self.acquire(remote_dir=remote_dir, local_dir=local_dir,
            max_file_size_mb=max_file_size_mb, min_timeout=min_timeout).artifacts)
