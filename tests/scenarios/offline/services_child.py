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

"""Narrow service child CLI fixture: deny before product imports, exact controlled ports."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import threading
from types import SimpleNamespace

def deny(*args, **kwargs):
    raise AssertionError('Service child forbids real networking and unguarded subprocesses')

def audit(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.posix_spawn',
            'os.exec', 'os.spawn', 'os.fork', 'os.forkpty', 'os.startfile', 'os.startfile/2'):
        deny()

sys.addaudithook(audit)
for name in ('create_connection', 'create_server', 'socketpair', 'fromfd', 'getaddrinfo',
             'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo', 'getfqdn'):
    if hasattr(socket, name):
        setattr(socket, name, deny)
for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
    setattr(subprocess, name, deny)
for name in ('system', 'popen', 'startfile', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
             'spawnv', 'spawnve', 'spawnvp', 'spawnvpe'):
    if hasattr(os, name):
        setattr(os, name, deny)
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))

from bytefault.application import Application
from bytefault.core.records import decode_value, encode_value
from bytefault.fuzzers.transport import EngineTransport, SendFailure
from bytefault.fuzzers import cli
import bytefault.management.collection as collection

root, mode = Path(sys.argv[1]), sys.argv[2]
first_pending_close = threading.Event()

def process(command, **options):
    assert command[0] == 'rsync'
    assert first_pending_close.wait(8)
    (Path(command[-1]) / 'core').write_bytes(b'C')
    return SimpleNamespace(returncode=0,
        stdout='BF|>f+++++++++|1|2026/10/22-15:00:57|core\nNumber of files: 2 (reg: 1, dir: 1)',
        stderr='')
collection.subprocess.run = process

traces = []
class Stream:
    def __init__(self, trace):
        self.trace = trace
    def settimeout(self, value):
        pass
    def connect(self, target):
        pass
    def send(self, data):
        self.trace.append(('offer', bytes(data)))
        if mode == 'replay_root_partial':
            if data == b'BB':
                return 1
            if data == b'B':
                raise SendFailure('controlled item 2 send failure', accepted_count=0)
        return len(data)
    def close(self):
        pass

def transport(request):
    trace = []; stream = Stream(trace)
    traces.append((trace, stream))
    return EngineTransport(request, socket_factory=lambda *args: stream, sleep=lambda value: None)

class OwnedApplication(Application):
    def close(self):
        result = super().close()
        if result['services'] and result['services']['pending']:
            first_pending_close.set()
        return result
    def _attach_services(self, request):
        super()._attach_services(request)
        if mode == 'report_failure':
            def failure(*args):
                raise OSError('controlled late report output failure')
            self.reporting.layout._render = failure

configuration = {'health_check_mode': 'disabled', 'rules': [
    {'rule_id': 'unrequested', 'kind': 'unrequested', 'actions': [{'collect': True, 'report': True}]}]}
if mode == 'replay_root_partial':
    configuration.update(retry_rules=[], retries=0)
if mode.startswith('replay_'):
    from bytefault.monitoring import Monitoring
    from bytefault.monitoring.configuration import configuration_from_data
    app = OwnedApplication(transport_factory=transport,
        monitoring=Monitoring(configuration=configuration_from_data(configuration)))
else:
    app = OwnedApplication(transport_factory=transport)
common = ['--port', '1234', '--no-ui', '--records', str(root / 'run.bfr'),
    '--results', str(root / 'results'), '--ssh-key', 'controlled-key', '--core-dump-wait', '0']
if mode.startswith('replay_'):
    import runpy
    if mode != 'replay_root_partial':
        # Execute the documented source-script entry with no repository src
        # path first: the script owns its current source launch bootstrap.
        import contextlib
        import io
        script = Path(__file__).resolve().parents[3] / 'src' / 'bytefault' / 'replay' / 'replay_packet.py'
        src = str(script.parents[2])
        sys.path[:] = [path for path in sys.path if path != src]
        sys.argv = [str(script), '--help']
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                runpy.run_path(str(script), run_name='__main__')
            except SystemExit as exit:
                assert exit.code == 0
        assert src in sys.path
        sys.modules.pop('bytefault.replay.replay_packet', None)
        packet_file = root / 'packets.txt'
        packet_file.write_text('# comment\n42\n\ninvalid\n43\n', encoding='utf-8')
        arguments = ['controlled', '41', '@' + str(packet_file), '44', '--no-recv', *common]
        sys.argv = [str(script), *arguments]
        if mode == 'replay_module':
            entry = lambda: runpy.run_module('bytefault.replay.replay_packet', run_name='__main__')
        elif mode == 'replay_script':
            sys.path[:] = [path for path in sys.path if path != src]
            entry = lambda: runpy.run_path(str(script), run_name='__main__')
        else:
            script = Path(__file__).resolve().parents[3] / 'bytefault.py'
            sys.argv = [str(script), 'replay', 'raw', *arguments]
            entry = lambda: runpy.run_path(str(script), run_name='__main__')
    else:
        script = Path(__file__).resolve().parents[3] / 'bytefault.py'
        sys.argv = [str(script), 'replay', 'raw', 'controlled', '41', '4242', '43', '--no-recv', *common]
        entry = lambda: runpy.run_path(str(script), run_name='__main__')
    try:
        cli.Application = lambda: app
        entry()
    except SystemExit as exit:
        code = exit.code
else:
    cli.Application = lambda: app
    code = cli.main(['controlled', '--port', '1234', '--seed-hex', '00ff', '--no-ui',
    '--records', str(root / 'run.bfr'), '--results', str(root / 'results'),
    '--ssh-key', 'controlled-key', '--core-dump-wait', '0',
    '--monitoring-json', json.dumps(encode_value(configuration))])
marker = {'code': code, 'store_closed': app.management.store.closed,
    'root_closed': app.reporting.root.closed, 'pending': len(app.management.status()['pending']),
    'pending_close_observed': first_pending_close.is_set(),
    'ui_imported': any(name.startswith('bytefault.ui') for name in sys.modules),
    'offered': [entry[1].hex() for trace, stream in traces for entry in trace if entry[0] == 'offer']}
(root / 'exit.json').write_text(json.dumps(marker))
raise SystemExit(code)
