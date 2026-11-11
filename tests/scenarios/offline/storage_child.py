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

"""Exact local F07 child: deny networking before product import, then wait to die."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True

def deny(*args, **kwargs):
    raise AssertionError('Offline child forbids real networking and subprocesses')

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

root, point = Path(sys.argv[1]).resolve(), sys.argv[2]
assert Path.cwd().resolve() == root
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))

# Prove the inherited child guard itself before loading the product.
import _socket
for operation in (lambda: _socket.socket(), lambda: socket.getaddrinfo('localhost', 1),
                  lambda: subprocess.Popen(['ssh', 'localhost'])):
    try:
        operation()
    except AssertionError:
        pass
    else:
        raise AssertionError('child networking guard escaped')

from bytefault.core.storage import LocalRecordStore, frame_record
from bytefault.core.records import Record
from bytefault.core.contracts import TransportRequest, ReceiveRequest
from bytefault.fuzzers.transport import EngineTransport
from bytefault.fuzzers.fuzzer import ProtocolFuzzer
from bytefault.fuzzers.inputs import raw_request

def ready():
    (root / 'ready').write_text(point, encoding='utf-8')
    while True:
        time.sleep(0.02)

store = LocalRecordStore(root / 'required.bfr')
store.append('previous_acknowledged', {'run_id': 'prior'}, {'bytes': b'\x00\xff\x80'})

class Stream:
    def settimeout(self, value):
        pass
    def connect(self, target):
        pass
    def send(self, value):
        (root / 'offered').write_bytes(value)
        return len(value)
    def close(self):
        pass

stream = Stream()
adapter = EngineTransport(TransportRequest('offline.invalid', 1, 10),
    socket_factory=lambda *args: stream, sleep=lambda value: None)
engine = ProtocolFuzzer('offline.invalid', transport=adapter, record_store=store)
original_append = store.append

def append(kind, identity, data):
    if kind == 'action_result' and point in ('offer', 'partial_tail'):
        if point == 'partial_tail':
            frame = frame_record(Record('interrupted-record', kind, identity, data))
            assert store._stream.write(frame[:len(frame) // 2]) == len(frame) // 2
            store._stream.flush()
            os.fsync(store._stream.fileno())
        ready()
    return original_append(kind, identity, data)

store.append = append

def acknowledged(kind, identity, data, ref):
    if (point, kind) in (('ack_start', 'case_start'),
                         ('ack_materialization', 'materialization'),
                         ('ack_result', 'action_result')):
        ready()

engine.add_required_sink(acknowledged)
engine.execute_conversation(raw_request(b'\x00\xff\x80', receive=ReceiveRequest(requested=False),
    original_request={'password': 'marker-X', '$bytes': {'$type': 'literal-key'}}))
raise AssertionError('expected termination boundary was not reached')
