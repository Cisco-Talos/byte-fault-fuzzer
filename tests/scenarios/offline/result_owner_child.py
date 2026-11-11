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

"""Registered filesystem ownership child; denial precedes product imports."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

def deny(*args, **kwargs):
    raise AssertionError('owner child forbids networking and subprocesses')
def audit(event,args):
    if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn',
            'os.exec','os.spawn','os.fork','os.forkpty','os.startfile','os.startfile/2'):
        deny()
sys.addaudithook(audit)
for name in ('create_connection','create_server','socketpair','fromfd','getaddrinfo',
        'gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo','getfqdn'):
    if hasattr(socket,name): setattr(socket,name,deny)
for name in ('Popen','run','call','check_call','check_output'): setattr(subprocess,name,deny)
for name in ('system','popen','startfile','spawnl','spawnle','spawnlp','spawnlpe',
        'spawnv','spawnve','spawnvp','spawnvpe'):
    if hasattr(os,name): setattr(os,name,deny)
import _socket
for operation in (lambda:_socket.socket(),lambda:socket.getaddrinfo('localhost',1),
        lambda:subprocess.Popen(['ssh','localhost'])):
    try: operation()
    except AssertionError: pass
    else: raise AssertionError('owner child denial escaped')

work, mode, result_root = Path(sys.argv[1]).resolve(),sys.argv[2],Path(sys.argv[3]).resolve()
assert Path.cwd().resolve() == work and result_root.is_relative_to(work.parent)
assert sys.flags.isolated and sys.dont_write_bytecode and mode in ('attempt','hold','abrupt')
checkout = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(checkout/'src'))
from bytefault.application import Application
from bytefault.core.contracts import TransportRequest, MonitoringAction, Correlation
from bytefault.management.configuration import ServiceConfiguration
from bytefault.reporting import ReportRequest, WriterAttachedError

app = Application(transport_factory=deny,
    service_configuration=ServiceConfiguration(result_root=str(result_root),heartbeat=False))
facts = {'mode':mode,'admitted':False}
def origins():
    paths = {name:module.__file__ for name,module in tuple(sys.modules.items())
        if (name == 'bytefault' or name.startswith('bytefault.')) and getattr(module,'__file__',None)}
    expected = checkout/'src'
    assert paths and all(Path(path).resolve().is_relative_to(expected) for path in paths.values())
    return paths

def report(number):
    selected = MonitoringAction(mode+'-action-'+str(number),mode+'-event',mode+'-observation',
        Correlation(mode+'-run','independent',mode+'-session','result_owner','1'),'followup',{'report':True})
    outcome = app.service('reporting',ReportRequest(mode+'-report-'+str(number),selected,'disabled',
        context={'independent':True,'exact':b'\0\xff'}))
    assert outcome.status == 'succeeded',outcome
    return outcome.report_id
try:
    try:
        with app.independent_operation(TransportRequest('offline.invalid',1234,1), services=True,
                log_path=str(work/'actions.bfr')):
            facts['admitted'] = True
            assert not app._runs and not app._heartbeats
            if mode != 'attempt':
                facts['first_report'] = report(0)
                facts['origins'] = origins()
                facts['runtime'] = {'prefix':sys.prefix,
                    'isolated':bool(sys.flags.isolated),'cwd':str(Path.cwd().resolve())}
                (work/'ready').write_text(json.dumps(facts),encoding='utf-8')
                deadline = time.monotonic()+15
                while not (work/'release').exists():
                    assert time.monotonic() < deadline,'owner child release timeout'
                    time.sleep(.01)
                facts['last_report'] = report(1)
    except WriterAttachedError as error:
        facts.update(error_type=type(error).__name__,error=str(error))
finally:
    facts['close'] = {'outcome':app.close()['outcome']}
    if app.management is not None:
        app.management._worker.join(3)
        facts['worker_alive'] = app.management._worker.is_alive()
    facts['closed'] = app.reporting is None or app.reporting.root.closed
    facts['origins'] = origins()
    (work/'observed.json').write_text(json.dumps(facts,indent=2),encoding='utf-8')
    print(json.dumps(facts))
