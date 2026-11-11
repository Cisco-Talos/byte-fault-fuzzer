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

"""Narrow Windows ConPTY qualification driver for one exact guarded child."""
import ctypes as C
from ctypes import wintypes as W
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
REPO = Path(__file__).resolve().parents[3]
MODE = sys.argv[1]
RUN = sys.argv[2]
assert MODE in ('surface','hide','no_banner','plain','fallback','natural','throw','block','sink_block','interrupt',
                'generated','formatter','stage_only','resume_rich','resume_plain')
assert RUN.replace('-','').isalnum()
assert sys.version_info >= (3, 13), 'Windows ConPTY qualification requires Python 3.13 or newer'
if MODE not in ('plain', 'fallback', 'resume_plain') and importlib.util.find_spec('rich') is None:
    raise RuntimeError(f'{MODE} requires the optional Rich package')
PYTHON = Path(sys.executable)
CHILD = ROOT / 'terminal_child.py'
OUT = REPO / 'artifacts' / 'windows-terminal' / RUN / MODE
OUT.mkdir(parents=True,exist_ok=False)
ready_file = OUT / 'trace.jsonl'

K = C.WinDLL('kernel32', use_last_error=True)
SIZE = C.c_size_t
HANDLE = W.HANDLE
class COORD(C.Structure):
    _fields_ = [('X', C.c_short), ('Y', C.c_short)]
class STARTUPINFO(C.Structure):
    _fields_ = [('cb', W.DWORD), ('lpReserved', W.LPWSTR), ('lpDesktop', W.LPWSTR),
        ('lpTitle', W.LPWSTR), ('dwX', W.DWORD), ('dwY', W.DWORD),
        ('dwXSize', W.DWORD), ('dwYSize', W.DWORD), ('dwXCountChars', W.DWORD),
        ('dwYCountChars', W.DWORD), ('dwFillAttribute', W.DWORD),
        ('dwFlags', W.DWORD), ('wShowWindow', W.WORD), ('cbReserved2', W.WORD),
        ('lpReserved2', C.POINTER(C.c_byte)), ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE), ('hStdError', HANDLE)]
class STARTUPINFOEX(C.Structure):
    _fields_ = [('StartupInfo', STARTUPINFO), ('lpAttributeList', C.c_void_p)]
class PROCESSINFO(C.Structure):
    _fields_ = [('hProcess', HANDLE), ('hThread', HANDLE),
                ('dwProcessId', W.DWORD), ('dwThreadId', W.DWORD)]

def api(name, args, result=W.BOOL):
    fn = getattr(K, name)
    fn.argtypes, fn.restype = args, result
    return fn

CreatePipe = api('CreatePipe', [C.POINTER(HANDLE), C.POINTER(HANDLE), C.c_void_p, W.DWORD])
CreatePC = api('CreatePseudoConsole', [COORD, HANDLE, HANDLE, W.DWORD, C.POINTER(HANDLE)], C.c_long)
ResizePC = api('ResizePseudoConsole', [HANDLE, COORD], C.c_long)
ClosePC = api('ClosePseudoConsole', [HANDLE], None)
Close = api('CloseHandle', [HANDLE])
InitAttr = api('InitializeProcThreadAttributeList', [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(SIZE)])
UpdateAttr = api('UpdateProcThreadAttribute', [C.c_void_p, W.DWORD, SIZE, C.c_void_p, SIZE, C.c_void_p, C.c_void_p])
DeleteAttr = api('DeleteProcThreadAttributeList', [C.c_void_p], None)
CreateProcess = api('CreateProcessW', [W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p,
    W.BOOL, W.DWORD, C.c_void_p, W.LPCWSTR, C.POINTER(STARTUPINFOEX), C.POINTER(PROCESSINFO)])
Read = api('ReadFile', [HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p])
Write = api('WriteFile', [HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p])
Wait = api('WaitForSingleObject', [HANDLE, W.DWORD], W.DWORD)
ExitCode = api('GetExitCodeProcess', [HANDLE, C.POINTER(W.DWORD)])
Terminate = api('TerminateProcess', [HANDLE, W.UINT])

def checked(value):
    if not value:
        raise C.WinError(C.get_last_error())
    return value

trace = []
def note(kind, **data):
    trace.append(dict(kind=kind, at=time.monotonic(), **data))
    (OUT / 'driver.json').write_text(json.dumps(trace, indent=2), encoding='utf-8')

stdin_read, stdin_write, stdout_read, stdout_write, hpc = [HANDLE() for _ in range(5)]
checked(CreatePipe(C.byref(stdin_read), C.byref(stdin_write), None, 0))
checked(CreatePipe(C.byref(stdout_read), C.byref(stdout_write), None, 0))
hr = CreatePC(COORD(120, 35), stdin_read, stdout_write, 0, C.byref(hpc))
if hr:
    raise OSError(f'CreatePseudoConsole HRESULT={hr:#x}')
Close(stdin_read)
Close(stdout_write)
note('conpty_created', columns=120, rows=35)

chunks = []
def receive():
    buf = C.create_string_buffer(8192)
    count = W.DWORD()
    while Read(stdout_read, buf, len(buf), C.byref(count), None):
        chunks.append(buf.raw[:count.value])
        (OUT / 'terminal.ansi').write_bytes(b''.join(chunks))

reader = threading.Thread(target=receive, daemon=True)
reader.start()
size = SIZE()
InitAttr(None, 1, 0, C.byref(size))
attrs = C.create_string_buffer(size.value)
checked(InitAttr(attrs, 1, 0, C.byref(size)))
checked(UpdateAttr(attrs, 0, 0x20016, hpc, C.sizeof(HANDLE), None, None))
startup = STARTUPINFOEX()
startup.StartupInfo.cb = C.sizeof(startup)
startup.lpAttributeList = C.cast(attrs, C.c_void_p)
process = PROCESSINFO()
command = (str(PYTHON), '-B', str(CHILD), str(OUT), MODE)
assert command[2:] == (str(CHILD), str(OUT), MODE)
note('exact_child_launch', executable=str(PYTHON), command=command, cwd=str(ROOT))
try:
    checked(CreateProcess(str(PYTHON), C.create_unicode_buffer(subprocess.list2cmdline(command)),
        None, None, False, 0x80000, None, str(ROOT), C.byref(startup), C.byref(process)))
    Close(process.hThread)
    deadline = time.monotonic() + 8
    while not ready_file.exists() and time.monotonic() < deadline:
        time.sleep(.05)
    if not ready_file.exists():
        raise RuntimeError('child ready evidence unavailable')
    if MODE in ('surface','throw','block','sink_block','interrupt'):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            entries=[json.loads(line) for line in ready_file.read_text(encoding='utf-8').splitlines()]
            if any(r['kind'] in ('frame','render_block_entered','sink_block_entered','renderer_throw_entered') for r in entries):
                break
            time.sleep(.05)
        else:
            raise RuntimeError('actual display start unavailable')
    log_positions={}
    def send(label,data,pause=.3):
        previous=[json.loads(line) for line in ready_file.read_text(encoding='utf-8').splitlines()]
        before=next((r for r in reversed(previous) if r['kind']=='frame'),{})
        expected_verbosity=(0 if label=='verbosity_reset' else
            max(0,before.get('verbosity',0)-1) if label=='verbosity_down' else
            min(4,before.get('verbosity',0)+1))
        count = W.DWORD()
        checked(Write(stdin_write, data, len(data), C.byref(count), None))
        note('input', label=label, hex=data.hex(), written=count.value)
        time.sleep(pause)
        if MODE=='surface' and label not in ('pause','resume','quit'):
            deadline=time.monotonic()+12
            while time.monotonic()<deadline:
                observed=[json.loads(line) for line in ready_file.read_text(encoding='utf-8').splitlines()]
                frames=[r for r in observed if r['kind']=='frame' and r['at']>trace[-1]['at']]
                if frames:
                    latest=frames[-1]
                    expected_screen={'F2':'dashboard','F3':'crashes','F4':'log'}.get(label)
                    okay=(expected_screen is None or latest['screen']==expected_screen)
                    if label.startswith('verbosity'): okay=okay and latest['verbosity']==expected_verbosity
                    if label=='theme': okay=okay and latest['theme']!=before.get('theme')
                    if label.endswith('help') or label=='help': okay=okay and latest['help']
                    if label=='escape': okay=okay and not latest['help']
                    if label=='home': okay=okay and latest['scroll']==0
                    if label=='end': okay=okay and latest['scroll']==-1
                    if label=='search': okay=okay and latest['search']=='marker-row' and latest['match_count']>1
                    if label=='detail': okay=okay and latest['detail'] and 'DETAIL ' in latest['text'] and 'marker-row' in latest['text']
                    if label=='detail_back': okay=okay and not latest['detail'] and ' LOG' in latest['text']
                    if label=='next': okay=okay and latest['match_index']==1
                    if label=='previous': okay=okay and latest['match_index']==0
                    numbered=re.findall(r'^\s*(\d+)\s+[^\n]*',latest['text'],re.M) if latest['screen']=='log' else []
                    top=int(numbered[0]) if numbered else None
                    if label=='home': okay=okay and top==1 and 'LINE 1-' in latest['text']
                    if label=='down': okay=okay and top==2
                    if label=='page_down': okay=okay and top==32
                    if label=='up': okay=okay and top==31
                    if label=='page_up': okay=okay and top==1
                    if label=='end': okay=okay and top is not None and top>100 and 'FOLLOW' in latest['text']
                    if label=='search':
                        okay=okay and bool(re.search(r'^\s*\d+\s+[^\n]*marker-row',latest['text'],re.M))
                    geometry=tuple(latest['geometry'])
                    if label=='next': okay=okay and top!=log_positions.get((geometry,'search'))
                    if label=='previous': okay=okay and top==log_positions.get((geometry,'search'))
                    if okay:
                        log_positions[(geometry,label)]=top
                        note('observed_viewport',label=label,frame_at=latest['at'],geometry=latest['geometry'],
                            top=top,scroll=latest['scroll'],match_index=latest['match_index'],
                            verbosity=latest['verbosity'],theme=latest['theme'])
                        break
                time.sleep(.05)
            else:
                raise RuntimeError('actual viewport did not follow input '+label)
    def resize(columns,rows):
        hr=ResizePC(hpc,COORD(columns,rows))
        if hr: raise OSError(f'ResizePseudoConsole HRESULT={hr:#x}')
        note('resize',columns=columns,rows=rows); time.sleep(.4)
    time.sleep(.7)
    if MODE.startswith('resume_'):
        frame_kind='frame' if MODE=='resume_rich' else 'resume_plain_frame'
        def observe(phase,words,geometry=None,reports=None):
            deadline=time.monotonic()+12
            while time.monotonic()<deadline:
                entries=[json.loads(line) for line in ready_file.read_text(encoding='utf-8').splitlines()]
                frames=[r for r in entries if r['kind']==frame_kind and r.get('phase')==phase]
                if frames:
                    frame=frames[-1]
                    if (all(word in frame['text'] for word in words) and
                            (geometry is None or frame['geometry']==list(geometry)) and
                            (reports is None or frame.get('reports',0)>=reports)):
                        assert frame['attributes']
                        note('observed_resume',phase=phase,geometry=frame['geometry'],frame_at=frame['at'],words=words)
                        return frame
                time.sleep(.05)
            raise RuntimeError('actual resume viewport missing '+repr((phase,words,geometry)))
        held_words=(['RESUME inherited','NEW tests=0 attempts=0','WAIT collection one=succeeded','deadline=known','CHOICE rerun acknowledged']
            if MODE=='resume_rich' else ['RESUME inherited','NEW tests=0 attempts=0','WAIT collection action=one succeeded','deadline=known','CHOICE'])
        observe('hold',held_words,(120,35))
        if MODE=='resume_rich':
            send('F3',b'\x1bOR',.2)
            observe('hold',['ORIGINAL original-run attempt=','NEW execution=','deadline=known','CHOICE rerun acknowledged'],(120,35))
            send('F2',b'\x1bOQ',.2)
            resize(72,22)
            observe('hold',['RESUME inherited','NEW tests=0 attempts=0','WAIT collection one=succeeded','pending'],(72,22))
            resize(120,35)
        send('pause',b' ',.2); send('resume',b' ',.2)
        (OUT/'complete-gate').write_text('external eligible completions',encoding='ascii')
        observe('late',['RESUME inherited completed=1','NEW tests=0 attempts=0'],(120,35))
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            entries=[json.loads(line) for line in ready_file.read_text(encoding='utf-8').splitlines()]
            completed=[r for r in entries if r['kind']=='late_primary_complete']
            if completed: break
            time.sleep(.05)
        assert completed and completed[-1]['outcome']=='completed' and not completed[-1]['active']
        if MODE=='resume_plain':
            send('ignored_log_screen',b'\x1bOS',.05)
            send('ignored_log_search',b'/',.05)
        send('quit',b'q',.2)
        observe('reattached',['RESUME inherited completed=1','NEW tests=0 attempts=0'],(120,35))
        (OUT/'release-collection').write_text('external collection release',encoding='ascii')
        observe('reattached',['RESUME inherited completed=1'],reports=1)
        if MODE=='resume_rich':
            send('F3',b'\x1bOR',.2)
            # Existing report column ellipsizes long destinations. Exact full
            # path and original correlation are checked against owner records.
            observe('reattached',['late-original','succeeded',str(REPO)[:20]],reports=1)
            resize(72,22)
            observe('reattached',['late-original','succeeded',str(REPO)[:20]],geometry=(72,22),reports=1)
        else:
            observe('reattached',['REPORT.md'],reports=1)
        (OUT/'finish-view').write_text('actual late viewport observed',encoding='ascii')
    elif MODE=='surface':
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            observed=[json.loads(line) for line in ready_file.read_text(encoding='utf-8').splitlines()]
            frames=[r for r in observed if r['kind']=='frame']
            if frames and {'response_anomaly','service_unavailable'}<=set(frames[-1]['classifications']) and frames[-1]['reports']>=2:
                break
            time.sleep(.05)
        else:
            raise RuntimeError('actual classified result/report readiness unavailable')
        send('pause',b' ',.45)
        for dimensions in ((120,35),(72,22)):
            resize(*dimensions)
            for label,data in (('F2',b'\x1bOQ'),('verbosity_reset',b'VVVV'),('verbosity1',b'v'),('verbosity2',b'v'),
                ('verbosity3',b'v'),('verbosity4',b'v'),('verbosity_down',b'V'),('theme',b't'),
                ('help',b'?'),('escape',b'\x1b'),('F3',b'\x1bOR'),('help',b'?'),('escape',b'\x1b'),
                ('F4',b'\x1bOS'),('home',b'\x1b[H'),('down',b'\x1b[B'),('page_down',b'\x1b[6~'),
                ('up',b'\x1b[A'),('page_up',b'\x1b[5~'),('end',b'\x1b[F'),
                ('search',b'/marker-row\r'),('detail',b'd'),('detail_back',b'd'),
                ('next',b'n'),('previous',b'p'),
                ('cancel_search',b'/unused\x1b'),('log_help',b'?'),('escape',b'\x1b'),
                ('cycle_next',b'>'),('cycle_previous',b'<')):
                send(label,data,.2)
        send('resume',b' ',1)
        send('quit',b'q',.2)
    elif MODE in ('throw','block','sink_block'):
        time.sleep(.8)  # actual stalled-render detection must precede later keys
        send('pause_after_degradation',b' ',.4)
        send('resume_after_degradation',b' ',.4)
        send('quit_after_degradation',b'q',.2)
    elif MODE=='interrupt':
        send('interrupt',b'\x03',.2)
    if Wait(process.hProcess, 6000) != 0:
        Terminate(process.hProcess, 3)
        raise RuntimeError('terminal fixture timeout')
    code = W.DWORD()
    checked(ExitCode(process.hProcess, C.byref(code)))
    note('child_exit', code=code.value)
finally:
    if process.hProcess:
        if Wait(process.hProcess, 0) != 0:
            Terminate(process.hProcess, 3)
            Wait(process.hProcess, 2000)
        Close(process.hProcess)
    DeleteAttr(attrs)
    Close(stdin_write)
    ClosePC(hpc)
    reader.join(2)
    Close(stdout_read)
    note('closed', reader_alive=reader.is_alive(), output_bytes=sum(map(len, chunks)))

child=[json.loads(line) for line in ready_file.read_text(encoding='utf-8').splitlines()]
ready=next(r for r in child if r['kind']=='ready')
assert ready['isatty'] == [True, True]
assert len(ready['guard']) == 2
assert ready['executable'] == str(PYTHON)
if MODE not in ('plain', 'fallback', 'resume_plain'):
    assert ready['rich'], 'Rich mode did not record its installed Rich version'
output = b''.join(chunks)
if MODE not in ('plain','fallback','resume_plain'):
    assert b'\x1b[?1049h' in output and b'\x1b[?1049l' in output
assert b'CONPTY NORMAL SCREEN RESTORED' in output and not reader.is_alive()
cleanup=next(r for r in child if r['kind']=='cleanup')
assert not cleanup['key_reader_threads'] and not cleanup['terminal_threads']
assert cleanup['root_closed'] and cleanup['management_closed']
if MODE.startswith('resume_'):
    assert any(r['kind']=='exact_gate_completed' for r in child)
    assert any(r['kind']=='callable_detached' and r['owners_open'] and r['pending'] for r in child)
    assert any(r['kind']=='late_identity' and r['empty_resume_offers']==0 and r['original']['run_id']=='late-original' for r in child)
    assert [r['command'] for r in child if r['kind']=='control' and r.get('run_id')!='original-run']==['pause','resume','stop']
    note('PASS',mode=MODE,guard_before_product=True,actual_terminal=True,output_bytes=len(output),
        frames=sum(r['kind'] in ('frame','resume_plain_frame') for r in child))
    raise SystemExit(0)
if MODE=='surface':
    frames=[r for r in child if r['kind']=='frame']
    assert {tuple(r['geometry']) for r in frames} >= {(120,35),(72,22)}
    for geometry in ((120,35),(72,22)):
        selected=[r for r in frames if tuple(r['geometry'])==geometry and tuple(r['render_geometry'])==geometry]
        assert {r['screen'] for r in selected}=={'dashboard','crashes','log'}
        assert any(r['help'] for r in selected)
        assert any(r['search']=='marker-row' and r['matches'] for r in selected)
        assert any('BYTEFAULT HELP' in r['text'] and 'Cancel search' in r['text'] for r in selected if r['help'])
        assert any('LINE ' in r['text'] and '/marker-row' in r['text'] for r in selected if r['search']=='marker-row' and not r['help'])
        assert any('Home' in r['text'] for r in selected if r['help'])
        assert any('00000000' in r['text'] and 'Offered' in r['text'] for r in selected if r['verbosity']>=2 and r['screen']=='dashboard' and not r['help'])
        observations=[r for r in trace if r['kind']=='observed_viewport' and tuple(r['geometry'])==geometry]
        observed={r['label']:r for r in observations}
        assert observed['home']['top']==1 and observed['down']['top']==2
        assert observed['page_down']['top']==32 and observed['up']['top']==31 and observed['page_up']['top']==1
        assert observed['end']['top']>100 and observed['next']['top']!=observed['search']['top']
        assert observed['previous']['top']==observed['search']['top']
    assert {r['verbosity'] for r in frames} >= {0,1,2,3,4}
    commands=[r['command'] for r in child if r['kind']=='control']
    assert commands.count('pause')>=1 and commands.count('resume')>=1 and 'stop' in commands
    healthy=[]; failed=[]; unknown=[]
    for frame in frames:
        for row,line in enumerate(frame['text'].splitlines()):
            match=re.search('[▱▰]{3}',line)
            if match:
                begin=row*frame['geometry'][0]+match.start()
                observed=(match.group(),tuple(frame['attributes'][begin:begin+3]))
                if frame['heartbeat'] is True: healthy.append(observed)
                if frame['heartbeat'] is False: failed.append(observed)
                if frame['heartbeat'] is None: unknown.append(observed)
    assert len(set(healthy))>=2 and failed and unknown
    assert {styles for _,styles in healthy}!={styles for _,styles in failed}
    assert not {styles for _,styles in unknown}&({styles for _,styles in healthy}|{styles for _,styles in failed})
    note('stable_resize_and_heartbeat',transition_frames=sum(r['geometry']!=r['render_geometry'] for r in frames),
        healthy_animation_variants=len(set(healthy)),failed_variants=len(set(failed)),unknown_variants=len(set(unknown)))
if MODE in ('throw','block','sink_block'):
    assert [r['command'] for r in child if r['kind']=='control']==['pause','resume','stop']
    assert b'DISPLAY DEGRADED' in output or MODE=='sink_block'
evidence=next(r for r in child if r['kind']=='authoritative')
assert evidence['history_issue'] is None and evidence['log_issue'] is None
assert evidence['log_action_results']==len(evidence['actions'])
expected='0044585900ff'+bytes(range(64)).hex()
for action in evidence['actions']:
    if MODE=='generated': continue
    if action['action']=='A':
        assert action['intended']==expected
        assert not action['receive_requested'] and not action['received'] and action['receive_outcome']=='unrequested'
    else:
        assert action['intended']=='53'
if MODE in ('natural','hide','no_banner','plain','fallback','formatter'):
    assert evidence['outcome']=='completed' and evidence['counters']==dict(
        prepared_cases=2,selected_cases=2,fuzz_tests=2,attempts=2,setup_attempts=2)
    assert [r['hex'] for r in child if r['kind']=='offer']==['53',expected,'53',expected]
    assert [r['kind'] for r in child if r['kind'] in ('offer','read')]==['offer','read','offer']*2
    assert all(action['offered']==action['intended'] and action['acceptance']=='accepted' for action in evidence['actions'])
    assert [action['received'] for action in evidence['actions'] if action['action']=='S']==['4f4b']*2
    if MODE in ('plain','fallback'):
        # ConPTY inserts cursor moves and wrap sequences in its byte stream.
        # Retain the actual sink writes and the current console viewport too.
        plain=(OUT/'plain.txt').read_text(encoding='utf-8')
        assert 'SUMMARY outcome=completed' in plain and 'known-accepted-bytes=142' in plain
        assert 'PROGRESS case=2' in plain and 'tests=2 attempts=2 setup=2' in plain
        assert 'ACCEPTED_PREFIX '+expected in plain
        assert plain.count('Test 1 run=')==1 and plain.count('Test 2 run=')==1
        viewport=next(r for r in child if r['kind']=='plain_viewport')
        assert 'SUMMARY outcome=completed' in viewport['text'] and viewport['geometry']==[120,35]
        if MODE=='fallback': assert 'Rich unavailable; using Plain display.' in plain
    else:
        complete=[r for r in child if r['kind']=='frame' and 'final accounted' in r['text']]
        assert complete
        text=complete[-1]['text']
        assert 'tests=2 attempts=2 setup=2' in text and 'RX=unrequested' in text
        assert 'A/outbound/left [2:4] 58 59' in text and 'A/outbound/right [4:6] 00 ff' in text
        if MODE=='hide':
            assert 'FIELDS ' not in text and 'A/outbound/left=5859' not in text and 'A/outbound/right=00ff' not in text
        else:
            assert 'FIELDS A/outbound/left=5859 | A/outbound/right=00ff' in text
        delimiters=sum(line=='─'*120 for line in text.splitlines())
        assert delimiters==(2 if MODE=='no_banner' else 4)
        if MODE=='formatter':
            assert 'CONTROLLED FORMAT left=5859 right=00ff receive=unrequested' in text
if MODE=='generated':
    assert evidence['outcome']=='completed' and evidence['counters']==dict(
        prepared_cases=3,selected_cases=2,fuzz_tests=2,attempts=2,setup_attempts=0)
    assert evidence['cases']==[dict(number=1,selected=False),dict(number=2,selected=True),dict(number=3,selected=True)]
    assert [action['intended'] for action in evidence['actions']]==['415943','415a43']
    assert [r['hex'] for r in child if r['kind']=='offer']==['415943','415a43']
    assert not any(r['kind']=='read' for r in child)
    frames=[r for r in child if r['kind']=='frame']
    assert any(r['case']==2 and r['intended']=='415943' for r in frames)
    assert any(r['case']==3 and r['intended']=='415a43' and 'tests=2 attempts=2 setup=0' in r['text']
        and 'CASE 3' in r['text'] for r in frames)
if MODE=='stage_only':
    assert evidence['counters']['fuzz_tests']==0 and evidence['counters']['attempts']==0
    assert evidence['counters']['setup_attempts']==2
    # Current configured campaign policy advances a setup path that never
    # reaches its selected action as monitoring_failed, with zero test attempts.
    assert evidence['outcome']=='monitoring_failed' and evidence['case_outcomes']==['monitoring_failed']*2
    assert [action['action'] for action in evidence['actions']]==['S']*2
    assert all(action['iteration'] is None for action in evidence['actions'])
    assert [r['hex'] for r in child if r['kind']=='offer']==['53']*2
    assert any(r['kind']=='frame' and 'SETUP' in r['text'] and 'tests=0 attempts=0 setup=2' in r['text'] for r in child)
if MODE=='interrupt':
    assert evidence['outcome']=='stopped'
    assert any(r['kind']=='control' and r['command']=='stop' for r in child)
json_lines=(OUT/'stdout.jsonl').read_text(encoding='utf-8').splitlines()
assert json_lines and all(isinstance(json.loads(line),(list,dict)) for line in json_lines)
note('PASS',mode=MODE,guard_before_product=True,actual_terminal=True,
     output_bytes=len(output),frames=sum(r['kind']=='frame' for r in child))
print(json.dumps(trace[-1]))
