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

"""Optional application terminal client with separate controls and rendering.

At most one executing render and one replaceable frame exist. No renderer or
formatter runs on execution, required-record, service or control threads.
"""
import copy
import os
import queue
import shutil
import sys
import threading
import time

from bytefault.ui.application_client import ApplicationView


class TerminalController:
    def __init__(self, view, reader, *, output_formatter=None, stream=None, renderer=None):
        if not isinstance(view,ApplicationView):
            raise TypeError('TerminalController requires an ApplicationView')
        self.view,self._keypress_reader=view,reader
        self.output_formatter=output_formatter
        self.stream=stream or sys.stderr
        self.renderer=renderer
        self._done=threading.Event()
        self._lock=threading.RLock()
        self._threads=[]
        self._live=None
        self._frame=None
        self._version=0
        self._rendering_since=None
        self._diagnosed=set()
        self._diagnostics=queue.Queue(maxsize=1)
        self._last_pause=False
        self._stop_sent=False
        self._last_geometry=None
        self._rendered=threading.Event()
        self._final_rendered=threading.Event()
        self.quit_requested=threading.Event()
        self._log_wake=threading.Event()
        self._log_cancel=threading.Event()
        self._log_search_cancel=threading.Event()
        self._log_revision=0
        self._log_requested_source=None
        self._log_started=False
        self._log_cancelled=False
        self._log_select_first=False
        self._log_navigation={'next':0,'jump':'','delta':0,'detail':False}

    @property
    def session_state(self):
        return self.view.state

    def _diagnostic(self,message):
        self.view.state.degraded=message
        if message not in self._diagnosed:
            if len(self._diagnosed)>=16:
                self._diagnosed.clear()
            self._diagnosed.add(message)
            try:
                self._diagnostics.put_nowait(message)
            except queue.Full:
                pass

    def _diagnose(self):
        while not self._done.is_set() or not self._diagnostics.empty():
            try:
                message=self._diagnostics.get(timeout=.1)
            except queue.Empty:
                continue
            try:
                self.stream.write('\nBYTEFAULT DISPLAY DEGRADED: '+message+'\n')
                self.stream.flush()
            except Exception:
                # The degraded state remains queryable even when the display
                # stream itself fails. No control or required owner awaits it.
                pass
            finally:
                self._diagnostics.task_done()

    def start(self,live):
        self._live=live
        self._keypress_reader.start()
        for name,target in (('control',self._controls),('projection',self._project),
                ('render',self._render_loop),('diagnostic',self._diagnose),('log',self._logs)):
            thread=threading.Thread(target=target,name='bytefault-terminal-'+name,daemon=True)
            self._threads.append(thread); thread.start()

    def _controls(self):
        reader=self._keypress_reader
        while not self._done.wait(.025):
            # Dispatch controls before acquiring any view/projection/render lock.
            if reader.should_stop and not self._stop_sent:
                result=self.view.control('stop'); self._stop_sent=True
                self.session_state.control_outcome=str(result)
                self._log_cancel.set()
                self._log_search_cancel.set()
                self.quit_requested.set()
            if reader.paused!=self._last_pause:
                result=self.view.control('pause' if reader.paused else 'resume')
                self._last_pause=reader.paused
                self.session_state.control_outcome=str(result)
            if self._rendering_since is not None and time.monotonic()-self._rendering_since>.5:
                self._diagnostic('renderer stalled; controls and authoritative recording remain active')
            if not self._lock.acquire(blocking=False):
                continue
            try:
                st=self.session_state
                st.verbosity_level=reader.verbosity_level
                st.rain_enabled=reader.rain_enabled
                st.active_screen=reader.active_screen; st.show_help=reader.show_help
                direction=reader.consume_theme_signal()
                if direction:
                    from bytefault.ui.theme import cycle_theme, get_theme_name
                    cycle_theme(direction); st.theme_name=get_theme_name()
                self._process_log_signals(reader)
            finally:
                self._lock.release()

    def _process_log_signals(self,reader):
        """Admit bounded presentation intent; never scan or read a match here."""
        signals=reader.consume_log_signals(); st=self.session_state
        source=(st.log_file,shutil.get_terminal_size((80,24)).columns)
        if source!=self._log_requested_source:
            if self._log_requested_source is not None:
                st.log_lines=[]; st.log_search_matches=[]; st.log_index_ready=False; st.log_issue=''
                st.log_detail_rows=None
            self._log_requested_source=source
            self._replace_log_work(source=True)
        if st.active_screen=='log' and not self._log_started:
            self._log_started=True
            self._log_wake.set()
        if signals['search_start']:
            st.log_search_active=True; st.log_search_input=''
        for char in signals['search_chars']:
            if st.log_search_active:
                st.log_search_input=st.log_search_input[:-1] if char=='\x08' else st.log_search_input+char
        if signals['search_cancel']:
            st.log_search_active=False; st.log_search_input=''
            if st.log_detail_rows is not None:
                st.log_detail_rows=None
            if st.log_search_pending:
                self._log_cancelled=True
                self._replace_log_work()
                st.log_search_pending=False; st.log_search_issue='cancelled'
        if signals['search_submit']:
            st.log_search_active=False; st.log_search_query=st.log_search_input; st.log_search_input=''
            st.log_detail_rows=None
            self._log_cancelled=False; self._replace_log_work()
            self._log_select_first=True
            st.log_search_matches=[]; st.log_search_index=0
            st.log_search_pending=bool(st.log_search_query); st.log_search_issue=''
        self._log_navigation['next']+=signals['search_next']
        self._log_navigation['detail'] ^= bool(signals['detail_toggle'])
        if signals['jump']:
            self._log_navigation['jump']=signals['jump']; self._log_navigation['delta']=0
        self._log_navigation['delta']+=signals['scroll_delta']
        self._log_wake.set()

    def _replace_log_work(self,*,source=False):
        if source:
            self._log_cancel.set()
            self._log_cancel=threading.Event()
        self._log_search_cancel.set()
        self._log_search_cancel=threading.Event()
        self._log_revision+=1
        self._log_wake.set()

    def _logs(self):
        """One optional worker owns page builds, full matching and navigation.

        Publication checks both the input generation and ViewState identity.
        Immutable indexes stay leased by old frames until their last reference
        goes away; replacing a query never closes a displayed frame's index.
        """
        from pathlib import Path
        from bytefault.ui.log_view import LogRows,LogRowsLease
        rows=None; stamp=None; verified_key=None; matches=None; failed_key=None
        matched_query=None; matched_cancelled=None; matched_logical=0; matched_revision=None
        while not self._done.is_set():
            self._log_wake.wait(.075); self._log_wake.clear()
            if not self._lock.acquire(timeout=.025):
                continue
            try:
                st=self.session_state
                if not self._log_started:
                    continue
                revision,cancel,search_cancel=(self._log_revision,self._log_cancel,self._log_search_cancel)
                if cancel.is_set():
                    st.log_search_pending=False; st.log_search_issue='cancelled'
                    continue
                path,width=st.log_file,shutil.get_terminal_size((80,24)).columns
                query=st.log_search_query
                search_cancelled=self._log_cancelled
                current_rows=st.log_lines
            finally:
                self._lock.release()
            try:
                try:
                    info=Path(path).stat(); wanted=(path,info.st_size,info.st_mtime_ns,width)
                except OSError:
                    wanted=(path,None,width)
                request_key=(revision,wanted,query,search_cancelled)
                if request_key==failed_key:
                    continue
                # Reuse an already indexed direct ApplicationView snapshot too.
                if rows is None and isinstance(current_rows,(LogRows,LogRowsLease)) and self.view._log_stamp==wanted[1:]:
                    rows=current_rows.owner if isinstance(current_rows,LogRowsLease) else current_rows
                    stamp=wanted
                if wanted!=stamp:
                    with self._lock:
                        if self.session_state is st: st.log_index_pending=True
                    rebuilt=False
                    progress=lambda:self.view._log_append_progress(path)
                    extended=(rows is not None and stamp is not None and len(stamp)==4 and
                        path==stamp[0] and width==stamp[3] and
                        rows.extend(path,cancelled=self._done.is_set,superseded=cancel.is_set,
                                    append_progress=progress))
                    if not extended:
                        rows=LogRows(path,width,cancelled=self._done.is_set,superseded=cancel.is_set,
                                     append_progress=progress)
                        rebuilt=True
                    wanted=(path,*rows.source_stamp) if rows.source_stamp is not None else wanted
                    stamp=wanted; verified_key=None
                    if rebuilt:
                        matches=None; matched_query=None; matched_logical=0
                else:
                    rebuilt=extended=False
                lease=rows.snapshot()
                key=(revision,stamp,query,search_cancelled)
                if (matches is None or revision!=matched_revision or query!=matched_query or
                        search_cancelled!=matched_cancelled or
                        lease.logical_count<matched_logical):
                    if not self._lock.acquire(timeout=.025):
                        continue
                    try:
                        if self.session_state is not st or revision!=self._log_revision or st.log_search_query!=query:
                            continue
                        st.log_search_pending=bool(query) and not search_cancelled
                    finally:
                        self._lock.release()
                    matches=lease.matches('' if search_cancelled else query,
                        cancelled=lambda:cancel.is_set() or search_cancel.is_set())
                    matched_query,matched_cancelled,matched_revision=query,search_cancelled,revision
                    matched_logical=lease.logical_count
                elif lease.logical_count>matched_logical:
                    lease.matches('' if search_cancelled else query,
                        cancelled=lambda:cancel.is_set() or search_cancel.is_set(),
                        logical_start=matched_logical,result=matches)
                    matched_logical=lease.logical_count
                if cancel.is_set() or search_cancel.is_set() or self._done.is_set():
                    continue
                if verified_key!=key:
                    if extended:
                        source_ok=rows.boundary_current(path,append_progress=progress,
                                                        cancelled=cancel.is_set)
                    else:
                        source_ok=rows.source_current(path,cancelled=cancel.is_set)
                    if not source_ok:
                        stamp=None; matched_query=None
                        continue
                    verified_key=key
                if not self._lock.acquire(timeout=.025):
                    continue
                try:
                    if (self.session_state is not st or revision!=self._log_revision or st.log_file!=path
                            or st.log_search_query!=query):
                        continue
                    navigation=self._log_navigation
                    self._log_navigation={'next':0,'jump':'','delta':0,'detail':False}
                    first=self._log_select_first
                    index,offset=st.log_search_index,st.log_scroll_offset
                    detail_rows=None if rebuilt else st.log_detail_rows
                    detail_offset=st.log_detail_scroll_offset
                finally:
                    self._lock.release()
                # Every database lookup happens outside the control/state lock.
                index=index%len(matches) if matches else 0
                if first and matches:
                    index=0; offset=max(0,matches[0]-(0 if matches.location(0)[2] else 2))
                    detail_rows=None
                if navigation['next'] and matches:
                    index=(index+navigation['next'])%len(matches)
                    offset=max(0,matches[index]-(0 if matches.location(index)[2] else 2))
                    detail_rows=None
                if navigation['detail']:
                    if detail_rows is not None:
                        detail_rows=None
                    elif len(lease):
                        selected=(matches[index] if matches and query else
                            max(0,len(lease)-1) if offset<0 else min(offset,len(lease)-1))
                        detail_rows=lease.detail(selected,width-8)
                        match_offset=matches.location(index)[1] if matches and query else 0
                        detail_offset=max(0,detail_rows.row_at_offset(match_offset)-2)
                if detail_rows is not None:
                    if navigation['jump']=='home': detail_offset=0
                    elif navigation['jump']=='end': detail_offset=max(0,len(detail_rows)-3)
                    detail_offset=max(0,min(len(detail_rows)-1,
                        detail_offset+navigation['delta']))
                else:
                    if navigation['jump']=='home': offset=0
                    elif navigation['jump']=='end': offset=-1
                    if navigation['delta']:
                        if offset<0:
                            height=max(3,shutil.get_terminal_size((80,24)).lines-6)
                            offset=max(0,len(lease)-height)
                        offset=max(0,offset+navigation['delta'])
                with self._lock:
                    if (self._done.is_set() or cancel.is_set() or self.session_state is not st
                            or revision!=self._log_revision or st.log_file!=path or st.log_search_query!=query
                            or shutil.get_terminal_size((80,24)).columns!=width):
                        continue
                    st.log_lines,st.log_issue=lease,lease.issue
                    st.log_index_ready=True; st.log_index_pending=False
                    self.view._log_stamp=wanted[1:]
                    st.log_search_matches=matches.snapshot(); st.log_search_index=index; st.log_scroll_offset=offset
                    st.log_detail_rows=detail_rows; st.log_detail_scroll_offset=detail_offset
                    st.log_match_in_record=bool(matches and matches.location(index)[2])
                    st.log_search_pending=False
                    st.log_search_issue='cancelled' if search_cancelled else ''
                    self._log_select_first=False
                    failed_key=None
            except InterruptedError:
                pass
            except Exception as exc:
                failed_key=request_key
                with self._lock:
                    if revision==self._log_revision:
                        self.session_state.log_index_pending=False
                        self.session_state.log_search_pending=False
                        self.session_state.log_issue='index failed: '+str(exc)
                self._diagnostic('log presentation failed: '+str(exc))

    def _project(self):
        while not self._done.is_set():
            try:
                with self._lock:
                    self.view.refresh()
                    self._version+=1
                    self._frame=(self._version,copy.deepcopy(self.session_state),
                        tuple(self.view.tx_history),tuple(self.view.rx_history))
            except Exception as exc:
                self._diagnostic('projection refresh failed: '+str(exc))
            self._done.wait(.075)

    def _build(self,state,tx,rx):
        if self.renderer is not None:
            return self.renderer(state,tx,rx)
        from bytefault.ui.rich_renderables import build_crash_screen,build_dashboard,build_log_screen
        if self.output_formatter and state.last_sent is not None and state.active_screen=='dashboard':
            text=self.output_formatter(dict(state.current_field_bytes),state.last_received)
            state.formatted_output=str(text) if text else ''
        if state.active_screen=='crashes':
            result=build_crash_screen(state)
        elif state.active_screen=='log':
            result=build_log_screen(state)
        else:
            result=build_dashboard(state,tx_history=tx,rx_history=rx)
        return result

    def _render_loop(self):
        self._rendering_since=time.monotonic()
        try:
            if hasattr(self._live,'start'):
                self._live.start()
        except Exception as exc:
            self._diagnostic('display start failed: '+str(exc))
        finally:
            self._rendering_since=None
        last=0
        while not self._done.wait(.025):
            frame=self._frame
            if frame is None or frame[0]==last:
                continue
            last=frame[0]
            try:
                self._rendering_since=time.monotonic()
                renderable=self._build(*frame[1:])
                if not self._done.is_set():
                    self._live.update(renderable,refresh=True)
                    self._rendered.set()
                    if not frame[1].run_active:
                        self._final_rendered.set()
            except Exception as exc:
                self._diagnostic('renderer failed: '+str(exc))
            finally:
                self._rendering_since=None

    def stop(self):
        self._done.set()
        self._log_cancel.set(); self._log_search_cancel.set(); self._log_wake.set()
        self._keypress_reader.stop()
        for thread in self._threads:
            thread.join(.25)
        pending=tuple(thread.name for thread in self._threads if thread.is_alive())
        if pending:
            self._diagnostic('detached pending display worker: '+', '.join(pending))
        self._live=None
        return pending


def run_terminal(application,request,options=None,*,stream=None,output_formatter=None,renderer=None):
    """Execute through Application.start; presentation is optional and stderr-only.

    Callers retain Application ownership. This view finishes at run completion;
    later services remain discoverable by a new ApplicationView.
    """
    options=dict(options or {}); stream=stream or sys.stderr
    handle=application.start(request)
    view=ApplicationView(application,handle.run_id,request=request,options=options)
    rich=options.get('ui',True) and not options.get('no_ui',False)
    fallback_notice=False
    if rich:
        try:
            from rich.console import Console
            from rich.live import Live
        except ImportError:
            fallback_notice=True; rich=False
    if not rich:
        from bytefault.ui.plain import ApplicationPlainClient
        client=ApplicationPlainClient(view,stream=stream,output_formatter=output_formatter)
        jobs=queue.Queue(maxsize=2); detached=threading.Event()
        projected=threading.Event(); quit_requested=threading.Event()
        def display():
            if fallback_notice:
                try:
                    stream.write('Rich unavailable; using Plain display.\n'); stream.flush()
                except Exception as exc:
                    view.state.degraded='Plain fallback notice failed: '+str(exc)
            while not detached.is_set() or not jobs.empty():
                try:
                    state,updates=jobs.get(timeout=.05)
                except queue.Empty:
                    continue
                try:
                    client.render(state,updates)
                except Exception as exc:
                    view.state.degraded='Plain display failed: '+str(exc)
                finally:
                    jobs.task_done()
        worker=threading.Thread(target=display,name='bytefault-terminal-plain',daemon=True)
        worker.start()
        from bytefault.ui.keypress import KeypressReader
        reader=KeypressReader(controls_only=True)
        def controls():
            paused=False; stopped=False
            while not detached.wait(.025):
                if reader.should_stop and not stopped:
                    view.control('stop'); stopped=True
                    quit_requested.set()
                if reader.paused!=paused:
                    view.control('pause' if reader.paused else 'resume'); paused=reader.paused
        keys=None
        if sys.stdin.isatty():
            reader.start()
            keys=threading.Thread(target=controls,name='bytefault-terminal-control',daemon=True); keys.start()
        def project():
            while not detached.is_set():
                try:
                    view.refresh()
                    try:
                        jobs.put_nowait((copy.deepcopy(view.state),tuple(view.action_updates)))
                    except queue.Full:
                        view.state.degraded='Plain display queue full; required history remains complete'
                    if not view.state.run_active:
                        projected.set()
                except Exception as exc:
                    view.state.degraded='Plain projection failed: '+str(exc)
                detached.wait(.075)
        projection=threading.Thread(target=project,name='bytefault-terminal-projection',daemon=True)
        projection.start()
        try:
            while True:
                result=handle.wait(.05)
                pending=(application.status(handle.run_id).get('followup') or {}).get('pending',())
                if result is not None and (quit_requested.is_set() or not pending):
                    projected.wait(.2)
                    return result
        except KeyboardInterrupt:
            view.control('stop')
            while handle.wait(.05) is None:
                pass
            return handle.wait()
        finally:
            detached.set(); reader.stop()
            if keys is not None: keys.join(.2)
            projection.join(.25)
            worker.join(.25)
            if worker.is_alive() or projection.is_alive():
                view.state.degraded='detached pending Plain display/projection worker'
            view.close()
    from bytefault.ui.keypress import KeypressReader
    reader=KeypressReader(); reader.verbosity_level=view.state.verbosity_level
    reader.rain_enabled=view.state.rain_enabled
    controller=TerminalController(view,reader,stream=stream,renderer=renderer,output_formatter=output_formatter)
    console=Console(file=stream)
    live=Live(console=console,screen=True,auto_refresh=False,redirect_stdout=False,redirect_stderr=False)
    controller.start(live)
    try:
        while True:
            result=handle.wait(.05)
            pending=(application.status(handle.run_id).get('followup') or {}).get('pending',())
            if result is not None and (controller.quit_requested.is_set() or not pending):
                break
            time.sleep(.025)
        # Final projection is optional too. Never acquire its lock or perform
        # record reads on the primary wait/interrupt path.
        controller._final_rendered.wait(.2)
        return handle.wait()
    except KeyboardInterrupt:
        view.control('stop')
        while handle.wait(.05) is None:
            pass
        return handle.wait()
    finally:
        controller.stop()
        # Console teardown can itself stall in a supplied output implementation;
        # never make application/required-service completion depend on its lock.
        def restore():
            try:
                live.stop()
            except Exception as exc:
                view.state.degraded='display cleanup failed: '+str(exc)
        cleanup=threading.Thread(target=restore,name='bytefault-terminal-cleanup',daemon=True)
        cleanup.start(); cleanup.join(.25)
        if cleanup.is_alive():
            try:
                os.write(stream.fileno(),b'\x1b[?25h\x1b[?1049l')
            except (OSError,AttributeError):
                pass
        view.close()
