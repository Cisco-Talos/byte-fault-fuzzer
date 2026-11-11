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

"""File-backed presentation rows and logical search over unchanged required logs.

The screen owns one temporary index, never the source writer. Page and match
access are bounded; arbitrary navigation/search remains available without
retaining/deepcopying every decoded line or match in memory.
"""
from collections.abc import Sequence
from bisect import bisect_right
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading

from bytefault.core.records import encode_value
from bytefault.core.storage import MAGIC,reopen_records


_SPACE='\t\n\v\f\r '
_WORD_BREAK=re.compile(r'[\t\n\v\f\r -]')
_NON_SPACE=re.compile(r'[^\t\n\v\f\r ]')
_NON_DASH=re.compile(r'[^-]')


def _word(char):
    return char=='_' or char.isalnum()


def _letter(char):
    # TextWrapper's [^\d\W], including underscore/nondecimal word numbers.
    return _word(char) and not char.isdecimal()


def _chunk_spans(line,check):
    """TextWrapper wordsep semantics as cancellable spans, without giant copies.

    Whitespace runs, em dashes, and the stdlib's two hyphen-word boundaries are
    retained across every row. Bounded regex windows only skip ordinary text;
    they never become new lexical boundaries.
    """
    end=len(line); start=position=0
    def skip(pattern,position):
        while position<end:
            check(); limit=min(end,position+4096)
            found=pattern.search(line,position,limit)
            if found: return found.start()
            position=limit
        return end
    while position<end:
        check()
        if line[position] in _SPACE:
            if start<position:
                yield start,position
            following=skip(_NON_SPACE,position)
            yield position,following
            start=position=following
            continue
        boundary=skip(_WORD_BREAK,position)
        if boundary==end:
            yield start,end; return
        if line[boundary] in _SPACE:
            yield start,boundary
            start=position=boundary
            continue
        dash_end=skip(_NON_DASH,boundary)
        punct=boundary>0 and (_word(line[boundary-1]) or line[boundary-1] in '!"\'&.,?')
        if dash_end-boundary>=2 and punct and dash_end<end and _word(line[dash_end]):
            if start<boundary: yield start,boundary
            yield boundary,dash_end
            start=position=dash_end
            continue
        if dash_end-boundary==1 and boundary>start:
            before=(boundary>=2 and _letter(line[boundary-2]) and _letter(line[boundary-1])) or (
                boundary>=3 and _letter(line[boundary-3]) and line[boundary-2]=='-' and _letter(line[boundary-1]))
            after=boundary+1<end and _letter(line[boundary+1]) and (
                boundary+2<end and _letter(line[boundary+2]) or
                boundary+3<end and line[boundary+2]=='-' and _letter(line[boundary+3]))
            if before and after:
                yield start,dash_end; start=dash_end
        position=dash_end
    if start<end:
        yield start,end


def wrapped_rows(line,width,*,cancelled=lambda:False):
    """Exact retained TextWrapper policy, streamed with lexical span identity."""
    if width<1: raise ValueError('invalid width')
    def check():
        if cancelled(): raise InterruptedError('log projection cancelled')
    check()
    if len(line)<=width:
        yield line
        return
    row=[]; used=0
    for start,end in _chunk_spans(line,check):
        while start<end:
            check(); length=end-start
            if used+length<=width:
                row.append(line[start:end]); used+=length; break
            if length>width:
                space=width-used
                if space:
                    prefix=line[start:start+space]; take=space
                    hyphen=prefix.rfind('-')
                    if hyphen>0 and any(char!='-' for char in prefix[:hyphen]):
                        take=hyphen+1
                    row.append(prefix[:take]); start+=take
            yield ''.join(row); row=[]; used=0
    if row: yield ''.join(row)
    elif not line: yield ''


class LogSource:
    def __init__(self,path):
        self.path,self.issue=path,''
        self.framed=False
        self.valid_bytes=0

    def __iter__(self):
        for display,_,_ in self.entries():
            yield display

    @staticmethod
    def record_entry(record):
        header=record.record_id+' '+record.kind
        identity=json.dumps(encode_value(record.identity),ensure_ascii=True,separators=(',',':'))
        display=header+' '+identity
        if len(display)>240:
            display=display[:237]+'...'
        exact=header+'\n'+json.dumps(encode_value({'identity':record.identity,'data':record.data}),
            ensure_ascii=True,indent=2)
        return display,exact,record.record_id

    def entries(self):
        """Bound displayed rows while retaining complete decoded search text."""
        if not self.path:
            yield '(no log file specified)','(no log file specified)',None; return
        try:
            with open(self.path,'rb') as stream:
                self.framed=stream.read(4)==MAGIC
            if self.framed:
                recovered=reopen_records(self.path)
                if recovered.refs:
                    last=recovered.refs[-1]
                    self.valid_bytes=last.offset+last.length
                for record in recovered.records:
                    yield self.record_entry(record)
                if recovered.issue:
                    self.issue=str(recovered.issue)
            else:
                with open(self.path,encoding='utf-8',errors='replace') as stream:
                    for line in stream:
                        display=line.rstrip('\r\n')
                        yield display,display,None
                self.valid_bytes=os.stat(self.path).st_size
        except OSError as exc:
            self.issue=str(exc)
            display='(log unavailable: '+str(exc)+')'
            yield display,display,None


class LogRows(Sequence):
    def __init__(self,path,width,*,cancelled=lambda:False,superseded=lambda:False,
                 append_progress=None):
        temporary=tempfile.NamedTemporaryFile(prefix='bytefault-view-',suffix='.sqlite',delete=False)
        self.path=Path(temporary.name); temporary.close()
        self._lock=threading.RLock()
        self._connection=sqlite3.connect(self.path,check_same_thread=False)
        self._cancelled=cancelled
        self.count=0
        self._logical_count=0
        self._framed=False
        self._valid_bytes=0
        self._connection.execute('CREATE TABLE logical(id INTEGER PRIMARY KEY,text TEXT,search TEXT,full INTEGER)')
        self._connection.execute('CREATE TABLE rows(id INTEGER PRIMARY KEY,logical INTEGER,start INTEGER,text TEXT)')
        self._connection.execute('CREATE INDEX row_location ON rows(logical,start)')
        self._connection.execute('CREATE TABLE record_ids(id TEXT PRIMARY KEY)')
        self._source_path=self.path.with_suffix('.source')
        self._original_path=Path(path).resolve()
        self._source_identity=None
        self.source_stamp=None
        self._append_progress=append_progress
        self._trusted_progress=None
        self._pending_progress=None
        try:
            snapshot=path
            before=append_progress() if append_progress is not None else None
            try:
                original=open(path,'rb')
            except OSError:
                original=None
            if original is not None:
                # Cache output failures are presentation failures, never a
                # reason to fall back to an unverified live-source read.
                with original, self._source_path.open('wb') as copied:
                    info=os.fstat(original.fileno())
                    self._source_identity=(info.st_dev,info.st_ino)
                    owned=self._progress_fits(info,before)
                    boundary=before.committed_end if owned else info.st_size
                    self.source_stamp=(boundary,before.mtime_ns if owned else info.st_mtime_ns,width)
                    remaining=boundary
                    while remaining:
                        if cancelled() or superseded(): raise InterruptedError('log projection cancelled')
                        chunk=original.read(min(65536,remaining))
                        if not chunk:
                            raise InterruptedError('log source truncated during snapshot copy')
                        copied.write(chunk); remaining-=len(chunk)
                snapshot=self._source_path
                after=append_progress() if append_progress is not None else None
                if owned and self._progress_continues(before,after):
                    self._pending_progress=before
            # A finite raw snapshot is decoded only by the existing core reader.
            # Its validated acknowledged prefix stays usable during appends.
            source=LogSource(snapshot)
            count,logical=self._index(source.entries(),self._connection,width,
                cancelled=lambda:cancelled() or superseded())
            self._connection.commit()
            self.count,self._logical_count=count,logical
            self._framed,self._valid_bytes=source.framed,source.valid_bytes
            self.issue=source.issue
        except BaseException:
            self.close(); raise

    def _progress_fits(self,info,progress):
        return (progress is not None and progress.path==str(self._original_path) and
            (progress.device,progress.inode)==self._source_identity and
            progress.committed_end<=info.st_size)

    @staticmethod
    def _progress_continues(previous,current):
        return (previous is not None and current is not None and
            previous.owner_token==current.owner_token and previous.path==current.path and
            (previous.device,previous.inode)==(current.device,current.inode) and
            current.append_count>=previous.append_count and
            current.appended_bytes-previous.appended_bytes==
                current.committed_end-previous.committed_end>=0 and
            (current.append_count>previous.append_count or current.mtime_ns==previous.mtime_ns))

    def _prefix_matches(self,original,size,check):
        """Exact comparison for unowned files or an untrusted source change."""
        with self._source_path.open('rb') as snapshot:
            remaining=size
            while remaining:
                if check(): raise InterruptedError('log verification cancelled')
                chunk=snapshot.read(min(65536,remaining))
                if not chunk or original.read(len(chunk))!=chunk: return False
                remaining-=len(chunk)
        return True

    def _index(self,entries,connection,width,*,cancelled):
        count,logical=self.count,self._logical_count
        logical_batch=[]; logical_size=0; batch=[]
        for display,search,record_id in entries:
            if cancelled(): raise InterruptedError('log projection cancelled')
            logical_batch.append((logical,display,search,int(record_id is not None)))
            logical_size+=len(display)+len(search)
            if record_id is not None:
                connection.execute('INSERT INTO record_ids VALUES (?)',(record_id,))
            start=0
            for row in wrapped_rows(display,max(16,width-8),cancelled=cancelled):
                batch.append((count,logical,start,row)); count+=1; start+=len(row)
                if len(batch)>=512:
                    connection.executemany('INSERT INTO rows VALUES (?,?,?,?)',batch); batch=[]
            logical+=1
            if len(logical_batch)>=256 or logical_size>=65536:
                connection.executemany('INSERT INTO logical VALUES (?,?,?,?)',logical_batch)
                logical_batch=[]; logical_size=0
        connection.executemany('INSERT INTO logical VALUES (?,?,?,?)',logical_batch)
        connection.executemany('INSERT INTO rows VALUES (?,?,?,?)',batch)
        return count,logical

    def extend(self,path,*,cancelled=lambda:False,superseded=lambda:False,
               append_progress=None):
        """Index only new complete BFR frames after verifying the retained prefix.

        A failed or interrupted extension leaves the published rows and source
        snapshot at their previous boundary. Text files retain rebuild behavior
        because an append may complete their previously unterminated last line.
        """
        if not self._framed or self.source_stamp is None:
            return False
        check=lambda:cancelled() or superseded()
        old_size,old_mtime,width=self.source_stamp
        provider=append_progress if append_progress is not None else self._append_progress
        progress=provider() if provider is not None else None
        with open(path,'rb') as original:
            info=os.fstat(original.fileno())
            if self._source_identity!=(info.st_dev,info.st_ino) or info.st_size<old_size:
                return False
            owned=self._progress_fits(info,progress)
            if owned and progress.committed_end<old_size:
                # A prior finite snapshot may include an in-flight tail. Wait
                # for its owner to acknowledge that boundary before extending.
                raise InterruptedError('log append boundary not yet acknowledged')
            previous=self._trusted_progress
            trusted=(owned and previous is not None and
                previous.committed_end==old_size and previous.mtime_ns==old_mtime and
                self._progress_continues(previous,progress))
            boundary=progress.committed_end if owned else info.st_size
            if trusted:
                original.seek(old_size)
            elif not self._prefix_matches(original,old_size,check):
                return False
            added=original.read(boundary-old_size)
            if len(added)!=boundary-old_size:
                raise InterruptedError('log append boundary changed during read')
            after=os.fstat(original.fileno())
        final_progress=provider() if provider is not None else None
        current=os.stat(path)
        identity=(info.st_dev,info.st_ino)
        stable=((after.st_dev,after.st_ino)==identity and
            (current.st_dev,current.st_ino)==identity)
        if owned:
            stable=(stable and after.st_size>=boundary and current.st_size>=boundary and
                self._progress_continues(progress,final_progress))
        else:
            stable=(stable and (after.st_size,after.st_mtime_ns)==
                (info.st_size,info.st_mtime_ns) and
                (current.st_size,current.st_mtime_ns)==(info.st_size,info.st_mtime_ns))
        if check() or not stable:
            raise InterruptedError('log source changed during extension')
        boundary_mtime=progress.mtime_ns if owned else info.st_mtime_ns
        if not added:
            self.source_stamp=(boundary,boundary_mtime,width)
            self._append_progress=provider
            self._trusted_progress=progress if owned else None
            return True
        delta=self._source_path.with_suffix('.delta')
        writer=sqlite3.connect(self.path)
        try:
            with self._source_path.open('ab') as snapshot:
                snapshot.write(added)
            with self._source_path.open('rb') as snapshot, delta.open('wb') as tail:
                snapshot.seek(self._valid_bytes)
                while True:
                    if check(): raise InterruptedError('log projection cancelled')
                    chunk=snapshot.read(65536)
                    if not chunk: break
                    tail.write(chunk)
            recovered=reopen_records(delta)
            entries=(LogSource.record_entry(record) for record in recovered.records)
            count,logical=self._index(entries,writer,width,cancelled=check)
            if owned:
                final_progress=provider()
                current=os.stat(path)
                valid=((current.st_dev,current.st_ino)==identity and
                    current.st_size>=boundary and
                    self._progress_continues(progress,final_progress))
            else:
                current=os.stat(path)
                valid=((current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns)==
                    (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns))
            if check() or not valid:
                raise InterruptedError('log source changed during extension')
            writer.commit()
            self.count,self._logical_count=count,logical
            if recovered.refs:
                last=recovered.refs[-1]
                self._valid_bytes+=last.offset+last.length
            self.issue=str(recovered.issue) if recovered.issue else ''
            self.source_stamp=(boundary,boundary_mtime,width)
            self._append_progress=provider
            self._trusted_progress=progress if owned else None
            return True
        except BaseException:
            writer.rollback()
            with self._source_path.open('r+b') as snapshot:
                snapshot.truncate(old_size)
            raise
        finally:
            writer.close()
            delta.unlink(missing_ok=True)

    def snapshot(self):
        return LogRowsLease(self,self.count,self._logical_count,self.source_stamp,self.issue)

    def detail(self,row,width):
        """Open one exact decoded record on demand, without wrapping the log."""
        with self._lock:
            found=self._connection.execute('SELECT logical FROM rows WHERE id=?',(row,)).fetchone()
            if found is None: raise IndexError(row)
            exact=self._connection.execute('SELECT search FROM logical WHERE id=?',(found[0],)).fetchone()[0]
        return LogDetailRows(exact,max(16,width))

    def __len__(self): return self.count
    def __deepcopy__(self,memo): return self

    def __getitem__(self,index):
        with self._lock:
            if isinstance(index,slice):
                start,stop,step=index.indices(self.count)
                if step!=1:
                    return [self[i] for i in range(start,stop,step)]
                return [r[0] for r in self._connection.execute(
                    'SELECT text FROM rows WHERE id>=? AND id<? ORDER BY id',(start,stop))]
            if index<0: index+=self.count
            row=self._connection.execute('SELECT text FROM rows WHERE id=?',(index,)).fetchone()
            if row is None: raise IndexError(index)
            return row[0]

    def matches(self,query,*,cancelled=lambda:False,logical_limit=None,
                logical_start=0,result=None):
        # Searching never holds the page/navigation connection's lock. Results
        # have their own disk index, so even a dense query cannot monopolize
        # previously displayed rows or matches. Appends scan only new logical
        # records and publish a fixed-count lease after commit.
        fresh=result is None
        result=LogMatches() if fresh else result
        old_count=result.count
        source=sqlite3.connect(self.path)
        def check():
            if self._cancelled() or cancelled():
                raise InterruptedError('log search cancelled')
        try:
            check()
            batch=[]
            if query:
                folded_query=query.casefold()
                limit=self._logical_count if logical_limit is None else logical_limit
                for logical,text,search_text,full in source.execute(
                        'SELECT id,text,search,full FROM logical WHERE id>=? AND id<? ORDER BY id',
                        (logical_start,limit)):
                    check()
                    folded=search_text.casefold()
                    position=folded.find(folded_query)
                    if position<0:
                        continue
                    locations=iter(source.execute('SELECT start,id FROM rows WHERE logical=? ORDER BY start',(logical,)))
                    current=next(locations); following=next(locations,None)
                    if full:
                        # One navigable result per framed record. The exact
                        # match offset opens its full decoded detail on demand.
                        original=position
                        if len(folded)!=len(search_text):
                            folded_at=0
                            for original,char in enumerate(search_text):
                                if folded_at+len(char.casefold())>position: break
                                folded_at+=len(char.casefold())
                                if original%512==0: check()
                        batch.append((result.count+len(batch),current[1],logical,original,1))
                        if len(batch)>=512:
                            check(); result._append(batch); batch=[]
                        continue
                    coordinates=iter(enumerate(text)) if not full and len(folded)!=len(text) else None
                    folded_start=0; character=next(coordinates,None) if coordinates else None
                    while position>=0:
                        original=position
                        if coordinates:
                            advanced_characters=0
                            while character and folded_start+len(character[1].casefold())<=position:
                                folded_start+=len(character[1].casefold()); character=next(coordinates,None)
                                advanced_characters+=1
                                if advanced_characters%512==0: check()
                            original=character[0]
                        advanced=0
                        while following and following[0]<=original:
                            current=following; following=next(locations,None); advanced+=1
                            if advanced%512==0: check()
                        batch.append((result.count+len(batch),current[1],logical,original,0))
                        if len(batch)>=512:
                            check(); result._append(batch); batch=[]
                        position=folded.find(folded_query,position+max(1,len(folded_query)))
            check(); result._append(batch)
            with result._lock: result._connection.commit()
            return result
        except BaseException:
            if fresh:
                result.close()
            else:
                with result._lock:
                    result._connection.rollback()
                    result.count=old_count
            raise
        finally:
            source.close()

    def source_current(self,path,*,cancelled=lambda:False):
        """Verify exact retained prefix and file identity, not size growth alone."""
        try:
            with open(path,'rb') as current:
                info=os.fstat(current.fileno())
                if self._source_identity!=(info.st_dev,info.st_ino): return False
                with self._source_path.open('rb') as snapshot:
                    if os.fstat(snapshot.fileno()).st_size!=self.source_stamp[0]: return False
                    while True:
                        if self._cancelled() or cancelled(): raise InterruptedError('log verification cancelled')
                        chunk=snapshot.read(65536)
                        if not chunk: break
                        if current.read(len(chunk))!=chunk: return False
                current_progress=(self._append_progress() if self._pending_progress is not None and
                    self._append_progress is not None else None)
                final=os.stat(path)
                valid=(self._source_identity==(final.st_dev,final.st_ino) and
                       final.st_size>=self.source_stamp[0])
                if valid and self._pending_progress is not None:
                    if self._progress_continues(self._pending_progress,current_progress):
                        self._trusted_progress=self._pending_progress
                    self._pending_progress=None
                return valid
        except OSError:
            return self._source_identity is None

    def boundary_current(self,path,*,append_progress=None,cancelled=lambda:False):
        """Check a published finite boundary against the same active writer."""
        progress=self._trusted_progress
        provider=append_progress if append_progress is not None else self._append_progress
        try:
            current=provider() if progress is not None and provider is not None else None
            info=os.stat(path)
            if (info.st_dev,info.st_ino)!=self._source_identity or info.st_size<self.source_stamp[0]:
                return False
            if progress is not None and provider is not None:
                if self._progress_continues(progress,current):
                    return True
                # A closed/reopened or mismatched owner loses the fast path.
                return self.source_current(path,cancelled=cancelled)
            return (info.st_size,info.st_mtime_ns)==self.source_stamp[:2]
        except OSError:
            return False

    def close(self):
        if getattr(self,'_connection',None) is not None:
            self._connection.close(); self._connection=None
        self.path.unlink(missing_ok=True)
        if getattr(self,'_source_path',None): self._source_path.unlink(missing_ok=True)

    def __del__(self):
        try: self.close()
        except Exception: pass


class LogRowsLease(Sequence):
    """A fixed row boundary over an append-only index for in-flight frames."""
    def __init__(self,owner,count,logical_count,source_stamp,issue):
        self.owner,self.count,self.logical_count=owner,count,logical_count
        self.source_stamp,self.issue=source_stamp,issue

    def __len__(self): return self.count
    def __deepcopy__(self,memo): return self
    def __getitem__(self,index):
        if isinstance(index,slice):
            start,stop,step=index.indices(self.count)
            return self.owner[slice(start,stop,step)]
        if index<0: index+=self.count
        if index<0 or index>=self.count: raise IndexError(index)
        return self.owner[index]
    def matches(self,query,*,cancelled=lambda:False,logical_start=0,result=None):
        return self.owner.matches(query,cancelled=cancelled,logical_limit=self.logical_count,
                                  logical_start=logical_start,result=result)
    def source_current(self,path,*,cancelled=lambda:False):
        return self.owner.source_current(path,cancelled=cancelled)
    def detail(self,row,width):
        if row<0 or row>=self.count: raise IndexError(row)
        return self.owner.detail(row,width)


class LogDetailRows(Sequence):
    """Fixed-width slices of one exact record, materialized only when selected."""
    def __init__(self,text,width):
        self.text,self.width=text,width
        self.lines=text.split('\n')
        self._starts=[0]
        for line in self.lines:
            self._starts.append(self._starts[-1]+max(1,(len(line)+width-1)//width))
    def __len__(self): return self._starts[-1]
    def __deepcopy__(self,memo): return self
    def __getitem__(self,index):
        if isinstance(index,slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if index<0: index+=len(self)
        if index<0 or index>=len(self): raise IndexError(index)
        line=bisect_right(self._starts,index)-1
        column=(index-self._starts[line])*self.width
        return self.lines[line][column:column+self.width]
    def row_at_offset(self,offset):
        offset=max(0,min(offset,len(self.text)))
        line=self.text.count('\n',0,offset)
        previous=self.text.rfind('\n',0,offset)
        column=offset-(previous+1)
        return self._starts[line]+column//self.width


class LogMatches(Sequence):
    def __init__(self):
        temporary=tempfile.NamedTemporaryFile(prefix='bytefault-matches-',suffix='.sqlite',delete=False)
        self.path=Path(temporary.name); temporary.close()
        self._lock=threading.RLock()
        self._connection=sqlite3.connect(self.path,check_same_thread=False)
        self._connection.execute('CREATE TABLE matches(id INTEGER PRIMARY KEY,row INTEGER,logical INTEGER,position INTEGER,full INTEGER)')
        self.count=0
    def _append(self,batch):
        with self._lock:
            self._connection.executemany('INSERT INTO matches VALUES (?,?,?,?,?)',batch)
            self.count+=len(batch)
    def snapshot(self): return LogMatchesLease(self,self.count)
    def __len__(self): return self.count
    def __deepcopy__(self,memo): return self
    def __repr__(self): return repr(self[:8])+(' ...' if self.count>8 else '')
    def __getitem__(self,index):
        with self._lock:
            if isinstance(index,slice):
                return [self[i] for i in range(*index.indices(self.count))]
            if index<0: index+=self.count
            row=self._connection.execute('SELECT row FROM matches WHERE id=?',(index,)).fetchone()
            if row is None: raise IndexError(index)
            return row[0]
    def location(self,index):
        with self._lock:
            if index<0: index+=self.count
            row=self._connection.execute('SELECT logical,position,full FROM matches WHERE id=?',(index,)).fetchone()
            if row is None: raise IndexError(index)
            return row
    def close(self):
        if getattr(self,'_connection',None) is not None:
            self._connection.close(); self._connection=None
        self.path.unlink(missing_ok=True)
    def __del__(self):
        try: self.close()
        except Exception: pass


class LogMatchesLease(Sequence):
    """A fixed result count for frames while the matching index grows."""
    def __init__(self,owner,count): self.owner,self.count=owner,count
    def __len__(self): return self.count
    def __deepcopy__(self,memo): return self
    def __getitem__(self,index):
        if isinstance(index,slice):
            return self.owner[slice(*index.indices(self.count))]
        if index<0: index+=self.count
        if index<0 or index>=self.count: raise IndexError(index)
        return self.owner[index]
    def location(self,index):
        if index<0: index+=self.count
        if index<0 or index>=self.count: raise IndexError(index)
        return self.owner.location(index)
