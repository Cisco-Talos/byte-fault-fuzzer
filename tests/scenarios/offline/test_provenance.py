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

"""R02 closed passive graph values preserve exact evidence without expansion."""
from copy import deepcopy

import pytest

from bytefault.core.contracts import ContractError, freeze
from bytefault.core.provenance import pack, export, load
from bytefault.core.records import encode_value, decode_value
from bytefault.core.validation import passive
from bytefault.fuzzers.inputs import request_to_data, value_from_data


def test_exact_graph_values_codecs_and_prefix_shared_ancestry():
    original={'bytes':b'\x00\xff\x80', 'literal_tag':{'$provenance':{'format':'operator data'}},
        'ordered':({'record_id':'one','choice':'uncertain'}, {'record_id':'two','choice':'skip'}),
        'scalars':(None,True,1,1.25,'marker')}
    retained=pack(original)
    assert retained==original
    assert freeze(retained) is retained
    assert isinstance(retained['ordered'],tuple)
    passive(retained)
    assert decode_value(encode_value(retained))==retained
    assert value_from_data(request_to_data(retained))==retained
    with pytest.raises(TypeError):retained.bytes=b'changed'
    with pytest.raises(TypeError):retained['ordered'].changed=True
    with pytest.raises(TypeError):retained['ordered'].__dict__['changed']=True
    nodes=[]
    history=()
    for number in range(8):
        history=history+({'record_id':str(number),'previous_snapshot':retained},)
        retained=pack({'history':history,'original':original})
        nodes.append(len(export(retained)['nodes']))
        if number==0:
            assert retained.history[-1].previous_snapshot['bytes']==original['bytes']
        else:
            assert retained.history[-1].previous_snapshot.history[-1].record_id==str(number-1)
    # Each actual new record/snapshot adds a fixed amount of unique data. The
    # preceding history remains reachable by reference and shares its prefix.
    increments=[b-a for a,b in zip(nodes,nodes[1:])]
    assert max(increments)==min(increments)
    assert retained.original==original


def test_missing_cyclic_conflicting_and_unknown_graph_references_are_typed():
    archive=export(pack({'value':b'\0x'}))
    missing=deepcopy(archive)
    child=missing['nodes'][missing['root']][1][0][1]
    del missing['nodes'][child]
    with pytest.raises(ContractError,match='missing_reference'):load(missing)
    cyclic={'format':archive['format'],'version':1,'root':'cycle',
        'nodes':{'cycle':['mapping',[['next','cycle']]]}}
    with pytest.raises(ContractError,match='cyclic_reference'):load(cyclic)
    conflicting=deepcopy(archive)
    conflicting['nodes'][child]=('bytes','00ff')
    with pytest.raises(ContractError,match='conflicting_reference'):load(conflicting)
    unknown=deepcopy(archive);unknown['version']=2
    with pytest.raises(ContractError,match='unsupported_version'):load(unknown)
    with pytest.raises(ContractError,match='unsupported_version'):
        decode_value(['provenance',unknown])
    with pytest.raises(ContractError,match='unsupported_version'):
        value_from_data({'$provenance':unknown})
    raw={};raw['self']=raw
    with pytest.raises(ContractError,match='cyclic_reference'):pack(raw)


def test_invalid_graph_frame_preserves_acknowledged_prefix_and_original_tail(tmp_path):
    import json
    import zlib
    from bytefault.core.records import Record
    from bytefault.core.storage import frame_record, reopen_records, HEADER, MAGIC
    first=Record('acknowledged','checkpoint',{}, {'bytes':b'\x00\xff'})
    damaged=encode_value(Record('broken','checkpoint',{},pack({'value':b'\x80'})))
    archive=next(item[1][1] for item in damaged[1] if item[0]=='data')
    child=archive['nodes'][archive['root']][1][0][1]
    del archive['nodes'][child]
    body=json.dumps(damaged,separators=(',',':')).encode('utf-8')
    original=frame_record(first)+HEADER.pack(MAGIC,len(body),zlib.crc32(body))+body
    path=tmp_path/'invalid-reference.bfr'
    path.write_bytes(original)
    recovered=reopen_records(path)
    assert recovered.records==(first,)
    assert recovered.issue.kind=='corrupt' and 'missing_reference' in recovered.issue.reason
    assert recovered.issue.offset==len(frame_record(first))
    assert path.read_bytes()==original
