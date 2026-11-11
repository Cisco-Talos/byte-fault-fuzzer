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

"""Independent exact strategy bytes and complete family/source identity parity."""
from dataclasses import replace
import pytest
from bytefault.core.contracts import CampaignOptions, Calculation
from bytefault.fuzzers.inputs import positional_plan
from bytefault.monitoring import Monitoring, ConfiguredPolicy
from test_campaign import base, offers


def execute(application_factory,tmp_path,name,value,options=CampaignOptions(),plan=None,calculations=()):
    app,traces=application_factory(monitoring=Monitoring(ConfiguredPolicy()))
    request=base(tmp_path,name)
    if plan is not None:
        request=replace(request,conversation=replace(request.conversation,plan=plan,
            selected_actions=tuple(a.action_id for a in plan.actions[1:]),calculations=calculations,repair=True))
    result=app.campaign(request,generation=value,options=options)
    return app,traces,result,app.read_records(name).records


@pytest.mark.parametrize('strategy,expected',[
    ('zip',(b'a1C',b'b2C')),
    ('cartesian',(b'a1C',b'a2C',b'a3C',b'b1C',b'b2C',b'b3C')),
    ('single',(b'a1C',b'b1C',b'a1C',b'a2C',b'a3C')),
    ('one-position',(b'aBC',b'bBC',b'AaC',b'AbC')),
    ('broadcast',(b'aaC',b'bbC')),
    ('hybrid-cartesian',(b'a1C',b'b1C'))])
def test_all_strategies_actual_campaign_exact_bytes(tmp_path,application_factory,strategy,expected):
    shared=strategy in ('one-position','broadcast')
    sources=[{'source_id':'X','kind':'list','options':{'payloads':(b'a',b'b')}}]
    sets=[{'set_id':'X','source_id':'X'}]
    if not shared:
        sources.append({'source_id':'Y','kind':'random' if strategy=='hybrid-cartesian' else 'list',
            'options':{'min_len':1,'max_len':1,'byte_range':(49,49),'seed':7} if strategy=='hybrid-cartesian' else {'payloads':(b'1',b'2',b'3')}})
        sets.append({'set_id':'Y','source_id':'Y'})
    value={'sources':tuple(sources),'sets':tuple(sets),'strategy':strategy,'positions':(
        {'position_id':'X','set_id':'X','operation':'overwrite','offset':0},
        {'position_id':'Y','set_id':'X' if shared else 'Y','operation':'overwrite','offset':1})}
    app,traces,result,records=execute(application_factory,tmp_path,strategy,value)
    assert result.outcome=='completed' and offers(traces)==list(expected)
    assert result.prepared_cases==result.selected_cases==result.prepared_variants==result.executed_variants==result.fuzz_tests==len(expected)
    requests=[r.data['request'] for r in records if r.kind=='case_start']
    assert [r['campaign']['case_number'] for r in requests]==list(range(1,len(expected)+1))
    if strategy=='hybrid-cartesian':
        assert [next(c for c in r['row']['contributions'] if c['set_id']=='Y')['source_result']['index'] for r in requests]==[1,2]
    # Every strategy retains original row/source/materialization identities when
    # an explicit numbered selection intersects skip. No omitted packet is sent.
    last = len(expected)
    _, selected_trace, selected, selected_records = execute(application_factory, tmp_path,
        strategy + '-selected', value, CampaignOptions(selected_cases=(1, last), skip=1))
    assert offers(selected_trace) == [expected[-1]]
    assert selected.selected_cases == selected.fuzz_tests == 1
    assert evidence(selected_records) == {key: item for key, item in evidence(records).items() if key[0] == last}


@pytest.mark.parametrize('filtered',[False,True])
def test_empty_and_allfiltered_no_traffic(tmp_path,application_factory,filtered):
    value={'sources':({'source_id':'S','kind':'list','options':{'payloads':(b'',b'') if filtered else ()}},),
        'sets':({'set_id':'S','source_id':'S','transforms':({'mutator_id':'empty','kind':'filter_empty'},) if filtered else ()},),
        'positions':({'position_id':'P','set_id':'S','operation':'append'},)}
    app,traces,result,records=execute(application_factory,tmp_path,'empty',value)
    assert result.outcome=='completed' and result.prepared_cases==result.executed_variants==result.fuzz_tests==0
    assert offers(traces)==[] and not any(r.kind=='case_start' for r in records)
    assert result.preparation_summary['dispositions']==(2 if filtered else 0)


def rich(tmp_path):
    source=tmp_path/'lines.bin';source.write_bytes(b'#ignore\n7a\n\n59\n5858\n')
    return {'sources':(
        {'source_id':'X','kind':'random','options':{'min_len':1,'max_len':3,'count':3,'seed':13,'length_scope':'sample_once'}},
        {'source_id':'Y','kind':'random','options':{'min_len':1,'max_len':3,'count':3,'seed':22,'content_scope':'sample_once'}},
        {'source_id':'Z','kind':'file','options':{'path':str(source),'source_mode':'lines'}}),
        'sets':({'set_id':'X','source_id':'X','transforms':({'mutator_id':'x-bit','kind':'mutate','options':{'operation':'flip_bit','seed':8}},)},
                {'set_id':'Y','source_id':'Y','transforms':({'mutator_id':'y-byte','kind':'mutate','options':{'operation':'flip_byte','seed':14,'scopes':{'index':'sample_once'}}},)},
                {'set_id':'Z','source_id':'Z','transforms':({'mutator_id':'comments','kind':'filter_comments'}, {'mutator_id':'empty','kind':'filter_empty'}, {'mutator_id':'decode','kind':'hex_decode'})}),
        'positions':({'position_id':'X','set_id':'X','operation':'overwrite','offset':2,'offset_range':(2,4),'offset_seed':55,'offset_scope':'sample_once'},
                     {'position_id':'Y','set_id':'Y','operation':'overwrite','offset':7,'offset_range':(7,9),'offset_seed':66},
                     {'position_id':'Z','set_id':'Z','operation':'append'}),'strategy':'zip'}


def normalize(value):
    """Only run-specific iteration identity is removed; choices/indices remain."""
    if hasattr(value,'items'):
        return {k:normalize(v) for k,v in value.items() if k!='iteration_id'}
    if isinstance(value,tuple):return tuple(normalize(v) for v in value)
    return value


def evidence(records):
    result={}
    for record in records:
        if record.kind!='case_start':continue
        request=record.data['request'];identity=request['campaign']
        row=request['row'];key=(identity['case_number'],identity['variant_id'])
        for c in row['contributions']:
            action=next(p['action_id'] for p in row['placements'] if p['contribution_id']==c['contribution_id'])
            assert all(choice['iteration_id']==request['conversation_id']+':'+action for choice in c['random_choices'] if choice['scope']=='per_test')
        result[key]=normalize({'row':row,'materialized':record.data['materialized'],'calculations':request['calculations']})
        for material in record.data['materialized'][1:]:
            body=bytearray(material['seed'])
            for placement in (p for p in row['placements'] if p['action_id']==material['action_id']):
                data=next(c['data'] for c in row['contributions'] if c['contribution_id']==placement['contribution_id'])
                if placement['operation']=='append':body.extend(data)
                else:body[placement['offset']:placement['offset']+len(data)]=data
            body[:2]=(4 if identity['variant_id']=='length4' else len(body)-2).to_bytes(2,'big')
            assert material['final_bytes']==bytes(body)
    return result


def test_full_single_range_sparse_skip_multisend_three_sources(tmp_path,application_factory):
    value=rich(tmp_path)
    plan=positional_plan((b'SETUP',b'\0\0abcdefghij',b'\0\0ABCDEFGHIJ'))
    calculations=tuple(Calculation('length-'+a,a,'payload_length',0,2,payload_offset=2) for a in ('2','3'))
    variants=('normal','length4')
    app,traces,result,records=execute(application_factory,tmp_path,'full',value,CampaignOptions(variants=variants),plan,calculations)
    full=evidence(records)
    assert (result.prepared_cases,result.prepared_variants,result.executed_variants,result.fuzz_tests,result.setup_sends)==(3,6,6,12,6)
    assert len(offers(traces))==18 and len(full)==6
    for name,numbers,skip,wanted in (('single',(3,),0,(3,)),('range',(2,3),0,(2,3)),('sparse',(1,3),0,(1,3)),('skip',(),1,(2,3)),('intersection',(1,2,3),2,(3,))):
        _,subset_trace,subset,subset_records=execute(application_factory,tmp_path,name,value,CampaignOptions(selected_cases=numbers,skip=skip,variants=variants),plan,calculations)
        actual=evidence(subset_records)
        assert actual=={key:v for key,v in full.items() if key[0] in wanted}
        assert subset.fuzz_tests==len(wanted)*4 and subset.executed_variants==len(wanted)*2
        assert all(offers(subset_trace)[i]==b'SETUP' for i in range(0,len(offers(subset_trace)),3))
    rows=[r.data['request']['row'] for r in records if r.kind=='case_start']
    reservoirs=[choice['resolved'] for row in rows for c in row['contributions'] if c['set_id']=='Y' for choice in c['random_choices'] if choice['owner']=='source' and choice['option']=='content']
    assert len(set(reservoirs))==1
    units=[choice['resolved']['unit'] for row in rows for c in row['contributions'] if c['set_id']=='Y' for choice in c['random_choices'] if choice['owner']=='mutator' and choice['option']=='y-byte.index.0']
    assert len(set(units))==1
    ys=[c for row in rows for c in row['contributions'] if c['set_id']=='Y']
    assert len({len(c['source_result']['data']) for c in ys})>1
    for c in ys:
        reservoir=next(choice['resolved'] for choice in c['random_choices'] if choice['owner']=='source' and choice['option']=='content')
        length=next(choice['resolved'] for choice in c['random_choices'] if choice['owner']=='source' and choice['option']=='length')
        assert c['source_result']['data']==reservoir[:length]
    index_bounds={choice['bounds'] for c in ys for choice in c['random_choices'] if choice['option']=='y-byte.index.0'}
    assert len(index_bounds)>1


@pytest.mark.parametrize('prefix,final,expected',[(False,False,('0003414243','0004414243')),
    (True,False,('ff0003414243','ff0004414243')),
    (True,True,('ffffff414243','ffffff414243'))])
def test_exact_two_byte_length_shift_and_final_authority(tmp_path,application_factory,prefix,final,expected):
    from bytefault.core.contracts import PreparedRow, PreparedContribution, SourceInvocation, Placement
    app,traces=application_factory(monitoring=Monitoring(ConfiguredPolicy()))
    request=base(tmp_path,'length')
    action=replace(request.conversation.plan.actions[0],seed=bytes.fromhex('000141'))
    row=PreparedRow('baseline',1)
    if final:
        row=replace(row,contributions=(PreparedContribution('final',b'\xff\xff',SourceInvocation('final','literal')),),
            final_overrides=(Placement('final','final','1','overwrite',1),))
    request=replace(request,conversation=replace(request.conversation,plan=replace(request.conversation.plan,actions=(action,)),
        row=row,repair=True,calculations=(Calculation('length','1','payload_length',0,2,payload_offset=2),)))
    value={'sources':({'source_id':'S','kind':'literal','options':{'data':b'BC'}},),
        'sets':({'set_id':'S','source_id':'S'},),'positions':({'position_id':'P','set_id':'S','operation':'append'},)}
    if prefix:
        value['sources']+=({'source_id':'prefix','kind':'literal','options':{'data':b'\xff'}},)
        value['sets']+=({'set_id':'prefix','source_id':'prefix'},)
        value['positions']=({'position_id':'prefix','set_id':'prefix','operation':'insert','offset':0},)+value['positions']
        value['strategy']='zip'
    result=app.campaign(request,generation=value,options=CampaignOptions(variants=('normal','length4')))
    assert result.fuzz_tests==result.executed_variants==2 and result.selected_cases==1
    assert offers(traces)==[bytes.fromhex(x) for x in expected]


def test_prepared_baseline_accounting_named_and_raw_preserves_final_authority(tmp_path, application_factory):
    from bytefault.core.contracts import (PreparedRow, PreparedContribution, SourceInvocation,
        Placement, FieldLocation, ContractError)
    for final in (False, True):
        app, traces = application_factory(monitoring=Monitoring(ConfiguredPolicy()))
        request = base(tmp_path, 'baseline-' + str(final))
        action = replace(request.conversation.plan.actions[0], seed=b'ABCDE', fields=(
            FieldLocation('body', 1, 2, variable=True), FieldLocation('tail', 3, 2),
            FieldLocation('body', 0, 1, buffer_id='logical')))
        row = PreparedRow('base', 1, (PreparedContribution('base', b'WXYZ', SourceInvocation('base', 'literal')),),
            (Placement('base', 'base', '1', 'replace', field_id='body'),))
        if final:
            row = replace(row, contributions=(*row.contributions,
                PreparedContribution('last', b'!', SourceInvocation('last', 'literal'))),
                final_overrides=(Placement('last', 'last', '1', 'append'),))
        request = replace(request, conversation=replace(request.conversation,
            plan=replace(request.conversation.plan, actions=(action,)), row=row))
        value = {'sources': ({'source_id': 'S', 'kind': 'literal', 'options': {'data': b'Z'}},),
            'sets': ({'set_id': 'S', 'source_id': 'S'},), 'strategy': 'one-position',
            'positions': tuple({'position_id': name, 'set_id': 'S', 'operation': 'replace', 'field_id': name}
                               for name in ('body', 'tail'))}
        result = app.campaign(request, generation=value)
        suffix = b'!' if final else b''
        assert result.outcome == 'completed' and offers(traces) == [b'AZDE' + suffix, b'AWXYZZ' + suffix]
        starts = [r.data.request for r in app.read_records(result.run_id).records if r.kind == 'case_start']
        for current in starts:
            selected = current.row.selection.bounds.per_action_selection['1']
            assert selected.unmodified_seed == b'AWXYZDE'
            assert tuple(b.baseline for b in selected.selection.bindings) == (b'WXYZ', b'DE')
            assert current.plan.actions[0].seed == b'ABCDE'  # execution applies each edit once
            assert current.row.placements[0].contribution_id == 'base'
            assert bool(current.row.final_overrides) is final
        assert starts[1].row.placements[-1].field_id == 'tail'
        location = starts[1].row.selection.bounds.per_action_selection['1']
        assert location.unmodified_seed[5:7] == b'DE'
        raw = {**value, 'strategy': 'zip', 'positions': ({'position_id': 'raw', 'set_id': 'S',
            'operation': 'replace', 'offset': 3, 'end': 'seed', 'baseline': b'YZDE'},)}
        raw_request = replace(request, conversation=replace(request.conversation,
            run_id='raw-' + str(final)), record_path=str(tmp_path / ('raw-' + str(final) + '.bfr')))
        raw_result = app.campaign(raw_request, generation=raw)
        assert raw_result.last_conversation.actions[0].transport.offered == b'AWXZ' + suffix
        raw_start = next(r.data.request for r in app.read_records(raw_result.run_id).records if r.kind == 'case_start')
        assert raw_start.row.placements[-1].end == 7
        assert raw_start.row.selection.bindings[0].baseline == b'YZDE'

    # An edit crossing a field boundary cannot invent a usable named identity.
    crossing = replace(request, conversation=replace(request.conversation, run_id='crossed',
        row=replace(row, placements=(Placement('base', 'base', '1', 'replace', 0, 2),))),
        record_path=str(tmp_path / 'crossed.bfr'))
    count = len(offers(traces))
    with pytest.raises(ContractError, match='unknown_field_location'):
        app.campaign(crossing, generation=value)
    assert len(offers(traces)) == count


def test_index_pool_reuse_keeps_source_and_refreshes_mutation(tmp_path,application_factory):
    value={'sources':({'source_id':'X','kind':'random','options':{'min_len':2,'max_len':2,'count':1,'seed':4}},
        {'source_id':'Y','kind':'list','options':{'payloads':(b'1',b'2',b'3')}}),
        'sets':({'set_id':'X','source_id':'X','pool_mode':'reuse','transforms':({'mutator_id':'mutate','kind':'mutate','options':{'operation':'flip_byte','seed':7}},)},
                {'set_id':'Y','source_id':'Y'}),'positions':({'position_id':'X','set_id':'X','operation':'overwrite','offset':0},
                {'position_id':'Y','set_id':'Y','operation':'append'}),'strategy':'cartesian'}
    _,traces,result,records=execute(application_factory,tmp_path,'reuse',value)
    rows=[r.data['request']['row'] for r in records if r.kind=='case_start']
    sources=[next(c for c in r['contributions'] if c['set_id']=='X') for r in rows]
    assert len({c['source_result']['sample_id'] for c in sources})==1
    assert len({c['source_result']['data'] for c in sources})==1
    assert len({c['data'] for c in sources})>1
    assert offers(traces)==[c['data']+b'C'+str(i).encode() for i,c in enumerate(sources,1)]
    _,selected_trace,selected,selected_records=execute(application_factory,tmp_path,'reuse-subset',value,CampaignOptions(selected_cases=(2,3)))
    assert offers(selected_trace)==offers(traces)[1:]
    assert selected.fuzz_tests==2
