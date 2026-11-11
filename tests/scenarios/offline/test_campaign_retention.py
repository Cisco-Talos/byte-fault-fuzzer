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

"""Actual process termination of one campaign; recognition never resumes it."""
import time
import pytest
from bytefault.core.storage import reopen_records


@pytest.mark.parametrize('point',['materialized','postoffer','result','partialtail','retry_resume'])
def test_acknowledged_campaign_prefix_and_interrupted_second_attempt(campaign_storage_child,point):
    process,root=campaign_storage_child(point)
    deadline=time.monotonic()+5
    while not (root/'ready').exists() and process.poll() is None and time.monotonic()<deadline:
        time.sleep(.01)
    if not (root/'ready').exists():
        process.kill();out,error=process.communicate(timeout=5)
        pytest.fail(repr((process.returncode,out,error)))
    journal=root/'campaign.bfr';actions=root/'campaign.bfr.actions.bfr'
    before=journal.read_bytes(),actions.read_bytes()
    process.kill();process.wait(timeout=5)
    evidence,log=reopen_records(journal),reopen_records(actions)
    assert evidence.records[0].kind=='campaign_start'
    first=[r for r in evidence.records if r.identity.get('case_number')==1]
    assert any(r.kind=='case_terminal' and r.data['result']['outcome']=='completed' for r in first)
    assert any(r.kind=='action_result' and r.data['result']['transport']['accepted_prefix']==b'XA' for r in first)
    second=[r for r in evidence.records if r.identity.get('case_number')==2]
    assert len(evidence.incomplete_cases)==1
    assert evidence.incomplete_cases[0]['identity']['case_id']=='case:row:2'
    assert evidence.incomplete_cases[0]['identity']['conversation_id']=='conversation:row:2:variant:normal'
    assert not any(r.kind=='campaign_terminal' for r in evidence.records)
    assert (root/'offered').read_bytes()==(b'XA' if point=='materialized' else b'XAXB')
    if point=='materialized':
        assert second[-1].kind=='materialization' and not any(r.kind=='action_result' for r in second)
        assert second[-1].data['materialized']['final_bytes']==b'XB'
    if point in ('postoffer','partialtail'):
        assert not any(r.kind=='action_result' for r in second)
    if point=='result':
        assert second[-1].kind=='action_result'
        assert second[-1].data['result']['transport']['accepted_prefix']==b'XB'
    if point=='retry_resume':
        kinds=[r.kind for r in second]
        assert kinds.index('case_terminal')<kinds.index('retry_case_resume')
        resume=second[-1]
        assert resume.kind=='retry_case_resume'
        assert resume.data['directive']['correlation']['case_id']==resume.identity['case_id']
        assert resume.data['directive']['correlation']['iteration_id']==resume.identity['iteration_id']
        assert resume.data['materialized'][0]['final_bytes']==b'XB'
    if point=='partialtail':assert evidence.issue.kind=='incomplete'
    else:assert evidence.issue is None
    assert log.issue is None
    # Every full root frame before the marker has all required action-sink acks.
    assert [r.kind for r in evidence.records]==[r.kind for r in log.records]
    for retained,reference,logged in zip(evidence.records,evidence.refs,log.records):
        assert logged.identity==retained.identity
        assert logged.data['action']==retained.data
        assert logged.data['evidence_reference']['record_id']==reference.record_id
        assert logged.data['evidence_reference']['path']==reference.path
    assert (journal.read_bytes(),actions.read_bytes())==before
    assert reopen_records(journal).records==evidence.records
