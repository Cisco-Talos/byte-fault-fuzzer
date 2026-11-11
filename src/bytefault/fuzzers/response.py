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

"""One passive inbound interpretation shared by ordinary and retry setup routes."""
from bytefault.core.contracts import ResponseFieldValue, ResponseInterpretation


def interpret_response(action, transport, following):
    values = []
    for field in action.response_fields:
        data = b''
        if not transport.receive_requested:
            outcome = 'unrequested'
        elif field.offset is None or field.size is None:
            outcome = 'unknown_location'
        elif transport.receive_outcome in ('not_reached', 'unrequested'):
            outcome = 'not_observed'
        else:
            data = transport.received[field.offset:field.offset + field.size]
            outcome = 'available' if len(data) == field.size else 'short'
        values.append(ResponseFieldValue(field.field_id, field.offset, field.size, data, outcome))
    values = tuple(values)
    # A failed/unoffered exchange cannot supply a successful continuation, even
    # when its preserved partial reply happens to contain the selected literal.
    if transport.error or transport.acceptance != 'accepted':
        return ResponseInterpretation(values, 'uninterpreted', None)
    if not action.edges:
        target = action.next_action if action.next_action != '__ordered__' else following
        return ResponseInterpretation(values, 'uninterpreted', target)
    selector = action.edges[0].field_id
    value = next((v for v in values if v.field_id == selector), None) if selector is not None else None
    observed = transport.received if selector is None else (
        value.data if value.outcome == 'available' else None)
    edge = next((edge for edge in action.edges if observed == edge.literal), None)
    return ResponseInterpretation(values, edge.meaning if edge else 'unknown',
        edge.target if edge else action.unknown_target, edge is not None,
        selector, edge.literal if edge else None)
