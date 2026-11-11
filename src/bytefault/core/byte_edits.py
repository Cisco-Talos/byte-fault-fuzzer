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

"""Exact ordered computations over supplied byte values; no orchestration."""
from .contracts import MaterializedAction, ResolvedPlacement, ContractError, FinalFieldLocation
from .calculations import calculation_size, calculation_problem, calculation_bytes


def materialize(action, row, calculations=(), repair=False):
    data = bytearray(action.seed)
    # Preserve identity of surviving seed bytes to locate a known calculated field.
    origins = list(range(len(data)))
    edited = [False] * len(data)
    traces, repairs = [], []
    contributions = {c.contribution_id: c.data for c in row.contributions}
    field_spans = {f.field_id: (f.offset, f.offset + f.size if f.size is not None else None)
                   if f.offset is not None else None for f in action.fields if f.buffer_id == action.buffer_id}

    def move_fields(start, end, length, operation, included_field=None):
        if operation == 'overwrite':
            return
        delta = length - (end - start)
        for name, span in tuple(field_spans.items()):
            if span is None:
                continue
            lo, hi = span
            if operation == 'replace' and hi is not None and start == lo and end == hi:
                field_spans[name] = (lo, lo + length)
            elif start == end:
                # Insertion at the start is before the field, at its end after it.
                if name == included_field:
                    field_spans[name] = (lo, hi + delta if hi is not None else None)
                elif start <= lo:
                    field_spans[name] = (lo + delta, hi + delta if hi is not None else None)
                elif hi is not None and start < hi:
                    field_spans[name] = (lo, hi + delta)
            elif end <= lo:
                field_spans[name] = (lo + delta, hi + delta if hi is not None else None)
            elif hi is not None and start >= hi:
                continue
            elif hi is not None and lo <= start and end <= hi:
                field_spans[name] = (lo, hi + delta)
            else:
                # An edit crossing a field boundary cannot invent a new identity.
                field_spans[name] = None

    def apply(placement):
        nonlocal data, origins, edited
        payload = contributions[placement.contribution_id]
        before = bytes(data)
        if placement.field_id is not None:
            span = field_spans.get(placement.field_id)
            if span is None or (placement.operation == 'replace' and span[1] is None):
                raise ContractError('row.placements.' + placement.placement_id,
                                    'unknown_field_location', placement.field_id)
            start = span[0]
        else:
            start = len(data) if placement.operation == 'append' else placement.offset
        if start > len(data):
            gap = start - len(data)
            data.extend(b'\0' * gap)
            origins.extend([None] * gap)
            edited.extend([True] * gap)
        if placement.operation in ('insert', 'append'):
            end = start
        elif placement.operation == 'overwrite':
            end = start + len(payload)
            if end > len(data):
                gap = end - len(data)
                data.extend(b'\0' * gap)
                origins.extend([None] * gap)
                edited.extend([True] * gap)
        else:
            end = span[1] if placement.field_id is not None else placement.end
            if end > len(data):
                gap = end - len(data)
                data.extend(b'\0' * gap)
                origins.extend([None] * gap)
                edited.extend([True] * gap)
        old_origins = origins[start:end]
        move_fields(start, end, len(payload), placement.operation,
            placement.field_id if placement.include_in_field else None)
        data[start:end] = payload
        # An overwrite preserves byte locations but marks every changed field byte.
        origins[start:end] = (old_origins if placement.operation == 'overwrite'
                              else [None] * len(payload))
        edited[start:end] = [True] * len(payload)
        traces.append(ResolvedPlacement(placement, payload, (start, end), before, bytes(data)))

    for p in row.placements:
        if p.action_id == action.action_id:
            apply(p)
    for calculation in calculations:
        if calculation.action_id != action.action_id:
            continue
        disposition = 'disabled'
        if repair or calculation.required or calculation.override_value is not None or calculation.rule == 'sequence':
            disposition = 'unavailable_rule_or_location'
            problem = calculation_problem(calculation, action)
            if not problem:
                size = calculation_size(calculation, action)
                if calculation.field_id is not None:
                    field = next(f for f in action.fields if f.field_id == calculation.field_id and
                                 f.buffer_id == calculation.buffer_id)
                    offset = field.offset
                else:
                    offset = calculation.offset
                if calculation.destination == 'append':
                    start = end = len(data)
                    positions = []
                elif offset + size <= len(action.seed):
                    original = range(offset, offset + size)
                    positions = [i for i, origin in enumerate(origins) if origin in original]
                    start = positions[0] if positions else 0
                    end = start + size
                    if (len(positions) != size or positions != list(range(start, end)) or
                            any(edited[i] for i in positions)):
                        disposition = 'explicit_edit'
                else:
                    start, end = offset, offset + size
                    positions = list(range(start, min(end, len(data))))
                    if any(edited[i] for i in positions):
                        disposition = 'explicit_edit'
                if disposition != 'explicit_edit':
                    if not problem:
                        try:
                            computed = calculation_bytes(calculation, data, size, start, end,
                                field_spans=field_spans, ordinal=row.ordinal)
                        except ContractError as exc:
                            problem = str(exc)
                            if calculation.required:
                                raise
                        except OverflowError as exc:
                            if calculation.required:
                                raise ContractError('calculations.' + calculation.calculation_id,
                                                    'calculation_overflow', str(exc)) from exc
                            disposition = 'unavailable_overflow'
                        else:
                            if start > len(data):
                                gap = start - len(data)
                                data.extend(b'\0' * gap)
                                origins.extend([None] * gap)
                                edited.extend([False] * gap)
                            old_origins = origins[start:end]
                            move_fields(start, end, len(computed), 'replace')
                            data[start:end] = computed
                            origins[start:end] = old_origins + [None] * (len(computed) - len(old_origins))
                            edited[start:end] = [False] * len(computed)
                            disposition = ('variant_override' if calculation.override_value is not None else
                                           'sequence' if calculation.rule == 'sequence' else 'repaired')
            if problem and calculation.required:
                raise ContractError('calculations.' + calculation.calculation_id,
                                    'unsupported_capability', problem)
            if calculation.override_value is not None and disposition in (
                    'unavailable_rule_or_location', 'explicit_edit_or_unavailable_location', 'unavailable_location'):
                raise ContractError('calculations.' + calculation.calculation_id, 'variant_unavailable',
                                    'known surviving length-field location required')
        repairs.append((calculation.calculation_id, disposition))
    for p in row.final_overrides:
        if p.action_id == action.action_id:
            apply(p)
    final_fields = []
    for location in action.fields:
        # Output eligibility cannot make an initially unavailable identity known
        # merely because later padding/appending happens to create bytes there.
        span = field_spans.get(location.field_id) if location.buffer_id == action.buffer_id else None
        if (location.offset is None or location.offset > len(action.seed) or
                (location.size is not None and location.offset + location.size > len(action.seed))):
            span = None
        if span is not None and (not 0 <= span[0] <= len(data) or
                (span[1] is not None and not span[0] <= span[1] <= len(data))):
            span = None
        offset, size = ((span[0], None if span[1] is None else span[1] - span[0])
                        if span is not None else (None, None))
        final_fields.append(FinalFieldLocation(action.action_id, location.buffer_id,
                            location.field_id, offset, size, location.variable))
    return MaterializedAction(action.action_id, action.seed, bytes(data), tuple(traces), tuple(repairs),
                              tuple(final_fields))
