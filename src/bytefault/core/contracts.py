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

"""UI-free value contracts. Local acceptance never asserts wire delivery."""
from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from types import MappingProxyType
from collections.abc import Mapping
from typing import Any


@dataclass(frozen=True)
class TransportRequest:
    host: str
    port: int
    timeout: float
    pre_delay: float = 0.0
    post_delay: float = 0.0
    connection_delay: float = 0.0


@dataclass(frozen=True)
class ReceiveRequest:
    requested: bool = True
    cap: int = 4096
    deadline: float = 3.0
    length_offset: int | None = None
    length_size: int = 2
    length_endian: str = "big"
    length_counts: str = "body"


@dataclass(frozen=True)
class TransportResult:
    prepared: bytes
    offered: bytes = b""
    accepted_prefix: bytes = b""
    accepted_count: int | None = 0
    acceptance: str = "not_offered"
    receive_requested: bool = False
    received: bytes = b""
    receive_outcome: str = "unrequested"
    response_boundary: str = "unknown"
    error: str | None = None
    offer_completed_at: float | None = None
    first_response_at: float | None = None
    receive_completed_at: float | None = None
    error_type: str | None = None
    connection: Mapping | None = None


@dataclass(frozen=True)
class TransportCleanup:
    """Local close-call evidence, separate from send/receive or target effects.

    Completed means close returned; uncertain means close raised, not that an
    OS resource is proven open. No repeated close follows an uncertain result.
    A post-delay error does not rewrite the independently known close outcome.
    """
    phase: str = 'conversation'
    outcome: str = 'not_attempted'
    error: str | None = None
    error_type: str | None = None
    pacing_error: str | None = None
    pacing: Mapping | None = None


@dataclass(frozen=True)
class ControlOutcome:
    command: str
    outcome: str
    reason: str = ""


@dataclass(frozen=True)
class EngineStatus:
    state: str
    paused: bool
    stop_requested: bool
    connected: bool
    last_transport: TransportResult | None
    presentation_dropped: int = 0
    presentation_failed: int = 0
    presentation_discarded_on_close: int = 0
    monitoring_hold: str | None = None
    required_record_failure: str | None = None
    cleanup: TransportCleanup | None = None


class ValueSnapshot(Mapping):
    """Recursively immutable value object with mapping and attribute reads."""
    __slots__ = ("_values",)

    def __init__(self, values):
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __setattr__(self, name, value):
        raise TypeError("event snapshots are immutable")

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __getattr__(self, name):
        try:
            return self._values[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def freeze(value: Any):
    from bytefault.core.provenance import is_view
    if is_view(value):
        return value
    if is_dataclass(value):
        return ValueSnapshot((f.name, freeze(getattr(value, f.name))) for f in fields(value))
    if isinstance(value, Mapping):
        return ValueSnapshot((k, freeze(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(freeze(v) for v in value)
    if isinstance(value, bytearray):
        return bytes(value)
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    raise TypeError(f"unsupported event value: {type(value).__name__}")


class ContractError(ValueError):
    """Attributed pretraffic refusal, including explicitly unavailable intent."""
    def __init__(self, path: str, code: str, message: str):
        self.path, self.code = path, code
        super().__init__(f"{path}: {code}: {message}")


@dataclass(frozen=True)
class Capability:
    name: str
    parameters: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'parameters', freeze(self.parameters))


@dataclass(frozen=True)
class ResponseEdge:
    literal: bytes
    target: str | None
    meaning: str  # an explicit declared meaning, not an engine auth assumption
    field_id: str | None = None  # None retains exact whole-response equality


@dataclass(frozen=True)
class ResponseField:
    """Known inbound byte span; None preserves an unknown location or extent."""
    field_id: str
    offset: int | None = None
    size: int | None = None


@dataclass(frozen=True)
class ResponseFieldValue:
    field_id: str
    offset: int | None
    size: int | None
    data: bytes
    outcome: str  # available, short, unknown_location, unrequested, not_observed


@dataclass(frozen=True)
class ResponseInterpretation:
    fields: tuple[ResponseFieldValue, ...]
    meaning: str
    target: str | None
    matched: bool | None = None
    field_id: str | None = None
    literal: bytes | None = None


@dataclass(frozen=True)
class FieldLocation:
    """Passive seed span, scoped by its containing action and buffer.

    None denotes unknown location/extent. Width is guidance, never a payload cap.
    Spans follow ordered edits; a replacement owns the replacement bytes.
    """
    field_id: str
    offset: int | None = None
    size: int | None = None
    buffer_id: str = 'outbound'
    variable: bool = False


@dataclass(frozen=True)
class ConversationAction:
    action_id: str
    seed: bytes
    stage_id: str = ''
    buffer_id: str = 'outbound'
    receive: ReceiveRequest = field(default_factory=lambda: ReceiveRequest(requested=False))
    edges: tuple[ResponseEdge, ...] = ()
    unknown_target: str | None = None
    kind: str = 'send'
    next_action: str | None = '__ordered__'
    fields: tuple[FieldLocation, ...] = ()
    response_fields: tuple[ResponseField, ...] = ()


@dataclass(frozen=True)
class PassivePlan:
    declaration_id: str
    version: int
    actions: tuple[ConversationAction, ...]
    stages: tuple[str, ...] = ()
    required_capabilities: tuple[Capability, ...] = ()
    entry_action: str | None = None


@dataclass(frozen=True)
class RandomChoice:
    choice_id: str
    owner: str  # source, mutator, placement
    option: str
    bounds: tuple[int, int]
    scope: str = 'per_test'
    resolved: Any = None
    iteration_id: str | None = None

    def __post_init__(self):
        object.__setattr__(self, 'resolved', freeze(self.resolved))


@dataclass(frozen=True)
class SourceInvocation:
    source_id: str
    mode: str  # literal/file/whole_file/line_file/list/dataset/seed_directory;
               # generator/iterator/random/sweep/edge/mutation/prepared
    module: str | None = None
    options: Mapping = field(default_factory=dict)
    input_reference: str | None = None

    def __post_init__(self):
        object.__setattr__(self, 'options', freeze(self.options))


@dataclass(frozen=True)
class MutatorInvocation:
    mutator_id: str
    module: str
    options: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'options', freeze(self.options))


@dataclass(frozen=True)
class SourceResult:
    source_id: str
    data: bytes
    index: int
    input_reference: str | None = None
    sample_id: str | None = None


@dataclass(frozen=True)
class MutatorResult:
    mutator_id: str
    input_data: bytes
    output_data: bytes
    transformation: str


@dataclass(frozen=True)
class PreparedContribution:
    contribution_id: str
    data: bytes
    source: SourceInvocation
    mutators: tuple[MutatorInvocation, ...] = ()
    set_id: str = ''
    set_index: int = 1
    random_choices: tuple[RandomChoice, ...] = ()
    source_result: SourceResult | None = None
    mutator_results: tuple[MutatorResult, ...] = ()


@dataclass(frozen=True)
class PositionBinding:
    placement_id: str
    set_id: str
    contribution_id: str
    baseline: bytes = b''
    choice: str = 'selected'  # selected, baseline, held, shared


@dataclass(frozen=True)
class SelectionIntent:
    strategy: str = 'prepared'
    bindings: tuple[PositionBinding, ...] = ()
    dimension_order: tuple[str, ...] = ()
    selected_cases: tuple[int, ...] = ()
    skip: int = 0
    seed: int | str | None = None
    bounds: Mapping = field(default_factory=dict)
    exhaustion: str = 'prepared'

    def __post_init__(self):
        object.__setattr__(self, 'bounds', freeze(self.bounds))


@dataclass(frozen=True)
class Placement:
    placement_id: str
    contribution_id: str
    action_id: str
    operation: str
    offset: int | None = None
    end: int | None = None
    buffer_id: str = 'outbound'
    coordinate: str = 'working'
    random_choices: tuple[RandomChoice, ...] = ()
    field_id: str | None = None
    include_in_field: bool = False


@dataclass(frozen=True)
class PreparedRow:
    row_id: str
    ordinal: int
    contributions: tuple[PreparedContribution, ...] = ()
    placements: tuple[Placement, ...] = ()
    selection: SelectionIntent = field(default_factory=SelectionIntent)
    final_overrides: tuple[Placement, ...] = ()


@dataclass(frozen=True)
class Calculation:
    calculation_id: str
    action_id: str
    rule: str
    offset: int | None = None
    size: int | None = None
    endian: str = 'big'
    payload_offset: int | None = None
    required: bool = False
    override_value: int | None = None
    sequence_start: int = 0
    sequence_step: int = 1
    sequence_wrap: int | None = None
    sequence_ordinal: int | None = None
    field_id: str | None = None
    buffer_id: str = 'outbound'
    destination: str = 'fixed'  # fixed seed offset, named field, or append
    counts: str = 'body'  # body/tail, full/packet, range, field
    counts_field: str | None = None
    range_start: int = 0
    range_end: int | None = None
    algorithm: str | None = None  # checksum: crc32, crc16, md5, sha1, sha256


@dataclass(frozen=True)
class CampaignIdentity:
    campaign_id: str
    case_number: int
    variant_id: str = 'normal'
    variant_number: int = 1


@dataclass(frozen=True)
class CampaignConnection:
    mode: str = 'fresh'
    reuse_entry_action: str | None = None
    reusable_after: tuple[str, ...] = ()
    reusable_meanings: tuple[str, ...] = ()
    retry_setup: tuple['CampaignSetupStep', ...] = ()


@dataclass(frozen=True)
class CampaignSetupStep:
    action_id: str
    choice: str = 'recorded'
    reapply_mutations: bool = False
    dynamic_source_reference: str | None = None


@dataclass(frozen=True)
class CampaignOptions:
    selected_cases: tuple[int, ...] = ()
    skip: int = 0
    case_limit: int | None = None
    variants: tuple[str, ...] = ('normal',)
    connection: CampaignConnection = field(default_factory=CampaignConnection)


@dataclass(frozen=True)
class CampaignResult:
    run_id: str
    outcome: str
    reason: str = ''
    prepared_cases: int = 0
    selected_cases: int = 0
    omitted_cases: int = 0
    fuzz_tests: int = 0
    attempts: int = 0
    setup_sends: int = 0
    missing_cases: tuple[int, ...] = ()
    last_conversation: Any = None
    cleanup: Any = None
    preparation_summary: Mapping = field(default_factory=dict)
    cleanup_errors: tuple[Mapping, ...] = ()
    monitoring: Mapping = field(default_factory=dict)
    prepared_variants: int = 0
    selected_variants: int = 0
    executed_variants: int = 0
    case_entry_attempts: int = 0
    setup_attempts: int = 0
    setup_retries: int = 0
    execution_outcome: str | None = None
    execution_reason: str = ''
    application_cleanup_errors: tuple[Mapping, ...] = ()
    # Complete finite literal-list projection. Generated streams retain ordered
    # case results in required records, without unbounded in-memory accumulation.
    literal_items: tuple[Mapping, ...] = ()
    resume: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'resume', freeze(self.resume))
        object.__setattr__(self, 'preparation_summary', freeze(self.preparation_summary))
        object.__setattr__(self, 'cleanup_errors', freeze(self.cleanup_errors))
        object.__setattr__(self, 'monitoring', freeze(self.monitoring))
        object.__setattr__(self, 'application_cleanup_errors', freeze(self.application_cleanup_errors))
        object.__setattr__(self, 'literal_items', freeze(self.literal_items))


@dataclass(frozen=True)
class ConversationRequest:
    plan: PassivePlan
    row: PreparedRow
    selected_actions: tuple[str, ...]
    run_id: str
    case_id: str
    conversation_id: str
    repair: bool = False
    calculations: tuple[Calculation, ...] = ()
    original_request: Mapping = field(default_factory=dict)
    campaign: CampaignIdentity | None = None
    # Files consumed by this prepared operation; not source recipe parameters or
    # generic reference labels. Reconstruction retires old operation files.
    input_files: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, 'original_request', freeze(self.original_request))


@dataclass(frozen=True)
class ResolvedPlacement:
    placement: Placement
    data: bytes
    span: tuple[int, int]
    before: bytes
    after: bytes


@dataclass(frozen=True)
class FinalFieldLocation:
    """Field location in final materialized bytes, never a seed-layout estimate.

    A known offset with size None retains an unknown extent. Both None denote
    an unavailable span; zero size is a known empty field at an available point.
    """
    action_id: str
    buffer_id: str
    field_id: str
    offset: int | None
    size: int | None
    variable: bool = False


@dataclass(frozen=True)
class MaterializedAction:
    action_id: str
    seed: bytes
    final_bytes: bytes
    placements: tuple[ResolvedPlacement, ...] = ()
    calculations: tuple[tuple[str, str], ...] = ()
    # None means final-location evidence was not retained (including old records).
    # An empty tuple means current materialization has no declared fields.
    final_fields: tuple[FinalFieldLocation, ...] | None = None


@dataclass(frozen=True)
class ActionResult:
    action_id: str
    stage_id: str
    iteration_id: str | None
    attempt_id: str
    materialized: MaterializedAction
    transport: TransportResult
    response_meaning: str = 'uninterpreted'
    # None distinguishes older records without retained interpretation evidence.
    response_interpretation: ResponseInterpretation | None = None


@dataclass(frozen=True)
class ConversationResult:
    run_id: str
    case_id: str
    conversation_id: str
    row_id: str
    outcome: str
    actions: tuple[ActionResult, ...]
    planned_actions: tuple[str, ...]
    unreached: tuple[tuple[str, str], ...]
    reason: str = ''
    cleanup: TransportCleanup | None = None
    execution_outcome: str | None = None
    execution_reason: str = ''
    application_cleanup_errors: tuple[Mapping, ...] = ()


@dataclass(frozen=True)
class Correlation:
    run_id: str
    case_id: str
    conversation_id: str
    action_id: str
    attempt_id: str
    iteration_id: str | None = None
    stage_id: str = ''


@dataclass(frozen=True)
class Observation:
    observation_id: str
    correlation: Correlation
    transport: TransportResult
    kind: str = 'action'
    service_readiness: str = 'unknown'
    observed_at: float | None = None
    prior_observation_id: str | None = None
    response_meaning: str = 'uninterpreted'
    parameters: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'parameters', freeze(self.parameters))


@dataclass(frozen=True)
class CampaignPolicyContext:
    campaign_id: str
    target_id: str
    test_id: str
    correlation: Correlation
    attempt_number: int
    response_meaning: str = 'uninterpreted'
    now: float = 0.0
    recovery_elapsed: float = 0.0
    recovery_exhausted: bool = False
    reconnect_exhausted: bool = False
    executed_test_number: int = 0
    final: bool = False


@dataclass(frozen=True)
class CampaignDirective:
    decision_id: str
    campaign_id: str
    test_id: str | None
    correlation: Correlation
    operation: str
    wait_seconds: float = 0.0
    reason: str = ''
    throttled: bool = False
    unrecovered: bool = False
    facts: Mapping = field(default_factory=dict)
    probes: tuple['ProbeRequest', ...] = ()
    scope: str = 'test'
    candidate_id: str | None = None

    def __post_init__(self):
        object.__setattr__(self, 'facts', freeze(self.facts))


@dataclass(frozen=True)
class CampaignSetupContext:
    campaign_id: str
    target_id: str
    candidate_id: str
    correlation: Correlation
    governed_actions: tuple[str, ...]
    used_retries: int = 0
    elapsed: float = 0.0
    response_meaning: str = 'uninterpreted'
    declared_target: str | None = None
    continuation_available: bool = False
    reconnect_exhausted: bool = False
    failure_recorded: bool = False


@dataclass(frozen=True)
class Assessment:
    assessment_id: str
    observation_id: str
    correlation: Correlation
    rule: str
    classification: str
    uncertainty: str
    parameters: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'parameters', freeze(self.parameters))


@dataclass(frozen=True)
class MonitoringAction:
    action_id: str
    event_id: str
    observation_id: str
    correlation: Correlation
    kind: str
    parameters: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'parameters', freeze(self.parameters))


@dataclass(frozen=True)
class ProbeRequest:
    probe_id: str
    observation_id: str
    correlation: Correlation
    prepared: bytes
    receive: ReceiveRequest = field(default_factory=lambda: ReceiveRequest(requested=False))
    kind: str = 'same_connection'
    decision_id: str | None = None
    delay: float = 0.0
    timeout: float = 3.0
    purpose: str = 'periodic'
    window: tuple[str, ...] = ()
    predicate: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, 'predicate', freeze(self.predicate))


@dataclass(frozen=True)
class MonitoringObligation:
    condition: str
    followup_action_id: str | None = None


@dataclass(frozen=True)
class MonitoringDecision:
    decision_id: str
    observation_id: str
    correlation: Correlation
    disposition: str  # continue, hold, stop
    mode: str = 'nonblocking'  # nonblocking or awaited
    required_conditions: tuple[str, ...] = ()
    assessments: tuple[Assessment, ...] = ()
    actions: tuple[MonitoringAction, ...] = ()
    probes: tuple[ProbeRequest, ...] = ()
    reason: str = ''
    obligations: tuple[MonitoringObligation, ...] = ()
    hold_timeout: float | None = None
    on_expiry: str = 'hold'
    on_failure: str = 'hold'


@dataclass(frozen=True)
class MonitoringCompletion:
    completion_id: str
    decision_id: str
    observation_id: str
    correlation: Correlation
    condition: str
    status: str  # succeeded, failed, pending, disabled
    reference: str | None = None
    followup_action_id: str | None = None
