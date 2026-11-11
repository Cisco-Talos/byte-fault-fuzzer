# Passive declaration and authoring interface

See [how Byte Fault Fuzzer works](ARCHITECTURE.md) for the declaration's role in the
ordinary application and fuzzer path, and [add a passive protocol](ADDING_PROTOCOL.md)
for the current directory workflow.

This is the current version-1 data contract. Protocol directories supply JSON
specifications, not executable framing/authentication callbacks, clients or sockets.
The fuzzer interprets declarations and owns all fuzz traffic and final bytes.
The JSON files are the current Raw/discovery carrier, not a claim that version 1
expresses every protocol workflow. Preserve version-1 Raw and saved provenance
if the declaration format evolves. Only Raw currently ships a
`protocol.json`/`declaration.json` directory. No converter or Wireshark runtime
is required for the current application.

## Directory and declaration

A movable child of the default `src/bytefault/protocols` root, or of an explicitly
selected root, contains `protocol.json` and its referenced declaration. The
declaration path is relative to that child and cannot leave it. The descriptor names a unique
protocol ID and optional aliases, TCP transport, and validated port and timing
defaults:

```json
{"format_version":1,"protocol_id":"example","aliases":[],"transport":"tcp","declaration":"declaration.json","defaults":{"port":null,"timeout":3,"pre_delay":0,"post_delay":0}}
```

```json
{"declaration_id":"example","version":1,"actions":[{"action_id":"send","seed_hex":"00ff","fields":[{"field_id":"prefix","offset":0,"size":1},{"field_id":"unmapped","offset":null,"size":null}],"receive":{"requested":false}}]}
```

A declared action can omit fields entirely and use an empty seed. With no
`receive` object, an action does not request a reply; the shipped Raw declaration
explicitly requests one. Unknown location/extent is explicit `null`; omitted field
knowledge does not invent a span or disable absolute raw edits. A named edit
needs a known offset; a named replacement also needs a known size. An absolute
raw offset or range can still be edited without field knowledge.
Field identities are scoped by action and buffer. Final field spans are current
materialization facts, not necessarily their original seed coordinates.

Top-level declaration keys are `declaration_id`, `version`, `actions`, optional
`stages`, `entry_action` and `required_capabilities`. Actions have `action_id` and
`seed_hex`, optional `stage_id`, `buffer_id`, `kind`, `receive`, `edges`,
`unknown_target`, `next_action`, `fields` and `response_fields`. Inbound
`response_fields` contain `field_id`, `offset` and `size`; null coordinates retain
unknown knowledge. Response edges contain `literal_hex`, `target`, `meaning` and
optional `field_id`. Omitted/null `field_id` compares the whole response; a declared
inbound field selects only its actual bytes for equality. An edge requires
`receive.requested: true`. This complete declaration branches on one known byte:

```json
{
  "declaration_id": "edge-example",
  "version": 1,
  "actions": [
    {"action_id": "probe", "seed_hex": "41", "receive": {"requested": true},
     "response_fields": [{"field_id": "flag", "offset": 0, "size": 1}],
     "edges": [{"literal_hex": "01", "field_id": "flag", "target": "next", "meaning": "positive"}]},
    {"action_id": "next", "seed_hex": "42"}
  ]
}
```

The `probe` edge selects the same flag from observed replies `0142` and `0143`,
while retaining the entire reply. One action uses either whole-response edges or
one declared field selector. The selector must name a declared inbound field.
When its size is known, the literal length must match that size. Admission also
permits an explicitly unknown offset or size, but such a field has
`unknown_location` at interpretation and cannot match an edge until its span is
known. A short field,
an unrequested receive and an unobserved reply have distinct outcomes. Failed
transport cannot establish successful continuation. An unmatched edge follows
`unknown_target` when one is declared. These spans do not establish framing,
authentication or target state. An omitted field selector compares the whole
observed response. The current `schema` operation returns exact fields,
calculation rules, algorithms and capability names from the application.

Version 1 executes finite, acyclic action paths. Only send actions with the
`outbound` action buffer are admitted. `stages` are optional labels for action
selection; `entry_action` can choose a declared starting action. Without an explicit
`next_action` or edges, actions continue in declaration order. A `receive` object
can also set cap, deadline and supported length-header conventions; `schema`
lists its exact members. These declarations guide traffic but do not supply
protocol framing or an executable client.

## Inspect, admit and export

```text
python bytefault.py schema
python bytefault.py inspect-declaration '{"declaration_id":"empty","version":1,"actions":[{"action_id":"send","seed_hex":""}]}'
python bytefault.py admit '{"declaration_id":"empty","version":1,"actions":[{"action_id":"send","seed_hex":""}]}'
python bytefault.py export-declaration '{"declaration_id":"empty","version":1,"actions":[{"action_id":"send","seed_hex":""}]}'
```

The direct equivalents are `Application.declaration_schema()`,
`inspect_declaration(data)`, `admit(data)` and `export_declaration(plan)`.
Inspection retains the supplied passive value plus an available plan or attributed
error. Admission/export use strict version-1 grammar: unknown JSON keys, executable
values, colliding identities, unsupported versions and unavailable named capability
references refuse. Explicit unknown knowledge is not arbitrary unknown JSON keys.
Nonempty capability parameters are currently unsupported. A refusal identifies
`ContractError.path` and `.code`; it does not veto a separate schema-free raw input.
Process commands print tagged JSON values; the callable methods return the
corresponding typed values or mappings.

In JSON declarations, `actions`, `stages`, `required_capabilities`, `edges`,
`fields` and `response_fields` must be arrays when supplied, not strings,
objects or `null`. Callable admission also accepts Python tuples for these
sequences; typed `PassivePlan` admission is unchanged.

For programmatic authoring, `inspect_declaration(data)` returns a mapping with
`status` and either an admitted `plan` or an attributed `error`; `admit(data)`
raises `ContractError` on refusal and returns a typed `PassivePlan` on success.
Admitting a standalone declaration does not install a protocol directory or
start traffic. To select it by name, put it in a protocol directory under a
discovery root and set that directory's `protocol.json` to reference it. Then
select the descriptor through the application.
Generated or LLM-authored declarations use this same admission path; there is
no bundled LLM client or automatic execution of generated declarations.

Export/admit preserves known fields, explicit unknowns, capabilities, stage/action
identity, receives and response edges. `export_request`/`import_request` round-trip
a `ConversationRequest`, including its closed typed values, but not the enclosing
`ApplicationRequest` transport and evidence paths. Saved-case provenance preserves
the original version/declaration/intent; a later partial declaration does not
rewrite it.

## Construction and limits

Generators supply bytes; mutators transform/select/combine them; ordered fuzzer
placements choose the outbound action, buffer, coordinate and operation. Arbitrary
insert/overwrite/replacement/append and final edits remain available without fields.
Optional repair acts only at known unedited calculated locations. Explicit final
bytes are not silently repaired or shortened to a schema width.

See the [application API](API.md#input-and-passive-declarations) and
[saved-case operations](API.md#replay-saved-cases-and-resume). This data interface
does not load executable dissector code or claim complete protocol semantics.
