# Add a passive protocol directory

Byte Fault Fuzzer currently discovers TCP protocol descriptions from version-1 UTF-8 JSON
files. Only Raw ships with the source release. A new directory supplies data to
the ordinary fuzzer; it does not provide a Python plugin or a separate network
client. Use the [schema reference](SCHEMA_SPEC.md) for the full declaration
format and the [Raw directory](../src/bytefault/protocols/raw/README.md) for a
shipped example.

## 1. Create the directory

For an external protocol root, make an immediate child containing a descriptor
and its referenced declaration:

```text
custom-protocols/
  demo/
    protocol.json
    declaration.json
```

`custom-protocols` is the root passed to `--declaration-dir`; `demo` is only a
directory name. Without an explicit root, discovery uses
`src/bytefault/protocols`, so a directory placed there is also discovered.
The selected root is authoritative: Byte Fault Fuzzer does not fall back to the
default root when an explicit one is supplied.

## 2. Describe identity and transport

Put this minimal descriptor in `demo/protocol.json`:

```json
{
  "format_version": 1,
  "protocol_id": "demo",
  "transport": "tcp",
  "declaration": "declaration.json"
}
```

`format_version`, `protocol_id`, `transport` and `declaration` are required.
The selection name is `protocol_id` or an optional name in `aliases`, not the
directory name. Names and aliases must be nonempty and distinct ignoring case;
the declaration reference must be relative and stay inside this directory.
Only TCP and descriptor version 1 are admitted. Optional `defaults` can set a
TCP `port` (1–65535 or `null`), positive finite `timeout`, and nonnegative
finite `pre_delay` and `post_delay`. Omitting `defaults` leaves no default port,
a 3-second timeout and zero pre/post delays. A request must supply `--port` if
the descriptor has no port. The descriptor's name and the declaration's ID may
differ; both are retained in request provenance.

## 3. Describe the conversation

Put this minimal declaration in `demo/declaration.json`:

```json
{
  "declaration_id": "demo",
  "version": 1,
  "actions": [{"action_id": "send", "seed_hex": "4142"}]
}
```

`declaration_id`, `version` and a nonempty `actions` list are required; every
action needs a unique `action_id` and a hex `seed_hex` value (which may be
empty). This action declares bytes `41 42` and, with no `receive` object,
requests no reply. It is a single outbound send, with no protocol-specific
framing or authentication. Version 1 admits finite, acyclic paths of `send`
actions using the `outbound` buffer. To add stages, fields, receives or response-based
edges, use the [schema reference](SCHEMA_SPEC.md) and inspect the exact accepted
fields and capabilities with `schema`. Response edges require a requested
receive. Unknown JSON keys, duplicate keys, unavailable capabilities and
nonempty capability parameters are refused.

## 4. Inspect and validate without target traffic

From the unpacked project root, replace the root path and host as needed:

```text
python bytefault.py schema
python bytefault.py inspect --directory custom-protocols
python bytefault.py validate demo 192.0.2.10 --declaration-dir custom-protocols --port 9000 --seed-hex 4142
```

`schema` reports the application's fixed version-1 grammar; it has no directory
option. `inspect` reports discovered entries and admission issues in the chosen
root. `validate` binds the selected descriptor and materializes the requested
bytes without opening a target connection. `--seed-hex` supplies exact run
bytes in place of the one action's declared seed. A malformed or colliding
descriptor elsewhere in the selected root can prevent selection; a child
without `protocol.json` is reported as pending rather than imported. Python
files in a protocol directory are never imported by discovery.

For callable clients, `Application.inspect(directory=...)` reports the root;
`inspect_declaration(data)` reports admission status for a supplied declaration,
while `admit(data)` raises `ContractError` on refusal. Neither installs the
declaration. `resolve_protocol("demo", directory=...)` checks the complete
directory. `app.protocol_request("demo", host, directory=root, seed=b"AB", port=9000)`
binds it to an ordinary request; `app.validate(request)` materializes that
request without target traffic. Close a caller-owned
`Application` after use; see the [API guide](API.md#entry-and-requests).

## 5. Execute through the ordinary fuzzer

After validating the selection, submit with an intended host and port:

```text
python bytefault.py fuzz demo HOST --declaration-dir custom-protocols --port 9000 --seed-hex 4142
```

This sends the selected test bytes through the ordinary fuzzer. Campaign service
checks follow the selected monitoring configuration; see
[usage](USAGE.md#monitoring-retrieval-and-maintenance).
The fuzzer owns connection, conversation, final-byte and evidence behavior.
For a multi-action declaration, a whole `--seed-hex` input is unavailable.
Supply a prepared `ConversationRequest` to `protocol_request`, or pass its
`Application.export_request` JSON as `--request-json` to the CLI. Selected
actions must agree with that prepared conversation; see the
[API guide](API.md#input-and-passive-declarations).
Selection identifies which actions are fuzzed, not the entire execution path.
Execution starts at the declaration entry and may send unselected setup and
other actions along that path.
The passive format does not load executable protocol callbacks, custom
transports or automatic schema/dissector converters. A rule outside the
admitted version-1 fields and supported capabilities is unavailable through
this directory path.
