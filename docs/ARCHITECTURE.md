# How Byte Fault Fuzzer works

Byte Fault Fuzzer has one application boundary for its command-line, callable Python and
optional terminal clients. `bytefault.py` starts the source-tree CLI;
`bytefault.application.Application` owns the in-process requests, runs, service
attachments and cleanup. The clients use the same request and result meanings.
The [API guide](API.md) gives the callable operations and ownership rules, and
the [usage guide](USAGE.md) gives operator workflows.

## From input to a conversation

1. The CLI or a Python caller selects a passive protocol declaration, target,
   source data and run options. `Application` validates the typed request.
   Discovery reads immediate protocol directories containing `protocol.json`
   and a referenced declaration; it does not import executable protocol code.
   The shipped Raw descriptor has no default port.
2. Sources and generators provide exact bytes or selected candidate sequences.
   Configured transforms and composition produce candidate values. The fuzzer
   prepares numbered cases and places contributions into the selected action
   buffers. Ordered placements and explicit final edits determine the bytes
   offered to transport; a field declaration does not restrict an explicit
   Raw edit.
3. The fuzzer owns the TCP connection, conversation path, sends, receives,
   campaign service checks, timing and continuation. A declared response edge
   guides a path only from the response actually observed. An unavailable
   capability is reported as a limit rather than delegated to a protocol-local
   client.

Preparation and validation can materialize bytes without opening a target
connection. Generated preparation still reads selected inputs and writes its
required preparation journal; it is not a filesystem-read-only operation.
Submission is the execution boundary. A saved case or literal
replay returns through the ordinary application and fuzzer path. See the
[passive schema](SCHEMA_SPEC.md), [Raw overview](../src/bytefault/protocols/raw/README.md)
and [Raw examples](../src/bytefault/protocols/raw/docs/USAGE.md).

## Observations, follow-up and evidence

The fuzzer records required case and action evidence and supplies transport
observations with run, case, action and attempt identities. Monitoring
classifies those observations under the selected rules and chooses actions or
wait conditions; the fuzzer enforces the continuation decision. Independent
ICMP reachability is a separate observation from a campaign service check.

Management coordinates selected follow-up, including core collection and
report requests. Collection uses the configured rsync/SSH path. Reporting
writes result bundles and supplied artifact associations. Action logs retain
ordinary activity even when no event produces a report. A report or copied
core is evidence of an observed event, not proof that a particular test caused
a crash. [USAGE](USAGE.md#monitoring-retrieval-and-maintenance) explains the
operator choices and paths.

Required records and action logs remain separate from optional terminal
rendering and event projections. If an event consumer misses an update, it can
read retained status and records through the owning `Application`. A new
process cannot reattach to an in-memory run by ID; saved cases and journal
readers use persisted evidence. A writable result root has one logical owner;
callers that supply an `Application` or service attachment retain its ownership.
The [API guide](API.md#results-and-required-evidence) describes these result
and lifetime contracts.

## Code boundaries

| Area | Current responsibility |
| --- | --- |
| `bytefault.application` and `bytefault.cli` | Validate and route public requests; the process or embedding caller owns its `Application` lifetime. |
| `bytefault.fuzzers` | Discover passive declarations, prepare cases, materialize actions, execute conversations and campaigns, and own fuzzing transport. |
| `bytefault.generators` | Read selected sources and produce or transform candidate values. |
| `bytefault.core` | Typed contracts, validation, byte calculations and storage helpers used by the owning modules. |
| `bytefault.monitoring` | Classify observations and choose configured follow-up and continuation. |
| `bytefault.management` | Coordinate collection, maintenance and report follow-up. |
| `bytefault.reporting` and `bytefault.logging` | Write result bundles and retain action history, respectively. |
| `bytefault.ui` | Render Plain or Rich views and send controls through the application; headless execution does not require it. |

For a new source or transform, preserve the source → candidate → placement
boundary. For a passive declaration, follow the [protocol authoring guide](ADDING_PROTOCOL.md)
and version-1 schema and admission operations; only Raw ships as a protocol
directory in this release. For a new client, use `Application` or its structured
process commands so execution,
control and evidence retain the same meanings.
