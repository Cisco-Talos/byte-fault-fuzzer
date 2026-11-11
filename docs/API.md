# Current application API

For the request, execution, follow-up and evidence flow between modules, see
[how Byte Fault Fuzzer works](ARCHITECTURE.md). This page defines the callable client
and its result and ownership contracts.

Byte Fault Fuzzer runs from the unpacked source tree with `python bytefault.py`. With
`src` on Python's module search path, `python -m bytefault` uses the same root
commands. The in-process boundary is `bytefault.application.Application`;
`bytefault.cli.execute_arguments(argv, application)` and
`bytefault.cli.resolve_arguments(argv, application=None)` provide the root command
client.
`execute_arguments` requires a supplied Application. `resolve_arguments` is
not uniformly preparation-only: generic submit and service commands can
execute. Without a supplied Application, the resolver may construct one but
owns and closes it after a complete result or error, draining admitted
Management work. A lazy preparation keeps that owner until exhaustion, error
or explicit `close()`; consume or close it. Cleanup failures are reported in
the result or preparation summary where those carry cleanup facts, and through
a stderr diagnostic. A supplied Application remains caller-owned. The process
launcher constructs, owns and drains its Application.
Direct `bytefault.fuzzers.cli.resolve_configuration(argv, application=None)`
also returns detached configuration and closes an Application it creates, on
success or error. Its `argument_request(argv)` helper uses the same ownership.
Root `--config PATH` reads and merges a text run configuration before the normal
command parser and resolver; a file/CLI overlap is rejected before execution.
`--help` bypasses configuration loading and does not validate the selected file.
Recorded argv remains the physical command line. Direct fuzz and replay module
launchers retain their own argument forms. See [usage](USAGE.md#text-run-configuration).

## Entry and requests

`Application.inspect(directory=None)` reports available passive directories,
operations and capabilities. `resolve_protocol(selection, directory=None)`
selects a discovered descriptor. `protocol_request(selection, host, *, seed=...,
port=..., ...)` builds a typed request from exact seed bytes or a prepared
`ConversationRequest` (supply exactly one). It can select action IDs or a declared
stage and override receive behavior. Raw has no default port: supply one even
for a prepared Raw request. `ApplicationRequest` contains a `ConversationRequest`,
`TransportRequest(host, port, timeout, pre_delay=0, post_delay=0,
connection_delay=0)`, and required record path; its log path is optional.
`protocol_request` chooses a run record path when none is supplied.
Without an explicit log path, the run action log uses the record path plus
`.actions.bfr`.
`CampaignRequest` adds case selection, generation or ordered literal cases, and
typed `MonitoringConfig` configuration. Conversation/run/case/action/attempt
identities stay distinct. `ContractError` carries `path`, `code` and a message
for invalid or unavailable selections.

Action/stage selection identifies fuzzed actions, not an execution allowlist.
Execution begins at the declared entry and can send unselected setup and other
actions along the selected response path.

`app.validate(ApplicationRequest)` materializes an ordinary request without
opening a target connection; its mapping has `request` and a tuple of
`materialized` actions with `final_bytes`. Run this example from the unpacked
source root; it adds `src` to the import path:

```python
from pathlib import Path
import sys

sys.path.insert(0, str(Path("src").resolve()))
from bytefault.application import Application

app = Application()
try:
    request = app.protocol_request("raw", "HOST", seed=b"\x00\xff",
                                   port=12345, no_receive=True)
    preview = app.validate(request)  # no target connection or submission
    print(preview["materialized"][0].final_bytes.hex())  # 00ff
finally:
    app.close()
```

`app.validate(CampaignRequest)` and `app.prepare(CampaignRequest)` return closable
campaign preparation. Iteration yields selected case families with materialized
actions; `summary` reports prepared, selected and omitted counts. Consume or
close the preparation explicitly. `app.submit(request)` executes
synchronously and returns a `ConversationResult` or `CampaignResult`.
`app.prepare(request, service_options=...)` can validate explicit service options
against the current owner configuration without applying them or starting
services. CLI `prepare` and `validate` use this preview for supplied credentials;
credentials alone do not select core collection. Execution validates the options
again when applying them. Generated preparation also writes a required
`RECORDS.preparation.bfr` journal, so network-free does not mean filesystem-read-only.
`app.start(request)` returns a `RunHandle` for asynchronous execution;
`wait(timeout)` returns the result, `None` while active, or rethrows the retained
execution exception. `status(run_id)`, `control(run_id, command)` and
`observe(run_id, after=cursor)` expose state, pause/resume/stop dispositions and
optional events. `status` includes `state`, `active`, `result`, `error`, engine
status and cleanup/recording facts. A control response reports completed or
rejected disposition. `app.prepare`, `app.validate` and `app.resolve_protocol`
do not submit target traffic; root `bytefault.cli.resolve_arguments` can
dispatch execution as described above.

## Input and passive declarations

`declaration_schema`, `inspect_declaration`, `admit`, `export_declaration`,
`export_request` and `import_request` are the passive authoring API. The version-1
format, optional known field spans, response edges and admission rules are in
the [schema guide](SCHEMA_SPEC.md). A declared response field can select observed
bytes for an edge; short, unrequested, unknown and unobserved replies remain
distinct. A response edge does not establish remote state or framing.
`export_request(conversation)` produces a closed JSON-compatible encoding of a
`ConversationRequest`; `import_request(data)` validates and restores that typed
conversation, including its run, case and conversation IDs. This round trip
does not produce a new execution identity. For another execution, the saved-case
API prepares a new request while retaining provenance. A manually built
`ApplicationRequest` for a new run needs a `ConversationRequest` with new
identities, plus transport and a record destination.

Sources provide exact whole files by default, selected line/list modes,
generators and mutation streams. Ordered placements choose action, buffer,
coordinate and insert/overwrite/replace/append operation. Explicit final bytes
are not silently shortened or repaired. Case selection retains original ordinal
identities. `single`, `one-position`, `broadcast`, `zip`, `cartesian` and
`hybrid-cartesian` have distinct combination rules; see [usage](USAGE.md#fuzz-and-replay).
For lazy generated inputs, `generate(base, configuration, *, limit=None,
campaign=None)` yields prepared requests; `validate_generated` and
`submit_generated` accept an ordinary `ApplicationRequest` base, configuration
and optional limit and yield ordinary validation or execution results. Campaign
bases are rejected before stream creation; use `prepare`/`submit` with a generated
`CampaignRequest` instead. The shared `generate` path still supports campaign
preparation. Consume or close these streams and inspect their `summary`.
The explicit `limit` bounds composed cases, not all source evaluation: filtering
can consume rejected candidates and Cartesian composition loads finite pools
before yielding. Without an explicit bound, an unbounded source remains unbounded.

## Results and required evidence

`ActionResult` holds materialized bytes, a `TransportResult` with offered bytes,
locally accepted prefix/count and receive facts, and response interpretation.
`ConversationResult` carries the conversation cleanup outcome. Local acceptance
does not prove remote receipt or target effect. A campaign result adds
selected/prepared/omitted counts, attempts, literal-item states, Monitoring and
cleanup facts. A known literal item that was never entered is `not_started`;
partial/failure/stop states preserve actual attempted work.

Required run journals and action logs are independent of optional UI events and
reports. `app.record_refs(run_id)` returns acknowledged references;
`app.read_records(run_id)` returns a `RecoveryResult` with `records`, aligned
`refs` and an optional `issue` for a missing, unreadable or damaged input.
`observe` returns events, cursor, drop/projection diagnostics and status. Recover
required records and status after an optional event gap or projection failure.
`bytefault.core.records.encode_value` / `decode_value` preserve bytes and typed
values in tagged process JSON; human report text is not an interchange format.
For a single result, process execution emits its primary JSON value first, then
separate late follow-up or nonclean cleanup rows. Lazy generated operations emit
per-row values and then a summary. A new process can read saved evidence but
cannot reattach an in-memory run handle from a prior process.

## Monitoring, collection and maintenance

Campaign service checks run by default after fuzz and replay tests; the default
mode uses a new connection at interval one. `--health-check-mode disabled` turns
them off for an explicit run. Monitoring classifies observations and selects
configured reporting, collection, waits or recovery. Independent ICMP heartbeat
is separate reachability evidence. A failed check does not prove process death
or associate a specific test with a core.

`--collect-cores` selects collection on the default failed-service rule;
credentials alone do not start SSH. Selected collection requires a key (optional
user, default `root`) or an explicit user and password; the modes conflict.
Both use one incremental rsync acquisition into a persistent cache. Newly
acquired cores receive report copies; a multiple-core report links each copy
under its exact acquired name when supplied by Collection, while structured
results retain copied paths and explicitly label unavailable names.
The newest core association is provisional, and older new cores remain unpaired.
An empty/no-new batch has no copied core. Explicit selected cleanup uses SSH and
is recorded separately. Selected collection needs local `rsync` and `ssh`.

`MaintenanceRequest` through `run_maintenance`, `Management.maintain`, or
`app.service('maintenance', request)` selects local and remote work by default.
Local-only and remote-only selections narrow that scope. Remote work requires a
host and one SSH credential mode; each selected operation has its own recorded
outcome. `run_maintenance(request, application=None)` can create and close its
own Application; the `app.service` route needs an attached Management owner.
The other `app.service(operation, request)` routes are `monitoring` with a typed
`Observation`, `management` with a `MonitoringAction`, and `reporting` with a
`ReportRequest`. Missing owner attachments return `Unavailable` where applicable.
`app.read_service_history(run_id=None, *, refresh=False)` returns an aligned batch of
records, references, per-path issues and generations. Required history failures
stop further target work; already-admitted reporting can still finish and report
its own outcome. A per-file failure can coexist with disjoint results.
The process client drains admitted independent work and reports late failures
separately. A caller-supplied owner remains caller-owned; `app.close()` reports
pending work and can finish owned cleanup after admitted work drains. Closing
an Application prevents new admission and requests stop for active runs; a
caller can inspect the pending outcome and close again after work settles.

## Replay, saved cases and resume

`replay` submits ordered inline hex packets and `@FILE` contents as an ordinary
literal campaign. File lines keep their source positions and diagnostics;
`CampaignResult.literal_items` preserves each selected packet's identity, state
and available result. Root Raw replay needs an explicit port; the direct replay
module retains its own default. `--enable-crash-handling` selects recovery
retries, while ordinary service checks run independently. `--no-recv` disables
selected receives. See [usage](USAGE.md#fuzz-and-replay).

`export_case` / `import_case` and `saved-case` / `saved-intent` preserve portable
recorded choices. `inspect_resume` reads an interrupted journal; `resume` and
`resume-run` require explicit rerun or skip choices for uncertain work. Saved and
resume process commands prepare by default; `--execute` submits the typed
request. Fresh choices require their current source inputs. A new execution
keeps its own identities and counters while retaining inherited provenance.
Report `case.json` is an ordinary saved-case input; see
[usage](USAGE.md#saved-cases-and-interrupted-history).

## Terminal client and ownership

Headless execution has no Rich dependency. Optional Plain and Rich terminal
clients read Application state and records; they do not own execution. Rich
provides Dashboard, Findings and Log views with navigation, search and controls.
An attached view can be closed without stopping its run. A callable Application
retains admitted work after a terminal detaches; process entry drains its own
accepted work before exit. Required evidence remains available if optional
rendering or event projection fails.
