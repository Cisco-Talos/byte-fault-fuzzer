# Current Byte Fault Fuzzer usage

This is the operator reference. For module responsibilities and the path from
input to evidence, see [how Byte Fault Fuzzer works](ARCHITECTURE.md).

From an unpacked project, run `python bytefault.py` with the subcommands below;
Python 3.13 or newer is required, but no pip installation or wheel build is
needed. Where examples say `bytefault`, substitute `python bytefault.py`. On
Windows PowerShell, use `python .\bytefault.py` from the project root. With
`src` on Python's module search path, `python -m bytefault` shares the same
public subcommands. A protocol becomes
available when its passive directory containing `protocol.json` and the
referenced `declaration.json` is placed in the default protocol root or an
explicit `--declaration-dir` root; no registry edit or install script is needed.
Headless use has no Python package dependency; Rich is optional for the Rich
terminal view. Direct fuzz and replay module launchers use their own argument
forms and do not read `--config`.

Selected features also require system tools. Independent ICMP observations use
local `ping`; if it is unavailable, heartbeat telemetry reports that state.
Core collection needs local SSH/rsync, a remote SSH service and rsync, and the
selected authentication credentials. Remote inventory/cleanup needs a compatible
shell and the `find -maxdepth ... -print0`, `stat -c`, and `rm -f --` command forms.
These tools are not requirements for unrelated headless workflows.

The project has been tested on Windows and Linux through WSL. Windows core-dump
retrieval has not been qualified because of its rsync requirement; this is a
testing exclusion, not a claim that retrieval is unsupported on Windows.

## Command map

| Command | Current operation |
| --- | --- |
| `inspect`, `schema` | Inspect discovered capabilities/protocols or export the passive declaration schema. |
| `configure`, `validate`, `prepare` | Resolve a fuzz request, validate it, or prepare its inputs without target traffic. |
| `fuzz`, `submit` | Submit the ordinary campaign; root `fuzz` forwards to `submit`. |
| `replay` | Submit ordered literal packets; `--prepare` returns the request without sending. |
| `saved-case`, `saved-intent`, `resume-run` | Prepare a saved case (the first two names are aliases) or interrupted-run continuation; `--execute` submits it. |
| `inspect-resume`, `export-case` | Inspect a retained journal for continuation or export a portable case. |
| `status`, `control`, `observe`, `record-refs`, `records` | Operate on a run retained by the same `Application` instance. |
| `service`, `maintenance` | Dispatch a typed request to an attached owner or perform selected local/remote maintenance. |
| `inspect-declaration`, `admit`, `export-declaration` | Inspect, admit, or export passive declaration data. |

Run `bytefault COMMAND --help` for that command's option spellings and choices.
The [configuration template](CONFIG_TEMPLATE.conf) lists the corresponding
long-option keys, command applicability and defaults in one place.

## Text run configuration

Copy the [complete commented template](CONFIG_TEMPLATE.conf) to any path and
select it with `bytefault --config PATH`. Put `command fuzz` (or another public
command) in its `[run]` section for file-only use, or use
`bytefault fuzz --config PATH` with additional CLI values. The selected file is
read before command parsing; without `--config`, no file is read. `--help`
bypasses configuration loading, including missing/malformed files, and is not
a configuration-validation check. The root
launcher and `python -m bytefault` accept the same forms. Direct fuzz and replay
module launchers retain their existing arguments. The selected file remains a
protected input: a run that would overwrite or remove it is refused before that
selected output is changed.

For example, this file resolves a Raw request without connecting to the host:

```text
format-version 1
[run]
command configure
protocol raw
host 192.0.2.10
[fuzz]
port 1234
seed-hex 414243
```

Save it as `run.conf` and run `bytefault --config run.conf`. Change `command`
to `fuzz` when you intend to execute the request against the selected host.
For JSON-bearing commands, a config file avoids shell-specific nested-quote
handling. For example, this file prepares a saved case on either Windows or
Linux; do not add shell quotes around the JSON in the file:

```text
format-version 1
[run]
command saved-case
intent-json {"path":"copied.case.json"}
[output]
records rerun.bfr
```

Run `bytefault --config saved.conf`; add `execute true` in `[prepared]` only
when you intend to send the prepared case. Place a valid `copied.case.json` in
the working directory or put its path in the JSON. A config file uses its own grammar,
so use `--config PATH` with the root launcher or `python -m bytefault`.

The file begins with `format-version 1` and groups options in sections. Active
assignments are `key value` with a canonical long-option key, omitting `--`.
The first whitespace run separates the key; the rest is one value. Quote a
whole value to keep `#` or surrounding spaces as data. Matching doubled quote
characters inside a whole quoted value become one quote; backslashes remain
literal. A `#` outside quotes starts a comment. Repeat append options and
replay `packet` lines in their intended order. Booleans use `true` or `false`;
count options such as `verbose` use a nonnegative number. The template labels
stable defaults, required values and values derived from the selected context.

The `[run]` section names the command and its positional group. Fuzz uses
`protocol` and `host` (or just `host` for schema-free input); replay requires
`protocol`, `host` and one or more ordered `packet` lines. Generic commands
use their named positional fields. Keep a command's entire positional group
in either the file or the CLI. A matching command in both is accepted.
File and CLI options can be combined when they select different settings;
overlap, including aliases, repeated options, booleans set to `false`, count
zero and a split positional group, fails before execution with both sources
identified. Existing command parsers and request validation still apply.

Host-only schema-free input bypasses descriptor discovery and defaults to no
receive. Selecting `raw` explicitly uses its descriptor, which requests a reply
unless overridden. The two forms are not interchangeable receive defaults.

## Inspect and prepare

```text
bytefault inspect
bytefault schema
bytefault configure raw HOST --port PORT --seed-hex 00ff80414243 --no-recv
bytefault validate raw HOST --port PORT --seed-hex 00ff80414243 --no-recv
bytefault prepare raw HOST --port PORT --seed-hex 00ff80414243 --no-recv
```

Inspection/preparation does not open target connections or initialize service
writers. Raw requires an explicit port. `--declaration-dir ROOT` selects an
external directory of passive drop-ins. Adding, moving/renaming or removing a
complete descriptor directory changes discovery without a registry edit.
Duplicate identities fail explicitly. Unknown production selections do not load
executable protocol code.
For the generic commands, `inspect --directory ROOT` selects the discovery root.
The `schema` command exports the fixed passive declaration schema and takes no
directory selection.

Generated preparation/validation consumes selected sources and writes a required
`RECORDS.preparation.bfr` journal. It needs writable evidence storage even though
it sends no target traffic. Use `--case-limit` or `--generation-limit` to bound
inspection cases when appropriate; rejected source candidates and finite
Cartesian pool loading can require work beyond that composed-case limit.
Supplied SSH options are validated without applying service configuration;
only explicit collection selection enables collection, and preparation never
starts SSH or rsync.

## Fuzz and replay

```text
bytefault fuzz raw HOST --port PORT --seed-hex 414243 --gen-field @1:list:5a,mode:overwrite --no-recv
bytefault replay raw HOST 41 @packets.txt 44 --port PORT --no-recv
bytefault replay raw HOST 41 @packets.txt 44 --port PORT --prepare
```

The first example overwrites `ABC` at byte 1 with `Z`, yielding `415a43`.
`mode:insert` yields `415a4243`; range replacement is available through ordered
structured placements. A replay file contains UTF-8 hex lines. Blank lines and
whole-line comments are ignored; an invalid line warns with its file/line while
valid packets retain order. For the example above, `packets.txt` can contain
`42` and `43` on separate lines; the packet order is `41`, `42`, `43`, `44`.
Invalid inline hex is an input error.
The `--prepare` replay form resolves the ordered campaign without target traffic.
`--wait SEC` adds a pre-connection delay to replay connections, including enabled
service-check and recovery connections, not just once per payload. `--offset`, `--fuzz-length`, `--value`
and `--fuzz-target` on replay label crash metadata without changing sent bytes.

Exact whole-file input is the default for binary file sources. Text/hex/line
interpretation is explicit. Source, mutation and ordered packet placement are
separate choices. `--cases 1,3-6,10`, `--case-limit` and `--skip` retain original
case numbering and actual source bounds. Random choices support explicit held
and per-test selection; a seed reproduces input choices, not target state.

Strategies are `single` (each set takes its turn, others use their first values),
`one-position` (other positions retain baseline bytes), `broadcast` (shared value),
`zip` (shortest set ends the stream), finite `cartesian`, and explicit
`hybrid-cartesian` for retained finite/infinite behavior. `broadcast` and
`one-position` require one explicitly shared set through `--generation-json`.
Consult `fuzz --help` for accepted source/mutator options. Unsupported advanced
options return their
attributed attachment/capability limits rather than using another executor.

## Saved cases and interrupted history

```text
bytefault export-case RUN.bfr CASE_RECORD_ID
bytefault saved-case '{"path":"copied.case.json"}' --records rerun.bfr
bytefault saved-case '{"path":"copied.case.json"}' --records rerun.bfr --execute
bytefault inspect-resume interrupted.bfr
bytefault resume-run '{"path":"interrupted.bfr","choices":[{"conversation_id":"ORIGINAL_ID","disposition":"rerun"}]}' --records continued.bfr --execute
```

Pass each JSON object as one argument with its double quotes intact; adapt
the outer quoting to your shell. Find the case record ID in the run records
and the original conversation ID in `inspect-resume` output.

Saved/resume commands prepare by default; `--execute` submits through the shared
Application. Recorded choices are portable; fresh derivation needs its actual
current sources. Inherited history and new execution identities/counters stay
separate. Uncertain interrupted work is unresolved until explicitly rerun or
skipped. `--start` selects a value range; it is not interrupted-run recovery.
The `case.json` copied into an event report is a portable saved-case input:
its recorded choice reuses the exact prepared outbound bytes for each action.
It can be used by `saved-case` without the original campaign journal; a
standalone hex packet file is unnecessary for this replay path.
See [saved and resume operations](API.md#replay-saved-cases-and-resume).

## Run inspection and service dispatch

The public grammar accepts `status RUN_ID`, `control RUN_ID COMMAND`
(`stop`, `pause`, or `resume`),
`observe RUN_ID [--after CURSOR]`, `record-refs RUN_ID`, and
`records RUN_ID`. The `--after` cursor defaults to zero. These commands look
up a run in the same `Application` instance that started it; `records` reads
that run's registered journal path. A new `python bytefault.py` process owns a
new Application and cannot reattach to an earlier run by ID.

With a caller-owned `app` and a `run_id` from its run handle or result, use
the root dispatcher while that Application is retained. From the unpacked
project root, put `src` on the import path before importing Byte Fault Fuzzer:

```python
from pathlib import Path
import sys

sys.path.insert(0, str(Path("src").resolve()))
from bytefault.cli import execute_arguments

status = execute_arguments(["status", run_id], app)
events = execute_arguments(["observe", run_id, "--after", "0"], app)
refs = execute_arguments(["record-refs", run_id], app)
history = execute_arguments(["records", run_id], app)
pause = execute_arguments(["control", run_id, "pause"], app)  # active run only
```

`observe` returns a new cursor and event-gap diagnostics; `records` returns
the recovered valid prefix and any read issue. Control of an ended run is
rejected. To inspect a retained journal after its Application has ended, use
`bytefault.core.storage.reopen_records("RUN.bfr")` and check its `issue`;
`inspect-resume PATH` and `export-case PATH RECORD_ID` are separate
path-based operations. See [API results and evidence](API.md#results-and-required-evidence).

`service OWNER REQUEST_JSON` accepts `monitoring`, `management`,
`reporting`, or `maintenance` as the owner and one lossless tagged JSON
argument. With the corresponding service attached to the caller-owned app,
dispatch a request of the type expected by that owner:

```python
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path("src").resolve()))
from bytefault.cli import execute_arguments
from bytefault.core.records import encode_value

service_result = execute_arguments(
    ["service", owner, json.dumps(encode_value(typed_request))], app)
```

Monitoring can also use an active run or an independent Monitoring attachment.
A standalone `bytefault service` starts a fresh Application with no attached
owner. For ordinary process-owned cleanup, use `bytefault maintenance` below.
See [API service ownership](API.md#monitoring-collection-and-maintenance).

## Monitoring, retrieval and maintenance

```text
bytefault fuzz raw HOST --port PORT --seed-hex 41
bytefault fuzz raw HOST --port PORT --seed-hex 41 --collect-cores --ssh-key KEY
bytefault fuzz raw HOST --port PORT --seed-hex 41 --collect-cores --ssh-user USER --ssh-pass PASS
bytefault fuzz raw HOST --port PORT --seed-hex 41 --health-check-mode disabled
bytefault maintenance --local-only --local-cache CACHE
bytefault maintenance HOST --remote-only --ssh-key KEY --remote-entry CORE_NAME
```

Campaign service checks run by default after fuzz and replay tests, with the default
new-connection interval of one. `--health-check-mode disabled` explicitly turns
them off. Fuzz also accepts `in_band` when its Monitoring configuration supplies
prepared check bytes and an observable response predicate; replay accepts only
`new_connection` or `disabled`. ICMP heartbeat remains independent reachability
evidence. Monitoring
rules select collection and reporting for observed events. `--collect-cores`
selects acquisition on the default failed-service rule; an SSH key or password
alone initiates no collection. Key mode uses `--ssh-key PATH` with optional
`--ssh-user` (default `root`). Password mode requires both `--ssh-user USER` and
cleartext `--ssh-pass PASS`; key and password modes conflict. Both modes use
the same selected rsync collection and SSH cleanup workflow. Owned Linux
fixture checks cover both credential modes and authentication failures.

Collection and remote maintenance use `StrictHostKeyChecking=no` for SSH,
including rsync's SSH transport. This intentionally accommodates host-key changes
after test-device resets or reconfiguration, trading host-identity enforcement
for unattended lab use. Use isolated, non-production networks and disposable
credentials; a substituted endpoint can affect collected evidence or receive
maintenance commands. OpenSSH still consults its known-host records. On a
stored-key mismatch, it can disable password and keyboard-interactive
authentication, so password-mode connections may still fail after a reset.

Reports remain available with collection off. Collection retains remote files unless cleanup
is selected by a Monitoring rule. Replay `--enable-crash-handling` retains its
recovery-retry choice; ordinary replay service checks no longer require it.
Maintenance affects selected local/remote resources and records each actual
outcome and partial failure. With neither `--local-only` nor `--remote-only`,
both sides are selected and remote host/credentials are required. `--local-entry`
selects an exact path relative to the cache root; `--remote-entry` selects an
exact immediate basename in `--remote-dir`. Both can be repeated. With no
entries for a selected side, maintenance selects the local root or every
discovered remote core, respectively. Selected remote maintenance accepts `--ssh-key`
with optional `--ssh-user`, or explicit `--ssh-user` with `--ssh-pass`. See
[application ownership and results](API.md#monitoring-collection-and-maintenance); use `fuzz --help` and
`maintenance --help` for current arguments.
With no `--local-cache`, maintenance uses an attached Collection's cache, then
a configured service cache, then the selected service result root's `collection`
directory. A new standalone maintenance process selects
`artifacts/runs/results/collection` under the working directory, or
`RESULTS/collection` when `--results RESULTS` is supplied. Use `--local-cache`
with the actual earlier run cache path to maintain that run's files.

Fuzz and literal replay commands accept `--connection-delay SEC` as an
additional wait between initiated connections; remote maintenance accepts the
same option for its inventory/stat/cleanup SSH connections. Fuzz uses protocol
pre/post delays for test/check connections unless `--tcp-pre-delay`
(`--tcp-spacing` alias) or `--tcp-post-delay` overrides them. Literal replay
uses `--wait` (default zero) as its pre-connection delay and zero post-delay.
The scheduled campaign check uses
`--delayed-crash-check SEC` (default zero) after its test action; recovery checks
have a separate wait schedule. A new-connection check follows the original
socket's close and post-delay. Fuzz recovery delays default to 3, 5, 10, 15 and
17 seconds when no `--recovery-delays` is supplied. A required collection hold,
or a required report
queued behind collection, after an intermediate same-socket action conflicts
with nonzero all-connection pacing. Known
configurations reject before connecting; an observation-dependent conflict stops
before the collection or next action. Selected collection requires SSH credentials
and locally available `rsync` and `ssh` commands. Selected remote maintenance and
cleanup use `ssh`.

Automatic collection runs one incremental rsync acquisition into a persistent
cache. In normal CLI execution, its default is `RESULT_BIN/collection`, where
`RESULT_BIN` is the first run's dated result bin beside its journal or the exact
`--results` path. `--core-cache` selects another root; an attached caller-owned
Collection retains its existing cache. Acquisition records unchanged, newly
acquired, skipped and failed batches from the same transfer's itemization.
Every newly acquired core is copied beside
the event result while its cache copy remains. The newest is only a provisional
match; older cores are unpaired with any individual test. For a multiple-core
batch the result highlights the acquired count and exact names linked to copied
cores. It also records the preceding successful collection boundary and
candidate test identities from every registered run log in that window,
including runs without reports. Missing registered logs are stated in the result.
If a batch fails after some verified copies, its failed status and those copied
cores both remain visible; an empty or no-new batch has no copied core artifact.
The default
`--core-max-size 0` imposes no per-file MiB cap. `--core-timeout` (default 30 seconds;
zero disables it) is an rsync stalled-I/O timeout, so a progressing large
transfer can continue.
Successful transfer does not by itself prove a core finished being written.

## Output, paths and clients

Stdout uses lossless tagged JSON/JSONL, except `export-case`, which emits the
portable `bytefault.case` object directly for the saved-case loader. Primary result, late follow-up aggregate
and nonclean cleanup are separate observations. Process entry drains admitted
work; callable owners retain their declared lifetime. Failures retain their
command-specific exit status. Required action records are independent
of display/report creation.

Configuration output, journals, logs, reports, and exported cases can retain
supplied credentials and other sensitive input. Use disposable test credentials
in non-production environments, protect retained evidence, and review any copy
before sharing it. Exact recording is intentional; do not assume sanitization.

Explicit `--records`, `--log-file`, `--results` and Collection cache paths retain
their meaning. `--results PATH` selects that exact result bin, including an
existing bin. Without it, the first run selects a bin beside its record file
named `YYYYMMDD_HHMMSS_<protocol>` (`raw` for Raw), reused by that application
owner. Each run registers its action-log path in the shared result bin when it
starts, even if the run produces no report. Command-line bare log names resolve
under `artifacts/logs` in the working directory for fuzz, replay, saved/resume,
and maintenance. Explicit relative paths with either Windows separator, absolute
paths and drive-relative paths resolve once. Callable `log_path` values stay exact. Default paths resolve
from the working directory. Each reported incident has one directory directly
under the selected bin, named `HHMMSS_<protocol>` from its supplied observation
timestamp, or current local time if that timestamp is absent or invalid,
with `_1`, `_2` and so on for collisions. Later revisions stay in
that directory. Readable `REPORT.md` links exact `event.json`, ordinary replay
`case.json` and copied cores; internal run/event/attempt identities remain distinct.

The CLI runs headlessly by default. For `fuzz`, `submit`, `replay`,
`saved-case`, `saved-intent` and `resume-run` execution,
`--ui` (or `--tui`) selects the interactive terminal client. With Rich
installed, it provides Dashboard/Findings/Log with F2/F3/F4,
search/navigation, pause/resume/quit, verbosity and themes; without Rich it
uses Plain. `--no-ui` selects Plain on an interactive terminal. Campaign
checks appear in the ordinary run. Headless execution needs no UI dependency.
Digital rain starts off in Rich; `m` toggles it without changing verbosity.
`--hide-field` hides only header summaries; `--no-test-banner` hides delimiters.
See the [terminal client and ownership](API.md#terminal-client-and-ownership)
and [callable entry](API.md#entry-and-requests).

## Passive authoring

`inspect-declaration`, `admit` and `export-declaration` accept JSON passive data;
[SCHEMA_SPEC](SCHEMA_SPEC.md) defines their current form and unknown/refusal rules.
The [protocol authoring guide](ADDING_PROTOCOL.md) shows how to install and
validate a passive directory through the current application.
No complete schema is needed for Raw exploration.
