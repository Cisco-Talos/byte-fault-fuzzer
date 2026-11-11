# Byte Fault Fuzzer

Byte Fault Fuzzer is a modular TCP fuzzer for exploring known and unknown byte protocols.
Exact bytes, an empty seed or a captured packet work without fields or a complete
schema. Generators and mutators produce candidates; the ordinary fuzzer owns
conversation traffic, final edits, observations and required records.

> **Early Concept Release**
>
> Byte Fault Fuzzer 0.1.0 is a functional foundation for further development, not a mature
> or feature-complete product. This release provides the initial Raw-only
> implementation for experimentation and evaluation. Interfaces, configuration,
> and supported workflows may change incompatibly as the project develops.

The current application uses the passive Raw protocol directory. A drop-in has
`protocol.json` for identity, transport and defaults, plus its referenced
`declaration.json` for the conversation. Placing or removing that directory
in the protocol root changes what is available without a registry edit or
install script. Protocol directories describe data; they do not supply
clients, sockets or callbacks.

## Run from source

Python 3.13 or newer is required. Unpack the project and run `python bytefault.py`
from its root; the launcher finds `src` relative to itself. No package build or
pip install is needed. Use the command for Python 3.13 or newer on your system
(`python3` where `python` is unavailable); the examples below use `python`.
Rich is optional for the Rich terminal view. Selected core
collection needs local `rsync` and `ssh` commands; selected remote maintenance
and cleanup also use `ssh`.
Python normally caches imported modules as `.pyc` files in `__pycache__`.
Those files are ignored by Git, unnecessary in a source archive, and generated
again when the directory is writable. `python -B` suppresses cache writes.

With `src` on Python's module search path, `python -m bytefault` uses the same
subcommands. `python -m bytefault.fuzzers.cli` retains its direct argument
interface. These entries use the shared Application and ordinary executor.

```text
python bytefault.py --help
python bytefault.py inspect
python bytefault.py schema
python bytefault.py fuzz raw HOST --port PORT --seed-hex 00ff80414243 --no-recv
python bytefault.py replay raw HOST 41 @packets.txt 44 --port PORT --no-recv
python bytefault.py fuzz raw HOST --port PORT --seed-hex 41 --health-check-mode disabled
python bytefault.py --config docs/CONFIG_TEMPLATE.conf --help
```

The `fuzz` and `replay` examples execute against the selected host and port;
`@packets.txt` is a file of hexadecimal packet lines. `inspect`, `schema` and
`--help` inspect local application information without target traffic.

Use the commented [run configuration template](docs/CONFIG_TEMPLATE.conf) to
select any public command from a text file. The file is read only with
`--config PATH`; see [config syntax and merge rules](docs/USAGE.md#text-run-configuration).

For development checks, install `pytest` separately; `rich` is needed only for
Rich-dependent tests, including cases in the offline suite. From the unpacked project root,
`python -m pytest -q tests/scenarios/offline/test_config_file.py` runs an offline
parser/config check without target traffic. The headless runtime has no Python
package dependency.

Use operator-selected host/port values for an intended experiment. Raw has no
implicit port. Traffic can include arbitrary malformed, state-changing and crashing
inputs; there is no extra product permission flag or safety-mode restriction.

Byte Fault Fuzzer is intended for authorized testing in isolated, non-production
environments. Use disposable test credentials, never production or reused
credentials. Inputs and execution evidence are retained for reproducibility;
configuration output, logs, reports, and exported cases may contain credentials
or other sensitive data. Protect these artifacts and review them before sharing.

## Inputs and evidence

Sources include exact whole files, explicitly selected lines/lists, generators,
mutation pipelines, literal replay and portable saved cases. Ordered placements
support insert, overwrite, range replacement and append. Named fields are optional
locations, not payload-size restrictions. Case selection retains original numbers
and seeded choices; interrupted work and explicit rerun/skip choices use the same
executor.

Run journals and required action logs retain actual case activity independently
of reports or the terminal view. Monitoring classifies observations and selects
configured actions; Management coordinates follow-up; Reporting writes result
bundles. A copied core is only a provisional event association. The process CLI
drains admitted follow-up and reports late status separately from the primary
result. See [usage](docs/USAGE.md#monitoring-retrieval-and-maintenance) for
timing, collection, output paths and result interpretation, and
[architecture](docs/ARCHITECTURE.md) for the data flow and module boundaries.

## Terminal and callable clients

The optional UI supplies Plain and Rich views, keys, log search, themes, byte/field
views, findings and report navigation. The CLI runs headlessly by default.
For `fuzz`, `submit` and `replay`, and for `saved-case`, `saved-intent` and
`resume-run` with `--execute`, `--ui` (or `--tui`) selects the Rich view on an
interactive terminal, falling back to Plain when Rich is unavailable.
On an interactive terminal, `--no-ui` selects Plain. Campaign service checks
appear in the ordinary run. Headless execution retains machine JSON/JSONL and
required evidence.

Automated clients, including LLM-driven tools, can use `inspect` and `schema`
to discover the current passive interface, `configure` to inspect resolved
options, and `prepare` or `validate` to inspect selected input before execution.
These commands use the same public source dispatcher as `fuzz` and `replay`;
`prepare` does not send target
traffic. These inspection and preparation commands emit tagged JSON for a
single result and JSONL for a stream. See the [usage workflows](docs/USAGE.md)
and [callable API](docs/API.md) for request and result forms.

Callable clients use `Application` for inspect/configure/validate, prepare/submit/
start, status/control/events, required records, independent services and saved/
resume operations. A callable terminal detach preserves the caller Application and
admitted work.

See [Usage](docs/USAGE.md), the [Raw companion and its examples](src/bytefault/protocols/raw/README.md),
the [protocol authoring guide](docs/ADDING_PROTOCOL.md), the [passive schema](docs/SCHEMA_SPEC.md),
the [current application API](docs/API.md) and [how Byte Fault Fuzzer works](docs/ARCHITECTURE.md).

No generic throughput, startup-time or memory-growth budget is claimed.

## Project and community

See [CONTRIBUTING.md](CONTRIBUTING.md) for issue and pull request guidance,
[SECURITY.md](SECURITY.md) for the vulnerability reporting policy,
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community conduct, and
[MAINTAINERS.md](MAINTAINERS.md) for project ownership.

## License

Distributed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
more information.

## Attribution

Copyright 2026 Cisco Systems, Inc. and its affiliates

Author: padesant@cisco.com (Patrick DeSantis)
