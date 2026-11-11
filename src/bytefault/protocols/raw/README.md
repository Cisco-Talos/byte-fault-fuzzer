# Raw passive companion

`protocol.json` declares canonical name `raw`, alias `tcp-raw`, TCP, no default
port, timeout 3 seconds and zero pre/post connection delays. `declaration.json`
declares one outbound action (`outbound`, stage `send`), an empty seed and receive
guidance (requested, cap 4096, deadline 3 seconds). No framing or authentication
is required. These are overridable defaults.

The generic application discovers this directory as data; it never imports its
Python package. Copy it under any selected discovery root. Descriptor identity
and aliases may change without changing the engine. Removing it removes its
names from that root.

For exact whole bytes through the current application:

```text
python bytefault.py fuzz raw HOST --port PORT --seed-hex 00ff80414243 --no-ui --no-recv
python bytefault.py fuzz tcp-raw HOST --declaration-dir ROOT --port PORT --seed-hex 00ff80414243 --no-ui
```

`ROOT` is the directory containing the Raw protocol directory. Omitting
`--no-recv` uses the declared receive guidance. `--receive-cap N` together
with `--receive-deadline SECONDS` supplies explicit bounds. Transport options
override descriptor defaults; `--port` is required because Raw has no default.
`--list-stages` / `--list-targets` inspect the actual passive data.

`--request-json` accepts an exact prepared conversation using the discovered plan,
including ordered contributions/placements and explicit selected actions. The
callable equivalent is `Application.protocol_request`; see the
[passive schema](../../../../docs/SCHEMA_SPEC.md) and
[application API](../../../../docs/API.md#entry-and-requests).

Generator/mutator options and raw offset workflows use the shared preparation
and execution path. See [Raw worked examples](docs/USAGE.md) for sweeps,
placements, mutation and file sources; [project usage](../../../../docs/USAGE.md)
for campaign, replay, saved-case and terminal workflows; and the
[application API](../../../../docs/API.md#input-and-passive-declarations) for
callable preparation. The [protocol authoring guide](../../../../docs/ADDING_PROTOCOL.md)
explains how another passive directory is discovered and admitted.
