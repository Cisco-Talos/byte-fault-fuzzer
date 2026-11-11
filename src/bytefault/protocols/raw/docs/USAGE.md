# Raw Usage (Protocol-Specific)

Raw sends prepared outbound bytes without adding framing or authentication.
Its descriptor has no default port, so supply `--port`. In the generation
examples, `payload` replaces the whole Raw seed; `@N` edits at byte offset N.
Replace the host, port and packet placeholders before running these commands.
The `fuzz` and `replay` forms execute against that host. The root `fuzz`
launcher accepts the `--` separator shown before generator options.

Refer to the project [usage guide](../../../../../docs/USAGE.md) for the
shared command options.

## Random Payloads

```bash
# Random payloads, 10-100 bytes, 1000 iterations
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field payload:random:10-100,count:1000,seed:42 -v

# Random payloads without null bytes
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field payload:random:10-100,count:1000,exclude:0x00 -v
```

## Length sweep

Sweep payload lengths to investigate a crash or behavioral change:

```bash
# Sweep payloads from 100 to 10000 bytes, stepping by 100
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field payload:sweep:100-10000,step:100,seed:42 -v

# Fine-grained sweep around a known crash length
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field payload:sweep:4090-4110 -v
```

## Offset Injection

Inject or overwrite bytes at a specific offset within a known-good baseline
packet.  This is the primary use case for raw + `@N`:

```bash
# Insert random bytes at byte offset 6
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field @6:random:1-100,count:1000 \
  --base-packet <HEX_PACKET> -v

# Overwrite 1 byte at offset 2 with all values
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field @2:iter:0-255,mode:overwrite \
  --base-packet <HEX_PACKET> -v

# Boundary values at offset 4 (2-byte, overwrite)
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field @4:edge:width:2,mode:overwrite \
  --base-packet <HEX_PACKET> -v

# Two offsets simultaneously (cartesian product)
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field @2:iter:0-15,mode:overwrite \
  --gen-field @6:list:DEAD,BEEF,CAFE,mode:overwrite \
  --gen-strategy cartesian \
  --base-packet <HEX_PACKET> -v
```

## Mutation

```bash
# Mutate a seed packet (raw mode — no schema)
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --mutate-seed <HEX_PACKET> --mutate-count 100 --mutate-raw -v
```

## Payloads from File

```bash
# One candidate: every exact byte of the file, including newlines and NULs
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field payload:file:/path/to/payload.bin -v

# Binary records, excluding only the selected newline delimiter; no hex decoding
python3 bytefault.py fuzz raw <DEVICE_IP> --port <PORT> -- \
  --gen-field payload:file:/path/to/records.bin,source_mode:lines -v
```

For hex text records, this example requires LF (`\n`) line endings. Line mode
removes only the LF delimiter; CRLF leaves a `\r` byte in each record, which
`hex_decode` rejects. Save this explicit source/transform configuration as
`hex-lines.json` (replace the input path):

```json
{
  "sources": [{"source_id": "text", "kind": "file",
    "options": {"path": "/path/to/hex-lines.txt", "source_mode": "lines"}}],
  "sets": [{"set_id": "decoded", "source_id": "text",
    "transforms": [{"mutator_id": "hex", "kind": "hex_decode"}]}],
  "positions": [{"position_id": "packet", "set_id": "decoded",
    "operation": "replace", "offset": 0, "end": "seed"}]
}
```

The flag accepts closed tagged JSON **text as one argument**, without `@file`
expansion. Run this from the unpacked project root after replacing the host,
port and input path. It adds `src` to Python's import path and uses the public
CLI dispatcher. The `fuzz` call executes against the target and returns a
synchronous campaign result:

```python
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path('src').resolve()))
from bytefault.application import Application
from bytefault.core.records import encode_value
from bytefault.cli import execute_arguments

configuration = json.loads(Path('hex-lines.json').read_text(encoding='utf-8'))
argv = ['fuzz', 'raw', '<DEVICE_IP>', '--port', '<PORT>',
        '--generation-json', json.dumps(encode_value(configuration)),
        '--no-ui', '--no-recv', '--health-check-mode', 'disabled']
app = Application()
try:
    result = execute_arguments(argv, app)
    print(result.outcome)
finally:
    app.close()
```

The caller retains `app` and closes it after execution. A file containing
`41\n42\n` then produces candidates `41` and
`42` as hexadecimal byte values. Without `hex_decode`, line mode produces the
literal ASCII records `3431` and `3432`; whole mode produces `34310a34320a` once.
For CRLF records, set
`configuration['sources'][0]['options']['delimiter'] = b'\r\n'` after loading
the JSON and before calling `encode_value`; line mode then removes that exact
delimiter.

Malformed hex is a transformation error. Literal replay has its separate
`python bytefault.py replay raw <DEVICE_IP> @hex-lines.txt --port <PORT>` syntax,
with comments, blanks and invalid-line diagnostics defined by replay.

## Notes

- Raw has no field layout, authentication or banner handling.
- These nonzero-offset examples use `--base-packet` to supply the bytes being
  edited. To overwrite existing bytes at both positions in the two-offset
  example, provide at least eight bytes. An offset beyond the baseline extends
  it with NUL bytes before the edit.
- A length associated with a crash indication requires follow-up to establish
  its cause.
