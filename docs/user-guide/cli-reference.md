# CLI Reference

VantaCore Engine provides a unified command-line interface `vantacore` for memory analysis, appliance detection, integrity verification, and structured data extraction.

## Global Synopsis

```bash
vantacore [--help] <command> [options] [arguments]
```

---

## Commands

### `vantacore scan`

Execute end-to-end memory dump analysis, including appliance detection, architecture translation backend binding, and DAG extractor execution.

#### Synopsis

```bash
vantacore scan <dump> [--output-dir OUTPUT_DIR] [--json] [--include-secrets] [--workers WORKERS] [--timeout TIMEOUT]
```

#### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `<dump>` | Positional | Required | Path to raw memory dump or ELF core file. |
| `--output-dir` | Path | `./vantacore_output_<hash>` | Directory where extraction artifacts and audit logs will be written. |
| `--json` | Flag | `False` | Output extraction results to stdout as formatted JSON. |
| `--include-secrets` | Flag | `False` | Include sensitive credentials (cleartext SNMP communities, VPN PSKs) in output. |
| `--workers` | Integer | CPU Count | Number of concurrent worker processes for memory scanning. |
| `--timeout` | Integer | `3600` | Global scan timeout limit in seconds. |

#### Example

```bash
# Scan a Cisco ASA dump with secrets included and custom output directory
vantacore scan /evidence/asa_core.bin --output-dir /cases/case001/evidence --include-secrets
```

---

### `vantacore detect`

Identify appliance platforms, detection confidence scores, translation architecture, and encryption indicators.

#### Synopsis

```bash
vantacore detect <dump> [--json]
```

#### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `<dump>` | Positional | Required | Path to memory dump file. |
| `--json` | Flag | `False` | Format detection result as JSON. |

#### Example

```bash
vantacore detect /evidence/cisco_ios.bin --json
```

---

### `vantacore verify`

Compute cryptographic hashes, validate ELF headers and program headers, check memory entropy, and confirm structural integrity.

#### Synopsis

```bash
vantacore verify <dump> [--json]
```

#### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `<dump>` | Positional | Required | Path to memory dump file. |
| `--json` | Flag | `False` | Output verification payload as JSON. |

#### Example

```bash
vantacore verify /evidence/dump_x86_64.bin
```

---

### `vantacore version`

Display package version and Python runtime details.

#### Synopsis

```bash
vantacore version
```

#### Example

```bash
vantacore version
# Output:
# vantacore-engine 0.1.0
# Python 3.12.13 ...
```
