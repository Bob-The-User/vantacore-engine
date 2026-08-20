# VantaCore Engine

> Zero-knowledge memory forensics for DRAM dumps, ELF64 core files, and network appliance memory images.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-181%20passing-brightgreen)](.github/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](.github/workflows/ci.yml)
[![CLA](https://img.shields.io/badge/CLA-required-orange)](CLA.md)

VantaCore Engine is an open-source CLI tool and Python library for forensic analysis of raw DRAM dumps, ELF64 core files, and network/security appliance memory images. It auto-detects the platform, walks virtual address translations, and runs a directed acyclic graph (DAG) of extractors to recover process lists, network connections, routing tables, crypto keys, CLI history, and more — without requiring a live system or kernel symbols.

---

## Supported Platforms

| Platform | Detection | Page Tables | Extractors | Status |
|---|---|---|---|---|
| **Cisco ASA** (lina ELF64 coredump) | ✅ Auto | x86_64 | `lina_process`, `conn_table`, `acl_rules`, `vpn_sessions`, `cli_history`, `snmp_config` | Stable |
| **Cisco IOS** (classic flat image) | ✅ Auto | Flat (physical) | `ios_processes`, `routing_table`, `running_config`, `cli_history`, `snmp_config` | Stable |
| **Cisco IOS-XE** | ✅ Auto | x86_64 | Linux + IOS extractors | Stable |
| **Generic Linux** (ELF64 / raw DRAM) | ✅ Auto | x86_64 PML4/PML5 | `process`, `network`, `modules`, `keys`, `strings` | Stable |
| **Palo Alto PAN-OS** | ✅ Auto | x86_64 | Generic Linux + pattern parsing | Experimental |
| **Ivanti Connect Secure** | ✅ Auto | x86_64 | Generic Linux + pattern parsing | Experimental |
| **Generic Flat Memory** | ✅ Auto | Physical only | `keys`, `strings` | Stable |

---

## Quick Start

### Install via Pixi (recommended — guarantees native dependencies)

```bash
git clone https://github.com/vantacore/vantacore-engine.git
cd vantacore-engine
pixi install
pixi run vantacore --help
```

### Install via pip (coming soon)

> PyPI publication is planned before the v0.1.0 public release. Until then, install from source via Pixi above.
>
> **Note**: Once published, ensure `llvm-strings` is in your `PATH` for full string extraction functionality.

---

## Usage

### 1. Detect platform and architecture

```bash
vantacore detect memory_dump.bin
vantacore detect --json memory_dump.bin
```

```json
{
  "platform_name": "cisco_asa",
  "confidence": 1.0,
  "translation_backend": "x86_64",
  "extractor_paths": ["generic", "linux", "cisco/common", "cisco/asa"],
  "encrypted": false
}
```

### 2. Verify dump integrity

```bash
vantacore verify memory_dump.bin
```

### 3. Run full extraction

```bash
vantacore scan memory_dump.bin --output-dir ./case_001
```

Include sensitive credentials (SNMP community strings, VPN pre-shared keys):

```bash
vantacore scan memory_dump.bin --output-dir ./case_001 --include-secrets
```

### Output artifacts

| File | Description |
|---|---|
| `vantacore_output.json` | Combined JSON results from all extractors |
| `vantacore_audit.jsonl` | HMAC-SHA256-chained forensic audit trail |

---

## Key Capabilities

- **Auto-detection** — identifies platform, architecture, and encryption status from binary signatures with confidence scoring
- **Virtual address translation** — x86_64 PML4/PML5 page-table walking with KASLR heuristics; physical-only fallback for flat images
- **DAG extractor pipeline** — Kahn's algorithm topological sort; cycle-safe; parallel worker processes via shared-memory ring buffer
- **DKOM-resistant process extraction** — dual-path: linked-list walk + slab carving fallback to detect hidden processes
- **Forensic audit trail** — append-only HMAC-SHA256-chained JSONL; chain-of-custody ready
- **Hook framework** — register callbacks on discovered nodes and edges for SIEM/SOAR integration
- **Structured output** — rich terminal tables and `--json` stdout for pipeline integration
- **Adversarial input hardening** — ELF header + PHDR bounds validation; 500K traversal hop cap; no `re` module (ReDoS-safe via `google-re2`)
- **License-clean** — zero GPL dependencies; AGPL-3.0 with a permissive dependency stack

---

## Documentation

Full documentation: [bob-the-user.github.io/vantacore-engine](https://bob-the-user.github.io/vantacore-engine)

- [Installation](docs/getting-started/installation.md)
- [Quickstart](docs/getting-started/quickstart.md)
- [Supported Platforms](docs/getting-started/supported-platforms.md)
- [CLI Reference](docs/user-guide/cli-reference.md)
- [Appliance Forensics Guide](docs/user-guide/appliance-forensics.md)
- [Chain of Custody](docs/user-guide/chain-of-custody.md)

---

## Development

```bash
# Run unit tests
pixi run pytest tests/unit/ -v --timeout=60

# Run full suite with coverage
pixi run pytest -v --timeout=300 --cov=vantacore_engine --cov-report=term-missing

# Lint (style + docstrings)
pixi run ruff check vantacore_engine/ tests/ --select E,F,W,D --ignore E501,D100,D104,D203,D213

# Build docs
pixi run mkdocs build --strict
```

Coverage gate: **≥90%**. All PRs require passing CI and a signed CLA.

---

## Contributing

Contributions are welcome. All contributors must sign the [Contributor License Agreement](CLA.md) before a PR can be merged — the CLA bot will prompt you automatically on your first pull request.

See the [Contributing Guide](docs/developer-guide/contributing.md) for code style, testing requirements, and the PR workflow.

---

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

A commercial Enterprise Edition (FastAPI + React WebGL UI, DuckDB OLAP backend, RBAC, OIDC/SAML SSO) is available separately. Contact us for licensing details.
