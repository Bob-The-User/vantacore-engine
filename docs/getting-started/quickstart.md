# Quickstart

This tutorial walks you through running your first forensic memory analysis with VantaCore Engine.

## Step 1: Detect Appliance Platform and Architecture

Before running a full extraction scan, you can inspect a memory dump to identify the appliance platform, translation backend architecture, and encryption status:

```bash
vantacore detect memory_dump.bin
```

To output raw JSON for machine parsing:

```bash
vantacore detect --json memory_dump.bin
```

Example JSON response:

```json
{
  "platform_name": "cisco_asa",
  "confidence": 0.95,
  "translation_backend": "x86_64",
  "extractor_paths": [
    "generic",
    "linux",
    "cisco/common",
    "cisco/asa"
  ],
  "encrypted": false
}
```

## Step 2: Verify Dump Integrity

Verify that the memory dump is uncorrupted, valid according to ELF specifications, and has an intact SHA-256 fingerprint:

```bash
vantacore verify memory_dump.bin
```

## Step 3: Run Full Extraction Scan

Execute the complete extractor DAG against the target dump:

```bash
vantacore scan memory_dump.bin --output-dir ./investigation_01
```

If the investigation requires extracting sensitive credentials (such as cleartext SNMP community strings or VPN pre-shared keys):

```bash
vantacore scan memory_dump.bin --output-dir ./investigation_01 --include-secrets
```

## Step 4: Review Extracted Evidence

The output directory contains structured forensic artifacts:

- `vantacore_output.json`: Full combined JSON results from all executed extractors.
- `vantacore_audit.jsonl`: Cryptographically chained forensic audit trail.
- Individual extractor artifact tables and logs.
