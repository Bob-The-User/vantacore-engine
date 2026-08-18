# Chain of Custody & Audit Integrity

Forensic admissibility in legal and regulatory proceedings requires strict adherence to evidence integrity and tamper-evident audit trails.

## Non-Destructive Ingestion

VantaCore Engine enforces read-only access to all input memory dump files:

1. **Cryptographic Fingerprinting**: Computes a streaming SHA-256 digest of the entire image during initial ingestion.
2. **Read-Only File Handles**: All memory handles are opened strictly in binary read (`rb`) mode.
3. **Deterministic Parsing**: Fixture generators and extractors operate deterministically without persistent side effects on source evidence.

## Forensic Audit Trail (`vantacore_audit.jsonl`)

Every action taken during a scan is recorded sequentially in a JSON Lines audit log:

```json
{"event": "scan_started", "timestamp": "2026-08-17T12:00:00Z", "sha256": "...", "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"}
{"event": "extractor_completed", "extractor": "cisco/asa/conn_table", "timestamp": "2026-08-17T12:00:02Z", "prev_hash": "a1b2c3..."}
```

- **Hash Chaining**: Each audit entry includes the SHA-256 hash of the preceding entry, forming a tamper-evident cryptographic chain.
- **Audit Verification**: Any post-investigation alteration of the audit log breaks the cryptographic hash chain.
