"""Cryptographically verifiable forensic audit trail logging."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Union


class ForensicAuditTrail:
    """Append-only, HMAC-SHA256 chained audit trail for forensic actions."""

    DUMP_INGESTED = "dump_ingested"
    ARCHITECTURE_DETECTED = "architecture_detected"
    TRANSLATION_INITIALIZED = "translation_initialized"
    PAGE_FAULT = "page_fault"
    NODE_EXTRACTED = "node_extracted"
    EDGE_EXTRACTED = "edge_extracted"
    EXTRACTOR_STARTED = "extractor_started"
    EXTRACTOR_COMPLETED = "extractor_completed"
    EXTRACTOR_FAILED = "extractor_failed"
    DKOM_ANOMALY = "dkom_anomaly"
    SCAN_COMPLETED = "scan_completed"

    def __init__(self, audit_path: Union[str, Path], dump_integrity_hash: str) -> None:
        """Initialize forensic audit trail and derive HMAC key.

        Args:
            audit_path: Destination file path for JSONL audit log.
            dump_integrity_hash: Hex SHA-256 string of the target dump file.

        """
        self._dump_hash = dump_integrity_hash
        self._hmac_key = hashlib.sha256(dump_integrity_hash.encode("utf-8")).digest()
        path = Path(audit_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")
        self._prev_hmac: str = ""

    def record(self, event_name: str, **fields: Any) -> None:
        """Record an audit event and update the cryptographic chain.

        Args:
            event_name: Predefined or custom forensic event name.
            **fields: Additional event-specific key-value fields.

        """
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_name,
            "dump_hash": self._dump_hash,
            **fields,
        }
        payload_json = json.dumps(payload, sort_keys=True)
        mac = hmac.new(
            self._hmac_key,
            (payload_json + self._prev_hmac).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        self._prev_hmac = mac
        final_record = {**payload, "hmac": mac}
        self._fh.write(json.dumps(final_record, sort_keys=True) + "\n")
        self._fh.flush()

    def close(self) -> None:
        """Flush and close the underlying log file."""
        if hasattr(self, "_fh") and not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    def __enter__(self) -> "ForensicAuditTrail":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Exit context manager and close file."""
        self.close()
