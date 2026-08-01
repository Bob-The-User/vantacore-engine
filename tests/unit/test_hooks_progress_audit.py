"""Unit tests for HookFramework, ProgressEventBus, ForensicAuditTrail, and logging configuration."""

import hashlib
import hmac
import json
import logging
from pathlib import Path
import time
from typing import Any
from vantacore_engine.core.audit import ForensicAuditTrail
from vantacore_engine.core.hooks import HookFramework
from vantacore_engine.core.logging_config import (
    JSONLinesFileHandler,
    configure_logging,
)
from vantacore_engine.core.progress import ProgressEventBus


def test_hook_framework_basic() -> None:
    """Verify hook framework registration and emission."""
    hooks = HookFramework()
    received = []

    def cb(va: int) -> None:
        received.append(va)

    hooks.register(HookFramework.ON_NODE_DISCOVERED, cb)
    hooks.emit(HookFramework.ON_NODE_DISCOVERED, va=0x1000)

    assert received == [0x1000]


def test_hook_framework_error_isolation() -> None:
    """Verify that exception in one callback does not block subsequent callbacks."""
    hooks = HookFramework()
    calls = []

    def cb1(va: int) -> None:
        calls.append("cb1")

    def cb_failing(va: int) -> None:
        raise RuntimeError("Callback failure")

    def cb2(va: int) -> None:
        calls.append("cb2")

    hooks.register("test_event", cb1)
    hooks.register("test_event", cb_failing)
    hooks.register("test_event", cb2)

    hooks.emit("test_event", va=0x1000)
    assert calls == ["cb1", "cb2"]


def test_hook_framework_unregistered_event() -> None:
    """Verify emitting an unregistered event completes silently without exception."""
    hooks = HookFramework()
    hooks.emit("unregistered_event", arg=123)


def test_progress_event_bus_rate_limiting() -> None:
    """Verify progress event bus rate limits events to max 10/sec (<= 3 in 0.05s burst)."""
    bus = ProgressEventBus()
    events = []

    def listener(data: dict[str, Any]) -> None:
        events.append(data)

    bus.add_listener(listener)

    start_time = time.monotonic()
    while time.monotonic() - start_time < 0.05:
        bus.emit("scanning", 50.0)

    assert len(events) <= 3
    assert len(events) >= 1

    payload = events[0]
    assert "phase" in payload
    assert "pct" in payload
    assert "timestamp" in payload


def test_forensic_audit_trail_chaining(tmp_output_dir: Path) -> None:
    """Verify HMAC chaining in ForensicAuditTrail across 3 sequential records."""
    audit_file = tmp_output_dir / "audit.jsonl"
    dump_hash = "a" * 64

    with ForensicAuditTrail(audit_file, dump_hash) as audit:
        audit.record(ForensicAuditTrail.DUMP_INGESTED, file_size=1024)
        audit.record(ForensicAuditTrail.ARCHITECTURE_DETECTED, arch="x86_64")
        audit.record(ForensicAuditTrail.SCAN_COMPLETED, nodes=10, edges=5)

    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3

    records = [json.loads(line) for line in lines]
    hmac_key = hashlib.sha256(dump_hash.encode("utf-8")).digest()

    # Re-verify HMAC chain manually
    prev_hmac = ""
    for r in records:
        recorded_hmac = r.pop("hmac")
        payload_json = json.dumps(r, sort_keys=True)
        expected_hmac = hmac.new(
            hmac_key,
            (payload_json + prev_hmac).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        assert recorded_hmac == expected_hmac
        prev_hmac = recorded_hmac


def test_forensic_audit_trail_hash_sensitivity(tmp_output_dir: Path) -> None:
    """Verify different dump_integrity_hash values produce distinct HMAC chains."""
    path1 = tmp_output_dir / "audit1.jsonl"
    path2 = tmp_output_dir / "audit2.jsonl"

    with ForensicAuditTrail(path1, "a" * 64) as audit1:
        audit1.record("event", val=1)

    with ForensicAuditTrail(path2, "b" * 64) as audit2:
        audit2.record("event", val=1)

    rec1 = json.loads(path1.read_text(encoding="utf-8").strip())
    rec2 = json.loads(path2.read_text(encoding="utf-8").strip())

    assert rec1["hmac"] != rec2["hmac"]


def test_logging_configuration(tmp_output_dir: Path) -> None:
    """Verify JSONLinesFileHandler and logging setup."""
    log_file = tmp_output_dir / "engine.jsonl"

    handler = JSONLinesFileHandler(str(log_file))
    logger = logging.getLogger("test_json_logger")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    logger.info("Test log message")
    handler.close()

    content = log_file.read_text(encoding="utf-8").strip()
    log_entry = json.loads(content)
    assert log_entry["level"] == "INFO"
    assert log_entry["message"] == "Test log message"
    assert log_entry["name"] == "test_json_logger"
    assert "ts" in log_entry


def test_configure_logging_root_logger(tmp_output_dir: Path) -> None:
    """Verify configure_logging sets up root logger handlers and guards re-configuration."""
    log_file = tmp_output_dir / "root.jsonl"
    logger = logging.getLogger()
    # Save original handlers
    orig_handlers = list(logger.handlers)
    logger.handlers.clear()

    try:
        configure_logging(log_file, debug=True)
        assert len(logger.handlers) >= 2

        # Second call should return early
        handlers_count = len(logger.handlers)
        configure_logging(log_file, debug=False)
        assert len(logger.handlers) == handlers_count
    finally:
        logger.handlers = orig_handlers

