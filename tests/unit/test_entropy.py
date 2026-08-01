"""Unit tests for EncryptedMemoryDetector."""

import io
import os
from pathlib import Path
from typing import Callable
from vantacore_engine.core.entropy import EncryptedMemoryDetector


def test_entropy_detector_all_zeros() -> None:
    """Verify that all-zero memory dump reports likely_encrypted False."""
    detector = EncryptedMemoryDetector()
    size = 16 * 1024 * 1024
    data = b"\x00" * size
    handle = io.BytesIO(data)

    res = detector.detect(handle, size)
    assert not res["likely_encrypted"]
    assert res["confidence"] == 0.0
    assert isinstance(res["evidence"], list)


def test_entropy_detector_high_entropy_random() -> None:
    """Verify that uniform random data reports likely_encrypted True."""
    detector = EncryptedMemoryDetector()
    size = 4 * 1024 * 1024
    # Deterministic pseudo-random bytes to keep test fast and repeatable
    data = os.urandom(size)
    handle = io.BytesIO(data)

    res = detector.detect(handle, size)
    assert res["likely_encrypted"]
    assert res["confidence"] >= 0.75


def test_entropy_detector_mixed_data_threshold() -> None:
    """Verify threshold gate: 25% random + 75% zeros stays below 0.75 confidence."""
    detector = EncryptedMemoryDetector()
    quarter = 4 * 1024 * 1024
    three_quarters = 12 * 1024 * 1024
    data = os.urandom(quarter) + (b"\x00" * three_quarters)
    size = len(data)
    handle = io.BytesIO(data)

    res = detector.detect(handle, size)
    assert not res["likely_encrypted"]
    assert res["confidence"] < 0.75


def test_entropy_detector_non_elf_msr_path() -> None:
    """Verify that non-ELF binary handle does not fail on MSR path."""
    detector = EncryptedMemoryDetector()
    data = b"NOT_AN_ELF_FILE_HEADER_AND_SOME_PADDING" + (b"\x00" * 8192)
    size = len(data)
    handle = io.BytesIO(data)

    res = detector.detect(handle, size)
    assert not res["likely_encrypted"]
    assert res["evidence"] == []


def test_entropy_detector_zero_size() -> None:
    """Verify zero-length file handle handling without exception."""
    detector = EncryptedMemoryDetector()
    handle = io.BytesIO(b"")
    res = detector.detect(handle, 0)

    assert res == {
        "likely_encrypted": False,
        "confidence": 0.0,
        "evidence": [],
    }


def test_entropy_detector_with_elf_fixture(dump_path: Callable[[str], Path]) -> None:
    """Verify entropy detector against the mock ELF core fixture file."""
    elf_path = dump_path("mock_elf_core_x86_64.bin")
    file_size = elf_path.stat().st_size

    detector = EncryptedMemoryDetector()
    with open(elf_path, "rb") as f:
        res = detector.detect(f, file_size)

    assert "likely_encrypted" in res
    assert "confidence" in res
    assert isinstance(res["evidence"], list)

