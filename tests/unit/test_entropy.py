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


def test_entropy_has_elftools_false_branch() -> None:
    """Verify that EncryptedMemoryDetector handles HAS_ELFTOOLS=False gracefully."""
    import unittest.mock

    detector = EncryptedMemoryDetector()
    data = b"\x7fELF" + (b"\x00" * 8192)
    size = len(data)
    handle = io.BytesIO(data)

    with unittest.mock.patch("vantacore_engine.core.entropy.HAS_ELFTOOLS", False):
        result = detector.detect(handle, size)

    assert isinstance(result, dict)
    assert result["likely_encrypted"] is False
    assert result["evidence"] == []


class _ShortReadBuffer(io.BytesIO):
    """BytesIO subclass that returns short reads for 4096-byte requests."""

    def read(self, size: int = -1) -> bytes:
        """Return a single byte when 4096 bytes are requested."""
        if size == 4096:
            return b"\x00"
        return super().read(size)


def test_entropy_short_page_read_skipped() -> None:
    """Verify that short page reads are skipped in sampling loop."""
    detector = EncryptedMemoryDetector()
    size = 16 * 4096
    handle = _ShortReadBuffer(b"\x00" * size)

    result = detector.detect(handle, size)
    assert result["confidence"] == 0.0
    assert result["likely_encrypted"] is False


def test_entropy_logger_critical_called_on_encrypted() -> None:
    """Verify that logger.critical is called when likely_encrypted is True."""
    import unittest.mock

    detector = EncryptedMemoryDetector()
    size = 4 * 1024 * 1024
    data = os.urandom(size)
    handle = io.BytesIO(data)

    with unittest.mock.patch("vantacore_engine.core.entropy.logger") as mock_logger:
        result = detector.detect(handle, size)

    assert mock_logger.critical.called
    assert result["likely_encrypted"] is True

