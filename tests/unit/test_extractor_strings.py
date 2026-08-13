"""Unit tests for StringsExtractor."""

from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.generic.strings import StringsExtractor


def test_strings_extractor_basic(tmp_path: Path) -> None:
    """Verify StringsExtractor runs llvm-strings on file and captures output."""
    dump_file = tmp_path / "test_dump.bin"
    dump_file.write_bytes(b"Hello World\x00This is a test string pattern\x00")

    ext = StringsExtractor()
    backend = FlatImageBackend()
    with open(dump_file, "rb") as fh:
        res = ext.run(backend, fh, tmp_path)

    assert isinstance(res["strings"], list)
    assert any("Hello World" in s or "This is a test string" in s for s in res["strings"])


def test_strings_extractor_missing_binary_raises_runtime_error() -> None:
    """Verify RuntimeError is raised when llvm-strings binary cannot be resolved."""
    ext = StringsExtractor()
    backend = FlatImageBackend()
    dummy_fh = MagicMock()
    dummy_fh.name = "/tmp/dummy.bin"

    with patch("pathlib.Path.exists", return_value=False), patch("shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="llvm-strings binary not found"):
            ext.run(backend, dummy_fh, Path("/tmp"))


def test_strings_extractor_truncates_at_50k_lines() -> None:
    """Verify output strings list is truncated to 50,000 entries max."""
    ext = StringsExtractor()
    backend = FlatImageBackend()
    dummy_fh = MagicMock()
    dummy_fh.name = "/tmp/dummy.bin"

    mock_stdout = "\n".join([f"string_{i}" for i in range(60_000)])
    completed_proc = subprocess.CompletedProcess(
        args=["llvm-strings"],
        returncode=0,
        stdout=mock_stdout,
        stderr="",
    )

    with patch("subprocess.run", return_value=completed_proc):
        res = ext.run(backend, dummy_fh, Path("/tmp"))

    assert len(res["strings"]) == 50_000
    assert res["strings"][0] == "string_0"
    assert res["strings"][-1] == "string_49999"


def test_strings_extractor_invalid_dump_handle_raises_runtime_error() -> None:
    """Verify error when dump_handle does not have a valid string path name."""
    ext = StringsExtractor()
    backend = FlatImageBackend()
    bad_fh = MagicMock()
    bad_fh.name = 12345  # Not a str or Path

    with patch("vantacore_engine.extractors.generic.strings._resolve_llvm_strings_binary", return_value=Path("/usr/bin/llvm-strings")):
        with pytest.raises(RuntimeError, match="dump_handle must be a file object"):
            ext.run(backend, bad_fh, Path("/tmp"))


def test_strings_extractor_nonzero_returncode_warning(caplog) -> None:
    """Verify warning logged when llvm-strings exits non-zero."""
    import logging

    caplog.set_level(logging.WARNING)
    ext = StringsExtractor()
    backend = FlatImageBackend()
    dummy_fh = MagicMock()
    dummy_fh.name = "/tmp/dummy.bin"

    completed_proc = subprocess.CompletedProcess(
        args=["llvm-strings"],
        returncode=1,
        stdout="some_string\n",
        stderr="error",
    )

    with patch("subprocess.run", return_value=completed_proc):
        res = ext.run(backend, dummy_fh, Path("/tmp"))

    assert "llvm-strings exited with code 1" in caplog.text
    assert res["strings"] == ["some_string"]

