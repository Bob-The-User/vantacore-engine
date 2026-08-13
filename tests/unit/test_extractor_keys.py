"""Unit tests for KeysExtractor."""

import io
import os
from pathlib import Path

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.generic.keys import KeysExtractor


def test_keys_extractor_all_zeros_returns_empty() -> None:
    """Verify zero-filled binary returns empty high_entropy_regions."""
    ext = KeysExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 4096)
    res = ext.run(backend, fh, Path("/tmp"))

    assert res["high_entropy_regions"] == []


def test_keys_extractor_high_entropy_random_bytes() -> None:
    """Verify random high-entropy bytes detect at least one high entropy region."""
    ext = KeysExtractor()
    backend = FlatImageBackend()
    # 4KB of random bytes will have Shannon entropy near 8.0
    fh = io.BytesIO(os.urandom(4096))
    res = ext.run(backend, fh, Path("/tmp"))

    assert len(res["high_entropy_regions"]) >= 1
    assert res["high_entropy_regions"][0]["entropy"] >= 7.0


def test_keys_extractor_hop_cap_truncation(caplog) -> None:
    """Verify 500,000-hop cap logs warning and returns partial results."""
    import logging

    caplog.set_level(logging.WARNING)
    ext = KeysExtractor()
    ext.MAX_HOPS = 3
    backend = FlatImageBackend()

    class MockHugeStream(io.BytesIO):
        def __init__(self, data: bytes) -> None:
            super().__init__(data)
            self._pos_val = 0

        def seek(self, target: int, whence: int = 0) -> int:
            if whence == 2:
                self._pos_val = 5000000000
                return 5000000000
            res = super().seek(target, whence)
            self._pos_val = res
            return res

        def tell(self) -> int:
            return self._pos_val

    fh = MockHugeStream(os.urandom(4096 * 10))
    res = ext.run(backend, fh, Path("/tmp"))

    assert "high_entropy_regions" in res
    assert "500,000-hop cap reached" in caplog.text


def test_calculate_shannon_entropy_empty() -> None:
    """Verify Shannon entropy helper returns 0.0 for empty input."""
    from vantacore_engine.extractors.generic.keys import _calculate_shannon_entropy

    assert _calculate_shannon_entropy(b"") == 0.0


def test_keys_extractor_seek_beyond_eof() -> None:
    """Verify KeysExtractor handles file handle already at EOF gracefully."""
    ext = KeysExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    fh.seek(1024)

    res = ext.run(backend, fh, Path("/tmp"))
    assert res["high_entropy_regions"] == []




