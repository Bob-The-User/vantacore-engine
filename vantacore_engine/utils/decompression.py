"""Decompression utilities for compressed memory pages and segments."""

import lz4.frame
import zstandard as zstd


def decompress_lz4(data: bytes) -> bytes:
    """Decompress LZ4 frame formatted data.

    Args:
        data: Compressed byte string.

    Returns:
        Decompressed byte string.

    """
    return lz4.frame.decompress(data)


def decompress_zstd(data: bytes) -> bytes:
    """Decompress Zstandard formatted data.

    Args:
        data: Compressed byte string.

    Returns:
        Decompressed byte string.

    """
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(data)


def decompress_lzo(data: bytes) -> bytes:
    """Stub for LZO decompression (requires system liblzo2 ctypes binding).

    Args:
        data: Compressed byte string.

    Returns:
        Decompressed byte string.

    Raises:
        NotImplementedError: LZO requires clean system library bindings to avoid GPL contamination.

    """
    # TODO: replace with actual issue URL when created
    raise NotImplementedError(
        "LZO decompression requires a ctypes binding to system liblzo2. "
        "GPL-safe implementation is tracked at: "
        "https://github.com/<repo>/vantacore-engine/issues/TBD"
    )
