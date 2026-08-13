"""KeysExtractor scanning memory for high-entropy secret/key candidate regions."""

import logging
import math
from pathlib import Path
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)


def _calculate_shannon_entropy(data: bytes) -> float:
    """Calculate base-2 Shannon entropy for a byte sequence.

    Args:
        data: Input byte array.

    Returns:
        Entropy float value between 0.0 and 8.0.

    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


class KeysExtractor(BaseExtractor):
    """Extractor that scans memory for high-entropy regions (cryptographic keys)."""

    name = "generic/keys"
    compatible_platforms = ["*"]
    dependencies: list[str] = []
    MAX_HOPS = 500_000

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory in 4 KB chunks for high-entropy 256-byte windows.

        Args:
            backend: TranslationBackend instance (unused for physical scan).
            dump_handle: Open file handle for physical memory access.
            output_dir: Output directory path.

        Returns:
            Dictionary containing list of high_entropy_regions.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        results = []
        hops = 0
        chunk_size = 4096
        window_size = 256
        stride = 256

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= self.MAX_HOPS:
                logger.warning(
                    "KeysExtractor: 500,000-hop cap reached at offset %d. Truncating scan.",
                    offset,
                )
                break

            chunk = dump_handle.read(chunk_size)
            if not chunk:
                break
            hops += 1

            for win_offset in range(0, len(chunk) - window_size + 1, stride):
                window = chunk[win_offset : win_offset + window_size]
                entropy = _calculate_shannon_entropy(window)
                if entropy >= 7.0:
                    results.append(
                        {
                            "offset": offset + win_offset,
                            "length": window_size,
                            "entropy": round(entropy, 4),
                        }
                    )

        return {"high_entropy_regions": results}
