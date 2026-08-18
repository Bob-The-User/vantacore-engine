"""CLI history extractor for Cisco appliances using pattern scanning."""

import logging
from pathlib import Path
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_CLI_SENTINELS = [b"show ", b"configure terminal", b"enable", b"no ", b"exit"]
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


def _is_cli_sentinel(chunk: bytes, offset: int) -> bool:
    """Check if byte sequence at given offset starts with a CLI command sentinel.

    Args:
        chunk: Byte buffer to check.
        offset: Offset within the buffer.

    Returns:
        True if offset starts with any known sentinel, False otherwise.

    """
    for sentinel in _CLI_SENTINELS:
        if chunk.startswith(sentinel, offset):
            return True
    return False


def _extract_command_string(chunk: bytes, offset: int, max_len: int = 256) -> Optional[str]:
    """Extract a printable null-terminated or newline-terminated ASCII string.

    Args:
        chunk: Byte buffer.
        offset: Starting byte offset.
        max_len: Maximum length to extract.

    Returns:
        Cleaned command string if valid printable ASCII, else None.

    """
    end = offset
    limit = min(len(chunk), offset + max_len)
    while end < limit:
        b = chunk[end]
        if b in (0, 10, 13):  # null, \n, \r
            break
        if b < 32 or b > 126:  # non-printable ASCII
            break
        end += 1

    if end == offset:
        return None

    try:
        cmd = chunk[offset:end].decode("ascii").strip()
        return cmd if cmd else None
    except UnicodeDecodeError:
        return None


class CLIHistoryExtractor(BaseExtractor):
    """Extractor recovering Cisco CLI execution history via pattern scanning."""

    name = "cisco/common/cli_history"
    compatible_platforms = [
        "cisco_asa",
        "cisco_ios",
        "cisco_iosxe",
        "cisco_nxos",
        "cisco_ftd",
    ]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical dump memory for CLI command strings and cluster into sessions.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing extracted cli_history clusters and confidence status.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        raw_matches: list[tuple[int, str]] = []
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("CLIHistoryExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            for sentinel in _CLI_SENTINELS:
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(sentinel, pos)
                    if idx == -1:
                        break
                    cmd = _extract_command_string(chunk, idx)
                    if cmd:
                        phys_off = offset + idx
                        raw_matches.append((phys_off, cmd))
                    pos = idx + len(sentinel)

        raw_matches.sort(key=lambda x: x[0])

        # Cluster matches where consecutive offsets differ by <= 512 bytes
        clusters: list[list[str]] = []
        if raw_matches:
            current_cluster: list[str] = [raw_matches[0][1]]
            prev_offset = raw_matches[0][0]

            for phys_off, cmd in raw_matches[1:]:
                if (phys_off - prev_offset <= 512) and (len(current_cluster) < 256):
                    current_cluster.append(cmd)
                else:
                    if current_cluster:
                        clusters.append(current_cluster)
                    current_cluster = [cmd]
                prev_offset = phys_off

            if current_cluster:
                clusters.append(current_cluster)

        cli_history = [
            {
                "commands": cluster,
                "source": "pattern_scan",
                "confidence": "LOW",
            }
            for cluster in clusters
        ]

        confidence = "FOUND" if cli_history else "NOT_FOUND"

        return {
            "cli_history": cli_history,
            "cli_history_confidence": confidence,
        }
