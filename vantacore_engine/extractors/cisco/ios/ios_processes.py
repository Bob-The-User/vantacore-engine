"""IOS process table and memory pool extractor for Cisco IOS/IOS-XE."""

import logging
from pathlib import Path
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_MEMPOOL_MAGIC = b"\xAB\x12\x34\xCD"
_PID_PATTERNS = [b"PID ", b"Pid:"]
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000
_MAX_MEMPOOL_HITS = 500


class IOSProcessesExtractor(BaseExtractor):
    """Extractor recovering processes and mempool regions from Cisco IOS dumps."""

    name = "cisco/ios/ios_processes"
    compatible_platforms = ["cisco_ios", "cisco_iosxe"]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory for IOS process definitions and mempool blocks.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing ios_processes and mempool_regions lists.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        processes: list[dict] = []
        mempool_regions: list[dict] = []
        seen_pids: set[int] = set()
        seen_mempool_offsets: set[int] = set()
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("IOSProcessesExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            # 1. Scan for PID patterns
            for pat in _PID_PATTERNS:
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(pat, pos)
                    if idx == -1:
                        break

                    snippet = chunk[idx : idx + 64]
                    pos = idx + len(pat)

                    try:
                        text = snippet.decode("latin-1", errors="ignore")
                        line = text.split("\x00")[0].split("\n")[0].strip()
                        tokens = line.split()
                        if len(tokens) >= 3:
                            # Token 0 is 'PID' / 'Pid:'
                            pid_str = tokens[1].strip(":,;()")
                            if pid_str.isdigit():
                                pid = int(pid_str)
                                name = tokens[2].strip(":,;()")
                                if pid not in seen_pids and name:
                                    seen_pids.add(pid)
                                    processes.append(
                                        {
                                            "pid": pid,
                                            "name": name,
                                            "physical_offset": offset + idx,
                                        }
                                    )
                    except Exception:
                        continue

            # 2. Scan for IOS mempool magic
            if len(mempool_regions) < _MAX_MEMPOOL_HITS:
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(_MEMPOOL_MAGIC, pos)
                    if idx == -1:
                        break
                    phys_off = offset + idx
                    if phys_off not in seen_mempool_offsets:
                        seen_mempool_offsets.add(phys_off)
                        mempool_regions.append({"physical_offset": phys_off})
                        if len(mempool_regions) >= _MAX_MEMPOOL_HITS:
                            break
                    pos = idx + 4

        return {
            "ios_processes": processes,
            "mempool_regions": mempool_regions,
        }
