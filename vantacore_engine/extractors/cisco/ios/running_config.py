"""Running configuration extractor for Cisco IOS, IOS-XE, and ASA appliances."""

import logging
from pathlib import Path
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_ANCHOR_SENTINELS = [
    b"hostname ",
    b"interface ",
    b"router ",
    b"ip route ",
    b"line vty",
    b"crypto ",
    b"aaa ",
]

_VERSION_PATTERNS = [
    b"Cisco Adaptive Security Appliance Software Version ",
    b"Cisco IOS Software, Version ",
    b"Cisco IOS XE Software, Version ",
]

_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


def _extract_printable_block(data: bytes, start: int, max_len: int = 4096) -> str:
    """Extract a block of printable ASCII / whitespace text starting at index.

    Args:
        data: Raw byte buffer.
        start: Starting byte index.
        max_len: Maximum length to consume.

    Returns:
        Decoded latin-1 string.

    """
    end = start
    limit = min(len(data), start + max_len)
    while end < limit:
        b = data[end]
        if b in (9, 10, 13) or (32 <= b <= 126):
            end += 1
        else:
            break

    if end == start:
        return ""

    try:
        return data[start:end].decode("latin-1", errors="ignore").strip()
    except Exception:
        return ""


def _detect_firmware_version(chunk: bytes) -> str:
    """Scan byte chunk for common Cisco firmware version banners.

    Args:
        chunk: Byte buffer from beginning of dump.

    Returns:
        Version string or 'unknown'.

    """
    for prefix in _VERSION_PATTERNS:
        idx = chunk.find(prefix)
        if idx != -1:
            start = idx + len(prefix)
            raw = chunk[start : start + 16].split(b"\x00")[0].split(b"\n")[0]
            try:
                ver = raw.decode("ascii", errors="ignore").strip()
                if ver:
                    return ver
            except Exception:
                pass
    return "unknown"


class RunningConfigExtractor(BaseExtractor):
    """Extractor recovering running configuration fragments via anchor sentinels."""

    name = "cisco/ios/running_config"
    compatible_platforms = ["cisco_ios", "cisco_iosxe", "cisco_asa"]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory for Cisco configuration section anchors.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing running_config details and confidence rating.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        first_chunk = dump_handle.read(65536)
        fw_version = _detect_firmware_version(first_chunk)
        dump_handle.seek(0)

        found_sections: list[str] = []
        found_anchors: set[str] = set()
        seen_offsets: set[int] = set()
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("RunningConfigExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            for anchor_bytes in _ANCHOR_SENTINELS:
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(anchor_bytes, pos)
                    if idx == -1:
                        break

                    phys_off = offset + idx
                    pos = idx + len(anchor_bytes)

                    bucket = (anchor_bytes, phys_off // 64)
                    if bucket not in seen_offsets:
                        seen_offsets.add(bucket)
                        section_text = _extract_printable_block(chunk, idx)
                        if section_text:
                            found_sections.append(section_text)
                            anchor_name = anchor_bytes.decode("ascii").strip()
                            found_anchors.add(anchor_name)

        sections_found = len(found_anchors)
        if sections_found == 0:
            confidence = "NOT_FOUND"
        elif sections_found in (1, 2):
            confidence = "LOW"
        elif 3 <= sections_found <= 5:
            confidence = "MEDIUM"
        else:
            confidence = "HIGH"

        joined_text = "\n\n".join(found_sections)

        return {
            "running_config": {
                "text": joined_text,
                "confidence": confidence,
                "sections_found": sections_found,
                "extraction_method": "text_pattern",
                "firmware_version": fw_version,
                "struct_layout_version": "N/A",
            }
        }
