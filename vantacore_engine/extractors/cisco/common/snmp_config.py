"""SNMP configuration extractor for Cisco appliances."""

import logging
from pathlib import Path
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_SNMP_PREFIX = b"snmp-server community "
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


def _extract_token(chunk: bytes, offset: int, max_len: int = 64) -> Optional[str]:
    """Extract a printable ASCII token up to first whitespace, null, or non-printable character.

    Args:
        chunk: Byte buffer.
        offset: Starting offset in buffer.
        max_len: Maximum length to scan.

    Returns:
        String token if valid printable ASCII, else None.

    """
    end = offset
    limit = min(len(chunk), offset + max_len)
    while end < limit:
        b = chunk[end]
        if b in (0, 9, 10, 13, 32):  # null, \t, \n, \r, space
            break
        if b < 32 or b > 126:  # non-printable ASCII
            break
        end += 1

    if end == offset:
        return None

    try:
        token = chunk[offset:end].decode("ascii").strip()
        return token if token else None
    except UnicodeDecodeError:
        return None


class SNMPConfigExtractor(BaseExtractor):
    """Extractor recovering SNMP community strings from memory."""

    name = "cisco/common/snmp_config"
    compatible_platforms = [
        "cisco_asa",
        "cisco_ios",
        "cisco_iosxe",
        "cisco_nxos",
        "cisco_ftd",
    ]
    dependencies: list[str] = []

    def __init__(self, include_secrets: bool = False) -> None:
        """Initialize SNMPConfigExtractor with secret redaction control.

        Args:
            include_secrets: If True, include plaintext community strings in output.

        """
        self._include_secrets = include_secrets

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory for SNMP community strings with secrets gating.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing snmp_community_strings list.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        seen_buckets: set[int] = set()
        findings: list[dict] = []
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("SNMPConfigExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            # 1. Scan for snmp-server community prefix
            pos = 0
            while pos < len(chunk):
                idx = chunk.find(_SNMP_PREFIX, pos)
                if idx == -1:
                    break
                val_start = idx + len(_SNMP_PREFIX)
                token = _extract_token(chunk, val_start)
                if token:
                    phys_off = offset + val_start
                    bucket = phys_off // 64
                    if bucket not in seen_buckets:
                        seen_buckets.add(bucket)
                        logger.warning(
                            "SNMP community string found at physical offset 0x%x. Handle with care.",
                            phys_off,
                        )
                        findings.append(
                            {
                                "value": token if self._include_secrets else None,
                                "redacted": not self._include_secrets,
                                "physical_offset": phys_off,
                            }
                        )
                pos = idx + len(_SNMP_PREFIX)

            # 2. Standalone public\x00 and private\x00 scan
            for standalone in (b"public\x00", b"private\x00"):
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(standalone, pos)
                    if idx == -1:
                        break
                    phys_off = offset + idx
                    bucket = phys_off // 64
                    if bucket not in seen_buckets:
                        seen_buckets.add(bucket)
                        name_str = standalone[:-1].decode("ascii")
                        logger.warning(
                            "SNMP community string found at physical offset 0x%x. Handle with care.",
                            phys_off,
                        )
                        findings.append(
                            {
                                "value": name_str if self._include_secrets else None,
                                "redacted": not self._include_secrets,
                                "physical_offset": phys_off,
                            }
                        )
                    pos = idx + len(standalone)

        return {"snmp_community_strings": findings}
