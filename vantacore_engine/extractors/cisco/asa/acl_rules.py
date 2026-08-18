"""Access Control List (ACL) extractor for Cisco ASA appliances."""

import logging
from pathlib import Path
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_VERSION_PREFIX = b"Cisco Adaptive Security Appliance Software Version "
_ACL_PREFIX = b"access-list "
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


def _extract_firmware_version(chunk: bytes) -> str:
    """Extract ASA firmware version string from memory chunk.

    Args:
        chunk: Byte buffer from dump.

    Returns:
        Firmware version string or 'unknown'.

    """
    idx = chunk.find(_VERSION_PREFIX)
    if idx != -1:
        start = idx + len(_VERSION_PREFIX)
        raw = chunk[start : start + 16].split(b"\x00")[0]
        try:
            ver = raw.decode("ascii", errors="ignore").strip()
            if ver:
                return ver
        except Exception:
            pass
    return "unknown"


class ASAACLRulesExtractor(BaseExtractor):
    """Extractor recovering compiled and textual ACL rules from Cisco ASA dumps."""

    name = "cisco/asa/acl_rules"
    compatible_platforms = ["cisco_asa"]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory for access-list definitions.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing acl_rules list.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        first_chunk = dump_handle.read(65536)
        fw_version = _extract_firmware_version(first_chunk)
        dump_handle.seek(0)

        acl_rules: list[dict] = []
        seen_rules: set[str] = set()
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("ASAACLRulesExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            pos = 0
            while pos < len(chunk):
                idx = chunk.find(_ACL_PREFIX, pos)
                if idx == -1:
                    break

                snippet = chunk[idx : idx + 256]
                pos = idx + len(_ACL_PREFIX)

                try:
                    text = snippet.decode("latin-1", errors="ignore")
                    line = text.split("\x00")[0].split("\n")[0].strip()
                    if line in seen_rules:
                        continue

                    tokens = line.split()
                    if len(tokens) < 4:
                        continue

                    # Find permit or deny
                    act_idx = -1
                    action = ""
                    for i, tok in enumerate(tokens):
                        if tok.lower() in ("permit", "deny"):
                            act_idx = i
                            action = tok.lower()
                            break

                    if act_idx == -1:
                        continue

                    # tokens[0] is "access-list"
                    # ACL name is token[1]
                    acl_name = tokens[1] if len(tokens) > 1 and tokens[0] == "access-list" else tokens[0]

                    protocol = tokens[act_idx + 1] if act_idx + 1 < len(tokens) else "ip"
                    rest = tokens[act_idx + 2 :] if act_idx + 2 < len(tokens) else []

                    # Split rest into source and destination
                    source = "any"
                    destination = "any"
                    if len(rest) == 1:
                        source = rest[0]
                    elif len(rest) == 2:
                        source = rest[0]
                        destination = rest[1]
                    elif len(rest) > 2:
                        # If first token is any or host x.x.x.x
                        if rest[0] == "any":
                            source = "any"
                            destination = " ".join(rest[1:])
                        elif rest[0] == "host" and len(rest) > 2:
                            source = f"host {rest[1]}"
                            destination = " ".join(rest[2:])
                        else:
                            half = len(rest) // 2
                            source = " ".join(rest[:half])
                            destination = " ".join(rest[half:])

                    seen_rules.add(line)
                    acl_rules.append(
                        {
                            "acl_name": acl_name,
                            "action": action,
                            "protocol": protocol,
                            "source": source,
                            "destination": destination,
                            "extraction_method": "text_pattern",
                            "firmware_version": fw_version,
                            "struct_layout_version": "N/A",
                        }
                    )
                except Exception:
                    continue

        return {"acl_rules": acl_rules}
