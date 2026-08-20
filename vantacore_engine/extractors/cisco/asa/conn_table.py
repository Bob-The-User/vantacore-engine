"""Connection table extractor for Cisco ASA appliances using pattern scanning."""

import logging
from pathlib import Path
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_VERSION_PREFIX = b"Cisco Adaptive Security Appliance Software Version "
_PATTERNS = [b"   TCP ", b"   UDP ", b"   ICMP ", b"TCP ", b"UDP ", b"ICMP "]
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


def _is_valid_ip(s: str) -> bool:
    """Validate IPv4 dotted-decimal string.

    Args:
        s: IP address string.

    Returns:
        True if valid non-broadcast, non-zero IPv4 address, False otherwise.

    """
    if s in ("0.0.0.0", "255.255.255.255"):
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
        return all(0 <= o <= 255 for o in octets)
    except ValueError:
        return False


def _parse_ip_port(token: str) -> Optional[tuple[str, int]]:
    """Parse and validate an IP:port or IP/port string.

    Args:
        token: String containing IP and port separated by colon.

    Returns:
        Tuple of (ip, port) or None if invalid.

    """
    clean = token.rstrip(",;)")
    if ":" not in clean:
        return None
    ip_part, port_part = clean.rsplit(":", 1)
    if not _is_valid_ip(ip_part):
        return None
    try:
        port = int(port_part)
        if 1 <= port <= 65535:
            return ip_part, port
    except ValueError:
        return None
    return None


def _extract_firmware_version(chunk: bytes) -> str:
    """Extract ASA firmware version string from memory chunk.

    Args:
        chunk: Byte buffer from dump.

    Returns:
        Firmware version or 'unknown'.

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


class ASAConnTableExtractor(BaseExtractor):
    """Extractor recovering active stateful connections from Cisco ASA dumps."""

    name = "cisco/asa/conn_table"
    compatible_platforms = ["cisco_asa"]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory for active connection patterns.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing connections list.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        # Detect firmware version from first 64KB
        first_chunk = dump_handle.read(65536)
        fw_version = _extract_firmware_version(first_chunk)
        dump_handle.seek(0)

        connections: list[dict] = []
        conn_id_counter = 1
        seen_tuples: set[tuple[str, str, int, str, int]] = set()
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("ASAConnTableExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            for pat in (b"   TCP ", b"   UDP ", b"   ICMP "):
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(pat, pos)
                    if idx == -1:
                        break

                    snippet = chunk[idx : idx + 128]
                    pos = idx + len(pat)

                    try:
                        text = snippet.decode("latin-1", errors="ignore")
                        lines = text.split("\n")
                        line = lines[0].strip()
                        tokens = line.split()
                        if len(tokens) < 3:
                            continue

                        protocol = tokens[0].upper()
                        src = _parse_ip_port(tokens[1])
                        dst = _parse_ip_port(tokens[2])

                        if src is None or dst is None:
                            continue

                        src_ip, src_port = src
                        dst_ip, dst_port = dst

                        key = (protocol, src_ip, src_port, dst_ip, dst_port)
                        if key in seen_tuples:
                            continue
                        seen_tuples.add(key)

                        flags: list[str] = []
                        if "flags" in line:
                            flags_idx = tokens.index("flags") if "flags" in tokens else -1
                            if flags_idx != -1 and flags_idx + 1 < len(tokens):
                                raw_parts = tokens[flags_idx + 1].split("\x00")[0].split()
                                raw_flag = raw_parts[0].strip(",") if raw_parts else ""
                                flags = [raw_flag] if raw_flag else []

                        bytes_val = 0
                        if "bytes" in line:
                            bytes_idx = tokens.index("bytes") if "bytes" in tokens else -1
                            if bytes_idx != -1 and bytes_idx + 1 < len(tokens):
                                try:
                                    bytes_val = int(tokens[bytes_idx + 1].strip(","))
                                except ValueError:
                                    bytes_val = 0

                        conn_entry = {
                            "conn_id": conn_id_counter,
                            "protocol": protocol,
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "flags": flags,
                            "bytes_in": bytes_val,
                            "bytes_out": 0,
                            "last_used_unix": 0,
                            "last_used_iso": "",
                            "ingress_interface": "",
                            "egress_interface": "",
                            "virtual_address": hex(offset + idx),
                            "extraction_method": "text_pattern",
                            "firmware_version": fw_version,
                            "struct_layout_version": "N/A",
                        }
                        connections.append(conn_entry)
                        conn_id_counter += 1

                    except Exception:
                        continue

        return {"connections": connections}
