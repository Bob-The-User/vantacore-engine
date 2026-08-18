"""Routing table extractor for Cisco IOS and IOS-XE platforms."""

import logging
from pathlib import Path
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000

_PROTOCOL_MAP = {
    b"O ": "OSPF",
    b"C ": "CONNECTED",
    b"S ": "STATIC",
    b"B ": "BGP",
    b"D ": "EIGRP",
    b"R ": "RIP",
}


def _is_valid_ip(s: str) -> bool:
    """Validate standard IPv4 address.

    Args:
        s: Candidate IP address string.

    Returns:
        True if valid IPv4 octets, False otherwise.

    """
    clean = s.strip("[],;()")
    parts = clean.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_valid_ipv4_prefix(s: str) -> bool:
    """Validate CIDR prefix format (e.g. 192.168.1.0/24).

    Args:
        s: Candidate prefix string.

    Returns:
        True if valid IPv4 CIDR prefix, False otherwise.

    """
    clean = s.strip("[],;()")
    if "/" not in clean:
        return False
    ip_part, mask_part = clean.split("/", 1)
    if not _is_valid_ip(ip_part):
        return False
    try:
        mask = int(mask_part)
        return 0 <= mask <= 32
    except ValueError:
        return False


def _mask_to_prefix_len(mask_str: str) -> Optional[int]:
    """Convert dotted-decimal subnet mask to prefix length.

    Args:
        mask_str: Dotted decimal mask string.

    Returns:
        Prefix length integer or None.

    """
    if not _is_valid_ip(mask_str):
        return None
    try:
        octets = [int(o) for o in mask_str.split(".")]
        binary_str = "".join(f"{o:08b}" for o in octets)
        if "01" in binary_str:
            return None
        return binary_str.count("1")
    except Exception:
        return None


class IOSRoutingTableExtractor(BaseExtractor):
    """Extractor recovering RIB routing table entries from Cisco IOS/IOS-XE dumps."""

    name = "cisco/ios/routing_table"
    compatible_platforms = ["cisco_ios", "cisco_iosxe"]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory for routing table and static route patterns.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing routing_table list.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        routes: list[dict] = []
        seen_prefixes: set[tuple[str, str]] = set()
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("IOSRoutingTableExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            # 1. Scan for show ip route style lines (protocol codes)
            for code_bytes, proto_name in _PROTOCOL_MAP.items():
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(code_bytes, pos)
                    if idx == -1:
                        break

                    snippet = chunk[idx : idx + 128]
                    pos = idx + len(code_bytes)

                    try:
                        text = snippet.decode("latin-1", errors="ignore")
                        line = text.split("\x00")[0].split("\n")[0].strip()
                        tokens = line.split()
                        if not tokens:
                            continue

                        prefix = ""
                        for tok in tokens:
                            if _is_valid_ipv4_prefix(tok):
                                prefix = tok.strip("[],;()")
                                break

                        if not prefix:
                            continue

                        next_hop = "directly connected"
                        if "via" in tokens:
                            via_idx = tokens.index("via")
                            if via_idx + 1 < len(tokens) and _is_valid_ip(tokens[via_idx + 1]):
                                next_hop = tokens[via_idx + 1].strip("[],;()")

                        key = (proto_name, prefix)
                        if key not in seen_prefixes:
                            seen_prefixes.add(key)
                            routes.append(
                                {
                                    "protocol": proto_name,
                                    "prefix": prefix,
                                    "next_hop": next_hop,
                                    "physical_offset": offset + idx,
                                }
                            )
                    except Exception:
                        continue

            # 2. Scan for 'ip route ' static config lines
            pos = 0
            while pos < len(chunk):
                idx = chunk.find(b"ip route ", pos)
                if idx == -1:
                    break

                snippet = chunk[idx : idx + 128]
                pos = idx + len(b"ip route ")

                try:
                    text = snippet.decode("latin-1", errors="ignore")
                    line = text.split("\x00")[0].split("\n")[0].strip()
                    tokens = line.split()
                    if len(tokens) >= 5 and tokens[0] == "ip" and tokens[1] == "route":
                        net = tokens[2]
                        mask = tokens[3]
                        hop = tokens[4]

                        if _is_valid_ip(net) and _is_valid_ip(mask):
                            prefix_len = _mask_to_prefix_len(mask)
                            prefix = f"{net}/{prefix_len}" if prefix_len is not None else f"{net} {mask}"
                            next_hop = hop if _is_valid_ip(hop) else "directly connected"
                            key = ("STATIC", prefix)
                            if key not in seen_prefixes:
                                seen_prefixes.add(key)
                                routes.append(
                                    {
                                        "protocol": "STATIC",
                                        "prefix": prefix,
                                        "next_hop": next_hop,
                                        "physical_offset": offset + idx,
                                    }
                                )
                except Exception:
                    continue

        return {"routing_table": routes}
