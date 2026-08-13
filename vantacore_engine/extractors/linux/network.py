"""LinuxNetworkExtractor scanning for network connections and socket structures."""

import logging
from pathlib import Path
import socket
import struct
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_INET_SOCK_SRC_IP = 0x4B8
_INET_SOCK_DST_IP = 0x4B4
_INET_SOCK_SPORT = 0x4C0
_INET_SOCK_DPORT = 0x4C2

_TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
}


def _is_valid_ipv4_bytes(ip_bytes: bytes) -> bool:
    if len(ip_bytes) != 4:
        return False
    if ip_bytes == b"\x00\x00\x00\x00" or ip_bytes == b"\xff\xff\xff\xff":
        return False
    # Avoid 0.x.x.x or 255.x.x.x
    if ip_bytes[0] in (0, 255):
        return False
    return True


def _format_ipv4(ip_bytes: bytes) -> str:
    try:
        return socket.inet_ntoa(ip_bytes)
    except Exception:
        return f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"


class LinuxNetworkExtractor(BaseExtractor):
    """Extractor scanning memory for IPv4 socket structures and connections."""

    name = "linux/network"
    compatible_platforms = ["linux", "cisco_iosxe"]
    dependencies = ["linux/process"]

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan dump file physical memory for socket candidate structures.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary file handle for physical memory scanning.
            output_dir: Output directory path.

        Returns:
            Dictionary containing list of extracted connections.

        """
        connections = []
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        chunk_size = 65536
        hops = 0
        max_hops = 500_000

        while True:
            offset = dump_handle.tell()
            if offset >= total_size or hops >= max_hops:
                break

            chunk = dump_handle.read(chunk_size)
            if not chunk:
                break

            # Scan chunk at 4-byte alignment
            for win_off in range(0, len(chunk) - 0x4D0, 4):
                if hops >= max_hops:
                    break

                src_ip_bytes = chunk[win_off + _INET_SOCK_SRC_IP : win_off + _INET_SOCK_SRC_IP + 4]
                dst_ip_bytes = chunk[win_off + _INET_SOCK_DST_IP : win_off + _INET_SOCK_DST_IP + 4]

                if _is_valid_ipv4_bytes(src_ip_bytes) and _is_valid_ipv4_bytes(dst_ip_bytes):
                    sport = struct.unpack_from(">H", chunk, win_off + _INET_SOCK_SPORT)[0]
                    dport = struct.unpack_from(">H", chunk, win_off + _INET_SOCK_DPORT)[0]

                    if 1 <= sport <= 65535 and 1 <= dport <= 65535:
                        hops += 1
                        local_addr = _format_ipv4(src_ip_bytes)
                        remote_addr = _format_ipv4(dst_ip_bytes)

                        connections.append(
                            {
                                "local_addr": local_addr,
                                "local_port": sport,
                                "remote_addr": remote_addr,
                                "remote_port": dport,
                                "proto": "TCP",
                                "state": "ESTABLISHED",
                                "offset": offset + win_off,
                            }
                        )

        logger.info("LinuxNetworkExtractor: socket heuristic scan complete. Results may be partial.")
        return {"connections": connections}
