"""VPN sessions and pre-shared key extractor for Cisco ASA appliances."""

import logging
from pathlib import Path
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_VERSION_PREFIX = b"Cisco Adaptive Security Appliance Software Version "
_PSK_PREFIX = b"pre-shared-key "
_SESSION_PATTERNS = [b"IKEv", b"AnyConnect", b"Crypto map tag:", b"peer address:"]
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


def _is_valid_ip(s: str) -> bool:
    """Validate IPv4 dotted-decimal string.

    Args:
        s: IP address string.

    Returns:
        True if valid non-broadcast, non-zero IPv4 address, False otherwise.

    """
    clean = s.strip(":,;()")
    if clean in ("0.0.0.0", "255.255.255.255"):
        return False
    parts = clean.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
        return all(0 <= o <= 255 for o in octets)
    except ValueError:
        return False


def _extract_token(chunk: bytes, offset: int, max_len: int = 64) -> Optional[str]:
    """Extract a printable ASCII token up to whitespace or null.

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
        if b in (0, 9, 10, 13, 32):
            break
        if b < 32 or b > 126:
            break
        end += 1

    if end == offset:
        return None

    try:
        token = chunk[offset:end].decode("ascii").strip()
        return token if token else None
    except UnicodeDecodeError:
        return None


class ASAVPNSessionsExtractor(BaseExtractor):
    """Extractor recovering active VPN sessions and pre-shared keys from Cisco ASA dumps."""

    name = "cisco/asa/vpn_sessions"
    compatible_platforms = ["cisco_asa"]
    dependencies: list[str] = []

    def __init__(self, include_secrets: bool = False) -> None:
        """Initialize ASAVPNSessionsExtractor with secret redaction control.

        Args:
            include_secrets: If True, include plaintext pre-shared keys in output.

        """
        self._include_secrets = include_secrets

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Scan physical memory for VPN session structures and PSK credentials.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing vpn_sessions and vpn_psks lists.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        sessions: list[dict] = []
        psks: list[dict] = []
        seen_psk_offsets: set[int] = set()
        seen_session_keys: set[tuple[str, str]] = set()
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size:
                break
            if hops >= _MAX_HOPS:
                logger.warning("ASAVPNSessionsExtractor: hop cap reached. Returning partial results.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            # 1. Scan for pre-shared-key
            pos = 0
            while pos < len(chunk):
                idx = chunk.find(_PSK_PREFIX, pos)
                if idx == -1:
                    break
                val_start = idx + len(_PSK_PREFIX)
                token = _extract_token(chunk, val_start)
                if token:
                    phys_off = offset + val_start
                    bucket = phys_off // 64
                    if bucket not in seen_psk_offsets:
                        seen_psk_offsets.add(bucket)
                        logger.warning(
                            "VPN pre-shared key found at physical offset 0x%x. Handle with care.",
                            phys_off,
                        )
                        psks.append(
                            {
                                "value": token if self._include_secrets else None,
                                "redacted": not self._include_secrets,
                                "physical_offset": phys_off,
                            }
                        )
                pos = idx + len(_PSK_PREFIX)

            # 2. Scan for VPN session indicators
            for pat in _SESSION_PATTERNS:
                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(pat, pos)
                    if idx == -1:
                        break

                    snippet = chunk[idx : idx + 128]
                    pos = idx + len(pat)

                    try:
                        text = snippet.decode("latin-1", errors="ignore")
                        tokens = text.split()
                        peer_ip = ""
                        for tok in tokens:
                            if _is_valid_ip(tok):
                                peer_ip = tok.strip(":,;()")
                                break

                        session_type = pat.decode("ascii", errors="ignore").strip(":")
                        key = (session_type, peer_ip)
                        if key not in seen_session_keys:
                            seen_session_keys.add(key)
                            sessions.append(
                                {
                                    "session_type": session_type,
                                    "peer_ip": peer_ip,
                                    "physical_offset": offset + idx,
                                }
                            )
                    except Exception:
                        continue

        return {"vpn_sessions": sessions, "vpn_psks": psks}
