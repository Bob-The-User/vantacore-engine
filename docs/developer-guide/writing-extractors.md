# Writing Extractors

Extractors analyze memory contents to recover specific forensic artifacts (processes, network connections, configuration fragments, credentials, or keys).

## Extractor Design Rules

1. **Iterative Traversal**: Never use recursion when walking linked lists or structures.
2. **Hop Cap**: Enforce a 500,000-hop hard cap on any scanning or pointer-following loop.
3. **No `re` Module**: Use `google-re2`, `bytes.find()`, or string operations to prevent ReDoS on adversarial memory dumps.
4. **Isolated Error Boundaries**: Handle malformed data gracefully without raising unhandled exceptions.
5. **Secret Redaction**: Always redact cryptographic keys and passwords unless `--include-secrets` is enabled.

---

## Minimal Extractor Example

The following is a complete, working extractor demonstrating platform compatibility, arguments, docstrings, and result formats:

```python
"""Sample banner extractor demonstrating the BaseExtractor interface."""

import logging
from pathlib import Path
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_BANNER_PREFIX = b"System initialized at "
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


class BannerExtractor(BaseExtractor):
    """Extractor recovering system initialization timestamps from memory."""

    name = "sample/banner"
    compatible_platforms = ["cisco_asa", "cisco_ios", "linux"]
    dependencies: list[str] = []

    def __init__(self, include_secrets: bool = False) -> None:
        """Initialize BannerExtractor with optional secrets configuration.

        Args:
            include_secrets: Whether to extract unredacted sensitive values.

        """
        self._include_secrets = include_secrets

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Execute extraction against memory dump and translation backend.

        Args:
            backend: TranslationBackend instance for virtual memory queries.
            dump_handle: Open binary file handle for physical memory scans.
            output_dir: Output path for temporary files and disk artifacts.

        Returns:
            Dictionary containing extracted forensic artifacts.

        """
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        banners: list[dict] = []
        hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size or hops >= _MAX_HOPS:
                if hops >= _MAX_HOPS:
                    logger.warning("BannerExtractor: hop cap reached.")
                break

            chunk = dump_handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            hops += 1

            pos = 0
            while pos < len(chunk):
                idx = chunk.find(_BANNER_PREFIX, pos)
                if idx == -1:
                    break

                raw = chunk[idx : idx + 64].split(b"\x00")[0].split(b"\n")[0]
                text = raw.decode("latin-1", errors="ignore").strip()
                banners.append(
                    {
                        "banner": text,
                        "physical_offset": offset + idx,
                    }
                )
                pos = idx + len(_BANNER_PREFIX)

        return {"banners": banners}
```
