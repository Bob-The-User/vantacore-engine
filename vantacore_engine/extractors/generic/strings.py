"""StringsExtractor running llvm-strings binary against memory dumps."""

import logging
from pathlib import Path
import shutil
import subprocess
import sys
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)


def _resolve_llvm_strings_binary() -> Path:
    """Resolve absolute path to llvm-strings executable.

    Returns:
        Path object pointing to llvm-strings binary.

    Raises:
        RuntimeError: If llvm-strings binary cannot be found.

    """
    candidate = Path(sys.prefix) / "bin" / "llvm-strings"
    if candidate.exists():
        return candidate

    which_path = shutil.which("llvm-strings")
    if which_path is not None:
        return Path(which_path)

    raise RuntimeError("llvm-strings binary not found. Install llvm-tools via pixi.")


class StringsExtractor(BaseExtractor):
    """Extractor executing llvm-strings to extract printable ASCII/UTF-8 strings."""

    name = "generic/strings"
    compatible_platforms = ["*"]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Run llvm-strings subprocess on dump file path and return extracted lines.

        Args:
            backend: TranslationBackend instance (unused).
            dump_handle: Open file handle for physical memory dump.
            output_dir: Output directory path.

        Returns:
            Dictionary containing list of extracted strings (up to 50,000).

        Raises:
            RuntimeError: If dump_handle lacks a valid file path name.

        """
        binary = _resolve_llvm_strings_binary()

        file_path = getattr(dump_handle, "name", None)
        if not file_path or not isinstance(file_path, (str, Path)):
            raise RuntimeError("dump_handle must be a file object with a valid file path name attribute")

        cmd = [str(binary), "-n", "6", str(file_path)]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
        )

        if result.returncode != 0:
            logger.warning("llvm-strings exited with code %d", result.returncode)

        lines = result.stdout.splitlines()
        return {"strings": lines[:50_000]}
