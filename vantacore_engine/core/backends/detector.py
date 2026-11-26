"""Architecture detector to auto-select and initialize translation backends."""

import logging
from typing import BinaryIO

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend
from vantacore_engine.core.translation_base import TranslationBackend, TranslationError

logger = logging.getLogger(__name__)


class ArchitectureDetector:
    """Detects target architecture and instantiates appropriate translation backend."""

    def detect(
        self,
        dump_handle: BinaryIO,
        file_size: int,
        force_pml5: bool = False,
    ) -> TranslationBackend:
        """Detect memory image architecture and return an initialized translation backend.

        Args:
            dump_handle: Open file-like handle to binary memory dump.
            file_size: Size of memory dump in bytes.
            force_pml5: If True, force PML5 5-level paging for x86_64.

        Returns:
            Initialized instance of TranslationBackend subclass.

        Raises:
            TranslationError: If no translation backend matches the memory dump.

        """
        backends = [X86_64TranslationBackend, FlatImageBackend]

        for backend_cls in backends:
            dump_handle.seek(0)
            backend = backend_cls()
            if backend.detect(dump_handle):
                dump_handle.seek(0)
                if backend_cls is X86_64TranslationBackend:
                    backend.initialize(dump_handle, force_pml5=force_pml5)
                else:
                    backend.initialize(dump_handle)
                logger.info("Architecture detected: %s", backend.get_architecture_name())
                return backend
            dump_handle.seek(0)

        raise TranslationError("Failed to detect architecture for memory dump")
