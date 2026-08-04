"""Generic flat memory dump fallback detector."""

import logging
from typing import BinaryIO, Type

from vantacore_engine.core.backends.appliances.base_appliance import BaseApplianceDetector
from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.core.translation_base import TranslationBackend

logger = logging.getLogger(__name__)


class GenericFlatDetector(BaseApplianceDetector):
    """Fallback detector for unrecognized or generic raw memory images."""

    def platform_name(self) -> str:
        """Get unique platform identifier string for generic flat image.

        Returns:
            String 'generic_flat'.

        """
        return "generic_flat"

    def detect(self, dump_handle: BinaryIO, file_size: int) -> float:
        """Return fallback confidence score below registry threshold.

        Args:
            dump_handle: Open file-like handle to binary dump.
            file_size: Size of memory dump in bytes.

        Returns:
            Float confidence score 0.1.

        """
        return 0.1

    def get_translation_backend_class(self) -> Type[TranslationBackend]:
        """Get translation backend class for generic flat images.

        Returns:
            FlatImageBackend class.

        """
        return FlatImageBackend

    def get_compatible_extractor_paths(self) -> list[str]:
        """Get compatible extractor paths for generic flat images.

        Returns:
            List containing 'generic'.

        """
        return ["generic"]
