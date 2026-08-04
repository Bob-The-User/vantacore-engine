"""Abstract base class for network appliance detectors."""

from abc import ABC, abstractmethod
from typing import BinaryIO, Type

from vantacore_engine.core.translation_base import TranslationBackend


class BaseApplianceDetector(ABC):
    """Abstract base class for vendor network security appliance detectors."""

    @abstractmethod
    def platform_name(self) -> str:
        """Get the unique string identifier for the appliance platform.

        Returns:
            Platform name string (e.g., 'cisco_asa', 'cisco_ios').

        """

    @abstractmethod
    def detect(self, dump_handle: BinaryIO, file_size: int) -> float:
        """Analyze memory dump and calculate confidence score for this platform.

        Args:
            dump_handle: Open file-like handle to binary memory dump.
            file_size: Size of memory dump in bytes.

        Returns:
            Float confidence score between 0.0 and 1.0.

        """

    @abstractmethod
    def get_translation_backend_class(self) -> Type[TranslationBackend]:
        """Get the translation backend class associated with this appliance platform.

        Returns:
            Uninstantiated subclass of TranslationBackend.

        """

    @abstractmethod
    def get_compatible_extractor_paths(self) -> list[str]:
        """Get list of compatible extractor module paths for this platform.

        Returns:
            List of extractor path strings (e.g., ['generic', 'cisco/common']).

        """

    def get_platform_metadata(self) -> dict:
        """Get additional metadata specific to the detected platform.

        Returns:
            Dictionary of key-value metadata pairs.

        """
        return {}
