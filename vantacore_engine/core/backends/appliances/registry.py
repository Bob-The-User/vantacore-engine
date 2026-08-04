"""Registry and auto-discovery for appliance platform detectors."""

import importlib
import inspect
import logging
import pkgutil
from typing import BinaryIO, Optional

from vantacore_engine.core.backends.appliances.base_appliance import BaseApplianceDetector

logger = logging.getLogger(__name__)


class PlatformDetectorRegistry:
    """Auto-discovers and manages platform detectors to match memory dumps."""

    def __init__(self) -> None:
        """Initialize detector registry and execute auto-discovery."""
        self._detectors: list[BaseApplianceDetector] = []
        self._auto_discover()

    def _auto_discover(self) -> None:
        """Scan appliances package for BaseApplianceDetector subclasses and instantiate them."""
        import vantacore_engine.core.backends.appliances as pkg

        pkg_path = pkg.__path__
        pkg_name = pkg.__name__

        for _finder, module_name, _is_pkg in pkgutil.iter_modules(pkg_path):
            if module_name in {"base_appliance", "registry"}:
                continue
            try:
                module = importlib.import_module(f"{pkg_name}.{module_name}")
                for _name, obj in inspect.getmembers(module, inspect.isclass):
                    if obj is BaseApplianceDetector or not issubclass(obj, BaseApplianceDetector):
                        continue
                    if not any(isinstance(d, obj) for d in self._detectors):
                        self._detectors.append(obj())
            except Exception as err:
                logger.warning("Failed to auto-discover detector module %s: %s", module_name, err)

    def list_registered(self) -> list[str]:
        """List platform names of all registered appliance detectors.

        Returns:
            List of platform name strings.

        """
        return [d.platform_name() for d in self._detectors]

    def detect(self, dump_handle: BinaryIO, file_size: int) -> Optional[BaseApplianceDetector]:
        """Run all registered detectors against dump handle and return best match >= 0.6.

        Args:
            dump_handle: Open file-like handle to binary dump.
            file_size: Size of memory dump in bytes.

        Returns:
            The highest scoring BaseApplianceDetector instance with score >= 0.6, or None.

        """
        results: list[tuple[float, BaseApplianceDetector]] = []

        for detector in self._detectors:
            try:
                dump_handle.seek(0)
                score = detector.detect(dump_handle, file_size)
                results.append((score, detector))
            except Exception as err:
                logger.warning("Detector %s raised %s; skipping", detector.platform_name(), err)

        qualified = [(score, detector) for score, detector in results if score >= 0.6]

        if not qualified:
            return None

        return max(qualified, key=lambda item: item[0])[1]
