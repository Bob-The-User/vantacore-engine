"""Unit tests for PlatformDetectorRegistry, appliance detectors, and ArchitectureDetector."""

import io
import os
from pathlib import Path
from typing import BinaryIO, Callable, Type

from vantacore_engine.core.backends.appliances.base_appliance import BaseApplianceDetector

from vantacore_engine.core.backends.appliances.cisco_asa import CiscoASADetector
from vantacore_engine.core.backends.appliances.cisco_ios import CiscoIOSDetector
from vantacore_engine.core.backends.appliances.cisco_iosxe import CiscoIOSXEDetector
from vantacore_engine.core.backends.appliances.generic_flat import GenericFlatDetector
from vantacore_engine.core.backends.appliances.registry import PlatformDetectorRegistry
from vantacore_engine.core.backends.detector import ArchitectureDetector
from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend
from vantacore_engine.core.translation_base import TranslationBackend


class FaultyDetector(BaseApplianceDetector):
    """Faulty detector subclass that raises an exception during detection."""

    def platform_name(self) -> str:
        """Return a fixed platform name for test identification."""
        return "faulty_platform"

    def detect(self, dump_handle: BinaryIO, file_size: int) -> float:
        """Simulate a detection failure by raising a RuntimeError."""
        raise RuntimeError("Faulty detector simulation error")

    def get_translation_backend_class(self) -> Type[TranslationBackend]:
        """Return FlatImageBackend as a no-op stub for test purposes."""
        return FlatImageBackend

    def get_compatible_extractor_paths(self) -> list[str]:
        """Return a minimal extractor path list for test purposes."""
        return ["generic"]


def test_registry_list_registered() -> None:
    """Verify registry auto-discovers all 4 appliance detectors."""
    registry = PlatformDetectorRegistry()
    registered = registry.list_registered()
    assert "cisco_asa" in registered
    assert "cisco_ios" in registered
    assert "cisco_iosxe" in registered
    assert "generic_flat" in registered


def test_registry_detect_cisco_asa(dump_path: Callable[[str], Path]) -> None:
    """Verify registry correctly detects Cisco ASA dump fixture."""
    registry = PlatformDetectorRegistry()
    asa_path = dump_path("mock_cisco_asa_lina.bin")
    file_size = os.path.getsize(asa_path)

    with open(asa_path, "rb") as fh:
        detector = registry.detect(fh, file_size)
        assert detector is not None
        assert isinstance(detector, CiscoASADetector)
        assert detector.platform_name() == "cisco_asa"
        assert detector.get_platform_metadata() == {"dump_type": "lina_elf64_coredump"}


def test_registry_detect_cisco_ios(dump_path: Callable[[str], Path]) -> None:
    """Verify registry correctly detects Cisco IOS dump fixture."""
    registry = PlatformDetectorRegistry()
    ios_path = dump_path("mock_cisco_ios.bin")
    file_size = os.path.getsize(ios_path)

    with open(ios_path, "rb") as fh:
        detector = registry.detect(fh, file_size)
        assert detector is not None
        assert isinstance(detector, CiscoIOSDetector)
        assert detector.platform_name() == "cisco_ios"


def test_registry_detect_cisco_iosxe(dump_path: Callable[[str], Path]) -> None:
    """Verify registry correctly detects Cisco IOS XE dump fixture."""
    registry = PlatformDetectorRegistry()
    iosxe_path = dump_path("mock_cisco_iosxe.bin")
    file_size = os.path.getsize(iosxe_path)

    with open(iosxe_path, "rb") as fh:
        detector = registry.detect(fh, file_size)
        assert detector is not None
        assert isinstance(detector, CiscoIOSXEDetector)
        assert detector.platform_name() == "cisco_iosxe"


def test_registry_detect_raw_dram_returns_none(dump_path: Callable[[str], Path]) -> None:
    """Verify registry returns None for featureless raw DRAM dump."""
    registry = PlatformDetectorRegistry()
    dram_path = dump_path("mock_raw_dram.bin")
    file_size = os.path.getsize(dram_path)

    with open(dram_path, "rb") as fh:
        detector = registry.detect(fh, file_size)
        assert detector is None


def test_individual_detector_scores(dump_path: Callable[[str], Path]) -> None:
    """Verify individual confidence scores for fixtures."""
    asa_path = dump_path("mock_cisco_asa_lina.bin")
    with open(asa_path, "rb") as fh:
        score = CiscoASADetector().detect(fh, os.path.getsize(asa_path))
        assert score >= 0.95

    ios_path = dump_path("mock_cisco_ios.bin")
    with open(ios_path, "rb") as fh:
        score = CiscoIOSDetector().detect(fh, os.path.getsize(ios_path))
        assert score >= 0.80

    iosxe_path = dump_path("mock_cisco_iosxe.bin")
    with open(iosxe_path, "rb") as fh:
        score = CiscoIOSXEDetector().detect(fh, os.path.getsize(iosxe_path))
        assert score >= 0.80

    generic_detector = GenericFlatDetector()
    dummy_io = io.BytesIO(b"data")
    assert generic_detector.detect(dummy_io, 4) == 0.1
    assert generic_detector.platform_name() == "generic_flat"


def test_registry_resilience_to_faulty_detector() -> None:
    """Verify registry handles detector exception without crashing."""
    registry = PlatformDetectorRegistry()
    registry._detectors.append(FaultyDetector())

    dummy_io = io.BytesIO(b"data")
    # Should complete without raising exception
    result = registry.detect(dummy_io, 4)
    assert result is None


def test_architecture_detector(dump_path: Callable[[str], Path]) -> None:
    """Verify ArchitectureDetector selects correct backend for ELF and flat dumps."""
    arch_detector = ArchitectureDetector()

    elf_path = dump_path("mock_elf_core_x86_64.bin")
    with open(elf_path, "rb") as fh:
        backend = arch_detector.detect(fh, os.path.getsize(elf_path))
        assert isinstance(backend, X86_64TranslationBackend)
        assert backend.get_architecture_name() == "x86_64"

    ios_path = dump_path("mock_cisco_ios.bin")
    with open(ios_path, "rb") as fh:
        backend = arch_detector.detect(fh, os.path.getsize(ios_path))
        assert isinstance(backend, FlatImageBackend)
        assert backend.get_architecture_name() == "flat"
