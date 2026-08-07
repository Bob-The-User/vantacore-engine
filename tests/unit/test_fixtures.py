"""Unit tests to verify generated test fixtures."""

import hashlib
import struct
from pathlib import Path
from typing import Callable
from tests.fixtures.generate_fixtures import generate_all

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def test_all_fixture_files_exist(dump_path: Callable[[str], Path]) -> None:
    """Verify that exactly seven binary fixture files exist."""
    bin_files = list(FIXTURES_DIR.glob("*.bin"))
    assert len(bin_files) == 7, f"Found {len(bin_files)} .bin files, expected 7"

    expected_files = {
        "mock_elf_core_x86_64.bin",
        "mock_raw_dram.bin",
        "mock_cisco_ios.bin",
        "mock_cisco_iosxe.bin",
        "mock_cisco_asa_lina.bin",
        "mock_elf_msr_note.bin",
        "mock_pml4_dram.bin",
    }
    actual_names = {f.name for f in bin_files}
    assert actual_names == expected_files


def test_fixture_files_nonempty(dump_path: Callable[[str], Path]) -> None:
    """Verify that all binary fixture files are non-empty."""
    for filename in [
        "mock_elf_core_x86_64.bin",
        "mock_raw_dram.bin",
        "mock_cisco_ios.bin",
        "mock_cisco_iosxe.bin",
        "mock_cisco_asa_lina.bin",
        "mock_elf_msr_note.bin",
        "mock_pml4_dram.bin",
    ]:
        path = dump_path(filename)
        assert path.exists()
        assert path.stat().st_size > 0



def test_x86_64_elf_magic(dump_path: Callable[[str], Path]) -> None:
    """Verify ELF magic header for x86_64 core mock."""
    path = dump_path("mock_elf_core_x86_64.bin")
    data = path.read_bytes()
    assert data[0:4] == b"\x7fELF"


def test_x86_64_elf_class_64(dump_path: Callable[[str], Path]) -> None:
    """Verify ELF class is 64-bit for x86_64 core mock."""
    path = dump_path("mock_elf_core_x86_64.bin")
    data = path.read_bytes()
    assert data[4] == 2  # ELFCLASS64


def test_x86_64_elf_type_core(dump_path: Callable[[str], Path]) -> None:
    """Verify ELF type is ET_CORE for x86_64 core mock."""
    path = dump_path("mock_elf_core_x86_64.bin")
    data = path.read_bytes()
    assert struct.unpack_from("<H", data, 16)[0] == 4  # ET_CORE


def test_x86_64_elf_machine(dump_path: Callable[[str], Path]) -> None:
    """Verify ELF machine type is EM_X86_64 for x86_64 core mock."""
    path = dump_path("mock_elf_core_x86_64.bin")
    data = path.read_bytes()
    assert struct.unpack_from("<H", data, 18)[0] == 62  # EM_X86_64


def test_asa_lina_elf_magic(dump_path: Callable[[str], Path]) -> None:
    """Verify ELF magic header for Cisco ASA lina core mock."""
    path = dump_path("mock_cisco_asa_lina.bin")
    data = path.read_bytes()
    assert data[0:4] == b"\x7fELF"


def test_asa_lina_has_asa_string(dump_path: Callable[[str], Path]) -> None:
    """Verify that Cisco ASA lina core mock contains the version string."""
    path = dump_path("mock_cisco_asa_lina.bin")
    data = path.read_bytes()
    assert b"Cisco Adaptive Security Appliance" in data


def test_asa_lina_has_lina_name(dump_path: Callable[[str], Path]) -> None:
    """Verify that Cisco ASA lina core mock contains the process name 'lina'."""
    path = dump_path("mock_cisco_asa_lina.bin")
    data = path.read_bytes()
    assert b"lina" in data


def test_ios_has_banner_string(dump_path: Callable[[str], Path]) -> None:
    """Verify that Cisco IOS mock contains the IOS banner string."""
    path = dump_path("mock_cisco_ios.bin")
    data = path.read_bytes()
    assert b"Cisco IOS Software" in data


def test_raw_dram_size(dump_path: Callable[[str], Path]) -> None:
    """Verify size of the raw DRAM mock is exactly 16MB."""
    path = dump_path("mock_raw_dram.bin")
    assert path.stat().st_size == 16 * 1024 * 1024


def test_raw_dram_pointer_at_0x1000(dump_path: Callable[[str], Path]) -> None:
    """Verify synthetic pointer is set at offset 0x1000 in raw DRAM mock."""
    path = dump_path("mock_raw_dram.bin")
    data = path.read_bytes()
    val = struct.unpack_from("<Q", data, 0x1000)[0]
    assert val == 0x1000


def test_raw_dram_pointer_at_0x2000(dump_path: Callable[[str], Path]) -> None:
    """Verify synthetic pointer is set at offset 0x2000 in raw DRAM mock."""
    path = dump_path("mock_raw_dram.bin")
    data = path.read_bytes()
    val = struct.unpack_from("<Q", data, 0x2000)[0]
    assert val == 0x2000


def test_fixture_generator_is_deterministic() -> None:
    """Verify that the fixture generator produces byte-identical outputs across runs."""
    filenames = [
        "mock_elf_core_x86_64.bin",
        "mock_raw_dram.bin",
        "mock_cisco_ios.bin",
        "mock_cisco_iosxe.bin",
        "mock_cisco_asa_lina.bin",
    ]

    # Helper function to compute hashes
    def get_hashes() -> dict[str, str]:
        hashes = {}
        for name in filenames:
            path = FIXTURES_DIR / name
            content = path.read_bytes()
            hashes[name] = hashlib.sha256(content).hexdigest()
        return hashes

    # Run generator, get initial hashes
    generate_all()
    hashes1 = get_hashes()

    # Run generator again, get second hashes
    generate_all()
    hashes2 = get_hashes()

    assert hashes1 == hashes2
