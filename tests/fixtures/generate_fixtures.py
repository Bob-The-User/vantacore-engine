"""Deterministic binary test fixture generator for VantaCore Engine."""

import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent


def generate_elf_core() -> None:
    """Generate mock_elf_core_x86_64.bin."""
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = struct.pack("<H", 4)      # ET_CORE = 4
    e_machine = struct.pack("<H", 62)  # EM_X86_64 = 62
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0)
    e_phoff = struct.pack("<Q", 0)
    e_shoff = struct.pack("<Q", 0)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 56)
    e_phnum = struct.pack("<H", 0)
    e_shentsize = struct.pack("<H", 64)
    e_shnum = struct.pack("<H", 0)
    e_shstrndx = struct.pack("<H", 0)

    header = (
        e_ident
        + e_type
        + e_machine
        + e_version
        + e_entry
        + e_phoff
        + e_shoff
        + e_flags
        + e_ehsize
        + e_phentsize
        + e_phnum
        + e_shentsize
        + e_shnum
        + e_shstrndx
    )

    assert len(header) == 64, f"Header length is {len(header)}, expected 64"

    out_path = FIXTURES_DIR / "mock_elf_core_x86_64.bin"
    out_path.write_bytes(header)
    print(f"Generated {out_path.name} ({len(header)} bytes)")


def generate_raw_dram() -> None:
    """Generate mock_raw_dram.bin (16MB flat binary with synthetic pointers)."""
    size = 16 * 1024 * 1024
    pattern = bytes(range(256))
    data = pattern * (size // 256)
    buf = bytearray(data)

    buf[0x1000 : 0x1000 + 8] = struct.pack("<Q", 0x1000)
    buf[0x2000 : 0x2000 + 8] = struct.pack("<Q", 0x2000)

    out_path = FIXTURES_DIR / "mock_raw_dram.bin"
    out_path.write_bytes(buf)
    print(f"Generated {out_path.name} ({len(buf)} bytes)")


def generate_cisco_ios() -> None:
    """Generate mock_cisco_ios.bin (flat binary with IOS banner)."""
    buf = bytearray(1 * 1024 * 1024)
    banner1 = b"Cisco IOS Software, Version 15.4(3)M2\x00"
    banner2 = b"IOS (tm) C2900 Software\x00"

    buf[0 : len(banner1)] = banner1
    buf[0x100 : 0x100 + len(banner2)] = banner2

    out_path = FIXTURES_DIR / "mock_cisco_ios.bin"
    out_path.write_bytes(buf)
    print(f"Generated {out_path.name} ({len(buf)} bytes)")


def generate_cisco_asa_lina() -> None:
    """Generate mock_cisco_asa_lina.bin."""
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = struct.pack("<H", 4)      # ET_CORE = 4
    e_machine = struct.pack("<H", 62)  # EM_X86_64 = 62
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0)
    e_phoff = struct.pack("<Q", 64)    # PHDR at offset 64
    e_shoff = struct.pack("<Q", 0)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 56)
    e_phnum = struct.pack("<H", 1)     # 1 program header
    e_shentsize = struct.pack("<H", 64)
    e_shnum = struct.pack("<H", 0)
    e_shstrndx = struct.pack("<H", 0)

    elf_header = (
        e_ident
        + e_type
        + e_machine
        + e_version
        + e_entry
        + e_phoff
        + e_shoff
        + e_flags
        + e_ehsize
        + e_phentsize
        + e_phnum
        + e_shentsize
        + e_shnum
        + e_shstrndx
    )
    assert len(elf_header) == 64

    p_type = struct.pack("<I", 4)        # PT_NOTE = 4
    p_flags = struct.pack("<I", 0)
    # Note data starts after header + phdr = 64 + 56 = 120
    p_offset = struct.pack("<Q", 120)
    p_vaddr = struct.pack("<Q", 0)
    p_paddr = struct.pack("<Q", 0)
    p_filesz = struct.pack("<Q", 156)    # 156 bytes note data size
    p_memsz = struct.pack("<Q", 0)
    p_align = struct.pack("<Q", 4)

    phdr = (
        p_type
        + p_flags
        + p_offset
        + p_vaddr
        + p_paddr
        + p_filesz
        + p_memsz
        + p_align
    )
    assert len(phdr) == 56

    note_header = struct.pack("<III", 5, 136, 3)  # NT_PRPSINFO
    note_name = b"CORE\x00" + b"\x00" * 3
    note_desc = bytearray(136)
    note_desc[40:45] = b"lina\x00"

    note_data = note_header + note_name + note_desc
    assert len(note_data) == 156

    version_str = b"Cisco Adaptive Security Appliance Software Version 9.14\x00"

    full_data = elf_header + phdr + note_data + version_str

    out_path = FIXTURES_DIR / "mock_cisco_asa_lina.bin"
    out_path.write_bytes(full_data)
    print(f"Generated {out_path.name} ({len(full_data)} bytes)")


def generate_cisco_iosxe() -> None:
    """Generate mock_cisco_iosxe.bin (ELF binary with IOS XE string identifiers)."""
    buf = bytearray(512 * 1024)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    buf[0 : len(e_ident)] = e_ident
    banner1 = b"Cisco IOS XE Software, Version 17.3.1\x00"
    banner2 = b"IOSd\x00"

    buf[0x10 : 0x10 + len(banner1)] = banner1
    buf[0x200 : 0x200 + len(banner2)] = banner2

    out_path = FIXTURES_DIR / "mock_cisco_iosxe.bin"
    out_path.write_bytes(buf)
    print(f"Generated {out_path.name} ({len(buf)} bytes)")



def generate_all() -> None:
    """Generate all mock binary test fixtures."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    generate_elf_core()
    generate_raw_dram()
    generate_cisco_ios()
    generate_cisco_iosxe()
    generate_cisco_asa_lina()


if __name__ == "__main__":
    generate_all()

