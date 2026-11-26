"""Deterministic binary test fixture generator for VantaCore Engine."""

import os
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
    os.chmod(out_path, 0o644)
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
    os.chmod(out_path, 0o644)
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
    os.chmod(out_path, 0o644)
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

    # Padding up to byte 512
    current_len = len(elf_header) + len(phdr) + len(note_data)
    pad = b"\x00" * (512 - current_len)

    patterns = (
        b"Cisco Adaptive Security Appliance Software Version 9.14.1.6\x00"
        b"   TCP 10.0.0.1:1234 10.0.1.2:443, idle 0:00:01, bytes 1024, flags UIO\x00"
        b"access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443\x00"
        b"show conn\x00enable\x00configure terminal\x00show run\x00"
        b"snmp-server community public RO\x00"
        b"hostname ASA-FW-01\x00"
    )

    full_data = elf_header + phdr + note_data + pad + patterns
    target_size = 512 * 1024
    if len(full_data) < target_size:
        full_data += b"\x00" * (target_size - len(full_data))

    assert len(full_data) == 524288

    out_path = FIXTURES_DIR / "mock_cisco_asa_lina.bin"
    out_path.write_bytes(full_data)
    os.chmod(out_path, 0o644)
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
    os.chmod(out_path, 0o644)
    print(f"Generated {out_path.name} ({len(buf)} bytes)")


def generate_elf_with_msr_note() -> None:
    """Generate mock_elf_msr_note.bin (ELF core dump with NT_X86_MSR note)."""
    # 64-byte ELF header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = struct.pack("<H", 4)      # ET_CORE = 4
    e_machine = struct.pack("<H", 62)  # EM_X86_64 = 62
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0)
    e_phoff = struct.pack("<Q", 64)    # PHDR at offset 64
    e_shoff = struct.pack("<Q", 64 + 56 + 36)  # SHDR after note data
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 56)
    e_phnum = struct.pack("<H", 1)
    e_shentsize = struct.pack("<H", 64)
    e_shnum = struct.pack("<H", 2)     # NULL + NOTE section
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

    # 56-byte PHDR
    phdr = struct.pack("<IIQQQQQQ", 4, 0, 120, 0, 0, 36, 0, 4)

    # Note payload: 12 bytes note header + 8 bytes name + 16 bytes desc = 36 bytes
    note_header = struct.pack("<III", 6, 16, 0x202)  # namesz=6, descsz=16, type=0x202 (NT_X86_MSR)
    note_name = b"LINUX\x00\x00\x00"
    note_desc = struct.pack("<IQ", 0x982, 1) + b"\x00" * 4  # 12 bytes MSR entry + 4 bytes pad = 16 bytes
    note_data = note_header + note_name + note_desc
    assert len(note_data) == 36

    # Section 0: NULL
    shdr0 = b"\x00" * 64
    # Section 1: SHT_NOTE (sh_type=7, sh_offset=120, sh_size=36, sh_addralign=4)
    shdr1 = struct.pack("<IIQQQQIIQQ", 0, 7, 0, 0, 120, 36, 0, 0, 4, 0)

    full_data = elf_header + phdr + note_data + shdr0 + shdr1
    if len(full_data) < 4096:
        full_data += b"\x00" * (4096 - len(full_data))

    out_path = FIXTURES_DIR / "mock_elf_msr_note.bin"
    out_path.write_bytes(full_data)
    os.chmod(out_path, 0o644)
    print(f"Generated {out_path.name} ({len(full_data)} bytes)")


def generate_pml4_raw_dram() -> None:
    """Generate mock_pml4_dram.bin (2MB flat binary with x86_64 PML4 page table chain)."""
    size = 2 * 1024 * 1024
    buf = bytearray(size)

    # For vaddr 0xffff888000005000:
    # pml4i = 0x111, pdpti = 0x0, pdi = 0x0, pti = 0x5
    # Offset 0x1000 (PML4 table): Entry at index 0x111 (273)
    # Offset in buffer = 0x1000 + 0x111 * 8 = 0x1888
    buf[0x1888 : 0x1890] = struct.pack("<Q", 0x2000 | 0x1)  # Present, points to PDPT at 0x2000

    # Offset 0x2000 (PDPT table): Entry at index 0x0 (0)
    # Offset in buffer = 0x2000 + 0x0 * 8 = 0x2000
    buf[0x2000 : 0x2008] = struct.pack("<Q", 0x3000 | 0x1)  # Present, points to PD at 0x3000

    # Offset 0x3000 (PD table): Entry at index 0x0 (0)
    # Offset in buffer = 0x3000 + 0x0 * 8 = 0x3000
    buf[0x3000 : 0x3008] = struct.pack("<Q", 0x4000 | 0x1)  # Present, points to PT at 0x4000

    # Offset 0x4000 (PT table): Entry at index 0x5 (5)
    # Offset in buffer = 0x4000 + 0x5 * 8 = 0x4028
    buf[0x4028 : 0x4030] = struct.pack("<Q", 0x5000 | 0x1)  # Present, points to Page at 0x5000

    # Offset 0x5000 (Page data): First 8 bytes
    buf[0x5000 : 0x5008] = struct.pack("<Q", 0xDEADBEEFCAFEBABE)

    # Offset 0x8000: IDT descriptor for KASLR scan
    # Limit: 0x0FFF at offset 0 (bytes 0-1)
    # Base: 0xFFFF800000000000 at offset 2 (bytes 2-9)
    buf[0x8000 : 0x8002] = struct.pack("<H", 0x0FFF)
    buf[0x8002 : 0x800A] = struct.pack("<Q", 0xFFFF800000000000)

    out_path = FIXTURES_DIR / "mock_pml4_dram.bin"
    out_path.write_bytes(buf)
    os.chmod(out_path, 0o644)
    print(f"Generated {out_path.name} ({len(buf)} bytes)")


def generate_pml5_dram() -> None:
    """Generate mock_pml5_dram.bin (64MB flat binary with PML5 5-level paging chain)."""
    size = 64 * 1024 * 1024
    buf = bytearray(size)

    # Candidate 1: Page 0 (CR3 0x0) index 511 points to physical 0x1000
    # Offset in buffer = 511 * 8 = 4088
    buf[4088:4096] = struct.pack("<Q", 0x1000 | 0x1)

    # Candidate 2: Page at 0x3000 index 511
    buf[0x3000 + 4088 : 0x3000 + 4096] = struct.pack("<Q", 0x1000 | 0x1)

    # Candidate 3: Page at 0x4000 index 511
    buf[0x4000 + 4088 : 0x4000 + 4096] = struct.pack("<Q", 0x1000 | 0x1)

    # Offset 0x1000 (PML4 table): Entry at index 256 (0x100) points to PDPT at 0x2000
    buf[0x1000 + 256 * 8 : 0x1000 + 256 * 8 + 8] = struct.pack("<Q", 0x2000 | 0x1)

    # Offset 0x2000 (PDPT table): Entry at index 0 points to PD at 0x5000
    buf[0x2000 : 0x2008] = struct.pack("<Q", 0x5000 | 0x1)

    # Offset 0x5000 (PD table): 2MB huge page entry (bit 7 set) pointing to 0x600000
    buf[0x5000 : 0x5008] = struct.pack("<Q", 0x600000 | 0x81)

    # Offset 0x8000: IDT descriptor for KASLR scan
    buf[0x8000 : 0x8002] = struct.pack("<H", 0x0FFF)
    buf[0x8002 : 0x800A] = struct.pack("<Q", 0xFFFF800000000000)

    out_path = FIXTURES_DIR / "mock_pml5_dram.bin"
    out_path.write_bytes(buf)
    os.chmod(out_path, 0o644)
    print(f"Generated {out_path.name} ({len(buf)} bytes)")


def generate_kpti_dram() -> None:
    """Generate mock_kpti_dram.bin (16MB flat binary with KPTI dual-PGD layout)."""
    size = 16 * 1024 * 1024
    buf = bytearray(size)

    # IDT descriptor at 0x2000 so _scan_kaslr_base finds detected_cr3_phys = 0x2000
    buf[0x2000 : 0x2002] = struct.pack("<H", 0x0FFF)
    buf[0x2002 : 0x200A] = struct.pack("<Q", 0xFFFF800000000000)

    # Kernel CR3 at detected_cr3_phys + 0x1000 = 0x3000
    # Entry 511 (offset 4088) present bit set pointing to 0x4000
    buf[0x3000 + 4088 : 0x3000 + 4096] = struct.pack("<Q", 0x4000 | 0x1)

    # Map vaddr 0xFFFF800000005000 in kernel PML4 (0x3000):
    # pml4i = (0xFFFF800000005000 >> 39) & 0x1FF = 0x100 = 256
    # 0x3000 + 256 * 8 = 0x3800 points to PDPT at 0x4000
    buf[0x3800 : 0x3808] = struct.pack("<Q", 0x4000 | 0x1)

    # PDPT at 0x4000: entry 0 points to PD at 0x5000
    buf[0x4000 : 0x4008] = struct.pack("<Q", 0x5000 | 0x1)

    # PD at 0x5000: entry 0 points to 2MB huge page at 0x200000 | 0x81
    buf[0x5000 : 0x5008] = struct.pack("<Q", 0x200000 | 0x81)

    # Page data at 0x205000
    secret_bytes = b"KPTI_KERNEL_OK!"
    buf[0x205000 : 0x205000 + len(secret_bytes)] = secret_bytes

    out_path = FIXTURES_DIR / "mock_kpti_dram.bin"
    out_path.write_bytes(buf)
    os.chmod(out_path, 0o644)
    print(f"Generated {out_path.name} ({len(buf)} bytes)")


def generate_elf_nt_file() -> None:
    """Generate mock_elf_nt_file.bin (ELF64 ET_CORE with NT_FILE note)."""
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
    e_phnum = struct.pack("<H", 1)
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

    # NT_FILE body
    count = 1
    page_size = 0x1000
    triplets = struct.pack("<QQQ", 0xFFFFFFFF81000000, 0xFFFFFFFF82000000, 0x10)
    filename = b"vmlinux\x00"
    desc = struct.pack("<QQ", count, page_size) + triplets + filename

    namesz = 5  # "CORE\x00"
    descsz = len(desc)
    nt_type = 0x46494C45  # NT_FILE ('FILE' in ASCII)
    note_header = struct.pack("<III", namesz, descsz, nt_type)
    note_name = b"CORE\x00\x00\x00\x00"  # 8 bytes padded
    note_data = note_header + note_name + desc

    # 56-byte PHDR
    phdr = struct.pack("<IIQQQQQQ", 4, 0, 120, 0, 0, len(note_data), 0, 4)
    assert len(phdr) == 56

    full_data = elf_header + phdr + note_data
    if len(full_data) < 4096:
        full_data += b"\x00" * (4096 - len(full_data))

    out_path = FIXTURES_DIR / "mock_elf_nt_file.bin"
    out_path.write_bytes(full_data)
    os.chmod(out_path, 0o644)
    print(f"Generated {out_path.name} ({len(full_data)} bytes)")


def generate_all() -> None:
    """Generate all mock binary test fixtures."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    generate_elf_core()
    generate_raw_dram()
    generate_cisco_ios()
    generate_cisco_iosxe()
    generate_cisco_asa_lina()
    generate_elf_with_msr_note()
    generate_pml4_raw_dram()
    generate_pml5_dram()
    generate_kpti_dram()
    generate_elf_nt_file()


if __name__ == "__main__":
    generate_all()


