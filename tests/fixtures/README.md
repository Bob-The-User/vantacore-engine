# Test Fixtures

This directory contains mock binary files used to test VantaCore Engine:

- `mock_elf_core_x86_64.bin`: A mock ELF64 core dump header (ET_CORE, EM_X86_64).
- `mock_raw_dram.bin`: A 16MB raw flat binary DRAM image containing synthetic pointers.
- `mock_cisco_ios.bin`: A 1MB flat binary memory image containing embedded Cisco IOS banners.
- `mock_cisco_asa_lina.bin`: A mock ELF64 core dump of Cisco ASA's `lina` process, including a PT_NOTE header, NT_PRPSINFO notes, and Cisco ASA version strings.

## Regeneration

These fixtures are deterministically generated and should not be modified manually. To regenerate them, run:

```bash
pixi run generate-fixtures
```

Or run the script directly:

```bash
python tests/fixtures/generate_fixtures.py
```
