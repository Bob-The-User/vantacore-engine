# Supported Platforms

VantaCore Engine supports a wide range of appliance operating environments and raw memory dump formats.

## Platform Support Matrix

The following table summarizes platform support in VantaCore Engine v0.1.0:

| Platform | Backend | Extractors | DKOM Detection | Struct-Parse | Status (v0.1.0) |
|---|---|---|---|---|---|
| **Cisco ASA (lina coredump)** | x86_64 Translation Backend | `lina_process`, `conn_table`, `acl_rules`, `vpn_sessions`, `cli_history`, `snmp_config`, `running_config` | Supported via carving fallback | ELF PT_NOTE + Text-pattern parsing | Stable |
| **Cisco IOS Classic** | FlatImageBackend | `ios_processes`, `routing_table`, `running_config`, `cli_history`, `snmp_config` | N/A (Flat Memory) | Text-pattern & Mempool Carving | Stable |
| **Cisco IOS-XE** | x86_64 Translation Backend | `linux/process`, `linux/network`, `linux/modules`, `cisco/ios/*`, `cisco/common/*` | Supported via slab carving | Kernel structs + IOSd pattern parsing | Stable |
| **Generic Linux (ELF / DRAM)** | x86_64 Translation Backend | `linux/process`, `linux/network`, `linux/modules`, `generic/keys`, `generic/strings` | Dual-Path (List-walk + Slab carve) | `task_struct`, `net_device`, `module` | Stable |
| **Palo Alto PAN-OS** | x86_64 Translation Backend | `generic/keys`, `generic/strings`, `linux/process` | Supported | Generic Linux + Pattern Parsing | Experimental |
| **Ivanti Pulse Secure** | x86_64 Translation Backend | `generic/keys`, `generic/strings`, `linux/process` | Supported | Generic Linux + Pattern Parsing | Experimental |
| **Generic Flat Memory** | FlatImageBackend | `generic/keys`, `generic/strings` | N/A | Heuristic entropy & string scanning | Stable |

## Support Tiers

1. **Tier 1 (Core Appliances)**: Native platform detectors, specialized forensic extractors, and automated regression test coverage against binary fixtures (Cisco ASA, Cisco IOS, Cisco IOS-XE, Linux x86_64).
2. **Tier 2 (Community / Experimental)**: Detected via base signatures with standard Linux/generic extractor coverage (PAN-OS, Ivanti Connect Secure).
