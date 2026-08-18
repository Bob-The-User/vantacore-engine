# VantaCore Engine Documentation

VantaCore Engine is an open-source, zero-knowledge memory forensics framework designed specifically for analyzing raw physical memory images, ELF64 core dumps, and proprietary appliance dumps from network security infrastructure.

``` mermaid
graph LR
    A[Memory Dump] --> B[Platform Detector]
    B --> C[Architecture Backend]
    C --> D[Extractor DAG]
    D --> E[JSON Output]
```

## Overview

Traditional memory forensics frameworks focus almost exclusively on commodity desktop and server operating systems (Linux, Windows, macOS). When incident response teams investigate compromised perimeter defenses—such as Cisco ASA firewalls, Palo Alto networks firewalls, or Ivanti VPN appliances—standard tooling often fails due to unique kernel structures, proprietary scheduler memory layouts, or flat physical memory architectures.

VantaCore Engine bridges this gap by providing:

- **Appliance Autodetection**: Heuristic and signature-based identification of appliance vendors and operating system platforms.
- **Pluggable Translation Backends**: Native x86_64 PML4 page table walk, ARM64 translation, and flat-image physical translation.
- **DAG-Driven Extraction**: Directed acyclic graph scheduling of extractors with topological sorting and cycle protection.
- **Tamper-Evident Chain of Custody**: Cryptographic SHA-256 validation and sequential SHA-256 JSONL audit logs.
- **Zero-Knowledge Safety**: Non-destructive read-only I/O, rigorous pointer bounds validation, and memory traversal limits.

## Quick Links

- [Installation Guide](getting-started/installation.md)
- [Quickstart Tutorial](getting-started/quickstart.md)
- [Supported Platforms](getting-started/supported-platforms.md)
- [CLI Reference](user-guide/cli-reference.md)
- [Developer Guide](developer-guide/architecture-overview.md)
