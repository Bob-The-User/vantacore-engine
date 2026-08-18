# Architecture Overview

VantaCore Engine is built on a modular pipeline designed for high performance, robust error isolation, and platform extensibility.

## Core Subsystems

``` mermaid
graph TD
    subgraph Ingestion
        A[Memory Dump File] --> B[InputValidator]
        A --> C[EncryptedMemoryDetector]
        A --> D[PlatformDetectorRegistry]
        A --> E[ArchitectureDetector]
    end

    subgraph Translation
        D --> F[TranslationBackend]
        E --> F
    end

    subgraph Extraction
        F --> G[ExtractorDAGExecutor]
        G --> H[BaseExtractor Plugins]
    end

    subgraph Output
        H --> I[vantacore_output.json]
        H --> J[ForensicAuditTrail]
    end
```

### 1. Platform & Architecture Detection

- **`PlatformDetectorRegistry`**: Discovers subclasses of `BaseApplianceDetector` and computes confidence scores (0.0 to 1.0) based on ELF metadata and firmware strings.
- **`ArchitectureDetector`**: Determines the CPU architecture (x86_64, ARM64, Flat) and instantiates the matching `TranslationBackend`.

### 2. Translation Backends

Translation backends abstract virtual-to-physical address translation:

- **`read_virtual(namespace, vaddr, size)`**: Translates a virtual address in a given namespace (e.g. `GLOBAL_KERNEL` or process CR3) to physical offsets and retrieves byte slices.
- **`read_physical(paddr, size)`**: Directly reads physical memory slices.

### 3. Extractor DAG Executor

- **Topological Sorting**: Resolves dependencies between extractors.
- **Platform Filtering**: Automatically filters extractors against `compatible_platforms`.
- **Fault Isolation**: Each extractor runs in an isolated `try/except` boundary so that an individual failure cannot crash the overall scan.
