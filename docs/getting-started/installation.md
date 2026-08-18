# Installation

VantaCore Engine is packaged as a standard Python package and reproducible Pixi workspace for Linux environments.

## Prerequisites

- Linux x86_64 environment
- Python 3.11 or 3.12
- Pixi package manager (recommended) or pip

## Installing via Pixi (Recommended)

Pixi guarantees reproducible native dependencies such as `libblas` (OpenBLAS), `capstone`, and `llvm-tools`.

```bash
# Clone the repository
git clone https://github.com/vantacore/vantacore-engine.git
cd vantacore-engine

# Install environment and dependencies
pixi install

# Run the CLI
pixi run vantacore --help
```

## Installing via PyPI

You can install `vantacore-engine` using `pip`:

```bash
pip install vantacore-engine
```

> **Note**: Ensure that `llvm-tools` or system `llvm-strings` is present in your `PATH` for full functionality of the generic string extractor.

## Verifying Installation

Verify that the CLI executable is available and outputs the expected version:

```bash
vantacore version
```
