# Contributing to VantaCore Engine

We welcome community contributions, extractor plugins, and platform detector improvements to VantaCore Engine.

## Development Setup

1. Fork and clone the repository.
2. Ensure you have Pixi installed on your Linux system.
3. Install the environment:
   ```bash
   pixi install
   ```

## Code Quality Standards

All pull requests must pass our automated validation checks:

- **Type Annotations**: Full Python 3.11+ type hints across all modules.
- **Docstrings**: Google-style docstrings on all public modules, classes, and functions (`ruff check --select D`).
- **Test Coverage**: Minimum 80% line coverage required (`--cov-fail-under=80`).
- **Licensing Compliance**: No GPL/AGPL dependencies permitted in `vantacore-engine` (MIT, Apache-2.0, BSD-2, BSD-3, LGPL allowed). Run `pixi run pip-licenses`.

## Running the Test Suite

```bash
# Run unit tests
pixi run pytest tests/unit/ -v

# Run full suite with coverage gate
pixi run pytest -v --timeout=300 --cov=vantacore_engine --cov-report=term-missing --cov-fail-under=80

# Run documentation build
pixi run mkdocs build --strict
```
