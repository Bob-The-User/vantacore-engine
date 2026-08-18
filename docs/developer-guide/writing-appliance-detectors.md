# Writing Appliance Detectors

Appliance detectors automatically classify unknown memory dumps into specific vendor platforms.

## Implementing an Appliance Detector

All appliance detectors inherit from `BaseApplianceDetector` in `vantacore_engine.core.backends.appliances.base_appliance`.

### Detector Interface

```python
from typing import BinaryIO
from vantacore_engine.core.backends.appliances.base_appliance import BaseApplianceDetector

class JuniperSRXDetector(BaseApplianceDetector):
    """Detector for Juniper SRX firewall memory images."""

    def platform_name(self) -> str:
        """Return unique platform identifier string."""
        return "juniper_srx"

    def detect(self, dump_handle: BinaryIO, file_size: int) -> float:
        """Analyze memory dump and return confidence score between 0.0 and 1.0.

        Args:
            dump_handle: Open binary file handle.
            file_size: Size of dump file in bytes.

        Returns:
            Float confidence score (0.0 to 1.0).

        """
        if file_size < 1024:
            return 0.0

        dump_handle.seek(0)
        chunk = dump_handle.read(min(file_size, 65536))

        if b"JUNOS" in chunk and b"srx" in chunk.lower():
            return 0.95
        if b"JUNOS" in chunk:
            return 0.70

        return 0.0

    def get_compatible_extractor_paths(self) -> list[str]:
        """Return list of extractor module path prefixes compatible with this platform."""
        return ["generic", "juniper/srx", "juniper/common"]
```

## Registering Detectors

Detectors placed in `vantacore_engine.core.backends.appliances` are automatically discovered by `PlatformDetectorRegistry` at runtime.
