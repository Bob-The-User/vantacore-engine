"""End-to-end integration tests for Linux ELF extractors."""

import os
from pathlib import Path

from vantacore_engine.core.backends.detector import ArchitectureDetector
from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend
from vantacore_engine.extractors.base import ExtractorDAGExecutor
from vantacore_engine.extractors.generic.keys import KeysExtractor
from vantacore_engine.extractors.generic.strings import StringsExtractor
from vantacore_engine.extractors.linux.modules import LinuxModulesExtractor
from vantacore_engine.extractors.linux.network import LinuxNetworkExtractor
from vantacore_engine.extractors.linux.process import LinuxProcessExtractor


def test_e2e_linux_elf_extractor_flow(tmp_path: Path) -> None:
    """Verify end-to-end detection, backend initialization, and DAG execution on ELF fixture."""
    fixture_path = Path("tests/fixtures/mock_elf_core_x86_64.bin")
    file_size = os.path.getsize(fixture_path)

    detector = ArchitectureDetector()
    with open(fixture_path, "rb") as fh:
        backend = detector.detect(fh, file_size)
        assert isinstance(backend, X86_64TranslationBackend)

        extractors = [
            KeysExtractor(),
            StringsExtractor(),
            LinuxProcessExtractor(),
            LinuxNetworkExtractor(),
            LinuxModulesExtractor(),
        ]
        executor = ExtractorDAGExecutor(extractors, "linux")

        fh.seek(0)
        res = executor.execute(backend, fh, tmp_path)

        assert "scan_status" in res
        assert res["scan_status"]["overall"] in ("COMPLETE", "PARTIAL")
        assert "generic/keys" in res["scan_status"]["extractors_succeeded"]
        assert "high_entropy_regions" in res


def test_e2e_platform_filter_enforced() -> None:
    """Verify ExtractorDAGExecutor filters out incompatible platform extractors."""
    from vantacore_engine.extractors.cisco.asa.acl_rules import ASAACLRulesExtractor
    from vantacore_engine.extractors.cisco.asa.conn_table import ASAConnTableExtractor
    from vantacore_engine.extractors.cisco.asa.lina_process import LinaProcessExtractor
    from vantacore_engine.extractors.cisco.asa.vpn_sessions import ASAVPNSessionsExtractor

    asa_extractors = [
        LinaProcessExtractor(),
        ASAConnTableExtractor(),
        ASAACLRulesExtractor(),
        ASAVPNSessionsExtractor(),
    ]
    executor = ExtractorDAGExecutor(asa_extractors, "linux")
    assert executor._execution_order == []

