"""End-to-end integration test for Cisco ASA extractor DAG flow."""

from pathlib import Path
from typing import Callable

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.base import ExtractorDAGExecutor
from vantacore_engine.extractors.cisco.asa.acl_rules import ASAACLRulesExtractor
from vantacore_engine.extractors.cisco.asa.conn_table import ASAConnTableExtractor
from vantacore_engine.extractors.cisco.asa.lina_process import LinaProcessExtractor
from vantacore_engine.extractors.cisco.asa.vpn_sessions import ASAVPNSessionsExtractor
from vantacore_engine.extractors.cisco.common.cli_history import CLIHistoryExtractor
from vantacore_engine.extractors.cisco.common.snmp_config import SNMPConfigExtractor
from vantacore_engine.extractors.cisco.ios.running_config import RunningConfigExtractor


def test_e2e_cisco_asa_extractor_flow(
    dump_path: Callable[[str], Path], tmp_path: Path
) -> None:
    """Verify execution of full Cisco ASA extractor suite against mock dump."""
    lina_path = dump_path("mock_cisco_asa_lina.bin")
    backend = FlatImageBackend()

    extractors = [
        LinaProcessExtractor(),
        ASAConnTableExtractor(),
        ASAACLRulesExtractor(),
        ASAVPNSessionsExtractor(include_secrets=True),
        CLIHistoryExtractor(),
        SNMPConfigExtractor(include_secrets=True),
        RunningConfigExtractor(),
    ]

    executor = ExtractorDAGExecutor(extractors, "cisco_asa")

    with open(lina_path, "rb") as fh:
        result = executor.execute(backend, fh, tmp_path)

    assert "scan_status" in result
    assert result["scan_status"]["overall"] in ("COMPLETE", "PARTIAL")
    assert "lina_threads" in result
    assert "connections" in result
    assert "cli_history" in result
    assert "acl_rules" in result
    assert "vpn_sessions" in result
    assert "snmp_community_strings" in result
    assert "running_config" in result
