"""tests/tools/recon/test_nmap.py - unit tests for the rich nmap surface.

Covers the typed entry point ``nmap_scan`` (modes / banner / scripts /
scan_mode flag composition, XML parsing, persist-evidence wiring) and
the helper functions (``_assemble_flags``, ``_parse_xml``,
``_evidence_filename``).

The legacy ``port_scan`` shim has its own backwards-compat test in
``test_recon_tools.py``; this file focuses on the new surface.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from config import ScanMode as ConfigScanMode
from models.network import (
    NmapBanner,
    NmapHostResult,
    NmapMode,
    NmapScanResult,
    NmapScripts,
)
from tools.recon.nmap import nmap_scan
from tools.recon.nmap.flags import _assemble_flags
from tools.recon.nmap.parser import _parse_xml
from tools.recon.nmap.scanner import _evidence_filename

pytestmark = pytest.mark.unit


# Real-shape XML fragments. Multi-line strings for readability; the
# parser sees these as one XML document.
_XML_TWO_HOSTS_WITH_BANNERS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.6p1" extrainfo="Ubuntu"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="93.184.216.35" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_XML_NO_HOSTS = """<?xml version="1.0"?>
<nmaprun></nmaprun>
"""


class TestAssembleFlags:
    def test_quick_ports_normal(self):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "-sS" in flags and "-F" in flags and "-T3" in flags
        assert "-sV" not in flags  # banner-grab only with SERVICE_VERSION+

    def test_service_version_adds_sv(self):
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.LIGHT,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "-sV" in flags
        assert "--version-intensity" in flags
        # Intensity argument follows --version-intensity.
        i = flags.index("--version-intensity")
        assert flags[i + 1] == "2"

    def test_banner_full_yields_intensity_9(self):
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.FULL,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        i = flags.index("--version-intensity")
        assert flags[i + 1] == "9"

    def test_banner_none_omits_intensity_arg(self):
        # NmapBanner.NONE with a -sV mode -> still no --version-intensity
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "--version-intensity" not in flags

    def test_banner_ignored_on_quick_ports(self):
        # Even with NmapBanner.FULL, QUICK_PORTS does not run -sV so
        # no intensity argument is added.
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.FULL,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "--version-intensity" not in flags

    @pytest.mark.parametrize(
        ("scripts", "expected_expr"),
        [
            (NmapScripts.HTTP_HEADERS, "banner,http-server-header,http-title"),
            (NmapScripts.SAFE, "safe"),
            (NmapScripts.VULN, "vuln"),
        ],
    )
    def test_scripts_argument(self, scripts, expected_expr):
        flags = _assemble_flags(
            NmapMode.FULL_INVENTORY,
            NmapBanner.LIGHT,
            scripts,
            ConfigScanMode.NORMAL,
        )
        assert f"--script={expected_expr}" in flags

    def test_scripts_none_omits_script_arg(self):
        flags = _assemble_flags(
            NmapMode.FULL_INVENTORY,
            NmapBanner.LIGHT,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert not any(f.startswith("--script=") for f in flags)

    @pytest.mark.parametrize(
        ("scan_mode", "expected_timing"),
        [
            (ConfigScanMode.STEALTH, "-T2"),
            (ConfigScanMode.NORMAL, "-T3"),
            (ConfigScanMode.RAID, "-T4"),
        ],
    )
    def test_scan_mode_timing(self, scan_mode, expected_timing):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            scan_mode,
        )
        assert expected_timing in flags

    def test_stealth_adds_retry_and_host_timeout_caps(self):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.STEALTH,
        )
        assert "--max-retries" in flags and "1" in flags
        assert "--host-timeout" in flags

    def test_raid_adds_min_rate(self):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.RAID,
        )
        assert "--min-rate" in flags

    def test_vuln_scripts_refused_under_stealth(self):
        # Loud script bundle vs explicit stealth posture -> raise at the
        # boundary so the OA sees the refusal and dials back.
        with pytest.raises(ValueError, match=r"VULN.*STEALTH"):
            _assemble_flags(
                NmapMode.FULL_INVENTORY,
                NmapBanner.LIGHT,
                NmapScripts.VULN,
                ConfigScanMode.STEALTH,
            )

    def test_os_detect_adds_minus_o(self):
        flags = _assemble_flags(
            NmapMode.OS_DETECT,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "-O" in flags


class TestParseXml:
    def test_parses_multi_host_with_banners(self):
        results = _parse_xml(_XML_TWO_HOSTS_WITH_BANNERS)
        assert len(results) == 2

        first = results[0]
        assert first.host == "93.184.216.34"
        assert len(first.services) == 2
        ports = {s.port for s in first.services}
        assert ports == {80, 22}

        nginx_svc = next(s for s in first.services if s.port == 80)
        assert nginx_svc.product == "nginx"
        assert nginx_svc.version == "1.18.0"

        ssh_svc = next(s for s in first.services if s.port == 22)
        assert ssh_svc.product == "OpenSSH"
        assert ssh_svc.version == "7.6p1"
        assert ssh_svc.extra_info == "Ubuntu"

    def test_emits_typed_technologies_from_banners(self):
        results = _parse_xml(_XML_TWO_HOSTS_WITH_BANNERS)
        # nginx + OpenSSH are in the seed catalogue; the parser routes
        # them through coerce_technologies and lands typed Technology
        # rows on the result.
        nginx_host = next(r for r in results if r.host == "93.184.216.34")
        names = {t.name for t in nginx_host.detected_technologies}
        assert "nginx" in names
        assert "openssh" in names

    def test_redis_falls_back_to_service_name(self):
        # Second host has only a service name (no product banner). The
        # parser falls back to the service name as the coerce input,
        # which is enough to land Redis as a typed Technology.
        results = _parse_xml(_XML_TWO_HOSTS_WITH_BANNERS)
        redis_host = next(r for r in results if r.host == "93.184.216.35")
        names = {t.name for t in redis_host.detected_technologies}
        assert "redis" in names

    def test_empty_xml_returns_empty(self):
        assert _parse_xml("") == []

    def test_no_hosts_xml_returns_empty(self):
        assert _parse_xml(_XML_NO_HOSTS) == []

    def test_malformed_xml_returns_empty(self):
        # Defensive - mid-scan truncation / nmap crash mid-output -> the
        # parser returns an empty list rather than raising.
        assert _parse_xml("this is not xml") == []

    def test_skips_host_without_address(self):
        # <host> with no <address> child - skip rather than raise.
        xml = "<?xml version='1.0'?><nmaprun><host></host></nmaprun>"
        assert _parse_xml(xml) == []

    def test_skips_port_with_non_numeric_portid(self):
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="1.1.1.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="not-a-number">'
            '<state state="open"/></port></ports>'
            "</host></nmaprun>"
        )
        results = _parse_xml(xml)
        assert len(results) == 1
        assert results[0].services == []


class TestEvidenceFilename:
    def test_deterministic_for_same_hosts(self):
        a = _evidence_filename(["x.example", "y.example"], NmapMode.QUICK_PORTS)
        b = _evidence_filename(["x.example", "y.example"], NmapMode.QUICK_PORTS)
        assert a == b

    def test_order_independent(self):
        # Sort the input so {x, y} and {y, x} produce the same filename.
        a = _evidence_filename(["x.example", "y.example"], NmapMode.QUICK_PORTS)
        b = _evidence_filename(["y.example", "x.example"], NmapMode.QUICK_PORTS)
        assert a == b

    def test_mode_in_name(self):
        name = _evidence_filename(["x.example"], NmapMode.FULL_INVENTORY)
        assert "full-inventory" in name

    def test_filename_shape(self):
        name = _evidence_filename(["x.example"], NmapMode.QUICK_PORTS)
        assert name.startswith("nmap-")
        assert name.endswith(".xml")


class TestNmapScan:
    def _mock_subprocess_result(self, xml: str):
        result = MagicMock()
        result.stdout = xml
        result.returncode = 0
        result.stderr = ""
        return result

    def test_returns_typed_result_with_parsed_hosts(self):
        mock_result = self._mock_subprocess_result(_XML_TWO_HOSTS_WITH_BANNERS)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(
                ["93.184.216.34", "93.184.216.35"],
                mode=NmapMode.SERVICE_VERSION,
                banner=NmapBanner.LIGHT,
                persist_evidence=False,
            )

        assert isinstance(result, NmapScanResult)
        assert result.mode == NmapMode.SERVICE_VERSION
        assert len(result.hosts) == 2
        assert all(isinstance(h, NmapHostResult) for h in result.hosts)

    def test_empty_host_list_short_circuits(self):
        # No subprocess invocation for empty input.
        with patch("tools.recon.nmap.scanner._require_binary") as mock_bin:
            result = nmap_scan([], mode=NmapMode.QUICK_PORTS)
        mock_bin.assert_not_called()
        assert result.hosts == []
        assert result.mode == NmapMode.QUICK_PORTS

    def test_subprocess_failure_returns_empty_result(self):
        # Network down / nmap missing -> degrade gracefully.
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", side_effect=OSError("nmap died")),
        ):
            result = nmap_scan(["x.example"], mode=NmapMode.QUICK_PORTS)
        assert result.hosts == []
        assert result.evidence_path is None

    def test_persist_evidence_writes_xml_to_run_dir(self, run_dir):
        # ``run_dir`` fixture points runtime.run_dir() at tmp_path.
        mock_result = self._mock_subprocess_result(_XML_TWO_HOSTS_WITH_BANNERS)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(
                ["93.184.216.34"],
                mode=NmapMode.QUICK_PORTS,
                persist_evidence=True,
            )

        assert result.evidence_path is not None
        on_disk = run_dir / result.evidence_path
        assert on_disk.exists()
        assert on_disk.read_text(encoding="utf-8") == _XML_TWO_HOSTS_WITH_BANNERS

    def test_persist_evidence_false_skips_write(self, run_dir):
        mock_result = self._mock_subprocess_result(_XML_TWO_HOSTS_WITH_BANNERS)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(
                ["93.184.216.34"],
                mode=NmapMode.QUICK_PORTS,
                persist_evidence=False,
            )
        assert result.evidence_path is None
        # No XML files written to the rundir.
        assert not any(run_dir.glob("nmap-*.xml"))

    def test_persist_skipped_without_run_binding(self):
        # No ``run_dir`` fixture -> runtime.run_dir() raises -> evidence
        # write is skipped gracefully, result still typed.
        mock_result = self._mock_subprocess_result(_XML_TWO_HOSTS_WITH_BANNERS)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(["x.example"], persist_evidence=True)
        assert result.evidence_path is None
        assert len(result.hosts) == 2  # parsing still happened

    def test_command_uses_oX_dash_for_xml_stdout(self):
        # Sanity: the assembled command pipes XML to stdout via -oX -,
        # not the grep format the old port_scan used.
        mock_result = self._mock_subprocess_result(_XML_NO_HOSTS)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result) as mock_run,
        ):
            nmap_scan(["x.example"], persist_evidence=False)
        cmd = mock_run.call_args.args[0]
        # -oX argument appears with its '-' partner immediately after.
        assert "-oX" in cmd
        idx = cmd.index("-oX")
        assert cmd[idx + 1] == "-"
