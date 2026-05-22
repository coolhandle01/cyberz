"""
tests/test_squad_penetration_tester.py - exercise a representative sample of
the @tool wrappers on the Penetration Tester.

42 tools live on this agent; the bodies are near-identical thin wrappers, so a
representative sample is enough for regression value without inflating the
test suite to no benefit. The wrappers unmarshal JSON, call into tools/*
helpers, and serialise the result; the underlying helpers are exercised in
their own dedicated test files.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestPenetrationTesterTools:
    def test_nuclei_scan_tool(self, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import nuclei_scan_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.penetration_tester.run_nuclei",
            return_value=[raw_finding_low],
        ):
            result = nuclei_scan_tool.func(endpoints_json, '["wordpress"]')

        assert result == [raw_finding_low]

    def test_sqlmap_tool(self, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import sqlmap_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.penetration_tester.run_sqlmap",
            return_value=[raw_finding_low],
        ):
            result = sqlmap_tool.func(endpoints_json)

        assert result == [raw_finding_low]

    def test_cookie_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import cookie_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester.http.set_programme") as mhttp,
            patch(
                "squad.penetration_tester.check_cookies",
                return_value=[raw_finding_low],
            ),
        ):
            result = cookie_check_tool.func("recon.json")

        assert result == [raw_finding_low]
        mhttp.assert_called_once_with(recon_result.programme.handle)

    def test_cors_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import cors_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_cors_misconfiguration",
                return_value=[raw_finding_low],
            ),
        ):
            result = cors_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_csrf_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import csrf_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_csrf",
                return_value=[raw_finding_low],
            ),
        ):
            result = csrf_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_ssrf_probe_tool(self, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import ssrf_probe_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.penetration_tester.check_ssrf",
            return_value=[raw_finding_low],
        ):
            result = ssrf_probe_tool.func(endpoints_json, None)

        assert result == [raw_finding_low]

    def test_header_injection_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import header_injection_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_header_injection",
                return_value=[raw_finding_low],
            ),
        ):
            result = header_injection_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_host_header_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import host_header_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_host_headers",
                return_value=[raw_finding_low],
            ),
        ):
            result = host_header_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_save_findings_tool(self, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import save_findings_tool

        findings_json = json.dumps([raw_finding_low.model_dump(mode="json")])
        with patch("runtime.run_dir", return_value=tmp_path):
            result = save_findings_tool.func(findings_json)

        assert result == "findings.json"
        assert (tmp_path / "findings.json").read_text(encoding="utf-8") == findings_json

    def test_recon_subdomains_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_subdomains_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = recon_subdomains_tool.func("recon.json")
        assert result == recon_result.subdomains

    def test_recon_endpoints_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_endpoints_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = recon_endpoints_tool.func("recon.json", status=200)
        from models import EndpointPage

        assert isinstance(result, EndpointPage)
        assert result.total == 1
        assert result.endpoints[0].url == recon_result.endpoints[0].url

    def test_recon_open_ports_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_open_ports_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        from models import OpenPortsMap

        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = recon_open_ports_tool.func("recon.json")
        assert isinstance(result, OpenPortsMap)
        assert result.hosts == recon_result.open_ports
