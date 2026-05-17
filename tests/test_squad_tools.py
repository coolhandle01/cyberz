"""
tests/test_squad_tools.py - exercise the @tool wrappers on each squad member.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit

# ----------------------------------------------------------------------------
# Programme Manager
# ----------------------------------------------------------------------------


class TestProgrammeManagerTools:
    def test_list_programmes_tool(self) -> None:
        from squad.programme_manager import list_programmes_tool

        sentinel = [{"handle": "acme"}]
        with patch("squad.programme_manager.h1.list_programmes", return_value=sentinel) as m:
            result = list_programmes_tool.func(page_size=5)

        assert result == sentinel
        m.assert_called_once_with(page_size=5)

    def test_get_scope_tool(self) -> None:
        from squad.programme_manager import get_scope_tool

        with (
            patch(
                "squad.programme_manager.h1.get_programme_policy",
                return_value={"data": {"x": 1}},
            ) as mp,
            patch(
                "squad.programme_manager.h1.get_structured_scope",
                return_value={"items": []},
            ) as ms,
        ):
            result = get_scope_tool.func("acme")

        assert result == {"policy": {"data": {"x": 1}}, "scope": {"items": []}}
        mp.assert_called_once_with("acme")
        ms.assert_called_once_with("acme")

    def test_get_programme_stats_tool(self) -> None:
        from squad.programme_manager import get_programme_stats_tool

        sentinel = {"reports_received": 100}
        with patch(
            "squad.programme_manager.h1.get_programme_stats",
            return_value=sentinel,
        ) as m:
            result = get_programme_stats_tool.func("acme")

        assert result == sentinel
        m.assert_called_once_with("acme")


# ----------------------------------------------------------------------------
# OSINT Analyst
# ----------------------------------------------------------------------------


class TestOsintAnalystTools:
    def test_recon_tool(self, programme, recon_result, tmp_path) -> None:
        from squad.osint_analyst import recon_tool

        with (
            patch("squad.osint_analyst.http.set_programme") as mhttp,
            patch(
                "squad.osint_analyst.h1.get_programme_policy",
                return_value={"data": {}},
            ),
            patch("squad.osint_analyst.h1.get_structured_scope", return_value={}),
            patch("squad.osint_analyst.h1.parse_programme", return_value=programme),
            patch("squad.osint_analyst.run_recon", return_value=recon_result) as mrun,
            patch("runtime.run_dir", return_value=tmp_path),
        ):
            result = recon_tool.func("acme")

        assert result == str(tmp_path / "recon.json")
        assert (tmp_path / "recon.json").exists()
        mhttp.assert_called_once_with("acme")
        mrun.assert_called_once_with(programme)

    def test_cert_transparency_tool(self) -> None:
        from squad.osint_analyst import cert_transparency_tool

        sentinel = ["api.example.com", "admin.example.com"]
        with patch(
            "squad.osint_analyst.cert_transparency",
            return_value=sentinel,
        ) as m:
            result = cert_transparency_tool.func("example.com")

        assert result == sentinel
        m.assert_called_once_with("example.com")

    def test_historical_urls_tool(self) -> None:
        from squad.osint_analyst import historical_urls_tool

        sentinel = ["https://example.com/old"]
        with patch(
            "squad.osint_analyst.historical_urls",
            return_value=sentinel,
        ) as m:
            result = historical_urls_tool.func("example.com")

        assert result == sentinel
        m.assert_called_once_with("example.com")

    def test_llm_detection_tool(self, endpoint) -> None:
        from squad.osint_analyst import llm_detection_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.osint_analyst.detect_llm_endpoints",
            return_value=[endpoint],
        ) as m:
            result = llm_detection_tool.func(endpoints_json)

        assert result == [endpoint.model_dump()]
        assert len(m.call_args[0][0]) == 1


# ----------------------------------------------------------------------------
# Vulnerability Researcher
# ----------------------------------------------------------------------------


class TestVulnerabilityResearcherTools:
    def test_triage_tool(self, raw_finding_high, programme, verified_vuln, tmp_path) -> None:
        from squad.vulnerability_researcher import triage_tool

        findings_path = tmp_path / "findings.json"
        findings_path.write_text(
            json.dumps([raw_finding_high.model_dump(mode="json")]),
            encoding="utf-8",
        )
        with (
            patch("squad.vulnerability_researcher.http.set_programme") as mhttp,
            patch(
                "squad.vulnerability_researcher.h1.get_programme_policy",
                return_value={"data": {}},
            ),
            patch(
                "squad.vulnerability_researcher.h1.get_structured_scope",
                return_value={},
            ),
            patch(
                "squad.vulnerability_researcher.h1.parse_programme",
                return_value=programme,
            ),
            patch(
                "squad.vulnerability_researcher.triage_findings",
                return_value=[verified_vuln],
            ),
            patch("runtime.run_dir", return_value=tmp_path),
        ):
            result = triage_tool.func(str(findings_path), "acme")

        assert result == str(tmp_path / "verified.json")
        assert (tmp_path / "verified.json").exists()
        mhttp.assert_called_once_with("acme")

    def test_lookup_cve_tool(self) -> None:
        from squad.vulnerability_researcher import lookup_cve_tool

        sentinel = [{"cve_id": "CVE-2024-1234"}]
        with patch(
            "squad.vulnerability_researcher.lookup_cve",
            return_value=sentinel,
        ) as m:
            result = lookup_cve_tool.func("sql injection")

        assert result == sentinel
        m.assert_called_once_with("sql injection")

    def test_check_duplicate_tool_matches(self) -> None:
        from squad.vulnerability_researcher import check_duplicate_tool

        reports = [
            {
                "id": "1",
                "attributes": {"title": "SQL Injection in search", "state": "open"},
            },
            {
                "id": "2",
                "attributes": {"title": "XSS in admin panel", "state": "triaged"},
            },
        ]
        with (
            patch("squad.vulnerability_researcher.http.set_programme"),
            patch(
                "squad.vulnerability_researcher.h1.list_reports",
                return_value=reports,
            ),
        ):
            result = check_duplicate_tool.func("acme", "SQL Injection in search")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["report_id"] == "1"

    def test_check_duplicate_tool_handles_missing_title(self) -> None:
        from squad.vulnerability_researcher import check_duplicate_tool

        reports = [{"id": "3", "attributes": {"state": "closed"}}]
        with (
            patch("squad.vulnerability_researcher.http.set_programme"),
            patch(
                "squad.vulnerability_researcher.h1.list_reports",
                return_value=reports,
            ),
        ):
            result = check_duplicate_tool.func("acme", "Anything")

        assert result == []


# ----------------------------------------------------------------------------
# Technical Author
# ----------------------------------------------------------------------------


class TestTechnicalAuthorTools:
    def test_create_report_tool(self, verified_vuln, disclosure_report, tmp_path) -> None:
        from squad.technical_author import create_report_tool

        verified_path = tmp_path / "verified.json"
        verified_path.write_text(
            json.dumps([verified_vuln.model_dump(mode="json")]),
            encoding="utf-8",
        )
        with (
            patch("squad.technical_author.http.set_programme") as mhttp,
            patch(
                "squad.technical_author.create_disclosure_report",
                return_value=disclosure_report,
            ),
            patch("squad.technical_author.save_report") as msave,
            patch("runtime.run_dir", return_value=tmp_path),
        ):
            result = create_report_tool.func(str(verified_path), "acme", "summary line")

        assert result == disclosure_report.model_dump()
        assert (tmp_path / "report.json").exists()
        mhttp.assert_called_once_with("acme")
        msave.assert_called_once_with(disclosure_report)

    def test_calculate_cvss_tool(self) -> None:
        from squad.technical_author import calculate_cvss_tool

        with patch(
            "squad.technical_author.calculate_cvss_score",
            return_value=8.8,
        ) as m:
            result = calculate_cvss_tool.func("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        assert result == 8.8
        m.assert_called_once_with("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


# ----------------------------------------------------------------------------
# Disclosure Coordinator
# ----------------------------------------------------------------------------


class TestDisclosureCoordinatorTools:
    def test_submit_report_tool(self, disclosure_report) -> None:
        from squad.disclosure_coordinator import submit_report_tool

        report_json = disclosure_report.model_dump_json()
        submission = MagicMock()
        submission.model_dump.return_value = {"submitted": True, "id": "h1-42"}

        with (
            patch("squad.disclosure_coordinator.http.set_programme") as mhttp,
            patch("squad.disclosure_coordinator.save_report") as msave,
            patch(
                "squad.disclosure_coordinator.h1.submit_report",
                return_value=submission,
            ) as msub,
        ):
            result = submit_report_tool.func(report_json)

        assert result == {"submitted": True, "id": "h1-42"}
        mhttp.assert_called_once_with(disclosure_report.programme_handle)
        msave.assert_called_once()
        msub.assert_called_once()

    def test_check_duplicate_tool(self) -> None:
        from squad.disclosure_coordinator import check_duplicate_tool

        reports = [
            {
                "id": "1",
                "attributes": {"title": "SQL Injection in search", "state": "open"},
            },
        ]
        with (
            patch("squad.disclosure_coordinator.http.set_programme"),
            patch(
                "squad.disclosure_coordinator.h1.list_reports",
                return_value=reports,
            ),
        ):
            result = check_duplicate_tool.func("acme", "SQL Injection in search")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["title"] == "SQL Injection in search"


# ----------------------------------------------------------------------------
# Penetration Tester - sample of @tool wrappers
#
# 42 tools live on this agent; the bodies are near-identical thin wrappers,
# so a representative sample is enough for regression value without inflating
# the test suite to no benefit.
# ----------------------------------------------------------------------------


class TestPenetrationTesterTools:
    def test_nuclei_scan_tool(self, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import nuclei_scan_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.penetration_tester.run_nuclei",
            return_value=[raw_finding_low],
        ):
            result = nuclei_scan_tool.func(endpoints_json, '["wordpress"]')

        assert result == [raw_finding_low.model_dump()]

    def test_sqlmap_tool(self, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import sqlmap_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.penetration_tester.run_sqlmap",
            return_value=[raw_finding_low],
        ):
            result = sqlmap_tool.func(endpoints_json)

        assert result == [raw_finding_low.model_dump()]

    def test_cookie_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import cookie_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("squad.penetration_tester.http.set_programme") as mhttp,
            patch(
                "squad.penetration_tester.check_cookies",
                return_value=[raw_finding_low],
            ),
        ):
            result = cookie_check_tool.func(str(recon_path))

        assert result == [raw_finding_low.model_dump()]
        mhttp.assert_called_once_with(recon_result.programme.handle)

    def test_cors_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import cors_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_cors_misconfiguration",
                return_value=[raw_finding_low],
            ),
        ):
            result = cors_check_tool.func(str(recon_path))

        assert result == [raw_finding_low.model_dump()]

    def test_csrf_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import csrf_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_csrf",
                return_value=[raw_finding_low],
            ),
        ):
            result = csrf_check_tool.func(str(recon_path))

        assert result == [raw_finding_low.model_dump()]

    def test_ssrf_probe_tool(self, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import ssrf_probe_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.penetration_tester.check_ssrf",
            return_value=[raw_finding_low],
        ):
            result = ssrf_probe_tool.func(endpoints_json, None)

        assert result == [raw_finding_low.model_dump()]

    def test_header_injection_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import header_injection_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_header_injection",
                return_value=[raw_finding_low],
            ),
        ):
            result = header_injection_tool.func(str(recon_path))

        assert result == [raw_finding_low.model_dump()]

    def test_host_header_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import host_header_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_host_headers",
                return_value=[raw_finding_low],
            ),
        ):
            result = host_header_tool.func(str(recon_path))

        assert result == [raw_finding_low.model_dump()]

    def test_save_findings_tool(self, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import save_findings_tool

        findings_json = json.dumps([raw_finding_low.model_dump(mode="json")])
        with patch("runtime.run_dir", return_value=tmp_path):
            result = save_findings_tool.func(findings_json)

        assert result == str(tmp_path / "findings.json")
        assert (tmp_path / "findings.json").read_text(encoding="utf-8") == findings_json

    def test_recon_subdomains_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_subdomains_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        result = recon_subdomains_tool.func(str(recon_path))
        assert result == recon_result.subdomains

    def test_recon_endpoints_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_endpoints_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        result = recon_endpoints_tool.func(str(recon_path), status=200)
        assert isinstance(result, dict)
        assert result["total"] == 1
        assert result["endpoints"][0]["url"] == recon_result.endpoints[0].url

    def test_recon_open_ports_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_open_ports_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        assert recon_open_ports_tool.func(str(recon_path)) == recon_result.open_ports


# ----------------------------------------------------------------------------
# Shared workspace tools
# ----------------------------------------------------------------------------


class TestSharedWorkspaceTools:
    def test_read_run_filelist_tool(self, tmp_path) -> None:
        from squad import read_run_filelist_tool

        (tmp_path / "recon.json").write_text("{}", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = read_run_filelist_tool.func()
        assert result == [{"name": "recon.json", "size_bytes": 2}]

    def test_read_run_file_tool(self, tmp_path) -> None:
        from squad import read_run_file_tool

        (tmp_path / "recon.json").write_text("hello", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = read_run_file_tool.func("recon.json")
        assert isinstance(result, dict)
        assert result["content"] == "hello"
        assert result["size_bytes"] == 5
        assert result["truncated"] is False

    def test_read_run_file_tool_refuses_escape(self, tmp_path) -> None:
        from squad import read_run_file_tool

        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="escapes the run directory"):
                read_run_file_tool.func("../etc/passwd")
