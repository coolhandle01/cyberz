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

# ----------------------------------------------------------------------------
# Programme Manager
# ----------------------------------------------------------------------------


@pytest.mark.unit
class TestProgrammeManagerTools:
    def test_find_programmes_tool_caches_each(self, programme, tmp_path) -> None:
        from pathlib import Path

        from squad.programme_manager import find_programmes_tool

        cache_paths: dict[str, Path] = {}

        def cache_path_for(handle):
            p = tmp_path / handle / "programme.json"
            cache_paths[handle] = p
            return p

        with (
            patch(
                "squad.programme_manager.h1.find_programmes",
                return_value=[programme],
            ) as mfind,
            patch(
                "squad.programme_manager.runtime.programme_cache_path",
                side_effect=cache_path_for,
            ),
        ):
            result = find_programmes_tool.func()

        assert result == [programme.model_dump()]
        mfind.assert_called_once_with(open_only=True, bounty_only=True)
        assert cache_paths[programme.handle].exists()

    def test_save_programme_tool_sets_handle_and_copies(self, programme, tmp_path) -> None:
        from squad.programme_manager import save_programme_tool

        cache = tmp_path / "cache" / "programme.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(programme.model_dump_json(), encoding="utf-8")
        run_dir = tmp_path / "run"

        import runtime

        with (
            patch(
                "squad.programme_manager.runtime.run_dir",
                return_value=run_dir,
            ),
            patch(
                "squad.programme_manager.runtime.programme_cache_path",
                return_value=cache,
            ),
        ):
            result = save_programme_tool.func(programme.handle)

        assert runtime.programme_handle == programme.handle
        assert result == str(run_dir)
        assert (run_dir / "programme.json").exists()


# ----------------------------------------------------------------------------
# OSINT Analyst
# ----------------------------------------------------------------------------


@pytest.mark.unit
class TestOsintAnalystTools:
    def test_recon_tool(self, programme, recon_result) -> None:
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
        ):
            result = recon_tool.func("acme")

        assert result == recon_result.model_dump()
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


@pytest.mark.unit
class TestVulnerabilityResearcherTools:
    def test_triage_tool(self, raw_finding_high, programme, verified_vuln) -> None:
        from squad.vulnerability_researcher import triage_tool

        raw_json = json.dumps([raw_finding_high.model_dump(mode="json")])
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
        ):
            result = triage_tool.func(raw_json, "acme")

        assert result == [verified_vuln.model_dump()]
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


@pytest.mark.unit
class TestTechnicalAuthorTools:
    def test_create_report_tool(self, verified_vuln, disclosure_report) -> None:
        from squad.technical_author import create_report_tool

        vuln_json = verified_vuln.model_dump_json()
        with (
            patch("squad.technical_author.http.set_programme") as mhttp,
            patch(
                "squad.technical_author.create_disclosure_report",
                return_value=disclosure_report,
            ),
            patch("squad.technical_author.save_report") as msave,
        ):
            result = create_report_tool.func("acme", vuln_json, "summary line")

        assert result == disclosure_report.model_dump()
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


@pytest.mark.unit
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


@pytest.mark.unit
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

    def test_cookie_check_tool(self, recon_result, raw_finding_low) -> None:
        from squad.penetration_tester import cookie_check_tool

        recon_json = recon_result.model_dump_json()
        with (
            patch("squad.penetration_tester.http.set_programme") as mhttp,
            patch(
                "squad.penetration_tester.check_cookies",
                return_value=[raw_finding_low],
            ),
        ):
            result = cookie_check_tool.func(recon_json)

        assert result == [raw_finding_low.model_dump()]
        mhttp.assert_called_once_with(recon_result.programme.handle)

    def test_cors_check_tool(self, recon_result, raw_finding_low) -> None:
        from squad.penetration_tester import cors_check_tool

        recon_json = recon_result.model_dump_json()
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_cors_misconfiguration",
                return_value=[raw_finding_low],
            ),
        ):
            result = cors_check_tool.func(recon_json)

        assert result == [raw_finding_low.model_dump()]

    def test_csrf_check_tool(self, recon_result, raw_finding_low) -> None:
        from squad.penetration_tester import csrf_check_tool

        recon_json = recon_result.model_dump_json()
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_csrf",
                return_value=[raw_finding_low],
            ),
        ):
            result = csrf_check_tool.func(recon_json)

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

    def test_header_injection_tool(self, recon_result, raw_finding_low) -> None:
        from squad.penetration_tester import header_injection_tool

        recon_json = recon_result.model_dump_json()
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_header_injection",
                return_value=[raw_finding_low],
            ),
        ):
            result = header_injection_tool.func(recon_json)

        assert result == [raw_finding_low.model_dump()]

    def test_host_header_tool(self, recon_result, raw_finding_low) -> None:
        from squad.penetration_tester import host_header_tool

        recon_json = recon_result.model_dump_json()
        with (
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_host_headers",
                return_value=[raw_finding_low],
            ),
        ):
            result = host_header_tool.func(recon_json)

        assert result == [raw_finding_low.model_dump()]
