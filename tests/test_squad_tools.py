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
    def test_run_initial_sweep_tool(self, programme, recon_result, tmp_path) -> None:
        from squad.osint_analyst import run_initial_sweep_tool

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
            result = run_initial_sweep_tool.func("acme")

        assert result == "sweep.json"
        assert (tmp_path / "sweep.json").exists()
        mhttp.assert_called_once_with("acme")
        mrun.assert_called_once_with(programme)

    @staticmethod
    def _patch_programme(programme):
        return [
            patch("squad.osint_analyst.http.set_programme"),
            patch(
                "squad.osint_analyst.h1.get_programme_policy",
                return_value={"data": {}},
            ),
            patch("squad.osint_analyst.h1.get_structured_scope", return_value={}),
            patch("squad.osint_analyst.h1.parse_programme", return_value=programme),
        ]

    def test_annotate_host_tool_writes_insight_and_returns_validation(
        self, programme, recon_result, tmp_path
    ) -> None:
        from squad.osint_analyst import annotate_host_tool

        (tmp_path / "sweep.json").write_text(recon_result.model_dump_json(), encoding="utf-8")

        patches = self._patch_programme(programme) + [
            patch("tools.recon_insights.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            result = annotate_host_tool.func(
                hostname="api.example.com",
                role="api",
                priority="high",
                notes=(
                    "Public REST gateway running Nginx in front of a React SPA; "
                    "primary attack surface for the programme."
                ),
                detected_tech=["Nginx", "React"],
                programme_handle="test-programme",
            )
        finally:
            for p in reversed(patches):
                p.stop()

        assert isinstance(result, dict)
        assert result["validation"]["ok"] is True
        assert (tmp_path / "host_insights" / "api.example.com.json").exists()

    def test_annotate_host_tool_surfaces_validation_issues(
        self, programme, recon_result, tmp_path
    ) -> None:
        from squad.osint_analyst import annotate_host_tool

        (tmp_path / "sweep.json").write_text(recon_result.model_dump_json(), encoding="utf-8")

        patches = self._patch_programme(programme) + [
            patch("tools.recon_insights.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            result = annotate_host_tool.func(
                hostname="api.example.com",
                role="api",
                priority="high",
                notes="too short",  # < 30 chars, also < 60 high-priority floor
                detected_tech=["Nginx"],
                programme_handle="test-programme",
            )
        finally:
            for p in reversed(patches):
                p.stop()

        assert isinstance(result, dict)
        assert result["validation"]["ok"] is False
        sections = {i["section"] for i in result["validation"]["issues"]}
        assert "notes" in sections

    def test_uncovered_hosts_tool_returns_missing(self, programme, recon_result, tmp_path) -> None:
        from squad.osint_analyst import uncovered_hosts_tool

        (tmp_path / "sweep.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch("tools.recon_insights.runtime.run_dir", return_value=tmp_path):
            result = uncovered_hosts_tool.func()

        assert isinstance(result, list)
        # recon_result fixture has https://api.example.com with status 200 -> interesting
        assert "api.example.com" in result

    def test_finalise_recon_tool_writes_recon_json(self, programme, recon_result, tmp_path) -> None:
        from squad.osint_analyst import annotate_host_tool, finalise_recon_tool

        (tmp_path / "sweep.json").write_text(recon_result.model_dump_json(), encoding="utf-8")

        patches = self._patch_programme(programme) + [
            patch("tools.recon_insights.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            annotate_host_tool.func(
                hostname="api.example.com",
                role="api",
                priority="high",
                notes=(
                    "Public REST gateway running Nginx in front of a React SPA; "
                    "primary attack surface for the programme."
                ),
                detected_tech=["Nginx", "React"],
                programme_handle="test-programme",
            )
            result = finalise_recon_tool.func("test-programme")
        finally:
            for p in reversed(patches):
                p.stop()

        assert result == "recon.json"
        assert (tmp_path / "recon.json").exists()

    def test_finalise_recon_tool_raises_without_insights(
        self, programme, recon_result, tmp_path
    ) -> None:
        from squad.osint_analyst import finalise_recon_tool

        (tmp_path / "sweep.json").write_text(recon_result.model_dump_json(), encoding="utf-8")

        patches = self._patch_programme(programme) + [
            patch("tools.recon_insights.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            with pytest.raises(ValueError, match="no host_insights"):
                finalise_recon_tool.func("test-programme")
        finally:
            for p in reversed(patches):
                p.stop()

    def test_probe_hostnames_tool(self, programme, endpoint) -> None:
        from squad.osint_analyst import probe_hostnames_tool

        patches = self._patch_programme(programme) + [
            patch(
                "squad.osint_analyst.filter_in_scope_impl",
                return_value=["api.example.com"],
            ),
            patch(
                "squad.osint_analyst.probe_endpoints_impl",
                return_value=[endpoint],
            ),
        ]
        for p in patches:
            p.start()
        try:
            result = probe_hostnames_tool.func(
                ["api.example.com"], programme_handle="test-programme"
            )
        finally:
            for p in reversed(patches):
                p.stop()

        assert isinstance(result, list)
        assert result[0]["url"] == endpoint.url

    def test_probe_hostnames_tool_empty_list(self) -> None:
        from squad.osint_analyst import probe_hostnames_tool

        assert probe_hostnames_tool.func([], programme_handle="test-programme") == []

    def test_probe_hostnames_tool_drops_out_of_scope(self, programme, bystander_url) -> None:
        from urllib.parse import urlparse

        from squad.osint_analyst import probe_hostnames_tool

        oos_host = urlparse(bystander_url).hostname
        mprobe = MagicMock()
        patches = self._patch_programme(programme) + [
            patch(
                "squad.osint_analyst.filter_in_scope_impl",
                return_value=[],
            ),
            patch("squad.osint_analyst.probe_endpoints_impl", mprobe),
        ]
        for p in patches:
            p.start()
        try:
            result = probe_hostnames_tool.func([oos_host], programme_handle="test-programme")
        finally:
            for p in reversed(patches):
                p.stop()

        assert result == []
        mprobe.assert_not_called()

    def test_detect_takeover_candidates_tool(self, programme) -> None:
        from squad.osint_analyst import detect_takeover_candidates_tool
        from tools.recon.dnsx import TakeoverCandidate

        candidate = TakeoverCandidate(
            hostname="legacy.example.com",
            cname="bucket.s3.amazonaws.com",
            reason="cname_to_vulnerable_provider",
            service="AWS S3",
        )
        patches = self._patch_programme(programme) + [
            patch(
                "squad.osint_analyst.filter_in_scope_impl",
                return_value=["legacy.example.com"],
            ),
            patch(
                "squad.osint_analyst.detect_takeover_candidates",
                return_value=[candidate],
            ),
        ]
        for p in patches:
            p.start()
        try:
            result = detect_takeover_candidates_tool.func(
                ["legacy.example.com"], programme_handle="test-programme"
            )
        finally:
            for p in reversed(patches):
                p.stop()

        assert isinstance(result, list)
        assert result == [
            {
                "hostname": "legacy.example.com",
                "cname": "bucket.s3.amazonaws.com",
                "reason": "cname_to_vulnerable_provider",
                "service": "AWS S3",
            }
        ]

    def test_detect_takeover_candidates_tool_empty(self) -> None:
        from squad.osint_analyst import detect_takeover_candidates_tool

        assert detect_takeover_candidates_tool.func([], programme_handle="test-programme") == []

    def test_detect_takeover_candidates_tool_drops_out_of_scope(
        self, programme, bystander_url
    ) -> None:
        from urllib.parse import urlparse

        from squad.osint_analyst import detect_takeover_candidates_tool

        oos_host = urlparse(bystander_url).hostname
        mdetect = MagicMock()
        patches = self._patch_programme(programme) + [
            patch(
                "squad.osint_analyst.filter_in_scope_impl",
                return_value=[],
            ),
            patch("squad.osint_analyst.detect_takeover_candidates", mdetect),
        ]
        for p in patches:
            p.start()
        try:
            result = detect_takeover_candidates_tool.func(
                [oos_host], programme_handle="test-programme"
            )
        finally:
            for p in reversed(patches):
                p.stop()

        assert result == []
        mdetect.assert_not_called()

    def test_lookup_cwe_tool(self) -> None:
        from squad.osint_analyst import lookup_cwe_tool

        result = lookup_cwe_tool.func("XSS")
        assert isinstance(result, list)
        assert result
        assert result[0]["cwe_id"] == 79

    def test_lookup_owasp_tool(self) -> None:
        from squad.osint_analyst import lookup_owasp_tool

        result = lookup_owasp_tool.func("sql injection")
        assert isinstance(result, list)
        assert any("SQL_Injection_Prevention" in r["url"] for r in result)

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

    def test_list_programme_reports_tool_returns_all(self) -> None:
        from squad.vulnerability_researcher import list_programme_reports_tool

        reports = [
            {
                "id": "1",
                "attributes": {
                    "title": "SQL Injection in search",
                    "severity_rating": "high",
                    "state": "open",
                },
            },
            {
                "id": "2",
                "attributes": {
                    "title": "XSS in admin panel",
                    "severity_rating": "medium",
                    "state": "triaged",
                },
            },
        ]
        with (
            patch("squad.vulnerability_researcher.http.set_programme"),
            patch(
                "squad.vulnerability_researcher.h1.list_reports",
                return_value=reports,
            ),
        ):
            result = list_programme_reports_tool.func("acme")

        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["report_id"] == "1"
        assert result[1]["severity"] == "medium"

    def test_list_programme_reports_tool_handles_missing_fields(self) -> None:
        from squad.vulnerability_researcher import list_programme_reports_tool

        reports = [{"id": "3", "attributes": {"state": "closed"}}]
        with (
            patch("squad.vulnerability_researcher.http.set_programme"),
            patch(
                "squad.vulnerability_researcher.h1.list_reports",
                return_value=reports,
            ),
        ):
            result = list_programme_reports_tool.func("acme")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["title"] is None
        assert result[0]["severity"] is None

    # Triage-task tools

    @staticmethod
    def _write_findings(tmp_path, raw_finding_high) -> None:
        (tmp_path / "findings.json").write_text(
            json.dumps([raw_finding_high.model_dump(mode="json")]),
            encoding="utf-8",
        )

    @staticmethod
    def _good_authoring(**overrides):
        base = {
            "finding_index": 0,
            "severity_decision": "keep",
            "severity": "high",
            "severity_rationale": (
                "Unauthenticated SQLi at a public endpoint with full DB read "
                "available - matches the PT high call."
            ),
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "title": "SQL Injection in /search?q allows database extraction",
            "description": (
                "The /search endpoint concatenates q into a SELECT statement without "
                "parameterisation. sqlmap exploits classic UNION-based injection to "
                "extract rows from the users table."
            ),
            "steps_to_reproduce": [
                "GET https://api.example.com/search?q=test' UNION SELECT 1,2,3-- ",
                "Observe the response body contains the union'd rows.",
            ],
            "impact": (
                "An authenticated attacker dumps the users table including bcrypt "
                "hashes and emails, enabling offline cracking and account takeover."
            ),
            "remediation": (
                "Use parameterised queries throughout. See "
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ),
            "programme_handle": "test-programme",
        }
        base.update(overrides)
        return base

    def test_list_raw_findings_tool(self, raw_finding_high, tmp_path) -> None:
        from squad.vulnerability_researcher import list_raw_findings_tool

        self._write_findings(tmp_path, raw_finding_high)
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = list_raw_findings_tool.func()

        assert isinstance(result, list)
        assert result[0]["index"] == 0
        assert result[0]["vuln_class"] == raw_finding_high.vuln_class
        assert result[0]["evidence_bytes"] == len(raw_finding_high.evidence)

    def test_read_raw_finding_tool(self, raw_finding_high, tmp_path) -> None:
        from squad.vulnerability_researcher import read_raw_finding_tool

        self._write_findings(tmp_path, raw_finding_high)
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = read_raw_finding_tool.func(0)

        assert isinstance(result, dict)
        assert result["target"] == raw_finding_high.target

    def test_read_raw_finding_tool_rejects_out_of_range(self, raw_finding_high, tmp_path) -> None:
        from squad.vulnerability_researcher import read_raw_finding_tool

        self._write_findings(tmp_path, raw_finding_high)
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="out of range"):
                read_raw_finding_tool.func(5)

    def test_lookup_cwe_tool_finds_known_class(self) -> None:
        from squad.vulnerability_researcher import lookup_cwe_tool

        result = lookup_cwe_tool.func("SQLi")
        assert isinstance(result, list)
        assert result
        assert result[0]["cwe_id"] == 89

    def test_lookup_owasp_tool_returns_cheatsheet(self) -> None:
        from squad.vulnerability_researcher import lookup_owasp_tool

        result = lookup_owasp_tool.func("sql injection")
        assert isinstance(result, list)
        assert any("SQL_Injection_Prevention" in r["url"] for r in result)

    def test_calculate_cvss_tool(self) -> None:
        from squad.vulnerability_researcher import calculate_cvss_tool

        result = calculate_cvss_tool.func("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result == 9.8

    @staticmethod
    def _patch_programme(programme):
        return [
            patch("squad.vulnerability_researcher.http.set_programme"),
            patch(
                "squad.vulnerability_researcher.h1.get_programme_policy",
                return_value={"data": {}},
            ),
            patch("squad.vulnerability_researcher.h1.get_structured_scope", return_value={}),
            patch(
                "squad.vulnerability_researcher.h1.parse_programme",
                return_value=programme,
            ),
        ]

    def test_assess_finding_tool_writes_assessment_and_returns_validation(
        self, raw_finding_high, programme, tmp_path
    ) -> None:
        from squad.vulnerability_researcher import assess_finding_tool

        self._write_findings(tmp_path, raw_finding_high)
        patches = self._patch_programme(programme) + [
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.triage_tools.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            result = assess_finding_tool.func(**self._good_authoring())
        finally:
            for p in reversed(patches):
                p.stop()

        assert isinstance(result, dict)
        assert result["validation"]["ok"] is True
        assert (tmp_path / "assessments" / "000.json").exists()

    def test_assess_finding_tool_surfaces_validation_issues(
        self, raw_finding_high, programme, tmp_path
    ) -> None:
        from squad.vulnerability_researcher import assess_finding_tool

        self._write_findings(tmp_path, raw_finding_high)
        patches = self._patch_programme(programme) + [
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.triage_tools.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            result = assess_finding_tool.func(**self._good_authoring(description="Too short."))
        finally:
            for p in reversed(patches):
                p.stop()

        assert isinstance(result, dict)
        assert result["validation"]["ok"] is False
        sections = {i["section"] for i in result["validation"]["issues"]}
        assert "description" in sections

    def test_discard_finding_tool_writes_discard(self, raw_finding_high, tmp_path) -> None:
        from squad.vulnerability_researcher import discard_finding_tool

        self._write_findings(tmp_path, raw_finding_high)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.triage_tools.runtime.run_dir", return_value=tmp_path),
        ):
            result = discard_finding_tool.func(
                finding_index=0,
                reason="false_positive",
                rationale="On reproduction the tool's marker did not appear.",
            )

        assert isinstance(result, dict)
        assert (tmp_path / "discards" / "000.json").exists()

    def test_discard_finding_tool_rejects_thin_rationale(self, raw_finding_high, tmp_path) -> None:
        from squad.vulnerability_researcher import discard_finding_tool

        self._write_findings(tmp_path, raw_finding_high)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.triage_tools.runtime.run_dir", return_value=tmp_path),
        ):
            with pytest.raises(ValueError, match="at least 10 chars"):
                discard_finding_tool.func(
                    finding_index=0, reason="false_positive", rationale="nope"
                )

    def test_finalise_triage_tool_consolidates_assessments(
        self, raw_finding_high, programme, tmp_path
    ) -> None:
        from squad.vulnerability_researcher import assess_finding_tool, finalise_triage_tool

        self._write_findings(tmp_path, raw_finding_high)
        patches = self._patch_programme(programme) + [
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.triage_tools.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            assess_finding_tool.func(**self._good_authoring())
            result = finalise_triage_tool.func("test-programme")
        finally:
            for p in reversed(patches):
                p.stop()

        assert result == "verified.json"
        assert (tmp_path / "verified.json").exists()

    def test_finalise_triage_tool_raises_on_unprocessed(
        self, raw_finding_high, programme, tmp_path
    ) -> None:
        from squad.vulnerability_researcher import finalise_triage_tool

        # write TWO raw findings but assess none
        (tmp_path / "findings.json").write_text(
            json.dumps(
                [
                    raw_finding_high.model_dump(mode="json"),
                    raw_finding_high.model_dump(mode="json"),
                ]
            ),
            encoding="utf-8",
        )
        patches = self._patch_programme(programme) + [
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.triage_tools.runtime.run_dir", return_value=tmp_path),
        ]
        for p in patches:
            p.start()
        try:
            with pytest.raises(ValueError, match="no assessment or discard"):
                finalise_triage_tool.func("test-programme")
        finally:
            for p in reversed(patches):
                p.stop()


# ----------------------------------------------------------------------------
# Technical Author
# ----------------------------------------------------------------------------


class TestTechnicalAuthorTools:
    @staticmethod
    def _write_verified(tmp_path, verified_vuln) -> None:
        (tmp_path / "verified.json").write_text(
            json.dumps([verified_vuln.model_dump(mode="json")]),
            encoding="utf-8",
        )

    @staticmethod
    def _good_authoring(**overrides):
        base = {
            "finding_index": 0,
            "title": "SQL Injection in /search?q allows full database extraction",
            "summary": (
                "The /search endpoint concatenates user input into a SELECT statement. "
                "An unauthenticated attacker can dump the entire users table."
            ),
            "description": (
                "The handler at routes/search.py concatenates the q parameter directly "
                "into the SQL statement with no parameterisation. Standard UNION-based "
                "injection extracts arbitrary rows from the users table."
            ),
            "steps_to_reproduce": [
                "Issue GET https://api.example.com/search?q=test' UNION SELECT 1,2,3-- ",
                "Observe the response body contains the union'd rows.",
            ],
            "evidence": 'HTTP/1.1 200 OK\n\n[{"username":"alice"}]',
            "impact": (
                "An unauthenticated attacker can dump the entire users table including "
                "bcrypt hashes and email addresses, enabling offline cracking and full "
                "account takeover."
            ),
            "remediation": (
                "Use parameterised queries throughout the ORM. See "
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ),
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": 89,
        }
        base.update(overrides)
        return base

    def test_draft_report_tool_writes_draft_and_returns_validation(
        self, verified_vuln, tmp_path
    ) -> None:
        from squad.technical_author import draft_report_tool

        self._write_verified(tmp_path, verified_vuln)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.report_tools.runtime.run_dir", return_value=tmp_path),
        ):
            result = draft_report_tool.func(**self._good_authoring())

        assert isinstance(result, dict)
        assert result["validation"]["ok"] is True
        assert (tmp_path / "drafts" / "000.json").exists()

    def test_draft_report_tool_surfaces_validation_issues(self, verified_vuln, tmp_path) -> None:
        from squad.technical_author import draft_report_tool

        self._write_verified(tmp_path, verified_vuln)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.report_tools.runtime.run_dir", return_value=tmp_path),
        ):
            result = draft_report_tool.func(**self._good_authoring(title="bad title"))

        assert isinstance(result, dict)
        assert result["validation"]["ok"] is False
        sections = {i["section"] for i in result["validation"]["issues"]}
        assert "title" in sections

    def test_draft_report_tool_rejects_out_of_range_index(self, verified_vuln, tmp_path) -> None:
        from squad.technical_author import draft_report_tool

        self._write_verified(tmp_path, verified_vuln)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.report_tools.runtime.run_dir", return_value=tmp_path),
        ):
            with pytest.raises(ValueError, match="out of range"):
                draft_report_tool.func(**self._good_authoring(finding_index=5))

    def test_finalise_reports_tool_consolidates_drafts(self, verified_vuln, tmp_path) -> None:
        from squad.technical_author import draft_report_tool, finalise_reports_tool

        self._write_verified(tmp_path, verified_vuln)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.report_tools.runtime.run_dir", return_value=tmp_path),
        ):
            draft_report_tool.func(**self._good_authoring())
            result = finalise_reports_tool.func("acme", "Session summary line.")

        assert result == "reports.json"
        assert (tmp_path / "reports.json").exists()

    def test_finalise_reports_tool_raises_on_unresolved_errors(
        self, verified_vuln, tmp_path
    ) -> None:
        from squad.technical_author import draft_report_tool, finalise_reports_tool

        self._write_verified(tmp_path, verified_vuln)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("tools.report_tools.runtime.run_dir", return_value=tmp_path),
        ):
            draft_report_tool.func(**self._good_authoring(title="bad title"))
            with pytest.raises(ValueError, match="unresolved errors"):
                finalise_reports_tool.func("acme", "Summary.")

    def test_sanitise_evidence_tool_returns_redactions(self) -> None:
        from squad.technical_author import sanitise_evidence_tool

        result = sanitise_evidence_tool.func("Authorization: Bearer abc.def.ghi")
        assert isinstance(result, dict)
        assert "Bearer abc.def.ghi" not in result["sanitised"]
        assert result["redactions"]

    def test_lookup_cwe_tool_finds_known_class(self) -> None:
        from squad.technical_author import lookup_cwe_tool

        result = lookup_cwe_tool.func("SQLi")
        assert isinstance(result, list)
        assert result
        assert result[0]["cwe_id"] == 89
        assert "cwe.mitre.org" in result[0]["url"]

    def test_lookup_cwe_tool_empty_for_unknown(self) -> None:
        from squad.technical_author import lookup_cwe_tool

        assert lookup_cwe_tool.func("zzz-not-a-class") == []

    def test_lookup_owasp_tool_returns_cheatsheet(self) -> None:
        from squad.technical_author import lookup_owasp_tool

        result = lookup_owasp_tool.func("sql injection")
        assert isinstance(result, list)
        assert result
        assert any("SQL_Injection_Prevention" in r["url"] for r in result)

    def test_calculate_cvss_tool(self) -> None:
        from squad.technical_author import calculate_cvss_tool

        with patch(
            "squad.technical_author.calculate_cvss_score",
            return_value=8.8,
        ) as m:
            result = calculate_cvss_tool.func("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        assert result == 8.8
        m.assert_called_once_with("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_list_programme_reports_tool(self) -> None:
        from squad.technical_author import list_programme_reports_tool

        h1_reports = [
            {
                "id": "1",
                "attributes": {
                    "title": "Existing report",
                    "severity_rating": "high",
                    "state": "triaged",
                },
            }
        ]
        with (
            patch("squad.technical_author.http.set_programme") as mhttp,
            patch("squad.technical_author.h1.list_reports", return_value=h1_reports) as mlist,
        ):
            result = list_programme_reports_tool.func("acme", page_size=10)

        assert result == [
            {
                "report_id": "1",
                "title": "Existing report",
                "severity": "high",
                "state": "triaged",
            }
        ]
        mhttp.assert_called_once_with("acme")
        mlist.assert_called_once_with("acme", page_size=10)


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
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester.http.set_programme") as mhttp,
            patch(
                "squad.penetration_tester.check_cookies",
                return_value=[raw_finding_low],
            ),
        ):
            result = cookie_check_tool.func("recon.json")

        assert result == [raw_finding_low.model_dump()]
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

        assert result == [raw_finding_low.model_dump()]

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
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester.http.set_programme"),
            patch(
                "squad.penetration_tester.check_header_injection",
                return_value=[raw_finding_low],
            ),
        ):
            result = header_injection_tool.func("recon.json")

        assert result == [raw_finding_low.model_dump()]

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

        assert result == [raw_finding_low.model_dump()]

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
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = recon_open_ports_tool.func("recon.json")
        assert result == recon_result.open_ports


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

    def test_read_run_file_tool_refuses_escape(self, tmp_path) -> None:
        from squad import read_run_file_tool

        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="must not contain '..'"):
                read_run_file_tool.func("../etc/passwd")
