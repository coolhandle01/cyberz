"""
tests/test_squad_osint_analyst.py - exercise the @tool wrappers on the OSINT
Analyst.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


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

        from tools.recon_insights import HostAnnotation

        assert isinstance(result, HostAnnotation)
        assert result.validation.ok is True
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

        from tools.recon_insights import HostAnnotation

        assert isinstance(result, HostAnnotation)
        assert result.validation.ok is False
        sections = {i.section for i in result.validation.issues}
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
        assert result[0].url == endpoint.url

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
        assert result == [candidate]

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
        from tools.cwe_data import CWEEntry

        result = lookup_cwe_tool.func("XSS")
        assert isinstance(result, list)
        assert result
        assert isinstance(result[0], CWEEntry)
        assert result[0].cwe_id == 79

    def test_lookup_owasp_tool(self) -> None:
        from squad.osint_analyst import lookup_owasp_tool
        from tools.owasp_data import OWASPEntry

        result = lookup_owasp_tool.func("sql injection")
        assert isinstance(result, list)
        assert all(isinstance(r, OWASPEntry) for r in result)
        assert any("SQL_Injection_Prevention" in r.url for r in result)

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
        from models import LlmEndpoint
        from squad.osint_analyst import llm_detection_tool

        endpoints_json = json.dumps([endpoint.model_dump(mode="json")])
        with patch(
            "squad.osint_analyst.detect_llm_endpoints",
            return_value=[endpoint],
        ) as m:
            result = llm_detection_tool.func(endpoints_json)

        assert result == [LlmEndpoint.model_validate(endpoint.model_dump())]
        assert len(m.call_args[0][0]) == 1
