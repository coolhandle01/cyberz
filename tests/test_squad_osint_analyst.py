"""
tests/test_squad_osint_analyst.py - exercise the @tool wrappers on the OSINT
Analyst.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


class TestOsintAnalystTools:
    def test_run_initial_sweep_tool(self, programme_in_workspace, recon_result, tmp_path) -> None:
        from squad.osint_analyst import run_initial_sweep_tool

        with patch("squad.osint_analyst.discovery.run_recon", return_value=recon_result) as mrun:
            result = run_initial_sweep_tool.func()

        assert result == "attack_graph.json"
        assert (tmp_path / "attack_graph.json").exists()
        mrun.assert_called_once_with(programme_in_workspace)

    def test_annotate_host_tool_writes_insight_and_returns_validation(
        self, programme_in_workspace, recon_result, tmp_path
    ) -> None:
        from squad.osint_analyst import annotate_host_tool

        (tmp_path / "attack_graph.json").write_text(
            recon_result.model_dump_json(), encoding="utf-8"
        )

        result = annotate_host_tool.func(
            hostname="api.example.com",
            role="api",
            priority="high",
            notes=(
                "Public REST gateway running Nginx in front of a React SPA; "
                "primary attack surface for the programme."
            ),
            detected_tech=["Nginx", "React"],
        )

        from models import HostAnnotation

        assert isinstance(result, HostAnnotation)
        assert result.validation.ok is True
        assert (tmp_path / "host_insights" / "api.example.com.json").exists()

    def test_annotate_host_tool_surfaces_validation_issues(
        self, programme_in_workspace, recon_result, tmp_path, target_apex
    ) -> None:
        from squad.osint_analyst import annotate_host_tool

        (tmp_path / "attack_graph.json").write_text(
            recon_result.model_dump_json(), encoding="utf-8"
        )

        result = annotate_host_tool.func(
            hostname=f"api.{target_apex}",
            role="api",
            priority="high",
            notes="too short",  # < 30 chars, also < 60 high-priority floor
            detected_tech=["Nginx"],
        )

        from models import HostAnnotation

        assert isinstance(result, HostAnnotation)
        assert result.validation.ok is False
        sections = {i.section for i in result.validation.issues}
        assert "notes" in sections

    def test_uncovered_hosts_tool_returns_missing(self, programme, recon_result, run_dir) -> None:
        from squad.osint_analyst import uncovered_hosts_tool

        (run_dir / "attack_graph.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        result = uncovered_hosts_tool.func()

        assert isinstance(result, list)
        # recon_result fixture has https://api.example.com with status 200 -> interesting
        assert "api.example.com" in result

    def test_finalise_recon_tool_writes_recon_json(
        self, programme_in_workspace, recon_result, run_dir, target_apex
    ) -> None:
        from squad.osint_analyst import annotate_host_tool, finalise_recon_tool

        (run_dir / "attack_graph.json").write_text(recon_result.model_dump_json(), encoding="utf-8")

        annotate_host_tool.func(
            hostname=f"api.{target_apex}",
            role="api",
            priority="high",
            notes=(
                "Public REST gateway running Nginx in front of a React SPA; "
                "primary attack surface for the programme."
            ),
            detected_tech=["Nginx", "React"],
        )
        result = finalise_recon_tool.func()

        assert result == "recon.json"
        assert (run_dir / "recon.json").exists()

    def test_finalise_recon_tool_raises_without_insights(
        self, programme_in_workspace, recon_result, run_dir
    ) -> None:
        from squad.osint_analyst import finalise_recon_tool

        (run_dir / "attack_graph.json").write_text(recon_result.model_dump_json(), encoding="utf-8")

        with pytest.raises(ValueError, match="no host_insights"):
            finalise_recon_tool.func()

    def test_probe_hostnames_tool(self, programme_in_workspace, endpoint) -> None:
        """Happy path: in-scope hostname passes the wrapper's scope filter,
        the body fires, the endpoint is returned.

        Exercises the real ``filter_in_scope`` against the fixture
        programme (in-scope: ``example.com`` + ``*.example.com``) -
        ``api.example.com`` matches the wildcard, so the wrapper hands
        the body the cleaned hostname.
        """
        from squad.osint_analyst import probe_hostnames_tool

        with patch(
            "squad.osint_analyst.discovery.probe_endpoints_impl",
            return_value=[endpoint],
        ):
            result = probe_hostnames_tool.func(["api.example.com"])

        assert isinstance(result, list)
        assert result[0].url == endpoint.url

    def test_probe_hostnames_tool_empty_list(self) -> None:
        """Empty input short-circuits in the body without touching the
        workspace - no ``current_programme()`` lookup, no run dir read."""
        from squad.osint_analyst import probe_hostnames_tool

        assert probe_hostnames_tool.func([]) == []

    def test_probe_hostnames_tool_drops_out_of_scope(
        self, programme_in_workspace, bystander_url, invoke_tool
    ) -> None:
        """Out-of-scope hostnames are dropped at args_schema validation
        before the body fires.

        Asserts on the real scope-guard path: the fixture programme's
        structured scope (``example.com`` + ``*.example.com``) does not
        cover ``bystander.example.org``, so the ``TargetFQDNs``
        validator empties the list and ``probe_endpoints_impl`` is
        never called.
        """
        from urllib.parse import urlparse

        from squad.osint_analyst import probe_hostnames_tool

        oos_host = urlparse(bystander_url).hostname
        mprobe = MagicMock()
        with patch("squad.osint_analyst.discovery.probe_endpoints_impl", mprobe):
            result = invoke_tool(probe_hostnames_tool, hostnames=[oos_host])

        assert result == []
        mprobe.assert_not_called()

    def test_detect_takeover_candidates_tool(self, programme_in_workspace) -> None:
        from squad.osint_analyst import detect_takeover_candidates_tool
        from tools.recon.dnsx import TakeoverCandidate

        candidate = TakeoverCandidate(
            hostname="legacy.example.com",
            cname="bucket.s3.amazonaws.com",
            reason="cname_to_vulnerable_provider",
            service="AWS S3",
        )
        with patch(
            "squad.osint_analyst.discovery.detect_takeover_candidates",
            return_value=[candidate],
        ):
            result = detect_takeover_candidates_tool.func(["legacy.example.com"])

        assert isinstance(result, list)
        assert result == [candidate]

    def test_detect_takeover_candidates_tool_empty(self) -> None:
        from squad.osint_analyst import detect_takeover_candidates_tool

        assert detect_takeover_candidates_tool.func([]) == []

    def test_detect_takeover_candidates_tool_drops_out_of_scope(
        self, programme_in_workspace, bystander_url, invoke_tool
    ) -> None:
        """Same scope-guard contract as ``test_probe_hostnames_tool_drops_out_of_scope``,
        on the DNS side: the ``TargetFQDNs`` validator drops the
        out-of-scope hostname at args_schema time, before any DNS
        traffic fires."""
        from urllib.parse import urlparse

        from squad.osint_analyst import detect_takeover_candidates_tool

        oos_host = urlparse(bystander_url).hostname
        mdetect = MagicMock()
        with patch("squad.osint_analyst.discovery.detect_takeover_candidates", mdetect):
            result = invoke_tool(detect_takeover_candidates_tool, hostnames=[oos_host])

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
            "squad.osint_analyst.discovery.cert_transparency",
            return_value=sentinel,
        ) as m:
            result = cert_transparency_tool.func("example.com")

        assert result == sentinel
        m.assert_called_once_with("example.com")

    def test_historical_urls_tool(self, target_apex) -> None:
        from squad.osint_analyst import historical_urls_tool

        sentinel = [f"https://{target_apex}/old"]
        with patch(
            "squad.osint_analyst.discovery.historical_urls",
            return_value=sentinel,
        ) as m:
            result = historical_urls_tool.func("example.com")

        assert result == sentinel
        m.assert_called_once_with("example.com")

    def test_llm_detection_tool(self, programme_in_workspace, endpoint) -> None:
        from models import LlmEndpoint
        from squad.osint_analyst import llm_detection_tool

        # CrewAI's args_schema validation hands us list[dict] at runtime;
        # the both-shape adapter inside the wrapper accepts either Endpoint
        # instances or dicts, so this exercises the dict path.
        endpoints_payload = [endpoint.model_dump(mode="json")]
        with patch(
            "squad.osint_analyst.discovery.detect_llm_endpoints",
            return_value=[endpoint],
        ) as m:
            result = llm_detection_tool.func(endpoints_payload)

        assert result == [LlmEndpoint.model_validate(endpoint.model_dump())]
        assert len(m.call_args[0][0]) == 1
