"""Penetration Tester - scans discovered attack surface for vulnerabilities."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from models import ReconResult
from squad import SquadMember
from tools.vuln_tools import check_header_injection, check_ssrf, run_pentest


@tool("Run Penetration Test")
def pentest_tool(recon_result_json: str) -> list[dict]:
    """
    Run nuclei, sqlmap, and custom checks against a serialised ReconResult.
    Returns a list of raw findings as dicts.
    """
    from models import ReconResult

    recon = ReconResult.model_validate_json(recon_result_json)
    findings = run_pentest(recon)
    return [f.model_dump() for f in findings]


@tool("SSRF Probe")
def ssrf_probe_tool(recon_result_json: str) -> list[dict]:
    """
    Probe parameterised endpoints for Server-Side Request Forgery by injecting
    internal address payloads and inspecting responses for cloud metadata markers.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_ssrf(recon.endpoints)]


@tool("Header Injection Check")
def header_injection_tool(recon_result_json: str) -> list[dict]:
    """
    Check for CRLF and header injection vulnerabilities by sending CR LF sequences
    in common request headers and detecting reflected canary values.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_header_injection(recon.endpoints)]


MEMBER = SquadMember(
    slug="penetration_tester",
    dir=Path(__file__).parent,
    tools=[pentest_tool, ssrf_probe_tool, header_injection_tool],
)
