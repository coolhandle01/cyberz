"""Penetration Tester - scans discovered attack surface for vulnerabilities."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from models import ReconResult
from squad import SquadMember
from tools.cloud import check_azure_storage, check_exposed_services, check_s3_buckets
from tools.pentest import (
    check_header_injection,
    check_host_headers,
    check_js_source_maps,
    check_ssrf,
    run_pentest,
)


@tool("Run Penetration Test")
def pentest_tool(recon_result_json: str) -> list[dict]:
    """
    Run nuclei, sqlmap, and all custom checks against a serialised ReconResult.
    Returns a list of raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    findings = run_pentest(recon)
    return [f.model_dump() for f in findings]


@tool("SSRF Probe")
def ssrf_probe_tool(recon_result_json: str) -> list[dict]:
    """
    Probe parameterised endpoints for SSRF by injecting internal address payloads
    and flagging responses that contain cloud metadata markers.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_ssrf(recon.endpoints)]


@tool("Header Injection Check")
def header_injection_tool(recon_result_json: str) -> list[dict]:
    """
    Check for CRLF injection in X-Forwarded-For and similar headers by detecting
    reflected canary values in the response.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_header_injection(recon.endpoints)]


@tool("Host Header Attacks")
def host_header_tool(recon_result_json: str) -> list[dict]:
    """
    Test for Host header reflection (X-Forwarded-Host, X-Host) indicating cache
    poisoning or password-reset poisoning risk, and X-Original-URL/X-Rewrite-URL
    path overrides that may bypass access controls on admin paths.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_host_headers(recon.endpoints)]


@tool("JS Source Map Scan")
def source_maps_tool(recon_result_json: str) -> list[dict]:
    """
    Discover .js.map source map files linked from live HTML pages, parse them, and
    scan reconstructed source code for leaked API keys, tokens, passwords, and
    internal file paths.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_js_source_maps(recon.endpoints)]


@tool("Cloud Misconfiguration Check")
def cloud_misconfig_tool(recon_result_json: str) -> list[dict]:
    """
    Check for publicly accessible S3 buckets, Azure Blob Storage containers,
    SAS tokens in URLs, unauthenticated Elasticsearch/CouchDB/Redis instances,
    exposed admin panels, and sensitive files (.git, .env, phpinfo).
    Runs against all hosts and endpoints in the recon surface.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    findings = []
    findings.extend(check_s3_buckets(recon))
    findings.extend(check_azure_storage(recon))
    findings.extend(check_exposed_services(recon))
    return [f.model_dump() for f in findings]


MEMBER = SquadMember(
    slug="penetration_tester",
    dir=Path(__file__).parent,
    tools=[
        pentest_tool,
        ssrf_probe_tool,
        header_injection_tool,
        host_header_tool,
        source_maps_tool,
        cloud_misconfig_tool,
    ],
)
