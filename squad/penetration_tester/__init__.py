"""Penetration Tester - runs targeted vulnerability checks against the recon surface."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from models import ReconResult
from squad import SquadMember
from tools.cloud import check_azure_storage, check_exposed_services, check_s3_buckets
from tools.pentest.cors import check_cors_misconfiguration
from tools.pentest.errors import check_error_disclosure
from tools.pentest.nuclei import run_nuclei
from tools.pentest.sourcemaps import check_js_source_maps
from tools.pentest.sqlmap import run_sqlmap
from tools.pentest.sri import check_sri
from tools.pentest.ssrf import check_ssrf
from tools.pentest.webapp_headers import check_header_injection, check_host_headers
from tools.pentest.xss import check_reflected_xss


@tool("Nuclei Scan")
def nuclei_scan_tool(recon_result_json: str) -> list[dict]:
    """
    Run nuclei against all live endpoints using severity-filtered templates.
    Best used when the recon surface includes known technologies (e.g. WordPress,
    Apache, Spring) - nuclei's template library has specific checks for these.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in run_nuclei(recon.endpoints)]


@tool("SQLMap Injection Scan")
def sqlmap_tool(recon_result_json: str) -> list[dict]:
    """
    Run sqlmap against endpoints that have URL parameters.
    Use when the recon surface includes parameterised endpoints or when error
    disclosure findings suggest SQL errors in the backend.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in run_sqlmap(recon.endpoints)]


@tool("CORS Misconfiguration Check")
def cors_check_tool(recon_result_json: str) -> list[dict]:
    """
    Check all live endpoints for CORS misconfigurations: origin reflection,
    null origin acceptance, and overly permissive Access-Control-Allow-Origin headers.
    Relevant wherever the target exposes an API or serves authenticated content.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_cors_misconfiguration(recon.endpoints)]


@tool("SSRF Probe")
def ssrf_probe_tool(recon_result_json: str) -> list[dict]:
    """
    Inject cloud metadata (169.254.169.254) and loopback (127.0.0.1) payloads
    into URL parameters to detect Server-Side Request Forgery.
    Use when the recon surface has parameterised endpoints that accept URLs,
    IDs, or file paths as input. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_ssrf(recon.endpoints)]


@tool("Header Injection Check")
def header_injection_tool(recon_result_json: str) -> list[dict]:
    """
    Check for CRLF injection via X-Forwarded-For and similar headers.
    Relevant on all endpoints - a single injectable header can affect
    logging, caching, and session handling globally.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_header_injection(recon.endpoints)]


@tool("Host Header Attack Check")
def host_header_tool(recon_result_json: str) -> list[dict]:
    """
    Test for Host header reflection (cache poisoning, password-reset poisoning)
    and X-Original-URL / X-Rewrite-URL overrides that may bypass access controls.
    Use on any target that serves HTML or has a password-reset flow.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_host_headers(recon.endpoints)]


@tool("JS Source Map Scan")
def source_maps_tool(recon_result_json: str) -> list[dict]:
    """
    Discover exposed .js.map source map files and scan reconstructed source for
    secrets and internal paths. Use when the recon surface includes HTML pages
    that load JavaScript bundles (React, Angular, Vue, etc.).
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_js_source_maps(recon.endpoints)]


@tool("Reflected XSS Probe")
def xss_probe_tool(recon_result_json: str) -> list[dict]:
    """
    Inject an angle-bracket canary into URL parameters and check for unescaped
    reflection in the response body. Use when the recon surface has endpoints
    with parameters that render user-supplied values in HTML.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_reflected_xss(recon.endpoints)]


@tool("Subresource Integrity Check")
def sri_check_tool(recon_result_json: str) -> list[dict]:
    """
    Scan HTML pages for cross-origin <script> and <link> tags missing an
    integrity= attribute. Use on any target that serves HTML pages loading
    resources from CDNs or third-party hosts.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_sri(recon.endpoints)]


@tool("Error and Stack Trace Disclosure Check")
def error_disclosure_tool(recon_result_json: str) -> list[dict]:
    """
    Probe endpoints with error-triggering inputs and scan responses for framework
    stack traces (Python, PHP, Java, Node, .NET) and SQL error messages.
    Use on all targets - disclosed stack traces accelerate further exploitation.
    Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_error_disclosure(recon.endpoints)]


@tool("Cloud Misconfiguration Check")
def cloud_misconfig_tool(recon_result_json: str) -> list[dict]:
    """
    Check for publicly accessible S3 buckets, Azure Blob Storage containers,
    exposed SAS tokens, and unauthenticated Elasticsearch, CouchDB, and Redis
    instances. Also probes for admin panels and sensitive files (.git, .env).
    Use when the recon surface includes cloud subdomains or the target is
    known to use AWS, Azure, or GCP infrastructure.
    Returns raw findings as dicts.
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
        nuclei_scan_tool,
        sqlmap_tool,
        cors_check_tool,
        ssrf_probe_tool,
        header_injection_tool,
        host_header_tool,
        source_maps_tool,
        xss_probe_tool,
        sri_check_tool,
        error_disclosure_tool,
        cloud_misconfig_tool,
    ],
)
