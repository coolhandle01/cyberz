"""Penetration Tester - runs targeted vulnerability checks against the recon surface."""

from __future__ import annotations

import json
from pathlib import Path

from crewai.tools import tool

from models import Endpoint, ReconResult
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


def _parse_endpoints(endpoints_json: str) -> list[Endpoint]:
    """Deserialise a JSON array of endpoint dicts into Endpoint objects."""
    return [Endpoint.model_validate(e) for e in json.loads(endpoints_json)]


@tool("Nuclei Scan")
def nuclei_scan_tool(endpoints_json: str, tech_tags_json: str = "[]") -> list[dict]:
    """
    Run nuclei against a specific set of endpoints, optionally filtered by template tags.

    endpoints_json: JSON array of endpoint objects to scan. Extract from ReconResult:
      select live endpoints (status_code < 500), serialise with model_dump().
      Example: '[{"url": "https://example.com/", "status_code": 200,
        "technologies": ["WordPress"]}]'

    tech_tags_json: JSON array of nuclei template tags to focus on. Map from detected
      technologies: WordPress -> ["wordpress"], Apache -> ["apache"], Spring -> ["spring"].
      Common tags: wordpress, drupal, joomla, apache, nginx, iis, spring, laravel,
      django, rails, php, cve, exposure, misconfig. Pass "[]" to run all templates.
      Example: '["wordpress", "cve"]'

    Prefer narrow tag lists when you have technology intel - running all templates
    against every endpoint is slow and noisy.
    Returns raw findings as dicts.
    """
    endpoints = _parse_endpoints(endpoints_json)
    tech_tags: list[str] = json.loads(tech_tags_json)
    return [f.model_dump() for f in run_nuclei(endpoints, tech_tags=tech_tags or None)]


@tool("SQLMap Injection Scan")
def sqlmap_tool(endpoints_json: str) -> list[dict]:
    """
    Run sqlmap against specific parameterised endpoints.

    endpoints_json: JSON array of endpoint objects that have parameters you want
      to test for SQL injection. Only pass endpoints where parameters is non-empty
      and where there is reason to suspect injection (e.g. error disclosure findings
      showing SQL errors, numeric/string parameters in URLs or forms).
      Example: '[{"url": "https://example.com/search", "parameters": ["q", "page"]}]'

    Do not pass all endpoints blindly - sqlmap is slow and loud. Pass only the
    endpoints where injection is plausible based on the recon context.
    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in run_sqlmap(_parse_endpoints(endpoints_json))]


@tool("CORS Misconfiguration Check")
def cors_check_tool(recon_result_json: str) -> list[dict]:
    """
    Check all live endpoints for CORS misconfigurations: origin reflection,
    null origin acceptance, and overly permissive Access-Control-Allow-Origin headers.
    Relevant wherever the target exposes an API or serves authenticated content.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_cors_misconfiguration(recon.endpoints)]


@tool("SSRF Probe")
def ssrf_probe_tool(endpoints_json: str) -> list[dict]:
    """
    Inject cloud metadata (169.254.169.254) and loopback (127.0.0.1) payloads
    into URL parameters to detect Server-Side Request Forgery.

    endpoints_json: JSON array of endpoint objects. Only pass endpoints that have
      parameters AND where those parameters plausibly accept URLs, hostnames,
      file paths, or resource identifiers (e.g. url=, path=, file=, redirect=, src=).
      Example: '[{"url": "https://example.com/fetch", "parameters": ["url"]}]'

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_ssrf(_parse_endpoints(endpoints_json))]


@tool("Header Injection Check")
def header_injection_tool(recon_result_json: str) -> list[dict]:
    """
    Check for CRLF injection via X-Forwarded-For and similar headers.
    Relevant on all endpoints - run this broadly.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_header_injection(recon.endpoints)]


@tool("Host Header Attack Check")
def host_header_tool(recon_result_json: str) -> list[dict]:
    """
    Test for Host header reflection (cache poisoning, password-reset poisoning)
    and X-Original-URL / X-Rewrite-URL overrides that may bypass access controls.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_host_headers(recon.endpoints)]


@tool("JS Source Map Scan")
def source_maps_tool(recon_result_json: str) -> list[dict]:
    """
    Discover exposed .js.map source map files and scan reconstructed source for
    secrets and internal paths. Use when the recon surface includes HTML pages
    that load JavaScript bundles (React, Angular, Vue, etc.).
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_js_source_maps(recon.endpoints)]


@tool("Reflected XSS Probe")
def xss_probe_tool(endpoints_json: str) -> list[dict]:
    """
    Inject an angle-bracket canary into URL parameters and check for unescaped
    reflection in the response body.

    endpoints_json: JSON array of endpoint objects. Only pass endpoints that have
      parameters AND where the response is HTML (i.e. the target renders user input
      back into a page rather than returning JSON or a redirect).
      Example: '[{"url": "https://example.com/search", "parameters": ["q"]}]'

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_reflected_xss(_parse_endpoints(endpoints_json))]


@tool("Subresource Integrity Check")
def sri_check_tool(recon_result_json: str) -> list[dict]:
    """
    Scan HTML pages for cross-origin <script> and <link> tags missing an
    integrity= attribute. Run broadly against all HTML-serving endpoints.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_sri(recon.endpoints)]


@tool("Error and Stack Trace Disclosure Check")
def error_disclosure_tool(endpoints_json: str) -> list[dict]:
    """
    Probe endpoints with error-triggering inputs and scan responses for framework
    stack traces and SQL error messages.

    endpoints_json: JSON array of endpoint objects to probe. Prioritise endpoints
      where parameters are present (they increase the chance of triggering errors)
      and any endpoint where the error disclosure passive findings from recon suggest
      verbose errors are already present.
      Example: '[{"url": "https://example.com/api/user", "parameters": ["id"]}]'

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_error_disclosure(_parse_endpoints(endpoints_json))]


@tool("S3 Bucket Check")
def s3_check_tool(recon_result_json: str) -> list[dict]:
    """
    Check for publicly accessible or listable AWS S3 buckets derived from the
    programme handle and any S3 subdomains in the recon surface.
    Use when the target is known to use AWS, or when S3 subdomains appear in recon.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_s3_buckets(recon)]


@tool("Azure Blob Storage Check")
def azure_storage_check_tool(recon_result_json: str) -> list[dict]:
    """
    Check for publicly accessible Azure Blob Storage containers and exposed SAS
    tokens in endpoint URLs. Use when the target is known to use Azure, or when
    *.blob.core.windows.net subdomains appear in recon.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_azure_storage(recon)]


@tool("Exposed Services Check")
def exposed_services_check_tool(recon_result_json: str) -> list[dict]:
    """
    Check for unauthenticated Elasticsearch (9200), CouchDB (5984), Redis (6379),
    and MongoDB (27017) instances, exposed admin panels, and sensitive files
    (.git, .env, phpinfo). Use when open_ports in the recon surface shows any of
    those ports, or when the target appears to be a self-hosted stack.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_exposed_services(recon)]


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
        s3_check_tool,
        azure_storage_check_tool,
        exposed_services_check_tool,
    ],
)
