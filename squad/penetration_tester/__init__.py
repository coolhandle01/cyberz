"""Penetration Tester - runs targeted vulnerability checks against the recon surface."""

from __future__ import annotations

import json
from pathlib import Path

from crewai.tools import tool

from models import Endpoint, ReconResult
from squad import SquadMember
from tools.cloud import (
    check_admin_panels,
    check_azure_storage,
    check_consul_vault,
    check_cpanel,
    check_directadmin,
    check_grafana,
    check_kibana,
    check_plesk,
    check_portainer,
    check_s3_buckets,
    check_sensitive_files,
    check_unauthenticated_databases,
    check_webmin,
)
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


@tool("Unauthenticated Databases Check")
def unauthenticated_databases_tool(recon_result_json: str) -> list[dict]:
    """
    Check for unauthenticated Elasticsearch (9200), CouchDB (5984), Redis (6379),
    and MongoDB (27017) instances. Only probes hosts where those ports appear in
    open_ports from the nmap recon.
    Use when open_ports shows any of 9200, 5984, 6379, or 27017.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_unauthenticated_databases(recon)]


@tool("Sensitive Files Check")
def sensitive_files_tool(endpoints_json: str) -> list[dict]:
    """
    Probe for exposed .git/HEAD, .env, phpinfo.php, Apache server-status, and
    .DS_Store files. Run broadly - these are high-value finds on any target.

    endpoints_json: JSON array of endpoint objects. Pass a representative set of
      live endpoints; the tool deduplicates by origin so you can pass many without
      redundant probes.
      Example: '[{"url": "https://example.com/", "status_code": 200}]'

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_sensitive_files(_parse_endpoints(endpoints_json))]


@tool("Admin Panels Check")
def admin_panels_tool(endpoints_json: str) -> list[dict]:
    """
    Probe common admin panel paths: /admin, /wp-admin, /phpmyadmin, /adminer,
    /manager/html, /_admin. Run broadly on all live endpoints.

    endpoints_json: JSON array of endpoint objects. The tool deduplicates by origin.
      Example: '[{"url": "https://example.com/", "status_code": 200}]'

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_admin_panels(_parse_endpoints(endpoints_json))]


@tool("cPanel/WHM Check")
def cpanel_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed cPanel hosting control panel (ports 2082/2083) and
    WHM (WebHost Manager) panel (ports 2086/2087) on all discovered hostnames.
    Use when open_ports shows 2082, 2083, 2086, or 2087, or when the target
    appears to be a shared/managed hosting environment.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_cpanel(recon)]


@tool("Plesk Check")
def plesk_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed Plesk web hosting control panel on ports 8880 (HTTP)
    and 8443 (HTTPS). Use when open_ports shows 8880 or 8443, or when the
    target is a managed hosting or VPS provider.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_plesk(recon)]


@tool("DirectAdmin Check")
def directadmin_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed DirectAdmin hosting control panel on port 2222.
    Use when open_ports shows 2222 on a target that appears to be shared hosting.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_directadmin(recon)]


@tool("Webmin Check")
def webmin_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed Webmin Linux server administration panel on port 10000.
    Use when open_ports shows 10000, or when the target is a self-hosted Linux server.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_webmin(recon)]


@tool("Grafana Check")
def grafana_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed Grafana metrics dashboard on port 3000 and via /grafana
    reverse-proxy path on existing endpoints.
    Use when open_ports shows 3000, or when technologies mention Grafana, or when
    the target is a DevOps/SRE-heavy organisation.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_grafana(recon)]


@tool("Kibana Check")
def kibana_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed Kibana log/data visualisation dashboard on port 5601 and
    via /kibana reverse-proxy path on existing endpoints.
    Use when open_ports shows 5601 or 9200 (Elasticsearch stack), or when
    technologies mention Kibana or Elasticsearch.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_kibana(recon)]


@tool("Portainer Check")
def portainer_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed Portainer Docker management UI on port 9000 and via
    /portainer reverse-proxy path on existing endpoints.
    Use when open_ports shows 9000, or when technologies mention Docker or
    containerised infrastructure.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_portainer(recon)]


@tool("Consul/Vault Check")
def consul_vault_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed HashiCorp Consul UI (port 8500) or Vault UI (port 8200),
    and via /consul/ui and /vault/ui reverse-proxy paths on existing endpoints.
    Use when open_ports shows 8500 or 8200, or when the target is a cloud-native
    or microservices environment.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    return [f.model_dump() for f in check_consul_vault(recon)]


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
        unauthenticated_databases_tool,
        sensitive_files_tool,
        admin_panels_tool,
        cpanel_tool,
        plesk_tool,
        directadmin_tool,
        webmin_tool,
        grafana_tool,
        kibana_tool,
        portainer_tool,
        consul_vault_tool,
    ],
)
