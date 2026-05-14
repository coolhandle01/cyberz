"""Penetration Tester - runs targeted vulnerability checks against the recon surface."""

from __future__ import annotations

import json
from pathlib import Path

from crewai.tools import tool

from models import Endpoint, ReconResult
from squad import SquadMember
from tools import http
from tools.cloud import (
    check_admin_panels,
    check_azure_storage,
    check_consul_vault,
    check_couchdb,
    check_cpanel,
    check_directadmin,
    check_elasticsearch,
    check_grafana,
    check_kibana,
    check_mongodb,
    check_mysql,
    check_plesk,
    check_portainer,
    check_postgresql,
    check_redis,
    check_s3_buckets,
    check_sensitive_files,
    check_webmin,
)
from tools.pentest.cookies import check_cookies
from tools.pentest.cors import check_cors_misconfiguration
from tools.pentest.errors import check_error_disclosure
from tools.pentest.hpp import check_hpp
from tools.pentest.ldap_injection import check_ldap_injection
from tools.pentest.nosqli import run_nosqli
from tools.pentest.nuclei import run_nuclei
from tools.pentest.open_redirect import check_open_redirect
from tools.pentest.path_traversal import check_path_traversal
from tools.pentest.prompt_injection import check_prompt_injection
from tools.pentest.sourcemaps import check_js_source_maps
from tools.pentest.sqlmap import run_sqlmap
from tools.pentest.sri import check_sri
from tools.pentest.ssrf import check_ssrf
from tools.pentest.ssti import check_ssti
from tools.pentest.webapp_headers import check_header_injection, check_host_headers
from tools.pentest.xss import check_reflected_xss


def _parse_endpoints(endpoints_json: str) -> list[Endpoint]:
    """Deserialise a JSON array of endpoint dicts into Endpoint objects."""
    return [Endpoint.model_validate(e) for e in json.loads(endpoints_json)]


def _recon_from_json(recon_result_json: str) -> ReconResult:
    """Parse a serialised ReconResult and seed the http programme context.

    Centralised here so any wrapper that has a ReconResult propagates the
    programme handle into outbound User-Agent headers without each call site
    having to remember the http.set_programme(...) call.
    """
    recon = ReconResult.model_validate_json(recon_result_json)
    http.set_programme(recon.programme.handle)
    return recon


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


@tool("Cookie Security Check")
def cookie_check_tool(recon_result_json: str) -> list[dict]:
    """
    Inspect Set-Cookie attributes across the recon surface for: missing
    Secure on HTTPS cookies, missing HttpOnly on session-shaped cookies,
    SameSite=None without Secure, Domain attribute scoped broader than the
    setting host, persistent (Max-Age/Expires) session-shaped cookies, and
    sensitive data (API keys, JWTs carrying password/secret claims, emails,
    base64-encoded JSON with sensitive keys) in cookie values.

    Run this broadly - one request per distinct host, findings deduped per
    (host, cookie name, check class). Especially useful on login, dashboard,
    and authenticated API endpoints where Set-Cookie is most likely.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_cookies(recon.endpoints)]


@tool("CORS Misconfiguration Check")
def cors_check_tool(recon_result_json: str) -> list[dict]:
    """
    Check all live endpoints for CORS misconfigurations: origin reflection,
    null origin acceptance, and overly permissive Access-Control-Allow-Origin headers.
    Relevant wherever the target exposes an API or serves authenticated content.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
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
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_header_injection(recon.endpoints)]


@tool("Host Header Attack Check")
def host_header_tool(recon_result_json: str) -> list[dict]:
    """
    Test for Host header reflection (cache poisoning, password-reset poisoning)
    and X-Original-URL / X-Rewrite-URL overrides that may bypass access controls.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_host_headers(recon.endpoints)]


@tool("JS Source Map Scan")
def source_maps_tool(recon_result_json: str) -> list[dict]:
    """
    Discover exposed .js.map source map files and scan reconstructed source for
    secrets and internal paths. Use when the recon surface includes HTML pages
    that load JavaScript bundles (React, Angular, Vue, etc.).
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_js_source_maps(recon.endpoints)]


@tool("Path Traversal Probe")
def path_traversal_tool(endpoints_json: str) -> list[dict]:
    """
    Inject directory-traversal payloads (plain, URL-encoded, double-encoded,
    backslash for Windows, null-byte truncation) into URL parameters and look
    for unique content markers from OS sentinel files (/etc/passwd,
    Windows win.ini) in the response body.

    endpoints_json: JSON array of endpoint objects. Prioritise endpoints that
      have parameters AND where any of the following apply:
      - Parameter names look filesystem-shaped (file, filename, path, page,
        template, include, require, download, doc, image, img, src, view)
      - URL path or query suggests file serving (/download, /view, /preview,
        /fetch, /report, /export)
      - The response Content-Type or filename hint shows the server is reading
        files based on the parameter
      Example: '[{"url": "https://example.com/download", "parameters": ["file"]}]'

    Read-only sentinel paths only; no writes, no destructive payloads. A
    confirmed match returns severity HIGH - traversal that yields /etc/passwd
    or win.ini almost always implies a file-read primitive worth escalating.
    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_path_traversal(_parse_endpoints(endpoints_json))]


@tool("HTTP Parameter Pollution Probe")
def hpp_probe_tool(endpoints_json: str) -> list[dict]:
    """
    Detect HTTP Parameter Pollution by sending a baseline request
    (`?param=1`) and a polluted request (`?param=1&param=2`) and comparing
    status code + body length. Any divergence proves the server treats
    duplicate values as distinguishable from a single value - the
    pre-condition for WAF bypass and access-control bypass exploits.

    endpoints_json: JSON array of endpoint objects. Prioritise endpoints
      where any of the following apply:
      - Parameter names look authorisation-shaped (role, admin, is_admin,
        permission, group, user_id) - HPP is most impactful when it can
        flip a privilege check
      - Endpoint sits behind a WAF or rate-limit (HPP is a classic WAF
        bypass primitive)
      - Endpoint is part of an auth or admin flow
      Example: '[{"url": "https://example.com/api/user", "parameters": ["role", "id"]}]'

    Severity LOW on its own - HPP is a class of behaviour that enables
    further exploitation rather than a vuln in itself. The VR should
    escalate when the divergence can be chained with another finding
    (SQLi filter bypass, access-control override, cache poisoning).
    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_hpp(_parse_endpoints(endpoints_json))]


@tool("Server-Side Template Injection Probe")
def ssti_probe_tool(endpoints_json: str) -> list[dict]:
    """
    Inject template-language expressions (Jinja2/Twig/Liquid, Mako/FreeMarker,
    ERB/EJS, Ruby interpolation) into URL parameters and look for the evaluated
    arithmetic product in the response body. Confirmation requires the product
    to appear AND the literal expression to be absent, which rules out the
    common false positive of an app that just echoes the raw input.

    endpoints_json: JSON array of endpoint objects. Prioritise endpoints where
      any of the following apply:
      - Parameter values are rendered into HTML the response returns (search,
        comment, preview, name, template parameters)
      - Technologies mention a template-heavy stack (Flask/Jinja2, Django,
        Symfony/Twig, Rails/ERB, Spring with FreeMarker, etc.)
      - Error disclosure findings mention template internals
      Example: '[{"url": "https://example.com/preview", "parameters": ["name"]}]'

    SSTI confirmed at the canary-arithmetic level is HIGH; the VR should
    escalate to CRITICAL when manual follow-up demonstrates RCE primitives
    (sandbox escape, attribute traversal, OS command execution).
    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_ssti(_parse_endpoints(endpoints_json))]


@tool("Open Redirect Probe")
def open_redirect_tool(endpoints_json: str) -> list[dict]:
    """
    Inject external URL payloads (https, protocol-relative, backslash, userinfo)
    into URL parameters and check whether the response Location, Refresh header,
    or meta-refresh tag points to the canary host.

    endpoints_json: JSON array of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names look redirect-shaped (redirect, redirect_uri, return,
        return_to, returnto, next, url, dest, destination, goto, target, link,
        forward, continue, callback, rurl, r, u)
      - Path looks like an auth flow (/login, /logout, /signin, /oauth, /sso)
      - Recon noted a 30x response on the endpoint already
      Example: '[{"url": "https://example.com/login", "parameters": ["next"]}]'

    Open redirect on its own is typically MEDIUM, but it escalates on OAuth
    redirect_uri and SSO callback endpoints (token theft) - flag those for VR.
    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_open_redirect(_parse_endpoints(endpoints_json))]


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
    recon = _recon_from_json(recon_result_json)
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
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_s3_buckets(recon)]


@tool("Azure Blob Storage Check")
def azure_storage_check_tool(recon_result_json: str) -> list[dict]:
    """
    Check for publicly accessible Azure Blob Storage containers and exposed SAS
    tokens in endpoint URLs. Use when the target is known to use Azure, or when
    *.blob.core.windows.net subdomains appear in recon.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_azure_storage(recon)]


@tool("Unauthenticated Elasticsearch Check")
def elasticsearch_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an unauthenticated Elasticsearch instance on port 9200.
    Probes /_cluster/health - a 200 response with cluster_name confirms no auth.
    Use when open_ports shows 9200, or when technologies mention Elasticsearch.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    findings = []
    for host, ports in recon.open_ports.items():
        if 9200 in ports:
            findings.extend(check_elasticsearch(host))
    return [f.model_dump() for f in findings]


@tool("Unauthenticated CouchDB Check")
def couchdb_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an unauthenticated CouchDB instance on port 5984.
    Probes /_all_dbs - a 200 response listing databases confirms no auth.
    Use when open_ports shows 5984.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    findings = []
    for host, ports in recon.open_ports.items():
        if 5984 in ports:
            findings.extend(check_couchdb(host))
    return [f.model_dump() for f in findings]


@tool("Unauthenticated Redis Check")
def redis_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an unauthenticated Redis instance on port 6379 via a PING command.
    A +PONG response without sending AUTH confirms no password is set.
    Use when open_ports shows 6379.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    findings = []
    for host, ports in recon.open_ports.items():
        if 6379 in ports:
            findings.extend(check_redis(host))
    return [f.model_dump() for f in findings]


@tool("Unauthenticated MongoDB Check")
def mongodb_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an unauthenticated MongoDB instance on port 27017.
    Sends a minimal isMaster wire-protocol query - a valid response without
    error confirms the instance accepts connections without credentials.
    Use when open_ports shows 27017.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    findings = []
    for host, ports in recon.open_ports.items():
        if 27017 in ports:
            findings.extend(check_mongodb(host))
    return [f.model_dump() for f in findings]


@tool("Exposed PostgreSQL Check")
def postgresql_tool(recon_result_json: str) -> list[dict]:
    """
    Check for PostgreSQL on port 5432. Returns CRITICAL if trust authentication
    allows connection without a password; MEDIUM if the port is exposed but
    credentials are required (unnecessary internet exposure).
    Use when open_ports shows 5432.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    findings = []
    for host, ports in recon.open_ports.items():
        if 5432 in ports:
            findings.extend(check_postgresql(host))
    return [f.model_dump() for f in findings]


@tool("Exposed MySQL/MariaDB Check")
def mysql_tool(recon_result_json: str) -> list[dict]:
    """
    Check for MySQL or MariaDB on port 3306. Returns MEDIUM if the port is
    reachable and the server responds with a valid handshake (unnecessary
    internet exposure; verify anonymous login is disabled).
    Use when open_ports shows 3306.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    findings = []
    for host, ports in recon.open_ports.items():
        if 3306 in ports:
            findings.extend(check_mysql(host))
    return [f.model_dump() for f in findings]


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
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_cpanel(recon)]


@tool("Plesk Check")
def plesk_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed Plesk web hosting control panel on ports 8880 (HTTP)
    and 8443 (HTTPS). Use when open_ports shows 8880 or 8443, or when the
    target is a managed hosting or VPS provider.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_plesk(recon)]


@tool("DirectAdmin Check")
def directadmin_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed DirectAdmin hosting control panel on port 2222.
    Use when open_ports shows 2222 on a target that appears to be shared hosting.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_directadmin(recon)]


@tool("Webmin Check")
def webmin_tool(recon_result_json: str) -> list[dict]:
    """
    Check for an exposed Webmin Linux server administration panel on port 10000.
    Use when open_ports shows 10000, or when the target is a self-hosted Linux server.
    Pass the full serialised ReconResult. Returns raw findings as dicts.
    """
    recon = _recon_from_json(recon_result_json)
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
    recon = _recon_from_json(recon_result_json)
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
    recon = _recon_from_json(recon_result_json)
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
    recon = _recon_from_json(recon_result_json)
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
    recon = _recon_from_json(recon_result_json)
    return [f.model_dump() for f in check_consul_vault(recon)]


@tool("Prompt Injection Probe")
def prompt_injection_tool(endpoints_json: str) -> list[dict]:
    """
    Probe LLM-backed endpoints for prompt injection by injecting a canary string
    in multiple request formats (OpenAI chat, generic message, prompt completion).

    endpoints_json: JSON array of endpoint objects. Use this tool when:
      - The OSINT Analyst's LLM Endpoint Detection tool returned results
      - Endpoint technologies include 'LLM'
      - URL paths suggest an AI assistant (/chat, /ask, /ai, /assistant, /copilot)
      - The target is known to use an AI product or chatbot feature

    Severity:
      - Canary reflected in response (direct injection): CRITICAL
      - Response contains system prompt shaped text (leakage): HIGH

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_prompt_injection(_parse_endpoints(endpoints_json))]


@tool("NoSQL Injection Scan")
def nosqli_tool(endpoints_json: str) -> list[dict]:
    """
    Run nosqli against parameterised endpoints to detect NoSQL injection vulnerabilities.

    endpoints_json: JSON array of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Technologies mention MongoDB, DocumentDB, Mongoose, or similar document stores
      - Parameters include id, user, username, filter, query, or similar lookup keys
      - Error disclosure findings mention BSON, ObjectId, or a MongoDB driver
      - Auth routes (login, signup, profile) with parameter-bearing URLs
      Example: '[{"url": "https://example.com/api/login", "parameters": ["username", "password"]}]'

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in run_nosqli(_parse_endpoints(endpoints_json))]


@tool("LDAP Injection Probe")
def ldap_injection_tool(endpoints_json: str) -> list[dict]:
    """
    Inject LDAP bypass and enumeration payloads into URL parameters to detect
    LDAP injection vulnerabilities against Active Directory or OpenLDAP backends.

    endpoints_json: JSON array of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names suggest authentication or directory lookup (username, user,
        login, email, uid, cn, search, filter, q)
      - URL path suggests auth or directory (/login, /auth, /search, /directory,
        /ldap, /user)
      - Technologies mention LDAP, Active Directory, OpenLDAP, or JNDI
      Example: '[{"url": "https://example.com/login", "parameters": ["username"]}]'

    Detection tiers:
      HIGH   - status code change vs baseline suggests auth bypass
      MEDIUM - LDAP/AD error strings in response body (confirms LDAP backend)
      MEDIUM - server error (500) only on LDAP payload, not on baseline

    Returns raw findings as dicts.
    """
    return [f.model_dump() for f in check_ldap_injection(_parse_endpoints(endpoints_json))]


MEMBER = SquadMember(
    slug="penetration_tester",
    dir=Path(__file__).parent,
    tools=[
        nuclei_scan_tool,
        sqlmap_tool,
        cookie_check_tool,
        cors_check_tool,
        ssrf_probe_tool,
        header_injection_tool,
        host_header_tool,
        source_maps_tool,
        ssti_probe_tool,
        hpp_probe_tool,
        open_redirect_tool,
        path_traversal_tool,
        xss_probe_tool,
        sri_check_tool,
        error_disclosure_tool,
        s3_check_tool,
        azure_storage_check_tool,
        elasticsearch_tool,
        couchdb_tool,
        redis_tool,
        mongodb_tool,
        postgresql_tool,
        mysql_tool,
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
        nosqli_tool,
        prompt_injection_tool,
        ldap_injection_tool,
    ],
)
