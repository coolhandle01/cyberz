"""
squad/penetration_tester/probes.py - all 25 @pentest_tool wrappers on
the Penetration Tester.

Co-locates every probe's args_schema with its wrapper (the
cybersquad-tool skill's "schema lives inline in the same module as the
wrapper" rule). The file is over the per-module line budget pylint
enforces; the suppression below carries the rationale - this is the
canonical pentest-probe registry, one cohesive responsibility, and
splitting probes across multiple files would obscure the per-probe
contract rather than clarifying it.
"""

# pylint: disable=C0302  # registry of every @pentest_tool wrapper; one file is the contract

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester._decorator import (
    _parse_endpoints,
    _recon_from_path,
    pentest_tool,
)
from tools.pentest.cmd_injection import CmdPayload, check_cmd_injection
from tools.pentest.cookies import check_cookies
from tools.pentest.cors import check_cors_misconfiguration
from tools.pentest.csrf import check_csrf
from tools.pentest.errors import check_error_disclosure
from tools.pentest.header_xss import XSSHeader, check_header_xss
from tools.pentest.hpp import check_hpp
from tools.pentest.idor import IDORAttack, check_idor
from tools.pentest.jwt import JwtAttack, check_jwt
from tools.pentest.ldap_injection import LdapPayload, check_ldap_injection
from tools.pentest.nosqli import run_nosqli
from tools.pentest.nuclei import run_nuclei
from tools.pentest.open_redirect import OpenRedirectPayload, check_open_redirect
from tools.pentest.path_traversal import PathTraversalPayload, check_path_traversal
from tools.pentest.prompt_injection import PromptPayload, check_prompt_injection
from tools.pentest.prototype_pollution import (
    PrototypePollutionPayload,
    check_prototype_pollution,
)
from tools.pentest.sourcemaps import check_js_source_maps
from tools.pentest.sqlmap import run_sqlmap
from tools.pentest.sri import check_sri
from tools.pentest.ssrf import SsrfPayload, check_ssrf
from tools.pentest.ssti import SstiPayload, check_ssti
from tools.pentest.webapp_headers import check_header_injection, check_host_headers
from tools.pentest.xss import check_reflected_xss
from tools.pentest.xxe import XxePayload, check_xxe


class _NucleiScanArgs(BaseModel):
    """Explicit args_schema for the Nuclei Scan tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Live endpoint objects to scan (status_code < 500). Pass the typed"
            " list directly from recon; do not stringify."
        ),
    )
    tech_tags: list[str] | None = Field(
        default=None,
        description=(
            "Optional nuclei template tags to focus on, mapped from detected"
            " technologies (e.g. ['wordpress', 'cve']). Omit or pass null to"
            " run all templates. Common tags: wordpress, drupal, joomla,"
            " apache, nginx, iis, spring, laravel, django, rails, php, cve,"
            " exposure, misconfig."
        ),
    )


@pentest_tool("Nuclei Scan", check_fn=run_nuclei, args_schema=_NucleiScanArgs)
def nuclei_scan_tool(
    endpoints: list[Endpoint], tech_tags: list[str] | None = None
) -> list[RawFinding]:
    """
    Run nuclei against a specific set of endpoints, optionally filtered by template tags.

    endpoints: list of endpoint objects to scan. Extract from ReconResult:
      select live endpoints (status_code < 500), use the typed list directly.
      Example: [{"url": "https://example.com/", "status_code": 200, "technologies": ["WordPress"]}]

    tech_tags: optional list of nuclei template tags to focus on. Map from detected
      technologies: WordPress -> ["wordpress"], Apache -> ["apache"], Spring -> ["spring"].
      Common tags: wordpress, drupal, joomla, apache, nginx, iis, spring, laravel,
      django, rails, php, cve, exposure, misconfig. Omit or pass an empty list to run all templates.
      Example: ["wordpress", "cve"]

    Prefer narrow tag lists when you have technology intel - running all templates
    against every endpoint is slow and noisy.

    """
    return list(run_nuclei(_parse_endpoints(endpoints), tech_tags=tech_tags or None))


class _SqlmapArgs(BaseModel):
    """Explicit args_schema for the SQLMap Injection Scan tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects to test for SQL injection. Pass"
            " only endpoints whose ``parameters`` is non-empty AND where"
            " injection is plausible (SQL errors observed, numeric/string"
            " parameters in URLs or forms). Do not pass all endpoints"
            " blindly - sqlmap is slow and loud."
        ),
    )


@pentest_tool("SQLMap Injection Scan", check_fn=run_sqlmap, args_schema=_SqlmapArgs)
def sqlmap_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Run sqlmap against specific parameterised endpoints.

    endpoints: list of endpoint objects that have parameters you want
      to test for SQL injection. Only pass endpoints where parameters is non-empty
      and where there is reason to suspect injection (e.g. error disclosure findings
      showing SQL errors, numeric/string parameters in URLs or forms).
      Example: [{"url": "https://example.com/search", "parameters": ["q", "page"]}]

    Do not pass all endpoints blindly - sqlmap is slow and loud. Pass only the
    endpoints where injection is plausible based on the recon context.

    """
    return list(run_sqlmap(_parse_endpoints(endpoints)))


class _CookieCheckArgs(BaseModel):
    """Explicit args_schema for the Cookie Security Check tool (#143)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Cookies are"
            " inspected across every host the OSINT Analyst recorded."
        ),
    )


@pentest_tool("Cookie Security Check", check_fn=check_cookies, args_schema=_CookieCheckArgs)
def cookie_check_tool(recon_path: str) -> list[RawFinding]:
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
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_cookies(recon.endpoints))


class _CorsCheckArgs(BaseModel):
    """Explicit args_schema for the CORS Misconfiguration Check tool (#143)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. CORS"
            " misconfigurations are probed against every live endpoint."
        ),
    )


@pentest_tool(
    "CORS Misconfiguration Check",
    check_fn=check_cors_misconfiguration,
    args_schema=_CorsCheckArgs,
)
def cors_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Check all live endpoints for CORS misconfigurations: origin reflection,
    null origin acceptance, and overly permissive Access-Control-Allow-Origin headers.
    Relevant wherever the target exposes an API or serves authenticated content.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_cors_misconfiguration(recon.endpoints))


class _CsrfCheckArgs(BaseModel):
    """Explicit args_schema for the CSRF Detection tool (#143)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. CSRF probes"
            " run against every HTML endpoint with a POST form."
        ),
    )


@pentest_tool("CSRF Detection", check_fn=check_csrf, args_schema=_CsrfCheckArgs)
def csrf_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Detect CSRF vulnerabilities across HTML endpoints in the recon surface.

    Tier 1 (MEDIUM): fetches each HTML endpoint and checks for page-level
    CSRF protection before inspecting forms.  When the response sets a
    CSRF-pattern cookie (Angular XSRF-TOKEN, Django csrftoken, Tornado _xsrf)
    or the HTML contains a <meta name="csrf-token"> tag (Rails, Spring), the
    missing-input finding is suppressed - those frameworks protect POSTs via JS
    without hidden form inputs.  For other pages, any POST form with no hidden
    input matching a CSRF token name pattern is flagged.

    Tier 2 (HIGH): POSTs to the form action with an evil Origin header and
    with the correct Origin.  Runs against every endpoint with a POST form,
    including those where Tier 1 was suppressed, because per-view bypasses
    (Django @csrf_exempt, Rails skip_before_action, Spring csrf().disable(),
    Laravel $except) mean a page-level cookie or meta tag cannot be trusted
    to cover every route.  When Tier 2 fires on a page-protected endpoint the
    evidence names the likely bypass pattern so the agent can report it
    accurately.

    Run broadly against all HTML-serving endpoints; especially relevant on
    login, registration, account management, and any state-changing form.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_csrf(recon.endpoints))


class _SsrfArgs(BaseModel):
    """Explicit args_schema for the SSRF Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects whose parameters plausibly accept URLs,"
            " hostnames, file paths, or resource identifiers (url=, path=,"
            " file=, redirect=, src=). Skip endpoints without parameters."
        ),
    )
    payloads: list[SsrfPayload] | None = Field(
        default=None,
        description=(
            "Optional list of internal-address variants to try; omit or pass"
            " null to try all. Pass ['aws-imds'] for an AWS-hosted target,"
            " ['localhost-ipv4'] / ['localhost-ipv6'] for internal-service"
            " reachability."
        ),
    )


@pentest_tool("SSRF Probe", check_fn=check_ssrf, args_schema=_SsrfArgs)
def ssrf_probe_tool(
    endpoints: list[Endpoint],
    payloads: list[SsrfPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject cloud metadata (169.254.169.254) and loopback (127.0.0.1) payloads
    into URL parameters to detect Server-Side Request Forgery.

    endpoints: list of endpoint objects. Only pass endpoints that have
      parameters AND where those parameters plausibly accept URLs, hostnames,
      file paths, or resource identifiers (e.g. url=, path=, file=, redirect=, src=).
      Example: [{"url": "https://example.com/fetch", "parameters": ["url"]}]

    payloads: optional list of internal-address variants to try; omit or pass
      null to try all. Useful for stealth or when the cloud provider is known
      (e.g. just "aws-imds" for an AWS-hosted target).


    """
    return list(check_ssrf(_parse_endpoints(endpoints), payloads))


class _HeaderInjectionArgs(BaseModel):
    """Explicit args_schema for the Header Injection Check tool (#143)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. CRLF probes"
            " run broadly against every endpoint."
        ),
    )


@pentest_tool(
    "Header Injection Check",
    check_fn=check_header_injection,
    args_schema=_HeaderInjectionArgs,
)
def header_injection_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for CRLF injection via X-Forwarded-For and similar headers.
    Relevant on all endpoints - run this broadly.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_header_injection(recon.endpoints))


class _HostHeaderArgs(BaseModel):
    """Explicit args_schema for the Host Header Attack Check tool (#143)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Host-header"
            " reflection and X-Original-URL / X-Rewrite-URL overrides are"
            " probed across every endpoint."
        ),
    )


@pentest_tool(
    "Host Header Attack Check",
    check_fn=check_host_headers,
    args_schema=_HostHeaderArgs,
)
def host_header_tool(recon_path: str) -> list[RawFinding]:
    """
    Test for Host header reflection (cache poisoning, password-reset poisoning)
    and X-Original-URL / X-Rewrite-URL overrides that may bypass access controls.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_host_headers(recon.endpoints))


class _HeaderXssArgs(BaseModel):
    """Explicit args_schema for the Header XSS Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Live HTML-serving endpoint objects. Error pages and admin paths"
            " are especially fruitful - they tend to echo request metadata"
            " into the response body."
        ),
    )
    header_names: list[XSSHeader] | None = Field(
        default=None,
        description=(
            "Optional list of headers to probe; omit or pass null to test all"
            " five. Narrow when recon evidence points to a specific header"
            " (e.g. ['User-Agent', 'Referer'])."
        ),
    )


@pentest_tool("Header XSS Probe", check_fn=check_header_xss, args_schema=_HeaderXssArgs)
def header_xss_tool(
    endpoints: list[Endpoint],
    header_names: list[XSSHeader] | None = None,
) -> list[RawFinding]:
    """
    Inject an angle-bracket canary into request headers and check whether the
    response body contains the canary verbatim (unencoded).

    Unencoded reflection confirms the application echoes raw header values into
    HTML output without sanitisation, which is sufficient evidence of a Header
    XSS vulnerability (H1 weakness: Improper Neutralization of HTTP Headers for
    Scripting Syntax).

    Use when:
      - The target renders content server-side (templates, SSR, admin dashboards)
      - Error pages are verbose and likely to echo request metadata
      - Recon found analytics or logging endpoints that display User-Agent strings
      - The target is an older web application (PHP, JSP, ASP) with legacy templating

    endpoints: list of endpoint objects. Pass a broad set of live
      HTML-serving endpoints; error pages and admin paths are especially fruitful.
      Example: [{"url": "https://example.com/error", "status_code": 404}]

    header_names: optional list of headers to probe; omit or pass null to test
      all five. Narrow this when recon evidence points to a specific header
      (e.g. error pages that echo the User-Agent, analytics that log Referer).
      Example: ["User-Agent", "Referer"]


    """
    return list(check_header_xss(_parse_endpoints(endpoints), header_names))


class _SourceMapsArgs(BaseModel):
    """Explicit args_schema for the JS Source Map Scan tool (#143)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Exposed"
            " .js.map files are discovered across every HTML page that"
            " loads JavaScript bundles."
        ),
    )


@pentest_tool(
    "JS Source Map Scan",
    check_fn=check_js_source_maps,
    args_schema=_SourceMapsArgs,
)
def source_maps_tool(recon_path: str) -> list[RawFinding]:
    """
    Discover exposed .js.map source map files and scan reconstructed source for
    secrets and internal paths. Use when the recon surface includes HTML pages
    that load JavaScript bundles (React, Angular, Vue, etc.).
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_js_source_maps(recon.endpoints))


class _PathTraversalArgs(BaseModel):
    """Explicit args_schema for the Path Traversal Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Prioritise filesystem-shaped"
            " parameter names (file, filename, path, page, template, include,"
            " require, download, doc, image, img, src, view) and paths that"
            " suggest file serving (/download, /view, /preview, /fetch,"
            " /report, /export)."
        ),
    )
    payloads: list[PathTraversalPayload] | None = Field(
        default=None,
        description=(
            "Optional list of traversal encoding variants to try; omit or"
            " pass null to try all. When the target OS is known, pass only"
            " the matching set (e.g. ['unix-basic', 'unix-encoded'] for"
            " Linux)."
        ),
    )


@pentest_tool(
    "Path Traversal Probe",
    check_fn=check_path_traversal,
    args_schema=_PathTraversalArgs,
)
def path_traversal_tool(
    endpoints: list[Endpoint],
    payloads: list[PathTraversalPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject directory-traversal payloads (plain, URL-encoded, double-encoded,
    backslash for Windows, null-byte truncation) into URL parameters and look
    for unique content markers from OS sentinel files (/etc/passwd,
    Windows win.ini) in the response body.

    endpoints: list of endpoint objects. Prioritise endpoints that
      have parameters AND where any of the following apply:
      - Parameter names look filesystem-shaped (file, filename, path, page,
        template, include, require, download, doc, image, img, src, view)
      - URL path or query suggests file serving (/download, /view, /preview,
        /fetch, /report, /export)
      - The response Content-Type or filename hint shows the server is reading
        files based on the parameter
      Example: [{"url": "https://example.com/download", "parameters": ["file"]}]

    payloads: optional list of traversal variants to try; omit or pass null
      to try all. When the OS is known, pass only the matching set (e.g. just
      "unix-basic" and "unix-encoded" for a Linux target).

    Read-only sentinel paths only; no writes, no destructive payloads. A
    confirmed match returns severity HIGH - traversal that yields /etc/passwd
    or win.ini almost always implies a file-read primitive worth escalating.

    """
    return list(check_path_traversal(_parse_endpoints(endpoints), payloads))


class _HppArgs(BaseModel):
    """Explicit args_schema for the HTTP Parameter Pollution Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Prioritise authorisation-shaped"
            " parameter names (role, admin, is_admin, permission, group,"
            " user_id), WAF-fronted endpoints, and auth or admin flows -"
            " HPP is highest-impact as a WAF bypass or privilege flip"
            " primitive."
        ),
    )


@pentest_tool(
    "HTTP Parameter Pollution Probe",
    check_fn=check_hpp,
    args_schema=_HppArgs,
)
def hpp_probe_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Detect HTTP Parameter Pollution by sending a baseline request
    (`?param=1`) and a polluted request (`?param=1&param=2`) and comparing
    status code + body length. Any divergence proves the server treats
    duplicate values as distinguishable from a single value - the
    pre-condition for WAF bypass and access-control bypass exploits.

    endpoints: list of endpoint objects. Prioritise endpoints
      where any of the following apply:
      - Parameter names look authorisation-shaped (role, admin, is_admin,
        permission, group, user_id) - HPP is most impactful when it can
        flip a privilege check
      - Endpoint sits behind a WAF or rate-limit (HPP is a classic WAF
        bypass primitive)
      - Endpoint is part of an auth or admin flow
      Example: [{"url": "https://example.com/api/user", "parameters": ["role", "id"]}]

    Severity LOW on its own - HPP is a class of behaviour that enables
    further exploitation rather than a vuln in itself. The VR should
    escalate when the divergence can be chained with another finding
    (SQLi filter bypass, access-control override, cache poisoning).

    """
    return list(check_hpp(_parse_endpoints(endpoints)))


class _SstiArgs(BaseModel):
    """Explicit args_schema for the Server-Side Template Injection Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints where the"
            " parameter is rendered into HTML the response returns (search,"
            " comment, preview, name, template parameters) and where the"
            " stack is template-heavy (Flask/Jinja2, Django, Symfony/Twig,"
            " Rails/ERB, Spring/FreeMarker)."
        ),
    )
    payloads: list[SstiPayload] | None = Field(
        default=None,
        description=(
            "Optional list of template-engine variants to try; omit or pass"
            " null to try all. When the engine is known from recon, pass"
            " only the matching engine (e.g. ['jinja2'] for a Flask target)."
        ),
    )


@pentest_tool(
    "Server-Side Template Injection Probe",
    check_fn=check_ssti,
    args_schema=_SstiArgs,
)
def ssti_probe_tool(
    endpoints: list[Endpoint],
    payloads: list[SstiPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject template-language expressions (Jinja2/Twig/Liquid, Mako/FreeMarker,
    ERB/EJS, Ruby interpolation) into URL parameters and look for the evaluated
    arithmetic product in the response body. Confirmation requires the product
    to appear AND the literal expression to be absent, which rules out the
    common false positive of an app that just echoes the raw input.

    endpoints: list of endpoint objects. Prioritise endpoints where
      any of the following apply:
      - Parameter values are rendered into HTML the response returns (search,
        comment, preview, name, template parameters)
      - Technologies mention a template-heavy stack (Flask/Jinja2, Django,
        Symfony/Twig, Rails/ERB, Spring with FreeMarker, etc.)
      - Error disclosure findings mention template internals
      Example: [{"url": "https://example.com/preview", "parameters": ["name"]}]

    payloads: optional list of engine variants to try; omit or pass null to
      try all. When the template engine is known from recon, pass only the
      matching engine (e.g. just "jinja2" for a Flask target).

    SSTI confirmed at the canary-arithmetic level is HIGH; the VR should
    escalate to CRITICAL when manual follow-up demonstrates RCE primitives
    (sandbox escape, attribute traversal, OS command execution).

    """
    return list(check_ssti(_parse_endpoints(endpoints), payloads))


class _OpenRedirectArgs(BaseModel):
    """Explicit args_schema for the Open Redirect Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Prioritise redirect-shaped"
            " parameter names (redirect, redirect_uri, return, return_to,"
            " returnto, next, url, dest, destination, goto, target, link,"
            " forward, continue, callback, rurl, r, u) and auth-flow paths"
            " (/login, /logout, /signin, /oauth, /sso)."
        ),
    )
    payloads: list[OpenRedirectPayload] | None = Field(
        default=None,
        description=(
            "Optional list of redirect encoding variants to try; omit or pass null to try all."
        ),
    )


@pentest_tool(
    "Open Redirect Probe",
    check_fn=check_open_redirect,
    args_schema=_OpenRedirectArgs,
)
def open_redirect_tool(
    endpoints: list[Endpoint],
    payloads: list[OpenRedirectPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject external URL payloads (https, protocol-relative, backslash, userinfo)
    into URL parameters and check whether the response Location, Refresh header,
    or meta-refresh tag points to the canary host.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names look redirect-shaped (redirect, redirect_uri, return,
        return_to, returnto, next, url, dest, destination, goto, target, link,
        forward, continue, callback, rurl, r, u)
      - Path looks like an auth flow (/login, /logout, /signin, /oauth, /sso)
      - Recon noted a 30x response on the endpoint already
      Example: [{"url": "https://example.com/login", "parameters": ["next"]}]

    payloads: optional list of encoding variants to try; omit or pass null to
      try all.

    Open redirect on its own is typically MEDIUM, but it escalates on OAuth
    redirect_uri and SSO callback endpoints (token theft) - flag those for VR.

    """
    return list(check_open_redirect(_parse_endpoints(endpoints), payloads))


class _XssArgs(BaseModel):
    """Explicit args_schema for the Reflected XSS Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Pass only endpoints whose"
            " response is HTML (the target renders user input back into a"
            " page) rather than JSON or a redirect."
        ),
    )


@pentest_tool(
    "Reflected XSS Probe",
    check_fn=check_reflected_xss,
    args_schema=_XssArgs,
)
def xss_probe_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Inject an angle-bracket canary into URL parameters and check for unescaped
    reflection in the response body.

    endpoints: list of endpoint objects. Only pass endpoints that have
      parameters AND where the response is HTML (i.e. the target renders user input
      back into a page rather than returning JSON or a redirect).
      Example: [{"url": "https://example.com/search", "parameters": ["q"]}]


    """
    return list(check_reflected_xss(_parse_endpoints(endpoints)))


class _SriCheckArgs(BaseModel):
    """Explicit args_schema for the Subresource Integrity Check tool (#143)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. SRI gaps are"
            " scanned across every HTML-serving endpoint."
        ),
    )


@pentest_tool(
    "Subresource Integrity Check",
    check_fn=check_sri,
    args_schema=_SriCheckArgs,
)
def sri_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Scan HTML pages for cross-origin <script> and <link> tags missing an
    integrity= attribute. Run broadly against all HTML-serving endpoints.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_sri(recon.endpoints))


class _ErrorDisclosureArgs(BaseModel):
    """Explicit args_schema for the Error and Stack Trace Disclosure Check tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects to probe with error-triggering inputs."
            " Prioritise parameterised endpoints (parameters increase the"
            " chance of triggering an error) and any endpoint where passive"
            " error-disclosure findings already suggest verbose errors."
        ),
    )


@pentest_tool(
    "Error and Stack Trace Disclosure Check",
    check_fn=check_error_disclosure,
    args_schema=_ErrorDisclosureArgs,
)
def error_disclosure_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Probe endpoints with error-triggering inputs and scan responses for framework
    stack traces and SQL error messages.

    endpoints: list of endpoint objects to probe. Prioritise endpoints
      where parameters are present (they increase the chance of triggering errors)
      and any endpoint where the error disclosure passive findings from recon suggest
      verbose errors are already present.
      Example: [{"url": "https://example.com/api/user", "parameters": ["id"]}]


    """
    return list(check_error_disclosure(_parse_endpoints(endpoints)))


class _PromptInjectionArgs(BaseModel):
    """Explicit args_schema for the Prompt Injection Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "LLM-backed endpoint objects. Pass endpoints where the OSINT"
            " Analyst's LLM Endpoint Detection tool returned results,"
            " technologies include 'LLM', or paths suggest an AI assistant"
            " (/chat, /ask, /ai, /assistant, /copilot)."
        ),
    )
    payloads: list[PromptPayload] | None = Field(
        default=None,
        description=(
            "Optional list of injection-technique variants to try; omit or"
            " pass null to try all. Use ['override'] for direct instruction"
            " override, ['conversation'] for transcript-style, ['token-"
            "boundary'] for models that recognise chat delimiter tokens."
        ),
    )


@pentest_tool(
    "Prompt Injection Probe",
    check_fn=check_prompt_injection,
    args_schema=_PromptInjectionArgs,
)
def prompt_injection_tool(
    endpoints: list[Endpoint],
    payloads: list[PromptPayload] | None = None,
) -> list[RawFinding]:
    """
    Probe LLM-backed endpoints for prompt injection by injecting a canary string
    in multiple request formats (OpenAI chat, generic message, prompt completion).

    endpoints: list of endpoint objects. Use this tool when:
      - The OSINT Analyst's LLM Endpoint Detection tool returned results
      - Endpoint technologies include 'LLM'
      - URL paths suggest an AI assistant (/chat, /ask, /ai, /assistant, /copilot)
      - The target is known to use an AI product or chatbot feature

    payloads: optional list of injection technique variants to try; omit or
      pass null to try all. Use "override" for direct instruction override,
      "conversation" for transcript-style injection, "token-boundary" for
      models that recognise chat delimiter tokens.

    Severity:
      - Canary reflected in response (direct injection): CRITICAL
      - Response contains system prompt shaped text (leakage): HIGH


    """
    return list(check_prompt_injection(_parse_endpoints(endpoints), payloads))


class _NosqliArgs(BaseModel):
    """Explicit args_schema for the NoSQL Injection Scan tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints where"
            " technologies mention MongoDB / DocumentDB / Mongoose, parameters"
            " include id / user / username / filter / query, error disclosure"
            " findings mention BSON / ObjectId, or the endpoint is an auth"
            " route (login, signup, profile) with parameter-bearing URLs."
        ),
    )


@pentest_tool("NoSQL Injection Scan", check_fn=run_nosqli, args_schema=_NosqliArgs)
def nosqli_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Run nosqli against parameterised endpoints to detect NoSQL injection vulnerabilities.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Technologies mention MongoDB, DocumentDB, Mongoose, or similar document stores
      - Parameters include id, user, username, filter, query, or similar lookup keys
      - Error disclosure findings mention BSON, ObjectId, or a MongoDB driver
      - Auth routes (login, signup, profile) with parameter-bearing URLs
      Example: [{"url": "https://example.com/api/login", "parameters": ["username", "password"]}]


    """
    return list(run_nosqli(_parse_endpoints(endpoints)))


class _LdapInjectionArgs(BaseModel):
    """Explicit args_schema for the LDAP Injection Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints whose"
            " parameter names suggest authentication or directory lookup"
            " (username, user, login, email, uid, cn, search, filter, q),"
            " paths suggest auth / directory (/login, /auth, /search,"
            " /directory, /ldap, /user), or technologies mention LDAP /"
            " Active Directory / OpenLDAP / JNDI."
        ),
    )
    payloads: list[LdapPayload] | None = Field(
        default=None,
        description=(
            "Optional list of LDAP injection variants to try; omit or pass"
            " null to try all. Use ['auth-bypass'] first on a /login"
            " endpoint to confirm the class with a single request, then"
            " escalate."
        ),
    )


@pentest_tool(
    "LDAP Injection Probe",
    check_fn=check_ldap_injection,
    args_schema=_LdapInjectionArgs,
)
def ldap_injection_tool(
    endpoints: list[Endpoint],
    payloads: list[LdapPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject LDAP bypass and enumeration payloads into URL parameters to detect
    LDAP injection vulnerabilities against Active Directory or OpenLDAP backends.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names suggest authentication or directory lookup (username, user,
        login, email, uid, cn, search, filter, q)
      - URL path suggests auth or directory (/login, /auth, /search, /directory,
        /ldap, /user)
      - Technologies mention LDAP, Active Directory, OpenLDAP, or JNDI
      Example: [{"url": "https://example.com/login", "parameters": ["username"]}]

    payloads: optional list of injection variants to try; omit or pass null
      to try all. Use "auth-bypass" first on a /login endpoint to confirm the
      class with a single request, then escalate.

    Detection tiers:
      HIGH   - status code change vs baseline suggests auth bypass
      MEDIUM - LDAP/AD error strings in response body (confirms LDAP backend)
      MEDIUM - server error (500) only on LDAP payload, not on baseline


    """
    return list(check_ldap_injection(_parse_endpoints(endpoints), payloads))


class _CmdInjectionArgs(BaseModel):
    """Explicit args_schema for the Command Injection Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints whose"
            " parameter names suggest shell / system interaction (cmd, exec,"
            " command, shell, run, ping, host, ip, addr, query, search,"
            " name, input), technologies mention CGI / Perl / PHP, paths"
            " suggest system utilities (/ping, /traceroute, /lookup, /exec,"
            " /run, /convert, /render, /preview, /generate), or error"
            " disclosure findings mention exec / popen / system / shell."
        ),
    )
    payloads: list[CmdPayload] | None = Field(
        default=None,
        description=(
            "Optional list of shell-separator variants to try; omit or pass"
            " null to try all. When the OS is known, pass only matching"
            " separators (e.g. ['windows-amp'] for an IIS target;"
            " ['semicolon', 'dollar-paren'] for a known Unix target)."
        ),
    )


@pentest_tool(
    "Command Injection Probe",
    check_fn=check_cmd_injection,
    args_schema=_CmdInjectionArgs,
)
def cmd_injection_tool(
    endpoints: list[Endpoint],
    payloads: list[CmdPayload] | None = None,
) -> list[RawFinding]:
    """
    Append OS command payloads to URL parameter values using common shell
    separators and look for a canary string echoed back in the response body.
    Confirmed echo is CRITICAL - it is direct proof of arbitrary command execution.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names suggest shell or system interaction (cmd, exec, command,
        shell, run, ping, host, ip, addr, query, search, name, input)
      - Technologies mention CGI, Perl, PHP, or shell-invoking frameworks
      - URL paths suggest system utilities (/ping, /traceroute, /lookup, /exec,
        /run, /convert, /render, /preview, /generate)
      - Error disclosure findings mention exec, popen, system, or shell functions
      Example: [{"url": "https://example.com/ping", "parameters": ["host"]}]

    payloads: optional list of separator variants to try; omit or pass null
      to try all. When the OS is known, pass only matching separators
      (e.g. just "windows-amp" for an IIS target; "semicolon" and
      "dollar-paren" for a known Unix target).

    Detection is in-band only. If no finding is returned on a suspicious endpoint,
    escalate to manual time-based testing (e.g. sleep 5 with response-time delta).

    """
    return list(check_cmd_injection(_parse_endpoints(endpoints), payloads))


class _XxeArgs(BaseModel):
    """Explicit args_schema for the XXE Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects. Prioritise endpoints whose technologies mention"
            " SOAP / XML-RPC / WSDL / XML / web services, paths contain"
            " /soap /xml /wsdl /rpc /service /api or end in .asmx / .wsdl /"
            " .xml, OSINT noted XML or SOAP in the response, or the endpoint"
            " accepts file uploads."
        ),
    )
    payloads: list[XxePayload] | None = Field(
        default=None,
        description=(
            "Optional list of probe variants to try; omit or pass null to"
            " try all. linux-* probes target /etc/passwd, windows-* probes"
            " target win.ini, error-* probes are MEDIUM-severity backend"
            " confirmation only. Select error-* alone for a quiet 'is there"
            " an XML parser?' reconnaissance pass."
        ),
    )


@pentest_tool("XXE Probe", check_fn=check_xxe, args_schema=_XxeArgs)
def xxe_probe_tool(
    endpoints: list[Endpoint],
    payloads: list[XxePayload] | None = None,
) -> list[RawFinding]:
    """
    POST crafted XML bodies to endpoints to detect XML External Entity (XXE)
    injection vulnerabilities.

    endpoints: list of endpoint objects. Prioritise endpoints where
      any of the following apply:
      - technologies mention SOAP, XML-RPC, WSDL, XML, or web services
      - URL path contains /soap, /xml, /wsdl, /rpc, /service, /api, or ends
        in .asmx, .wsdl, .xml
      - The OSINT Analyst noted XML or SOAP in the response body or headers
      - The endpoint accepts file uploads (multipart may include XML processing)
      Example: [{"url": "https://example.com/soap/service", "status_code": 200}]

    payloads: optional list of probe variants to try; omit or pass null to
      try all. linux-* probes target /etc/passwd, windows-* probes target
      win.ini. The error-* probes are MEDIUM-severity backend confirmation
      and only run if no file-read probe fires - select them alone for a
      quiet "is there an XML parser?" reconnaissance pass.

    Detection tiers:
      CRITICAL - file marker from /etc/passwd or Windows win.ini appears in
                 the response body (confirmed in-band file read via entity expansion)
      MEDIUM   - XML parser error strings in the response body (confirms XML
                 parsing backend; warrants manual OOB/blind XXE follow-up)

    Both generic XML and SOAP-envelope wrappers are tried automatically.

    """
    return list(check_xxe(_parse_endpoints(endpoints), payloads))


class _PrototypePollutionArgs(BaseModel):
    """Explicit args_schema for the Prototype Pollution Check tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects. Prioritise endpoints whose technologies mention"
            " Node.js / Express / Koa / Hapi / Fastify or other JS / TS"
            " server frameworks, the API accepts JSON request bodies, URL"
            " parameters are parsed server-side into plain objects (lodash"
            " merge, recursive assign), or the target is a REST / GraphQL"
            " API with a JavaScript backend."
        ),
    )
    payloads: list[PrototypePollutionPayload] | None = Field(
        default=None,
        description=(
            "Optional list of injection variants to try; omit or pass null"
            " to try all. proto-* / constructor-* target URL query-string"
            " vectors, json-* target JSON POST body vectors. Pass json-*"
            " alone for a JSON-only API or proto-* alone for a quick"
            " reconnaissance pass."
        ),
    )


@pentest_tool(
    "Prototype Pollution Check",
    check_fn=check_prototype_pollution,
    args_schema=_PrototypePollutionArgs,
)
def prototype_pollution_tool(
    endpoints: list[Endpoint],
    payloads: list[PrototypePollutionPayload] | None = None,
) -> list[RawFinding]:
    """
    Probe endpoints for prototype pollution by injecting __proto__ and
    constructor.prototype payloads via URL query strings and JSON POST bodies,
    then checking whether a canary property is reflected in the response or
    whether the server returns an unhandled error.

    endpoints: list of endpoint objects. Use this tool when:
      - Technologies mention Node.js, Express, Koa, Hapi, Fastify, or other
        JavaScript/TypeScript server frameworks
      - The API accepts JSON request bodies (Content-Type: application/json)
      - URL parameters are parsed server-side into plain objects (lodash merge,
        recursive assign, query-string to object conversions)
      - The target is a REST or GraphQL API with a JavaScript backend
      Example: [{"url": "https://api.example.com/users", "status_code": 200}]

    payloads: optional list of injection variants to try; omit or pass null
      to try all. The proto-* and constructor-* names are URL query-string
      vectors; the json-* names are JSON POST body vectors. Select just the
      json-* set for a JSON-only API, or just the proto-* set for a quick
      reconnaissance pass.

    Detection tiers:
      CRITICAL - the canary string appears in the response body after injection,
                 confirming the polluted property is accessible to application code.
      MEDIUM   - the server returns HTTP 500 only after an injection attempt,
                 suggesting the injection triggered an unhandled error during
                 prototype chain traversal (warrants manual follow-up).

    One finding per endpoint. CRITICAL takes priority over MEDIUM.

    """
    return list(check_prototype_pollution(_parse_endpoints(endpoints), payloads))


class _IdorArgs(BaseModel):
    """Explicit args_schema for the IDOR Probe tool (#143)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects. Prioritise endpoints whose URL path includes"
            " numeric segments (/api/users/42, /orders/9), parameters include"
            " id / user_id / account_id / order_id, or the endpoint handles"
            " authenticated or per-user data."
        ),
    )
    attacks: list[IDORAttack] | None = Field(
        default=None,
        description=(
            "Optional list of IDOR attack strategies to run; omit or pass"
            " null to run all three. Use ['boundary'] for a quiet recon pass"
            " (2 requests per candidate), ['sequential'] when an ID is"
            " already known and adjacent objects are suspected, or all three"
            " for maximum coverage."
        ),
    )


@pentest_tool("IDOR Probe", check_fn=check_idor, args_schema=_IdorArgs)
def idor_probe_tool(
    endpoints: list[Endpoint],
    attacks: list[IDORAttack] | None = None,
) -> list[RawFinding]:
    """
    Probe ID-shaped URL path segments and parameters for Insecure Direct
    Object Reference (IDOR) - the most-rewarded class on HackerOne (OWASP A01).

    Numeric path segments (e.g. /users/12345) and ID-shaped parameters (id,
    user_id, account_id, order_id, ...) are probed using the selected attack
    strategies (omit or pass null to run all three):

      sequential    - neighbour IDs: value-1, value+1, value-100 (numeric path
                      segments where the current value is visible in the URL).
                      For query parameters where no current value is known,
                      probes 1 and 2 instead.
      boundary      - 0 and -1; catches missing lower-bound checks.
      type-juggling - 1.0, 1e1, 01; targets backends that accept loose numeric
                      input and may bypass strict access-control comparisons.

    Detection signals:
      HIGH   - status changes from 401/403 to 200 (access-control bypass)
      HIGH   - 200 response body contains a PII pattern (email, sensitive key)
      MEDIUM - unexpected 200 for boundary ID (id=0 or id=-1)

    endpoints: list of endpoint objects. Prioritise endpoints where:
      - The URL path includes numeric segments (/api/users/42, /orders/9)
      - Parameters include id, user_id, account_id, order_id, or similar
      - The endpoint handles authenticated or per-user data
      Example: [{"url": "https://example.com/api/users/42", "status_code": 200}]

    Use attacks=["boundary"] for a quiet reconnaissance pass (2 requests per
    candidate). Use attacks=["sequential"] when you already know an ID and want
    to probe adjacent objects. Use all three (default) for maximum coverage.

    One finding per endpoint; stops after the first confirming probe. Does not
    brute-force ID ranges.
    """
    return list(check_idor(_parse_endpoints(endpoints), attacks))


class _JwtCheckArgs(BaseModel):
    """Explicit args_schema for the JWT Vulnerability Check tool (#143)."""

    token: str = Field(
        description=(
            "Raw JWT string (three base64url parts separated by dots)."
            " Source from Authorization: Bearer headers, Set-Cookie session"
            " / auth cookies, JS source or API responses with access_token /"
            " id_token fields, or any cookie value beginning with 'eyJ'"
            " (base64url-encoded JSON header)."
        ),
    )
    endpoint: str = Field(
        description=(
            "URL that validates the JWT - should return 401 / 403 without"
            " a valid token and 200 on success. Use the endpoint where the"
            " token was first observed (e.g. /api/profile, /api/me,"
            " /dashboard)."
        ),
    )
    attacks: list[JwtAttack] | None = Field(
        default=None,
        description=(
            "Optional list of attack classes to run; omit or pass null to"
            " run all seven. Useful when chaining - e.g. ['alg-none',"
            " 'claims-escalation'] to confirm missing signature verification"
            " without firing every kid variant against an endpoint where"
            " kid is not even in the header."
        ),
    )


@pentest_tool(
    "JWT Vulnerability Check",
    check_fn=check_jwt,
    args_schema=_JwtCheckArgs,
)
def jwt_check_tool(
    token: str,
    endpoint: str,
    attacks: list[JwtAttack] | None = None,
) -> list[RawFinding]:
    """
    Test a JWT token for common vulnerabilities by replaying forged tokens
    against the authenticated endpoint and detecting 4xx -> 2xx transitions.

    token: the raw JWT string (three base64url parts separated by dots).
      Source from: Authorization: Bearer headers in observed requests,
      Set-Cookie headers with session/auth cookies, JS source or API responses
      containing access_token or id_token fields, cookie values that begin with
      eyJ (base64url-encoded JSON header).

    endpoint: the URL that validates the JWT. Should return 401 or 403 without
      a valid token and 200 on success. Use the endpoint where the token was
      first observed in use (e.g. /api/profile, /api/me, /dashboard).

    attacks: optional list of attack classes to run; omit or pass null to run
      all seven. Useful when chaining - e.g. ["alg-none", "claims-escalation"]
      to confirm a missing-signature-verification class without firing every
      kid variant against an endpoint where kid is not even in the header.

    Attacks attempted (when not filtered): alg:none (4 variants), RS256->HS256
    confusion via JWKS, weak HMAC secret brute-force, kid path traversal,
    kid SQL injection, kid NoSQL injection (MongoDB operators), and claims
    tampering without re-signing.

    Run on every JWT discovered during recon, especially on admin and account
    endpoints. All confirmed bypasses are CRITICAL.

    """
    return list(check_jwt(token, endpoint, attacks))
