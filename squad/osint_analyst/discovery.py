"""
squad/osint_analyst/discovery.py - the OSINT discovery surface.

Tools the OA uses to map the in-scope attack surface: kick off the
initial sweep, slice over the in-progress sweep (subdomains /
endpoints / open ports), expand discovery via passive sources (cert
transparency, historical URL archive), spot LLM-bearing endpoints,
and follow up with active probes against newly-surfaced hostnames.
"""

from pydantic import BaseModel, Field

import runtime
from models import (
    Endpoint,
    EndpointPage,
    Hostname,
    LlmEndpoint,
    OpenPortsMap,
    TakeoverCandidate,
)
from models.h1 import Programme
from squad import cyber_tool
from tools import http
from tools.h1_api import h1
from tools.recon import (
    cert_transparency,
    detect_llm_endpoints,
    detect_takeover_candidates,
    historical_urls,
    run_recon,
)
from tools.recon import probe_endpoints as probe_endpoints_impl
from tools.recon.query import recon_endpoints, recon_open_ports, recon_subdomains
from tools.recon.scope import filter_in_scope as filter_in_scope_impl


class _RunInitialSweepArgs(BaseModel):
    """Explicit args_schema for the Run Initial Sweep tool."""

    programme_handle: str = Field(
        description=(
            "Exact HackerOne programme handle as it appears in the URL"
            " (lowercase, no slashes, no spaces). The sweep runs subfinder,"
            " httpx, nmap, ffuf, and passive TLS / DNS checks against the"
            " programme's structured scope - the handle is the authoritative"
            " key the H1 API uses to look the scope up."
        ),
    )


@cyber_tool("Run Initial Sweep", args_schema=_RunInitialSweepArgs)
def run_initial_sweep_tool(programme_handle: str) -> str:
    """
    Run the initial OSINT sweep against the in-scope assets of the given
    programme: subfinder for subdomain enumeration, httpx for live HTTP/S
    probing and tech detection, nmap for port scanning, ffuf for content
    discovery, plus passive TLS and DNS email-security checks. Writes the
    serialised inventory to ``sweep.json`` (the OA's internal draft) in the
    run directory and returns the relative filename.

    This is the inventory step. Annotate the interesting hosts with
    Annotate Host and call Finalise Recon to produce the canonical
    ``recon.json`` that downstream agents consume.
    """
    http.set_programme(programme_handle)
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    programme = h1.parse_programme(policy["data"], scope)
    result = run_recon(programme)
    out_path = runtime.run_dir() / "sweep.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.model_dump_json(), encoding="utf-8")
    return "sweep.json"


class _ReconSubdomainsArgs(BaseModel):
    """Explicit args_schema for the OSINT Recon Subdomains tool."""

    sweep_path: str = Field(
        default="sweep.json",
        description=(
            "Relative path to the OA's in-progress sweep file. Defaults to"
            " ``sweep.json`` (the canonical name written by Run Initial"
            " Sweep). Override only when re-inspecting a sweep written"
            " under a different name."
        ),
    )
    host_filter: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring match against each subdomain"
            " (e.g. 'api' returns every subdomain containing 'api',"
            " regardless of position). Omit or pass null to get the full"
            " list. Useful for scoping a per-role annotation pass."
        ),
    )


@cyber_tool("Recon Subdomains", args_schema=_ReconSubdomainsArgs)
def recon_subdomains_tool(
    sweep_path: str = "sweep.json", host_filter: str | None = None
) -> list[Hostname]:
    """
    Return the in-scope subdomains in the OA's draft sweep. ``host_filter`` is
    a case-insensitive substring (e.g. "api" returns every subdomain
    containing "api"). Use this to inspect the sweep before deciding which
    hosts to annotate. Each returned hostname is ready to pass straight
    into ``Annotate Host``, ``Probe Hostnames``, or ``Detect Takeover
    Candidates`` - no further normalisation needed.
    """
    return [Hostname(h) for h in recon_subdomains(sweep_path, host_filter=host_filter)]


class _ReconEndpointsArgs(BaseModel):
    """Explicit args_schema for the OSINT Recon Endpoints tool."""

    sweep_path: str = Field(
        default="sweep.json",
        description="Relative path to the OA's sweep file. Defaults to ``sweep.json``.",
    )
    status: int | None = Field(
        default=None,
        description=(
            "Exact HTTP status code to filter by (e.g. 200 for live, 401 /"
            " 403 for auth-shaped, 301 / 302 for redirectors). Omit or pass"
            " null for any status."
        ),
    )
    tech: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring match against each endpoint's"
            " technologies list (e.g. 'wordpress' matches 'WordPress 6.4')."
            " Use when scoping a per-stack annotation pass."
        ),
    )
    host_contains: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring match against the endpoint URL. Use"
            " to narrow to a hostname or path family."
        ),
    )
    offset: int = Field(
        default=0,
        description=(
            "Zero-based row offset for paging. Use with ``limit`` to walk large result sets."
        ),
    )
    limit: int = Field(
        default=50,
        description=(
            "Maximum number of endpoints to return in this page. The OA's"
            " context budget rewards small pages; default 50 is usually"
            " right - go larger only when the conjunctive filters above"
            " already narrowed the result heavily."
        ),
    )


@cyber_tool("Recon Endpoints", args_schema=_ReconEndpointsArgs)
def recon_endpoints_tool(
    sweep_path: str = "sweep.json",
    status: int | None = None,
    tech: str | None = None,
    host_contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> EndpointPage:
    """
    Return a paginated slice of endpoints from the sweep matching the given
    filters (conjunctive). ``tech`` matches case-insensitively as a
    substring against each endpoint's technologies; ``host_contains``
    matches the URL. Use this to find which hostnames run a given stack
    before annotating.
    """
    return recon_endpoints(
        sweep_path,
        status=status,
        tech=tech,
        host_contains=host_contains,
        offset=offset,
        limit=limit,
    )


class _ReconOpenPortsArgs(BaseModel):
    """Explicit args_schema for the OSINT Recon Open Ports tool."""

    sweep_path: str = Field(
        default="sweep.json",
        description="Relative path to the OA's sweep file. Defaults to ``sweep.json``.",
    )
    host: Hostname | None = Field(
        default=None,
        description=(
            "Exact hostname to restrict the result to (no wildcards, no"
            " substring). Validated as an RFC 1123 hostname - URLs / ports"
            " / paths reject upstream. Omit or pass null to get the full"
            " per-host port map."
        ),
    )


@cyber_tool("Recon Open Ports", args_schema=_ReconOpenPortsArgs)
def recon_open_ports_tool(
    sweep_path: str = "sweep.json", host: Hostname | None = None
) -> OpenPortsMap:
    """
    Return the open-port map per host from the sweep. Passing a ``host``
    restricts the result to that single host. Use to surface non-HTTP
    services (Redis 6379, Elasticsearch 9200, Mongo 27017, etc.) that an
    annotation should call out.
    """
    return OpenPortsMap(hosts=recon_open_ports(sweep_path, host=host))


class _CertTransparencyArgs(BaseModel):
    """Explicit args_schema for the Certificate Transparency Lookup tool."""

    domain: Hostname = Field(
        description=(
            "Apex domain to look up in crt.sh certificate transparency logs"
            " (e.g. 'example.com'). Validated as an RFC 1123 hostname"
            " (URLs / ports / paths reject upstream). Pass an apex, not a"
            " subdomain - crt.sh returns the broader set when queried on"
            " the apex."
        ),
    )


@cyber_tool("Certificate Transparency Lookup", args_schema=_CertTransparencyArgs)
def cert_transparency_tool(domain: Hostname) -> list[str]:
    """
    Query crt.sh certificate transparency logs to discover subdomains not
    found by active enumeration. Returns deduplicated hostnames. Feed
    newly discovered hosts to Probe Hostnames to determine which are live.
    """
    return cert_transparency(domain)


class _HistoricalUrlsArgs(BaseModel):
    """Explicit args_schema for the Historical URL Discovery tool."""

    domain: Hostname = Field(
        description=(
            "Domain to query waybackurls for (apex or subdomain). Validated"
            " as an RFC 1123 hostname (URLs / ports / paths reject"
            " upstream). Returns historical URLs the Wayback Machine has"
            " archived. Many paths will be 404s today; feed candidates to"
            " Probe Hostnames to confirm liveness before annotating."
        ),
    )


@cyber_tool("Historical URL Discovery", args_schema=_HistoricalUrlsArgs)
def historical_urls_tool(domain: Hostname) -> list[str]:
    """
    Use waybackurls to find historical endpoints for a domain from the
    Wayback Machine. Surfaces paths that may no longer be linked but still
    exist - candidates for Probe Hostnames.
    """
    return historical_urls(domain)


class _LlmDetectionArgs(BaseModel):
    """Explicit args_schema for the LLM Endpoint Detection tool."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Live endpoint objects from the sweep (or a filtered subset)."
            " Each entry needs ``url`` and ideally ``technologies``;"
            " ``status_code`` is honoured if present. Pass the typed list"
            " straight through from Recon Endpoints - do not stringify."
        ),
    )


@cyber_tool("LLM Endpoint Detection", args_schema=_LlmDetectionArgs)
def llm_detection_tool(endpoints: list[Endpoint]) -> list[LlmEndpoint]:
    """
    Scan a set of live endpoints for signals that they are backed by an LLM
    or AI assistant (URL path heuristics, OpenAI-format response keys,
    EventSource content-type, self-identification phrases). Pass the
    sweep's endpoint list (or a filtered subset) straight through from
    Recon Endpoints. Returned hits deserve a HIGH-priority annotation and
    a note pointing the Penetration Tester at prompt-injection probes.
    """
    # CrewAI's args_schema validation produces list[dict] from the LLM JSON
    # before invoking us; re-validate so we always see ``Endpoint`` instances
    # regardless of whether the caller is the runtime or a direct test invocation.
    parsed = [Endpoint.model_validate(e) for e in endpoints]
    return [LlmEndpoint.model_validate(ep.model_dump()) for ep in detect_llm_endpoints(parsed)]


def _normalise_and_filter_hostnames(
    hostnames: list[Hostname], programme: Programme
) -> list[Hostname]:
    """Strip / lowercase before delegating to the canonical scope filter.

    Wraps ``tools.recon.scope.filter_in_scope`` (imported as
    ``filter_in_scope_impl``) with the input-shaping the two OSINT
    probe tools used to do inline. Lives at module scope - rather than
    as a lambda passed to ``scope_filter=...`` - so the ``Probe
    Hostnames`` and ``Detect Takeover Candidates`` wrappers share the
    same normalisation step exactly once.
    """
    cleaned = [h.strip().lower() for h in hostnames if h.strip()]
    return filter_in_scope_impl(cleaned, programme)


class _ProbeHostnamesArgs(BaseModel):
    """Explicit args_schema for the Probe Hostnames tool."""

    hostnames: list[Hostname] = Field(
        description=(
            "Hostnames to re-probe with httpx for liveness, status code,"
            " and technology fingerprinting. Each entry is validated as an"
            " RFC 1123 hostname; URLs / ports / paths reject upstream"
            " (catches the common 'agent handed us a URL when we asked for"
            " a hostname' case before the scope filter silently drops it)."
            " Typically the net-new ones surfaced by Certificate"
            " Transparency or Historical URL Discovery that were missed by"
            " the initial sweep. The wrapper's scope filter drops any"
            " hostname outside the selected programme's structured scope"
            " before HTTP traffic fires."
        ),
    )


@cyber_tool(
    "Probe Hostnames",
    args_schema=_ProbeHostnamesArgs,
    scope_filter=("hostnames", _normalise_and_filter_hostnames),
)
def probe_hostnames_tool(hostnames: list[Hostname]) -> list[Endpoint]:
    """
    Re-probe a list of hostnames with httpx to confirm liveness, capture
    status codes, and fingerprint technologies. Use this on hostnames
    surfaced by Certificate Transparency or Historical URL Discovery that
    were not in the initial sweep.

    The wrapper scope-filters the hostnames against the selected
    programme's structured scope before this body runs; out-of-scope
    hostnames are dropped silently (we never probe outside scope, even
    for fingerprinting). Returns a list of Endpoint with {url,
    status_code, technologies, parameters}. Net-new endpoints can then
    be annotated with Annotate Host.
    """
    if not hostnames:
        return []
    return list(probe_endpoints_impl(hostnames))


class _DetectTakeoverCandidatesArgs(BaseModel):
    """Explicit args_schema for the Detect Takeover Candidates tool."""

    hostnames: list[Hostname] = Field(
        description=(
            "Hostnames to resolve via dnsx and flag for subdomain takeover."
            " Each entry is validated as an RFC 1123 hostname; URLs / ports"
            " / paths reject upstream. A candidate fires when the CNAME"
            " points to a known-vulnerable provider (AWS S3, Heroku,"
            " GitHub Pages, Azure, Vercel, Netlify, ...) or when the CNAME"
            " chain dangles. The wrapper's scope filter drops any hostname"
            " outside the selected programme's structured scope before any"
            " DNS traffic fires."
        ),
    )


@cyber_tool(
    "Detect Takeover Candidates",
    args_schema=_DetectTakeoverCandidatesArgs,
    scope_filter=("hostnames", _normalise_and_filter_hostnames),
)
def detect_takeover_candidates_tool(
    hostnames: list[Hostname],
) -> list[TakeoverCandidate]:
    """
    Resolve each hostname via dnsx and flag subdomain-takeover candidates.

    A candidate is flagged when the host's CNAME points to a known-vulnerable
    provider (AWS S3, Heroku, GitHub Pages, Azure, Vercel, Netlify, ...) or
    when the CNAME chain dangles (CNAME exists but resolves to no A records).
    Returns a list of TakeoverCandidate where ``reason`` is one of
    ``cname_to_vulnerable_provider`` or ``dangling_cname``.

    Each candidate is exactly that - a candidate. Follow up by annotating
    the host HIGH priority with a note pointing the Penetration Tester at
    the service-specific confirmation step (probe the host and check for
    the "no such bucket" / "no such app" / "there isn't a GitHub Pages
    site here" body fingerprint).

    The wrapper scope-filters the hostnames against the selected
    programme's structured scope before this body runs.
    """
    if not hostnames:
        return []
    return list(detect_takeover_candidates(hostnames))
