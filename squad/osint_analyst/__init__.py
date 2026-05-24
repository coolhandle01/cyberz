"""OSINT Analyst - maps the in-scope attack surface."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

import runtime
from models import (
    Endpoint,
    EndpointPage,
    HostInsight,
    HostPriority,
    HostRole,
    LlmEndpoint,
    OpenPortsMap,
)
from models.h1 import Programme
from squad import SquadMember, cyber_tool, read_run_file_tool, read_run_filelist_tool
from tools import http
from tools.cwe_data import CWEEntry
from tools.cwe_data import lookup as cwe_lookup
from tools.h1_api import h1
from tools.owasp_data import OWASPEntry
from tools.owasp_data import lookup as owasp_lookup
from tools.recon import (
    cert_transparency,
    detect_llm_endpoints,
    detect_takeover_candidates,
    historical_urls,
    run_recon,
)
from tools.recon import probe_endpoints as probe_endpoints_impl
from tools.recon.dnsx import TakeoverCandidate
from tools.recon.query import recon_endpoints, recon_open_ports, recon_subdomains
from tools.recon.scope import filter_in_scope as filter_in_scope_impl
from tools.recon_insights import (
    HostAnnotation,
    ReconFinalisationError,
    finalise_recon,
    save_insight,
    uncovered_interesting_hosts,
    validate_insight,
)
from tools.recon_insights import (
    load_insights as load_insights_impl,
)
from tools.recon_insights import (
    load_sweep as load_sweep_impl,
)


class _RunInitialSweepArgs(BaseModel):
    """Explicit args_schema for the Run Initial Sweep tool (#148)."""

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
    """Explicit args_schema for the OSINT Recon Subdomains tool (#148)."""

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
) -> list[str]:
    """
    Return the in-scope subdomains in the OA's draft sweep. ``host_filter`` is
    a case-insensitive substring (e.g. "api" returns every subdomain
    containing "api"). Use this to inspect the sweep before deciding which
    hosts to annotate.
    """
    return recon_subdomains(sweep_path, host_filter=host_filter)


class _ReconEndpointsArgs(BaseModel):
    """Explicit args_schema for the OSINT Recon Endpoints tool (#148)."""

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
    """Explicit args_schema for the OSINT Recon Open Ports tool (#148)."""

    sweep_path: str = Field(
        default="sweep.json",
        description="Relative path to the OA's sweep file. Defaults to ``sweep.json``.",
    )
    host: str | None = Field(
        default=None,
        description=(
            "Exact hostname to restrict the result to (no wildcards, no"
            " substring). Omit or pass null to get the full per-host port"
            " map. Use to look up a single host before annotating."
        ),
    )


@cyber_tool("Recon Open Ports", args_schema=_ReconOpenPortsArgs)
def recon_open_ports_tool(sweep_path: str = "sweep.json", host: str | None = None) -> OpenPortsMap:
    """
    Return the open-port map per host from the sweep. Passing a ``host``
    restricts the result to that single host. Use to surface non-HTTP
    services (Redis 6379, Elasticsearch 9200, Mongo 27017, etc.) that an
    annotation should call out.
    """
    return OpenPortsMap(hosts=recon_open_ports(sweep_path, host=host))


class _CertTransparencyArgs(BaseModel):
    """Explicit args_schema for the Certificate Transparency Lookup tool (#148)."""

    domain: str = Field(
        description=(
            "Apex domain to look up in crt.sh certificate transparency logs"
            " (e.g. 'example.com'). Returns historical subdomains across all"
            " certificates issued for the domain. Pass an apex, not a"
            " subdomain - crt.sh returns the broader set when queried on"
            " the apex."
        ),
    )


@cyber_tool("Certificate Transparency Lookup", args_schema=_CertTransparencyArgs)
def cert_transparency_tool(domain: str) -> list[str]:
    """
    Query crt.sh certificate transparency logs to discover subdomains not
    found by active enumeration. Returns deduplicated hostnames. Feed
    newly discovered hosts to Probe Hostnames to determine which are live.
    """
    return cert_transparency(domain)


class _HistoricalUrlsArgs(BaseModel):
    """Explicit args_schema for the Historical URL Discovery tool (#148)."""

    domain: str = Field(
        description=(
            "Domain to query waybackurls for (apex or subdomain). Returns"
            " historical URLs the Wayback Machine has archived. Many paths"
            " will be 404s today; feed candidates to Probe Hostnames to"
            " confirm liveness before annotating."
        ),
    )


@cyber_tool("Historical URL Discovery", args_schema=_HistoricalUrlsArgs)
def historical_urls_tool(domain: str) -> list[str]:
    """
    Use waybackurls to find historical endpoints for a domain from the
    Wayback Machine. Surfaces paths that may no longer be linked but still
    exist - candidates for Probe Hostnames.
    """
    return historical_urls(domain)


# TODO: switch ``endpoints_json: str`` to ``endpoints: list[Endpoint]`` per the
# #139 / cybersquad-tool convention. Out of scope for #148 (args_schema sweep);
# tracked as a separate cleanup.
class _LlmDetectionArgs(BaseModel):
    """Explicit args_schema for the LLM Endpoint Detection tool (#148)."""

    endpoints_json: str = Field(
        description=(
            "JSON-encoded list of Endpoint objects from the sweep (or a"
            " filtered subset). Each entry needs ``url`` and ideally"
            " ``technologies``; ``status_code`` is honoured if present."
            " Note: this is the legacy stringified-JSON pattern retired by"
            " #139 for the PT wrappers - a follow-up will migrate this to"
            " ``list[Endpoint]``."
        ),
    )


@cyber_tool("LLM Endpoint Detection", args_schema=_LlmDetectionArgs)
def llm_detection_tool(endpoints_json: str) -> list[LlmEndpoint]:
    """
    Scan a set of live endpoints for signals that they are backed by an LLM
    or AI assistant (URL path heuristics, OpenAI-format response keys,
    EventSource content-type, self-identification phrases). Pass the
    sweep's endpoint list (or a filtered subset) as JSON. Returned hits
    deserve a HIGH-priority annotation and a note pointing the Penetration
    Tester at prompt-injection probes.
    """
    endpoints = [Endpoint.model_validate(e) for e in json.loads(endpoints_json)]
    return [LlmEndpoint.model_validate(ep.model_dump()) for ep in detect_llm_endpoints(endpoints)]


class _ProbeHostnamesArgs(BaseModel):
    """Explicit args_schema for the Probe Hostnames tool (#148)."""

    hostnames: list[str] = Field(
        description=(
            "Hostnames to re-probe with httpx for liveness, status code,"
            " and technology fingerprinting. Typically the net-new ones"
            " surfaced by Certificate Transparency or Historical URL"
            " Discovery that were missed by the initial sweep. Each"
            " hostname is scope-filtered against the programme before"
            " any HTTP traffic fires - out-of-scope hostnames are"
            " dropped silently."
        ),
    )
    programme_handle: str = Field(
        description=(
            "Exact HackerOne programme handle for the scope guard. Required"
            " so the scope filter has the structured scope to check against;"
            " the scope guard never probes outside scope, even for"
            " fingerprinting."
        ),
    )


@cyber_tool("Probe Hostnames", args_schema=_ProbeHostnamesArgs)
def probe_hostnames_tool(hostnames: list[str], programme_handle: str) -> list[Endpoint]:
    """
    Re-probe a list of hostnames with httpx to confirm liveness, capture
    status codes, and fingerprint technologies. Use this on hostnames
    surfaced by Certificate Transparency or Historical URL Discovery that
    were not in the initial sweep.

    The hostnames are filtered against the programme's structured scope
    before any HTTP traffic is generated; out-of-scope hostnames are
    dropped silently (we never probe outside scope, even for fingerprinting).
    Returns a list of Endpoint with {url, status_code, technologies,
    parameters}. Net-new endpoints can then be annotated with Annotate Host.
    """
    if not hostnames:
        return []
    programme = _load_programme(programme_handle)
    in_scope = filter_in_scope_impl([h.strip().lower() for h in hostnames if h.strip()], programme)
    if not in_scope:
        return []
    return list(probe_endpoints_impl(in_scope))


class _DetectTakeoverCandidatesArgs(BaseModel):
    """Explicit args_schema for the Detect Takeover Candidates tool (#148)."""

    hostnames: list[str] = Field(
        description=(
            "Hostnames to resolve via dnsx and flag for subdomain takeover."
            " A candidate fires when the CNAME points to a known-vulnerable"
            " provider (AWS S3, Heroku, GitHub Pages, Azure, Vercel,"
            " Netlify, ...) or when the CNAME chain dangles. Hostnames are"
            " scope-filtered before any DNS traffic fires."
        ),
    )
    programme_handle: str = Field(
        description=(
            "Exact HackerOne programme handle for the scope guard. The"
            " resolver does not query outside the programme's structured"
            " scope - the handle is the authoritative key."
        ),
    )


@cyber_tool("Detect Takeover Candidates", args_schema=_DetectTakeoverCandidatesArgs)
def detect_takeover_candidates_tool(
    hostnames: list[str], programme_handle: str
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

    Hostnames are scope-filtered before any DNS traffic is generated.
    """
    if not hostnames:
        return []
    programme = _load_programme(programme_handle)
    in_scope = filter_in_scope_impl([h.strip().lower() for h in hostnames if h.strip()], programme)
    if not in_scope:
        return []
    return list(detect_takeover_candidates(in_scope))


class _OsintLookupCweArgs(BaseModel):
    """Explicit args_schema for the OSINT Lookup CWE tool (#148)."""

    query: str = Field(
        description=(
            "Free-text query against the Common Weakness Enumeration index."
            " Matches CWE id, name, or description (case-insensitive"
            " substring). Useful when annotating a host whose detected tech"
            " has a well-known weakness class (e.g. 'WordPress' -> XSS /"
            " SQLi; 'Spring Boot' -> SSTI / RCE)."
        ),
    )


@cyber_tool("Lookup CWE", args_schema=_OsintLookupCweArgs)
def lookup_cwe_tool(query: str) -> list[CWEEntry]:
    """
    Find Common Weakness Enumeration entries that match a query - useful
    when annotating a host whose detected tech has a well-known weakness
    class (e.g. "WordPress" -> XSS / SQLi; "Spring Boot" -> SSTI / RCE).
    Returns each match's cwe_id, name, short description, and the matching
    OWASP cheat-sheet topic.
    """
    return list(cwe_lookup(query))


class _OsintLookupOwaspArgs(BaseModel):
    """Explicit args_schema for the OSINT Lookup OWASP Guidance tool (#148)."""

    query: str = Field(
        description=(
            "Free-text query against the OWASP Cheat Sheet index. Matches"
            " on cheatsheet title and topic (case-insensitive substring)."
            " Use to surface guidance the downstream VR can reason against"
            " when building the attack plan."
        ),
    )


@cyber_tool("Lookup OWASP Guidance", args_schema=_OsintLookupOwaspArgs)
def lookup_owasp_tool(query: str) -> list[OWASPEntry]:
    """
    Find OWASP Cheat Sheet entries for a vuln class or topic - hint for
    the downstream VR's attack-plan reasoning. Returns each match's title,
    key_principles, and the canonical cheatsheetseries.owasp.org URL.
    """
    return list(owasp_lookup(query))


class _AnnotateHostArgs(BaseModel):
    """Explicit args_schema for the Annotate Host tool (#148)."""

    hostname: str = Field(
        description=(
            "Hostname to annotate. Must already be in the sweep, or have"
            " been surfaced by Certificate Transparency / Historical URL"
            " Discovery / Probe Hostnames. Lowercased before save."
        ),
    )
    role: str = Field(
        description=(
            "One of: admin, api, auth, app, cdn, static, mail, infra, dev,"
            " unknown. Drives downstream prioritisation - admin / auth"
            " hosts attract more probe budget than static / cdn ones."
        ),
    )
    priority: str = Field(
        description=(
            "One of: high, medium, low, skip. The curation signal the PT"
            " uses to allocate probe budget. ``high`` means 'spend probes"
            " here'; ``skip`` means 'do not probe this even if reachable'."
            " Must match the threat model in the notes."
        ),
    )
    notes: str = Field(
        description=(
            ">= 30 characters (>= 60 for high-priority). Explain what the"
            " host is, what tech runs on it, and why it matters (or why"
            " not). Quality gate fires below the length threshold and"
            " when the priority does not match the prose."
        ),
    )
    detected_tech: list[str] | None = Field(
        default=None,
        description=(
            "Ideally with versions ('Spring Boot 2.6.3' beats 'Spring"
            " Boot'). The quality gate warns when the sweep saw tech the"
            " annotation drops - the annotation is meant to be a curation"
            " of what was seen, not an alternate inventory."
        ),
    )
    sweep_path: str = Field(
        default="sweep.json",
        description="Relative path to the OA's sweep file. Defaults to ``sweep.json``.",
    )
    programme_handle: str | None = Field(
        default=None,
        description=(
            "Exact HackerOne programme handle. Required - the scope guard"
            " in ``validate_insight`` needs a real Programme to check"
            " against. ``None`` raises ValueError."
        ),
    )


@cyber_tool("Annotate Host", args_schema=_AnnotateHostArgs)
def annotate_host_tool(
    hostname: str,
    role: str,
    priority: str,
    notes: str,
    detected_tech: list[str] | None = None,
    sweep_path: str = "sweep.json",
    programme_handle: str | None = None,
) -> HostAnnotation:
    """
    Author one HostInsight for a single hostname and run the quality gate.

    Inputs:
      - hostname: a hostname from the sweep, or one newly discovered via
        Certificate Transparency / Historical URL Discovery / Probe Hostnames
      - role: one of admin, api, auth, app, cdn, static, mail, infra, dev,
        unknown
      - priority: one of high, medium, low, skip - the curation signal the
        Penetration Tester uses to allocate probe budget
      - notes: >= 30 chars (>= 60 for high-priority), explaining what the
        host is, what tech runs on it, and why it matters (or does not)
      - detected_tech: ideally with versions ("Spring Boot 2.6.3" beats
        "Spring Boot"); the warning fires when the sweep saw tech that the
        annotation drops

    Returns a HostAnnotation with the relative insight path and an
    InsightValidationReport. Re-run with the issues addressed when
    validation.ok is false.
    """
    sweep = load_sweep_impl(sweep_path)
    programme = _load_programme(programme_handle)

    insight = HostInsight(
        hostname=hostname.strip().lower(),
        role=HostRole(role),
        priority=HostPriority(priority),
        notes=notes.strip(),
        detected_tech=[t.strip() for t in (detected_tech or []) if t.strip()],
    )
    path = save_insight(insight)
    return HostAnnotation(
        path=str(path.relative_to(path.parents[1])),
        validation=validate_insight(insight, sweep, programme),
    )


class _UncoveredHostsArgs(BaseModel):
    """Explicit args_schema for the Uncovered Hosts tool (#148)."""

    sweep_path: str = Field(
        default="sweep.json",
        description=(
            "Relative path to the OA's sweep file. Defaults to"
            " ``sweep.json``. Returns interesting-status hostnames (200,"
            " 301, 302, 401, 403, ...) in the sweep that have no insight"
            " yet - use as a checklist before Finalise Recon."
        ),
    )


@cyber_tool("Uncovered Hosts", args_schema=_UncoveredHostsArgs)
def uncovered_hosts_tool(sweep_path: str = "sweep.json") -> list[str]:
    """
    Return interesting-status hostnames in the sweep (200, 301, 302, 401,
    403, ...) that have no insight yet. Use as a checklist before calling
    Finalise Recon - hosts you choose to leave uncovered should at least be
    a deliberate decision.
    """
    sweep = load_sweep_impl(sweep_path)
    insights = load_insights_impl()
    return uncovered_interesting_hosts(sweep, insights)


class _FinaliseReconArgs(BaseModel):
    """Explicit args_schema for the Finalise Recon tool (#148)."""

    programme_handle: str = Field(
        description=(
            "Exact HackerOne programme handle. The scope guard re-validates"
            " every insight against the programme's structured scope before"
            " writing recon.json - a mismatch raises and the workspace"
            " handle is not produced."
        ),
    )
    sweep_path: str = Field(
        default="sweep.json",
        description="Relative path to the OA's sweep file. Defaults to ``sweep.json``.",
    )


@cyber_tool("Finalise Recon", args_schema=_FinaliseReconArgs)
def finalise_recon_tool(
    programme_handle: str,
    sweep_path: str = "sweep.json",
) -> str:
    """
    Consolidate the sweep + every authored HostInsight into recon.json for
    the Vulnerability Researcher and Penetration Tester. Refuses if no
    insights have been authored, if any insight has unresolved validation
    errors, or if the surface is non-empty but no host has been marked
    HIGH priority. Returns the bare filename ``recon.json`` on success.
    """
    programme = _load_programme(programme_handle)
    try:
        path = finalise_recon(programme, sweep_filename=sweep_path)
    except ReconFinalisationError as exc:
        raise ValueError(str(exc)) from exc
    return path.name


# Helpers


def _load_programme(programme_handle: str | None) -> Programme:
    """Fetch and parse the Programme - the scope guard in validate_insight
    needs a real Programme to check against."""
    if not programme_handle:
        raise ValueError("programme_handle is required")
    http.set_programme(programme_handle)
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    return h1.parse_programme(policy["data"], scope)


MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[
        # Sweep
        run_initial_sweep_tool,
        # Inspect the sweep
        recon_subdomains_tool,
        recon_endpoints_tool,
        recon_open_ports_tool,
        # Supplementary discovery
        cert_transparency_tool,
        historical_urls_tool,
        probe_hostnames_tool,
        detect_takeover_candidates_tool,
        llm_detection_tool,
        # Citation hints
        lookup_cwe_tool,
        lookup_owasp_tool,
        # Authoring + finalisation
        annotate_host_tool,
        uncovered_hosts_tool,
        finalise_recon_tool,
        # Workspace
        read_run_filelist_tool,
        read_run_file_tool,
    ],
)
