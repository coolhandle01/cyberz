"""OSINT Analyst - maps the in-scope attack surface."""

from __future__ import annotations

import json
from pathlib import Path

from crewai.tools import tool

import runtime
from models import Endpoint, HostInsight, HostPriority, HostRole, Programme
from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from tools import cwe_data, http, owasp_data
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
from tools.recon_insights import (
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


@tool("Run Initial Sweep")
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


@tool("Recon Subdomains")
def recon_subdomains_tool(sweep_path: str = "sweep.json", host_filter: str | None = None) -> list:
    """
    Return the in-scope subdomains in the OA's draft sweep. ``host_filter`` is
    a case-insensitive substring (e.g. "api" returns every subdomain
    containing "api"). Use this to inspect the sweep before deciding which
    hosts to annotate.
    """
    return recon_subdomains(sweep_path, host_filter=host_filter)


@tool("Recon Endpoints")
def recon_endpoints_tool(
    sweep_path: str = "sweep.json",
    status: int | None = None,
    tech: str | None = None,
    host_contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict:
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
    ).model_dump(mode="json")


@tool("Recon Open Ports")
def recon_open_ports_tool(sweep_path: str = "sweep.json", host: str | None = None) -> dict:
    """
    Return the open-port map per host from the sweep. Passing a ``host``
    restricts the result to that single host. Use to surface non-HTTP
    services (Redis 6379, Elasticsearch 9200, Mongo 27017, etc.) that an
    annotation should call out.
    """
    return recon_open_ports(sweep_path, host=host)


@tool("Certificate Transparency Lookup")
def cert_transparency_tool(domain: str) -> list[str]:
    """
    Query crt.sh certificate transparency logs to discover subdomains not
    found by active enumeration. Returns deduplicated hostnames. Feed
    newly discovered hosts to Probe Hostnames to determine which are live.
    """
    return cert_transparency(domain)


@tool("Historical URL Discovery")
def historical_urls_tool(domain: str) -> list[str]:
    """
    Use waybackurls to find historical endpoints for a domain from the
    Wayback Machine. Surfaces paths that may no longer be linked but still
    exist - candidates for Probe Hostnames.
    """
    return historical_urls(domain)


@tool("LLM Endpoint Detection")
def llm_detection_tool(endpoints_json: str) -> list[dict]:
    """
    Scan a set of live endpoints for signals that they are backed by an LLM
    or AI assistant (URL path heuristics, OpenAI-format response keys,
    EventSource content-type, self-identification phrases). Pass the
    sweep's endpoint list (or a filtered subset) as JSON. Returned hits
    deserve a HIGH-priority annotation and a note pointing the Penetration
    Tester at prompt-injection probes.
    """
    endpoints = [Endpoint.model_validate(e) for e in json.loads(endpoints_json)]
    return [ep.model_dump() for ep in detect_llm_endpoints(endpoints)]


@tool("Probe Hostnames")
def probe_hostnames_tool(hostnames: list[str], programme_handle: str) -> list[dict]:
    """
    Re-probe a list of hostnames with httpx to confirm liveness, capture
    status codes, and fingerprint technologies. Use this on hostnames
    surfaced by Certificate Transparency or Historical URL Discovery that
    were not in the initial sweep.

    The hostnames are filtered against the programme's structured scope
    before any HTTP traffic is generated; out-of-scope hostnames are
    dropped silently (we never probe outside scope, even for fingerprinting).
    Returns ``[{url, status_code, technologies, parameters}]``. Net-new
    endpoints can then be annotated with Annotate Host.
    """
    if not hostnames:
        return []
    programme = _load_programme(programme_handle)
    in_scope = filter_in_scope_impl([h.strip().lower() for h in hostnames if h.strip()], programme)
    if not in_scope:
        return []
    eps = probe_endpoints_impl(in_scope)
    return [ep.model_dump(mode="json") for ep in eps]


@tool("Detect Takeover Candidates")
def detect_takeover_candidates_tool(hostnames: list[str], programme_handle: str) -> list[dict]:
    """
    Resolve each hostname via dnsx and flag subdomain-takeover candidates.

    A candidate is flagged when the host's CNAME points to a known-vulnerable
    provider (AWS S3, Heroku, GitHub Pages, Azure, Vercel, Netlify, ...) or
    when the CNAME chain dangles (CNAME exists but resolves to no A records).
    Returns ``[{hostname, cname, reason, service}]`` where ``reason`` is one
    of ``cname_to_vulnerable_provider`` or ``dangling_cname``.

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
    candidates = detect_takeover_candidates(in_scope)
    return [c.model_dump(mode="json") for c in candidates]


@tool("Lookup CWE")
def lookup_cwe_tool(query: str) -> list[dict]:
    """
    Find Common Weakness Enumeration entries that match a query - useful
    when annotating a host whose detected tech has a well-known weakness
    class (e.g. "WordPress" -> XSS / SQLi; "Spring Boot" -> SSTI / RCE).
    Returns each match's cwe_id, name, short description, and the matching
    OWASP cheat-sheet topic.
    """
    entries = cwe_data.lookup(query)
    return [
        {
            "cwe_id": e.cwe_id,
            "name": e.name,
            "description": e.description,
            "url": e.url,
            "owasp_topic": e.owasp_topic,
        }
        for e in entries
    ]


@tool("Lookup OWASP Guidance")
def lookup_owasp_tool(query: str) -> list[dict]:
    """
    Find OWASP Cheat Sheet entries for a vuln class or topic - hint for
    the downstream VR's attack-plan reasoning. Returns each match's title,
    key_principles, and the canonical cheatsheetseries.owasp.org URL.
    """
    entries = owasp_data.lookup(query)
    return [
        {
            "topic": e.topic,
            "title": e.title,
            "url": e.url,
            "key_principles": e.key_principles,
        }
        for e in entries
    ]


@tool("Annotate Host")
def annotate_host_tool(
    hostname: str,
    role: str,
    priority: str,
    notes: str,
    detected_tech: list[str] | None = None,
    sweep_path: str = "sweep.json",
    programme_handle: str | None = None,
) -> dict:
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

    Returns ``{"path": "host_insights/HOST.json", "validation": {ok, issues}}``.
    Re-run with the issues addressed when validation.ok is false.
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
    report = validate_insight(insight, sweep, programme)
    return {
        "path": str(path.relative_to(path.parents[1])),
        "validation": report.model_dump(),
    }


@tool("Uncovered Hosts")
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


@tool("Finalise Recon")
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
    slug="osint_analyst",
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
    task="Reconnaissance",
)
