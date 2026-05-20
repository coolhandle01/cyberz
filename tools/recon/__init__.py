"""
tools/recon - OSINT and reconnaissance tooling for the OSINT Analyst.

External binaries required: subfinder, httpx (CLI), nmap, waybackurls, testssl.sh
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from models import Endpoint, ReconResult
from models.h1 import Programme, ScopeType
from tools.recon.cert_transparency import cert_transparency
from tools.recon.dirfuzz import discover_paths
from tools.recon.dnsx import TakeoverCandidate, detect_takeover_candidates
from tools.recon.llm import detect_llm_endpoints
from tools.recon.nmap import port_scan
from tools.recon.probe import probe_endpoints
from tools.recon.scope import extract_domain, filter_in_scope
from tools.recon.subfinder import enumerate_subdomains
from tools.recon.tls import check_dns_email_security, check_tls
from tools.recon.traceroute import run_traceroute
from tools.recon.waybackurls import historical_urls

logger = logging.getLogger(__name__)

# Subdomain prefixes that are high-value dirfuzz targets: more likely to expose
# admin interfaces, internal APIs, or sensitive paths than generic subdomains.
_DIRFUZZ_HIGH_VALUE_PREFIXES = frozenset(
    {
        "admin",
        "api",
        "app",
        "beta",
        "console",
        "dashboard",
        "dev",
        "internal",
        "manage",
        "portal",
        "staging",
        "test",
    }
)


def _dirfuzz_targets(endpoints: list[Endpoint], seed_domains: list[str]) -> list[Endpoint]:
    """Sort endpoints for dirfuzz priority: root domains first, high-value subdomains second."""
    seed_set = set(seed_domains)

    def _priority(ep: Endpoint) -> int:
        hostname = urlparse(ep.url).hostname or ""
        if hostname in seed_set:
            return 0
        if hostname.split(".")[0].lower() in _DIRFUZZ_HIGH_VALUE_PREFIXES:
            return 1
        return 2

    return sorted(endpoints, key=_priority)


# Third-party code hosting platforms that appear in H1 scope lists as URL-type
# assets pointing to repos/orgs, but whose infrastructure must never be enumerated.
_CODE_HOSTS: frozenset[str] = frozenset(
    {"github.com", "gitlab.com", "bitbucket.org", "sourceforge.net"}
)

# Asset types that represent live web targets worth enumerating with subfinder.
# H1 returns URL for bare domains (dash.cloudflare.com) and wildcards (*.teams.cloudflare.com).
_ACTIVE_RECON_TYPES: frozenset[ScopeType] = frozenset(
    {ScopeType.URL, ScopeType.WILDCARD, ScopeType.IP_ADDRESS}
)


__all__ = [
    "_ACTIVE_RECON_TYPES",
    "_CODE_HOSTS",
    "TakeoverCandidate",
    "cert_transparency",
    "check_dns_email_security",
    "check_tls",
    "detect_llm_endpoints",
    "detect_takeover_candidates",
    "discover_paths",
    "enumerate_subdomains",
    "extract_domain",
    "filter_in_scope",
    "historical_urls",
    "port_scan",
    "probe_endpoints",
    "run_recon",
    "run_traceroute",
]


def run_recon(programme: Programme) -> ReconResult:
    """Full recon pipeline for a single programme."""
    seed_domains: list[str] = []
    for item in programme.in_scope:
        if item.asset_type not in _ACTIVE_RECON_TYPES:
            continue
        parsed = urlparse(
            item.asset_identifier
            if "://" in item.asset_identifier
            else f"http://{item.asset_identifier}"
        )
        hostname = (parsed.hostname or "").lstrip("*.")
        if not hostname or (parsed.path or "").strip("/") or hostname in _CODE_HOSTS:
            continue
        seed_domains.append(hostname)
    seed_domains = list(dict.fromkeys(seed_domains))

    all_subdomains: list[str] = []
    for domain in seed_domains:
        all_subdomains.extend(enumerate_subdomains(domain))
    all_subdomains = list(dict.fromkeys(all_subdomains))

    in_scope_hosts = filter_in_scope(all_subdomains, programme)
    endpoints = probe_endpoints(in_scope_hosts)
    live_hosts = [ep.url for ep in endpoints if ep.status_code and ep.status_code < 500]
    open_ports = port_scan(live_hosts[:20])

    discovered = discover_paths(_dirfuzz_targets(endpoints, seed_domains))
    endpoints = endpoints + discovered

    all_tech: list[str] = []
    for ep in endpoints:
        all_tech.extend(ep.technologies)

    # Passive findings: TLS and DNS checks run here so all downstream agents
    # have this context without the Penetration Tester needing to repeat them.
    passive_findings = list(check_tls(endpoints))
    ep_hosts = [urlparse(ep.url).hostname or "" for ep in endpoints]
    all_domains = list(dict.fromkeys(ep_hosts + in_scope_hosts))
    passive_findings.extend(check_dns_email_security(all_domains))

    network_hops = run_traceroute(in_scope_hosts[:20])

    return ReconResult(
        programme=programme,
        subdomains=in_scope_hosts,
        endpoints=endpoints,
        open_ports=open_ports,
        technologies=list(dict.fromkeys(all_tech)),
        passive_findings=passive_findings,
        network_hops=network_hops,
        notes=f"Seeded from {seed_domains}. {len(in_scope_hosts)} in-scope hosts.",
    )
