"""
tools/recon - OSINT and reconnaissance tooling for the OSINT Analyst.

External binaries required: subfinder, httpx (CLI), nmap, waybackurls, testssl.sh
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from models import Programme, ReconResult, ScopeType
from tools.recon.cert_transparency import cert_transparency
from tools.recon.dirfuzz import discover_paths
from tools.recon.nmap import port_scan
from tools.recon.probe import probe_endpoints
from tools.recon.scope import extract_domain, filter_in_scope
from tools.recon.subfinder import enumerate_subdomains
from tools.recon.tls import check_dns_email_security, check_tls
from tools.recon.traceroute import run_traceroute
from tools.recon.waybackurls import historical_urls

logger = logging.getLogger(__name__)

__all__ = [
    "cert_transparency",
    "check_dns_email_security",
    "check_tls",
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
    seed_domains: list[str] = [
        extract_domain(item.asset_identifier)
        for item in programme.in_scope
        if item.asset_type in (ScopeType.URL, ScopeType.WILDCARD)
    ]
    seed_domains = list(dict.fromkeys(seed_domains))

    all_subdomains: list[str] = []
    for domain in seed_domains:
        all_subdomains.extend(enumerate_subdomains(domain))

    in_scope_hosts = filter_in_scope(all_subdomains, programme)
    endpoints = probe_endpoints(in_scope_hosts)
    live_hosts = [ep.url for ep in endpoints if ep.status_code and ep.status_code < 500]
    open_ports = port_scan(live_hosts[:20])

    discovered = discover_paths(endpoints)
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
