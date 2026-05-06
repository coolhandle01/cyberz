"""
tools/recon - OSINT and reconnaissance tooling for the OSINT Analyst.

External binaries required: subfinder, httpx (CLI), nmap, waybackurls
"""

from __future__ import annotations

import logging

from models import Programme, ReconResult, ScopeType
from tools.recon.cert_transparency import cert_transparency
from tools.recon.httpx import probe_endpoints
from tools.recon.nmap import port_scan
from tools.recon.scope import extract_domain, filter_in_scope
from tools.recon.subfinder import enumerate_subdomains
from tools.recon.waybackurls import historical_urls

logger = logging.getLogger(__name__)

__all__ = [
    "cert_transparency",
    "enumerate_subdomains",
    "extract_domain",
    "filter_in_scope",
    "historical_urls",
    "port_scan",
    "probe_endpoints",
    "run_recon",
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

    all_tech: list[str] = []
    for ep in endpoints:
        all_tech.extend(ep.technologies)

    return ReconResult(
        programme=programme,
        subdomains=in_scope_hosts,
        endpoints=endpoints,
        open_ports=open_ports,
        technologies=list(dict.fromkeys(all_tech)),
        notes=f"Seeded from {seed_domains}. {len(in_scope_hosts)} in-scope hosts.",
    )
