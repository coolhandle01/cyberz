"""
tools/recon - OSINT and reconnaissance tooling for the OSINT Analyst.

External binaries required: subfinder, httpx (CLI), nmap, waybackurls, testssl.sh
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from models import AttackGraph, Endpoint, TLSCertificate
from models.h1 import Programme, ScopeType
from tools.recon.cert_transparency import cert_transparency
from tools.recon.dirfuzz import discover_paths
from tools.recon.dnsx import TakeoverCandidate, detect_takeover_candidates, resolve_records
from tools.recon.httpx import probe_endpoints
from tools.recon.ip_asset import compose_ip_assets
from tools.recon.llm import detect_llm_endpoints
from tools.recon.nmap import port_scan
from tools.recon.scope import filter_in_scope, host_of
from tools.recon.subfinder import enumerate_subdomains
from tools.recon.tls import check_dns_email_security, check_tls
from tools.recon.traceroute import run_traceroute
from tools.recon.waybackurls import historical_urls
from tools.recon_insights import save_tls_certificate

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
    "compose_ip_assets",
    "detect_llm_endpoints",
    "detect_takeover_candidates",
    "discover_paths",
    "enumerate_subdomains",
    "filter_in_scope",
    "historical_urls",
    "host_of",
    "port_scan",
    "probe_endpoints",
    "resolve_records",
    "run_recon",
    "run_traceroute",
]


def _emit_tls_certificates(endpoints: list[Endpoint]) -> list[TLSCertificate]:
    """Lift leaf certs off the probed endpoints into first-class assets.

    Writes one per-host evidence file (``hosts/<fqdn>/tls.json``) and
    returns the aggregate for ``AttackGraph.tls_certificates``. Mirrors
    the ``host_insights`` write/aggregate split. Empty unless a
    WEB_INVENTORY probe attached certs - the TECH_DETECT shim grabs
    none, so this is dormant on today's default recon, like the SAN
    promotion in ``run_recon``.
    """
    certificates = [ep.tls_certificate for ep in endpoints if ep.tls_certificate]
    for certificate in certificates:
        save_tls_certificate(certificate)
    return certificates


def run_recon(programme: Programme) -> AttackGraph:
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

    # Promote TLS SANs observed during probing to in-scope subdomains.
    # Multi-SAN certs leak every hostname the server is authoritative for;
    # the scope guard filters those that match the programme. Dormant
    # today because ``probe_endpoints`` is the TECH_DETECT shim (no
    # -tls-grab); activates the moment any caller flips run_recon to
    # HttpxMode.WEB_INVENTORY or an OA-side tool pipes WEB_INVENTORY
    # endpoints through this helper. Code lives upstream of the dormancy
    # so SANs join in_scope_hosts atomically with the probe that surfaced
    # them - downstream IP enrichment, traceroute, and DNS checks all see
    # the promoted hosts in one pass.
    san_candidates = list({san for ep in endpoints for san in ep.tls_sans})
    if san_candidates:
        promoted = filter_in_scope(san_candidates, programme)
        in_scope_hosts = list(dict.fromkeys(in_scope_hosts + promoted))

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

    # IP-rooted enrichment: resolve A records once for the in-scope hosts,
    # unique-ify the IPs, compose one IpAsset per IP via Cymru + RDAP +
    # dnsx PTR. One IpAsset = one amass IPAddress asset's worth of input.
    dns_records = resolve_records(in_scope_hosts)
    unique_ips = list(dict.fromkeys(ip for record in dns_records for ip in record.a_records))
    ip_assets = compose_ip_assets(unique_ips)
    tls_certificates = _emit_tls_certificates(endpoints)

    return AttackGraph(
        programme=programme,
        subdomains=in_scope_hosts,
        endpoints=endpoints,
        open_ports=open_ports,
        technologies=list(dict.fromkeys(all_tech)),
        passive_findings=passive_findings,
        network_hops=network_hops,
        ip_assets=ip_assets,
        tls_certificates=tls_certificates,
        notes=f"Seeded from {seed_domains}. {len(in_scope_hosts)} in-scope hosts.",
    )
