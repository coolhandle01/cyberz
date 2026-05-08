"""
Exposed service checks: unauthenticated databases, sensitive files, admin panels, and
branded control panels / monitoring tools.

Each public function is a focused check that the Penetration Tester agent invokes
selectively based on nmap open_ports data and detected technologies.
check_exposed_services() is a backwards-compat wrapper that calls all of them.
"""

from __future__ import annotations

import logging
import socket
from urllib.parse import urlparse, urlunparse

import requests

from config import config
from models import Endpoint, RawFinding, ReconResult, Severity

logger = logging.getLogger(__name__)

_SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    ("/.git/HEAD", "ref: refs/", "Git Repository Exposed"),
    ("/.env", "=", ".env File Exposed"),
    ("/phpinfo.php", "PHP Version", "phpinfo Exposed"),
    ("/server-status", "Apache", "Apache server-status Exposed"),
    ("/.DS_Store", "\x00\x00\x00\x01", "DS_Store File Exposed"),
]

_ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/adminer",
    "/adminer.php",
    "/manager/html",
    "/_admin",
]

_ADMIN_CONTENT_MARKERS = [
    "dashboard",
    "admin panel",
    "administration",
    "login",
    "sign in",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _origin(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def _unique_origins(endpoints: list[Endpoint]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for ep in endpoints:
        o = _origin(ep.url)
        if o not in seen:
            seen.add(o)
            result.append(o)
    return result


def _unique_hostnames(endpoints: list[Endpoint]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for ep in endpoints:
        h = urlparse(ep.url).hostname or ""
        if h and h not in seen:
            seen.add(h)
            result.append(h)
    return result


def _check_redis(host: str) -> bool:
    """Return True if Redis responds to PING without authentication."""
    try:
        with socket.create_connection((host, 6379), timeout=3) as sock:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            data = sock.recv(128)
            return b"+PONG" in data
    except Exception:
        return False


def _check_mongodb(host: str) -> bool:
    """Return True if MongoDB answers an isMaster query without authentication."""
    try:
        with socket.create_connection((host, 27017), timeout=3) as sock:
            # Minimal OP_QUERY against admin.$cmd: {isMaster: 1}
            bson_doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
            header = (
                b"\x00\x00\x00\x00"  # messageLength placeholder
                b"\x01\x00\x00\x00"  # requestID
                b"\x00\x00\x00\x00"  # responseTo
                b"\xd4\x07\x00\x00"  # opCode OP_QUERY
                b"\x00\x00\x00\x00"  # flags
            )
            coll = b"admin.$cmd\x00"
            skip_return = b"\x00\x00\x00\x00\x01\x00\x00\x00"
            body = header + coll + skip_return + bson_doc
            length = (len(body) + 4).to_bytes(4, "little")
            sock.sendall(length + body)
            data = sock.recv(256)
            return b"ismaster" in data.lower() or b"iswritableprimary" in data.lower()
    except Exception:
        return False


def _probe_panel(
    hostnames: list[str],
    scheme: str,
    port: int,
    path: str,
    marker: str,
    panel_name: str,
    tool_name: str,
) -> list[RawFinding]:
    """Probe a specific scheme/port/path on each hostname for panel content."""
    findings: list[RawFinding] = []
    for hostname in hostnames:
        url = f"{scheme}://{hostname}:{port}{path}"
        try:
            resp = requests.get(  # nosemgrep
                url,
                timeout=5,
                verify=False,  # nosec B501  # noqa: S501
                allow_redirects=True,
            )
            if resp.status_code == 200 and marker.lower() in resp.text.lower():
                findings.append(
                    RawFinding(
                        title=f"Exposed {panel_name} - {url}",
                        vuln_class="ExposedAdminPanel",
                        target=url,
                        evidence=f"HTTP 200 with {panel_name} content at {url}",
                        tool=tool_name,
                        severity_hint=Severity.HIGH,
                    )
                )
        except Exception as exc:
            logger.debug("%s check failed for %s: %s", panel_name, url, exc)
    return findings


def _probe_path(
    origins: list[str],
    path: str,
    marker: str,
    panel_name: str,
    tool_name: str,
) -> list[RawFinding]:
    """Probe a path on existing origins as a reverse-proxy fallback."""
    findings: list[RawFinding] = []
    for origin in origins:
        target_url = origin + path
        try:
            resp = requests.get(  # nosemgrep
                target_url,
                timeout=config.recon.http_timeout,
                allow_redirects=True,
            )
            if resp.status_code == 200 and marker.lower() in resp.text.lower():
                findings.append(
                    RawFinding(
                        title=f"Exposed {panel_name} - {target_url}",
                        vuln_class="ExposedAdminPanel",
                        target=target_url,
                        evidence=f"HTTP 200 with {panel_name} content at {target_url}",
                        tool=tool_name,
                        severity_hint=Severity.HIGH,
                    )
                )
        except Exception as exc:
            logger.debug("%s path check failed for %s: %s", panel_name, target_url, exc)
    return findings


# ---------------------------------------------------------------------------
# Public check functions
# ---------------------------------------------------------------------------


def check_unauthenticated_databases(recon: ReconResult) -> list[RawFinding]:
    """Check for unauthenticated Elasticsearch (9200), CouchDB (5984), Redis (6379),
    and MongoDB (27017) on hosts with those ports open."""
    findings: list[RawFinding] = []

    _http_checks: dict[int, tuple[str, str, str]] = {
        9200: ("Elasticsearch", "/_cluster/health", "cluster_name"),
        5984: ("CouchDB", "/_all_dbs", "["),
    }

    for host, ports in recon.open_ports.items():
        for port, (db_name, path, marker) in _http_checks.items():
            if port not in ports:
                continue
            url = f"http://{host}:{port}{path}"
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False)  # nosemgrep
                if resp.status_code == 200 and marker in resp.text:
                    findings.append(
                        RawFinding(
                            title=f"Unauthenticated {db_name} - {host}",
                            vuln_class="ExposedService",
                            target=url,
                            evidence=(
                                f"{db_name} responded without authentication.\n"
                                f"Response: {resp.text[:300]}"
                            ),
                            tool="unauthenticated_databases_check",
                            severity_hint=Severity.CRITICAL,
                        )
                    )
            except Exception as exc:
                logger.debug("%s check failed for %s: %s", db_name, host, exc)

        if 6379 in ports and _check_redis(host):
            findings.append(
                RawFinding(
                    title=f"Unauthenticated Redis - {host}",
                    vuln_class="ExposedService",
                    target=f"redis://{host}:6379",
                    evidence="Redis responded to PING without authentication.",
                    tool="unauthenticated_databases_check",
                    severity_hint=Severity.CRITICAL,
                )
            )

        if 27017 in ports and _check_mongodb(host):
            findings.append(
                RawFinding(
                    title=f"Unauthenticated MongoDB - {host}",
                    vuln_class="ExposedService",
                    target=f"mongodb://{host}:27017",
                    evidence=(
                        "MongoDB accepted a connection and responded to isMaster "
                        "without authentication."
                    ),
                    tool="unauthenticated_databases_check",
                    severity_hint=Severity.CRITICAL,
                )
            )

    logger.info("Unauthenticated databases check found %d findings", len(findings))
    return findings


def check_sensitive_files(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Probe for exposed .git/HEAD, .env, phpinfo.php, server-status, and .DS_Store."""
    findings: list[RawFinding] = []
    for origin in _unique_origins(endpoints):
        for path, marker, title in _SENSITIVE_PATHS:
            target_url = origin + path
            try:
                resp = requests.get(  # nosemgrep
                    target_url,
                    timeout=config.recon.http_timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200 and marker in resp.text:
                    findings.append(
                        RawFinding(
                            title=f"{title} - {target_url}",
                            vuln_class="SensitiveFileExposed",
                            target=target_url,
                            evidence=f"HTTP 200 - {resp.text[:300]}",
                            tool="sensitive_files_check",
                            severity_hint=Severity.HIGH,
                        )
                    )
            except Exception as exc:
                logger.debug("Sensitive file check failed for %s: %s", target_url, exc)
    logger.info("Sensitive files check found %d findings", len(findings))
    return findings


def check_admin_panels(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Probe common admin panel paths (/admin, /wp-admin, /phpmyadmin, etc.)."""
    findings: list[RawFinding] = []
    for origin in _unique_origins(endpoints):
        for path in _ADMIN_PATHS:
            target_url = origin + path
            try:
                resp = requests.get(  # nosemgrep
                    target_url,
                    timeout=config.recon.http_timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200:
                    body_lower = resp.text[:1000].lower()
                    if any(m in body_lower for m in _ADMIN_CONTENT_MARKERS):
                        findings.append(
                            RawFinding(
                                title=f"Exposed Admin Panel - {target_url}",
                                vuln_class="ExposedAdminPanel",
                                target=target_url,
                                evidence=(f"HTTP 200 with admin-related content at {target_url}"),
                                tool="admin_panels_check",
                                severity_hint=Severity.HIGH,
                            )
                        )
            except Exception as exc:
                logger.debug("Admin panel check failed for %s: %s", target_url, exc)
    logger.info("Admin panels check found %d findings", len(findings))
    return findings


def check_cpanel(recon: ReconResult) -> list[RawFinding]:
    """Check for exposed cPanel (ports 2082/2083) and WHM (ports 2086/2087)."""
    hostnames = _unique_hostnames(recon.endpoints)
    findings: list[RawFinding] = []
    for scheme, port, marker, label in [
        ("http", 2082, "cPanel", "cPanel"),
        ("https", 2083, "cPanel", "cPanel"),
        ("http", 2086, "WebHost Manager", "WHM"),
        ("https", 2087, "WebHost Manager", "WHM"),
    ]:
        findings.extend(_probe_panel(hostnames, scheme, port, "/", marker, label, "cpanel_check"))
    logger.info("cPanel/WHM check found %d findings", len(findings))
    return findings


def check_plesk(recon: ReconResult) -> list[RawFinding]:
    """Check for an exposed Plesk control panel (ports 8880/8443)."""
    hostnames = _unique_hostnames(recon.endpoints)
    findings = _probe_panel(hostnames, "http", 8880, "/", "Plesk", "Plesk", "plesk_check")
    findings += _probe_panel(
        hostnames, "https", 8443, "/login.php", "Plesk", "Plesk", "plesk_check"
    )
    logger.info("Plesk check found %d findings", len(findings))
    return findings


def check_directadmin(recon: ReconResult) -> list[RawFinding]:
    """Check for an exposed DirectAdmin control panel (port 2222)."""
    hostnames = _unique_hostnames(recon.endpoints)
    findings = _probe_panel(
        hostnames, "http", 2222, "/login.php", "DirectAdmin", "DirectAdmin", "directadmin_check"
    )
    logger.info("DirectAdmin check found %d findings", len(findings))
    return findings


def check_webmin(recon: ReconResult) -> list[RawFinding]:
    """Check for an exposed Webmin administration panel (port 10000)."""
    hostnames = _unique_hostnames(recon.endpoints)
    findings = _probe_panel(hostnames, "https", 10000, "/", "Webmin", "Webmin", "webmin_check")
    logger.info("Webmin check found %d findings", len(findings))
    return findings


def check_grafana(recon: ReconResult) -> list[RawFinding]:
    """Check for an exposed Grafana instance on port 3000 and via /grafana reverse-proxy
    path on existing endpoints."""
    hostnames = _unique_hostnames(recon.endpoints)
    findings = _probe_panel(hostnames, "http", 3000, "/", "Grafana", "Grafana", "grafana_check")
    findings += _probe_path(
        _unique_origins(recon.endpoints), "/grafana", "Grafana", "Grafana", "grafana_check"
    )
    logger.info("Grafana check found %d findings", len(findings))
    return findings


def check_kibana(recon: ReconResult) -> list[RawFinding]:
    """Check for an exposed Kibana instance on port 5601 and via /kibana reverse-proxy
    path on existing endpoints."""
    hostnames = _unique_hostnames(recon.endpoints)
    findings = _probe_panel(hostnames, "http", 5601, "/", "Kibana", "Kibana", "kibana_check")
    findings += _probe_path(
        _unique_origins(recon.endpoints), "/kibana", "Kibana", "Kibana", "kibana_check"
    )
    logger.info("Kibana check found %d findings", len(findings))
    return findings


def check_portainer(recon: ReconResult) -> list[RawFinding]:
    """Check for an exposed Portainer Docker management UI on port 9000 and via
    /portainer reverse-proxy path on existing endpoints."""
    hostnames = _unique_hostnames(recon.endpoints)
    findings = _probe_panel(
        hostnames, "http", 9000, "/", "Portainer", "Portainer", "portainer_check"
    )
    findings += _probe_path(
        _unique_origins(recon.endpoints), "/portainer", "Portainer", "Portainer", "portainer_check"
    )
    logger.info("Portainer check found %d findings", len(findings))
    return findings


def check_consul_vault(recon: ReconResult) -> list[RawFinding]:
    """Check for exposed Consul UI (port 8500) and Vault UI (port 8200), and via
    /consul/ui and /vault/ui reverse-proxy paths on existing endpoints."""
    hostnames = _unique_hostnames(recon.endpoints)
    origins = _unique_origins(recon.endpoints)
    findings = _probe_panel(
        hostnames, "http", 8500, "/ui/", "Consul", "Consul", "consul_vault_check"
    )
    findings += _probe_panel(
        hostnames, "http", 8200, "/ui/", "Vault", "Vault", "consul_vault_check"
    )
    findings += _probe_path(origins, "/consul/ui", "Consul", "Consul", "consul_vault_check")
    findings += _probe_path(origins, "/vault/ui", "Vault", "Vault", "consul_vault_check")
    logger.info("Consul/Vault check found %d findings", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Backwards-compat aggregate
# ---------------------------------------------------------------------------


def check_exposed_services(recon: ReconResult) -> list[RawFinding]:
    """Run all exposed-service checks in one call. Prefer individual targeted checks
    via the PT agent tools when you have nmap or technology context to be selective."""
    findings: list[RawFinding] = []
    findings.extend(check_unauthenticated_databases(recon))
    findings.extend(check_sensitive_files(recon.endpoints))
    findings.extend(check_admin_panels(recon.endpoints))
    findings.extend(check_cpanel(recon))
    findings.extend(check_plesk(recon))
    findings.extend(check_directadmin(recon))
    findings.extend(check_webmin(recon))
    findings.extend(check_grafana(recon))
    findings.extend(check_kibana(recon))
    findings.extend(check_portainer(recon))
    findings.extend(check_consul_vault(recon))
    return findings
