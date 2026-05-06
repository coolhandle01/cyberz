"""
Exposed service checks: unauthenticated databases, admin panels, and sensitive files.

Checks that should never be missed on any target:
  - Unauthenticated Elasticsearch, CouchDB, Redis
  - Exposed admin panels on well-known paths
  - Sensitive files: .git/HEAD, .env, phpinfo
"""

from __future__ import annotations

import logging
import socket
from urllib.parse import urlparse, urlunparse

import requests

from config import config
from models import RawFinding, ReconResult, Severity

logger = logging.getLogger(__name__)

# Unauthenticated database checks keyed by port
_DB_CHECKS: dict[int, tuple[str, str, str]] = {
    # port: (name, url_path, response_marker)
    9200: ("Elasticsearch", "/_cluster/health", "cluster_name"),
    5984: ("CouchDB", "/_all_dbs", "["),
}

_ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/adminer",
    "/adminer.php",
    "/manager/html",
    "/_admin",
    "/grafana",
    "/kibana",
    "/portainer",
    "/consul/ui",
    "/vault/ui",
]

_SENSITIVE_PATHS = [
    ("/.git/HEAD", "ref: refs/", "Git Repository Exposed"),
    ("/.env", "=", ".env File Exposed"),
    ("/phpinfo.php", "PHP Version", "phpinfo Exposed"),
    ("/server-status", "Apache", "Apache server-status Exposed"),
    ("/.DS_Store", "\x00\x00\x00\x01", "DS_Store File Exposed"),
]

_ADMIN_CONTENT_MARKERS = [
    "dashboard",
    "admin panel",
    "administration",
    "login",
    "sign in",
    "grafana",
    "kibana",
    "portainer",
    "consul",
]

# Brand-specific control panels that live on non-standard ports.
# Tuple: (scheme, port, path, response_content_marker, panel_name)
_PANEL_CHECKS: list[tuple[str, int, str, str, str]] = [
    ("http", 2082, "/", "cPanel", "cPanel"),
    ("https", 2083, "/", "cPanel", "cPanel"),
    ("http", 2086, "/", "WebHost Manager", "WHM"),
    ("https", 2087, "/", "WebHost Manager", "WHM"),
    ("http", 8880, "/", "Plesk", "Plesk"),
    ("https", 8443, "/login.php", "Plesk", "Plesk"),
    ("http", 2222, "/login.php", "DirectAdmin", "DirectAdmin"),
    ("https", 10000, "/", "Webmin", "Webmin"),
]


def _origin(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def _check_redis(host: str) -> bool:
    """Return True if Redis responds to PING without authentication."""
    try:
        with socket.create_connection((host, 6379), timeout=3) as sock:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            data = sock.recv(128)
            return b"+PONG" in data
    except Exception:
        return False


def check_exposed_services(recon: ReconResult) -> list[RawFinding]:
    """
    Check for unauthenticated databases, exposed admin panels, and sensitive
    files across the discovered recon surface.
    """
    findings: list[RawFinding] = []

    # --- Unauthenticated databases ---
    for host, ports in recon.open_ports.items():
        for port, (db_name, path, marker) in _DB_CHECKS.items():
            if port not in ports:
                continue
            url = f"http://{host}:{port}{path}"
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False)  # nosemgrep
                if resp.status_code == 200 and marker in resp.text:
                    findings.append(
                        RawFinding(
                            title=f"Unauthenticated {db_name} - {host}",
                            vuln_class="CloudMisconfiguration",
                            target=url,
                            evidence=(
                                f"{db_name} responded without authentication.\n"
                                f"Response: {resp.text[:300]}"
                            ),
                            tool="exposed_services_check",
                            severity_hint=Severity.CRITICAL,
                        )
                    )
            except Exception as exc:
                logger.debug("%s check failed for %s: %s", db_name, host, exc)

        if 6379 in ports and _check_redis(host):
            findings.append(
                RawFinding(
                    title=f"Unauthenticated Redis - {host}",
                    vuln_class="CloudMisconfiguration",
                    target=f"redis://{host}:6379",
                    evidence="Redis responded to PING without authentication.",
                    tool="exposed_services_check",
                    severity_hint=Severity.CRITICAL,
                )
            )

    # --- Admin panels and sensitive files (one probe per unique origin) ---
    seen_origins: set[str] = set()
    for ep in recon.endpoints:
        origin = _origin(ep.url)
        if origin in seen_origins:
            continue
        seen_origins.add(origin)

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
                                evidence=f"HTTP 200 with admin-related content at {target_url}",
                                tool="exposed_services_check",
                                severity_hint=Severity.HIGH,
                            )
                        )
            except Exception as exc:
                logger.debug("Admin panel check failed for %s: %s", target_url, exc)

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
                            tool="exposed_services_check",
                            severity_hint=Severity.HIGH,
                        )
                    )
            except Exception as exc:
                logger.debug("Sensitive file check failed for %s: %s", target_url, exc)

    # --- Branded control panels on non-standard ports ---
    seen_panel_hosts: set[str] = set()
    for ep in recon.endpoints:
        hostname = urlparse(ep.url).hostname or ""
        if not hostname or hostname in seen_panel_hosts:
            continue
        seen_panel_hosts.add(hostname)

        for scheme, port, path, marker, panel_name in _PANEL_CHECKS:
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
                            title=f"Exposed {panel_name} Panel - {url}",
                            vuln_class="ExposedAdminPanel",
                            target=url,
                            evidence=f"HTTP 200 with {panel_name} content at {url}",
                            tool="exposed_services_check",
                            severity_hint=Severity.HIGH,
                        )
                    )
            except Exception as exc:
                logger.debug("%s panel check failed for %s: %s", panel_name, url, exc)

    logger.info("Exposed services check found %d findings", len(findings))
    return findings
