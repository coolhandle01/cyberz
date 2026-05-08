"""Port scanning via nmap."""

from __future__ import annotations

import logging

from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)


def port_scan(hosts: list[str]) -> dict[str, list[int]]:
    """Run a lightweight nmap TCP SYN scan on common ports. Returns {host: [open_ports]}."""
    nmap = _require_binary("nmap")
    results: dict[str, list[int]] = {}
    for host in hosts:
        result = _run([nmap, "-sS", "--open", "-T4", "-F", "-oG", "-", host], timeout=60)
        open_ports: list[int] = []
        for line in result.stdout.splitlines():
            if "Ports:" in line:
                for token in line.split():
                    if "/open/" in token:
                        try:
                            open_ports.append(int(token.split("/")[0]))
                        except ValueError:
                            pass
        results[host] = open_ports
        logger.info("nmap: %s -> %s", host, open_ports)
    return results
