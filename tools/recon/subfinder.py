"""Subdomain enumeration via subfinder."""

from __future__ import annotations

import logging

from config import config
from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)


def enumerate_subdomains(domain: str) -> list[str]:
    """Use subfinder to enumerate subdomains. Returns deduplicated hostnames."""
    subfinder = _require_binary("subfinder")
    result = _run(
        [subfinder, "-d", domain, "-silent", "-o", "/dev/stdout"],
        timeout=180,
    )
    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    logger.info("subfinder found %d subdomains for %s", len(subdomains), domain)
    return list(dict.fromkeys(subdomains))[: config.recon.max_subdomains]
