"""Scope filtering for recon results."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from models import Programme, ScopeType

logger = logging.getLogger(__name__)


def extract_domain(identifier: str) -> str:
    """Pull the hostname out of a URL or bare hostname string."""
    parsed = urlparse(identifier if "://" in identifier else f"http://{identifier}")
    return parsed.hostname or identifier


def filter_in_scope(hosts: list[str], programme: Programme) -> list[str]:
    """
    Return only hosts that fall within the programme's declared in-scope assets.
    Uses exact-match or dot-boundary check to prevent subdomain confusion attacks.
    """
    allowed: list[str] = []
    for host in hosts:
        for scope_item in programme.in_scope:
            if scope_item.asset_type not in (ScopeType.URL, ScopeType.WILDCARD):
                continue
            pattern = scope_item.asset_identifier.lstrip("*.")
            if host == pattern or host.endswith("." + pattern):
                allowed.append(host)
                break
    logger.info(
        "Scope filter: %d/%d hosts in scope for %s",
        len(allowed),
        len(hosts),
        programme.handle,
    )
    return allowed
