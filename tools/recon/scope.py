"""Scope filtering for recon results."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from models.h1 import Programme, ScopeType

if TYPE_CHECKING:
    from models import Endpoint

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


def filter_endpoints_in_scope(
    endpoints: Sequence[Endpoint | Mapping[str, Any]], programme: Programme
) -> list[Endpoint | Mapping[str, Any]]:
    """Drop endpoints whose hostname is outside the programme's scope.

    Endpoint-shaped sibling of ``filter_in_scope``: extracts the host
    from each endpoint URL and delegates the in-scope decision to
    ``filter_in_scope`` so there is one scope check, not two. Lives
    here next to its sibling so every cloud / infra wrapper that
    declares ``scope_filter=("endpoints", filter_endpoints_in_scope)``
    shares the same canonical implementation.

    Accepts either ``Endpoint`` instances or mapping shapes (the form
    CrewAI hands the wrapper at runtime: ``args_schema`` validates,
    then ``model_dump()`` turns the typed value back into a dict before
    the wrapper body runs). The both-shapes adapter sits at the scope
    boundary so every endpoint-taking wrapper gets the same contract;
    individual wrappers still re-validate via ``_parse_endpoints``
    inside the body.
    """

    def _url(ep: Endpoint | Mapping[str, Any]) -> str:
        if isinstance(ep, Mapping):
            return str(ep["url"])
        return ep.url

    hosts = [extract_domain(_url(ep)) for ep in endpoints]
    in_scope = set(filter_in_scope(hosts, programme))
    return [ep for ep in endpoints if extract_domain(_url(ep)) in in_scope]
