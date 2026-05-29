"""
models.primitives - foundational typed-string and enum primitives shared
across the model graph.

Both ``Severity`` and ``FQDN`` are leaf dependencies - they have no
forward references into other model modules - so they live in the
deepest layer of the package. ``models.finding``, ``models.asset``,
``models.h1`` and the rest depend on them; nothing here depends on the
others.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ``FQDN`` is the typed string every scope-guard input flows through.
# Using ``Annotated[str, AfterValidator(...)]`` keeps the runtime type as
# ``str`` (anything expecting ``str`` keeps working) while pydantic applies
# the validator at model_validate time - so the schema rejects URLs / ports /
# paths / garbage upstream of any DNS or HTTP request.
#
# The validator is intentionally strict: it rejects a value the moment it
# stops looking like a bare RFC 1123 hostname. The agent occasionally hands
# us a URL where we asked for a hostname; the strict reject is the signal
# that surfaces the mismatch, instead of the scope filter silently dropping
# the value and the run going quiet.

_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")


def _validate_fqdn(value: str) -> str:
    """Normalise and validate a hostname per RFC 1123.

    Lowercases and strips, then enforces: non-empty, no scheme (``://``),
    no path (``/``), no port (``:``), total <= 253 chars, every dot-
    separated label is 1-63 chars of alphanumerics or hyphens with no
    leading or trailing hyphen. Returns the normalised value so downstream
    comparisons are case-insensitive without each call site re-lowering.
    """
    if not isinstance(value, str):
        raise ValueError(f"hostname must be a string, got {type(value).__name__}")
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("hostname cannot be empty")
    if "://" in cleaned:
        raise ValueError(f"hostname must not include a scheme: {value!r}")
    if "/" in cleaned:
        raise ValueError(f"hostname must not include a path: {value!r}")
    if ":" in cleaned:
        raise ValueError(f"hostname must not include a port: {value!r}")
    if len(cleaned) > 253:
        raise ValueError(f"hostname too long ({len(cleaned)} > 253 chars)")
    for label in cleaned.split("."):
        if not _HOSTNAME_LABEL_RE.match(label):
            raise ValueError(f"invalid hostname label {label!r} in {value!r}")
    return cleaned


FQDN = Annotated[str, AfterValidator(_validate_fqdn)]


# ``HttpUrl`` - URL validation delegated to Pydantic's built-in
# ``pydantic.HttpUrl`` (the canonical RFC-3986 parser); runtime type
# stays ``str`` so every call site that does
# ``endpoint.url.startswith(...)`` / ``.lower()`` / ``urlparse(ep.url)``
# / f-string interpolation keeps working with no audit tax.
#
# Pydantic's HttpUrl reference:
# https://docs.pydantic.dev/2.12/api/networks/#pydantic.networks.HttpUrl
#
# Deliberate departure from upstream: ``pydantic.HttpUrl``'s runtime
# type is ``Url`` (a wrapper exposing ``.host`` / ``.scheme`` / ``.port``
# properties), not ``str``. We keep the ``str`` runtime intentionally:
# the structured accessors are mostly cosmetic wins, and migrating
# would force ``str(ep.url)`` at every f-string / dict-key / comparison
# site (~50 across ``tools/pentest/*``) plus a cascade through
# ``RawFinding.target`` and siblings. Cite: #163 closed as not-planned.


def _validate_endpoint_url(value: str) -> str:
    """Validate that ``value`` is a parseable HTTP / HTTPS URL.

    URL shape (scheme / authority / RFC-3986 well-formedness) delegates
    to ``pydantic.HttpUrl``; the host component then runs through
    ``_validate_fqdn`` so RFC 1123 hostname strictness (no leading
    hyphens, no oversized labels) holds inside URLs too. The FQDN
    primitive guards "the LLM handed us a URL when we asked for a
    hostname" - the same RFC 1123 contract should hold when a hostname
    is wrapped in a URL, otherwise ``-evil.example.com`` rejects but
    ``https://-evil.example.com`` doesn't, giving the LLM a trivial
    bypass. Defense-in-depth, not belt-and-braces.

    Keeps the input as ``str`` so every downstream consumer that uses
    string methods on ``ep.url`` keeps working; see the module
    docstring above for why the ``str`` runtime is intentional.

    One workaround sits in front of the upstream call: stdlib
    ``urlparse`` reports an empty netloc for ``https:///path``, but
    Pydantic interprets the same input as ``https://path/`` (treats
    the path segment as the host). That LLM-facing contract should
    reject the empty-authority case rather than silently probe a host
    called "path".
    """
    from urllib.parse import urlparse

    from pydantic import HttpUrl as _PydanticHttpUrl

    if not isinstance(value, str):
        raise ValueError(f"url must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("url cannot be empty")
    if not urlparse(cleaned).netloc:
        raise ValueError(f"url must include an authority component: {value!r}")
    # Pydantic raises ``ValidationError`` on RFC-3986 violations; the
    # AfterValidator chain propagates it to the calling model as a
    # field-level error.
    parsed = _PydanticHttpUrl(cleaned)
    if parsed.host:
        _validate_fqdn(parsed.host)
    return cleaned


HttpUrl = Annotated[str, AfterValidator(_validate_endpoint_url)]


# ``IPAddress`` - typed string for an IPv4 or IPv6 address. Validates
# via stdlib ``ipaddress.ip_address`` (handles both versions; rejects
# malformed strings, CIDR notation, hostnames). Keeps the runtime as
# ``str`` to match the ``FQDN`` / ``HttpUrl`` convention - every
# consumer that does ``f"https://{ip}"`` / ``ip.startswith(...)`` /
# dict-key works without coercion. The ASN-lookup (`tools/recon/asn.py`
# via Team Cymru) and the future amass ``IPAddress`` asset type both
# read this primitive at the boundary.
#
# Deliberately separate from `FQDN` even though both end up in
# DNS-resolution paths: the validators are mutually exclusive (a string
# is either a valid IP literal or a valid hostname, never both), so
# union-typing them would let one slip past the wrong validator. Two
# primitives, two strict gates.


def _validate_ip_address(value: str) -> str:
    """Validate that ``value`` is a parseable IPv4 or IPv6 address literal.

    Delegates to stdlib ``ipaddress.ip_address``. Rejects:

    * CIDR notation (``1.2.3.0/24``) - that is a netblock, not an IP
    * FQDNs (``example.com``) - validator-distinct from ``FQDN``
    * IPv6 zone identifiers (``fe80::1%eth0``) - link-local scope IDs
      are not stable across hosts and shouldn't appear in recon JSON
    * Empty / whitespace-only input

    Returns the normalised form from ``ipaddress.ip_address`` so equality
    holds across input variations (``::1`` and ``0:0:0:0:0:0:0:1`` both
    resolve to the same canonical string).
    """
    import ipaddress

    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"IP address must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("IP address cannot be empty")
    if "/" in cleaned:
        raise ValueError(f"IP address must not include CIDR notation: {value!r}")
    if "%" in cleaned:
        raise ValueError(f"IP address must not include IPv6 zone identifier: {value!r}")
    try:
        parsed = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid IP address {value!r}: {exc}") from exc
    return str(parsed)


IPAddress = Annotated[str, AfterValidator(_validate_ip_address)]
