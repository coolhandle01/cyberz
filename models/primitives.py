"""
models.primitives - foundational typed-string and enum primitives shared
across the model graph.

Both ``Severity`` and ``Hostname`` are leaf dependencies - they have no
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


# ``Hostname`` is the typed string every scope-guard input flows through.
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


def _validate_hostname(value: str) -> str:
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


Hostname = Annotated[str, AfterValidator(_validate_hostname)]


# ``HttpUrl`` validator - light flavour. Parses with ``urlparse``, enforces
# http / https scheme + a Hostname-valid host underneath. Keeps the runtime
# type as ``str`` so every call site that does ``endpoint.url.startswith(...)``
# or compares against a string literal keeps working. The agent sees "this
# is a string" in the JSON schema but mis-shaped URLs still reject at
# model_validate time.
#
# Deliberate: Pydantic's built-in ``HttpUrl`` would expose structured
# ``.host`` / ``.scheme`` / ``.port`` accessors, but the runtime type would
# stop being ``str``. Every ``urlparse(ep.url)`` / f-string / dict-key
# consumer would have to switch in lockstep, and that audit-and-migrate
# cost is intentionally not paid here - the light validator catches the
# mis-shaped-URL risk class at args_schema time, which is what the typed
# primitive layer exists to do.


def _validate_endpoint_url(value: str) -> str:
    """Validate that ``value`` is a parseable HTTP / HTTPS URL with a valid
    ``Hostname`` underneath.

    Keeps the input as ``str`` (no canonicalisation - the caller already
    constructed the URL deliberately and we do not want to silently rewrite
    it). The hostname component runs through ``_validate_hostname`` so the
    RFC 1123 contract is enforced at the URL layer too: a malformed
    hostname inside the URL rejects the same as a bare malformed hostname.

    IPv6-bound URLs (``https://[2001:db8::1]/...``) reject: ``urlparse``
    returns the bare ``2001:db8::1`` from ``.hostname`` (brackets dropped),
    and the ``:`` in the address fails the ``Hostname`` per-label regex.
    HackerOne programmes name DNS-bound assets in structured scope, so the
    rejection is acceptable; a future contributor seeing an IPv6 reject
    here should not be surprised by it.
    """
    from urllib.parse import urlparse  # local import: only fires at validation time

    if not isinstance(value, str):
        raise ValueError(f"url must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("url cannot be empty")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"url must use http or https scheme: {value!r}")
    if not parsed.hostname:
        raise ValueError(f"url must include a hostname: {value!r}")
    # Validate the hostname through the same RFC 1123 contract Hostname uses;
    # this catches mis-shaped hosts inside an otherwise URL-shaped string.
    _validate_hostname(parsed.hostname)
    return cleaned


HttpUrl = Annotated[str, AfterValidator(_validate_endpoint_url)]
