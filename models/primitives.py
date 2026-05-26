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


# ``HttpUrl`` - URL validation delegated to Pydantic's built-in
# ``pydantic.HttpUrl`` (the canonical RFC-3986 parser); runtime type
# stays ``str`` so every call site that does
# ``endpoint.url.startswith(...)`` / ``.lower()`` / ``urlparse(ep.url)``
# / f-string interpolation keeps working without an audit-and-migrate
# sweep across every consumer.
#
# Pydantic's HttpUrl reference:
# https://docs.pydantic.dev/2.12/api/networks/#pydantic.networks.HttpUrl
#
# Deliberate departure from upstream: ``pydantic.HttpUrl``'s runtime
# type is ``Url`` (a wrapper exposing ``.host`` / ``.scheme`` / ``.port``
# properties), not ``str``. The full migration to that shape is a
# separate piece of work tracked in FIXME(#163) - it requires auditing
# every ``ep.url.xxx`` / ``urlparse(ep.url)`` / ``ep.url`` set-membership
# call site (~50 across ``tools/pentest/*``) so each switches to
# ``str(ep.url)`` or to Url's structured accessors. Until then we get
# upstream-blessed URL validation here while consumers stay string-
# typed.


def _validate_endpoint_url(value: str) -> str:
    """Validate that ``value`` is a parseable HTTP / HTTPS URL.

    Delegates to ``pydantic.HttpUrl`` (canonical RFC-3986 parser,
    http/https scheme, valid host). Keeps the input as ``str`` so every
    downstream consumer that uses string methods on ``ep.url`` keeps
    working; see the module docstring for the runtime-type migration
    plan in FIXME(#163).

    One workaround sits in front of the upstream call: stdlib
    ``urlparse`` reports an empty netloc for ``https:///path``, but
    Pydantic interprets the same input as ``https://path/`` (treats the
    path segment as the host). That LLM-facing contract should reject
    the empty-authority case rather than silently probe a host called
    "path", so we look at ``urlparse(...).netloc`` first.
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
    _PydanticHttpUrl(cleaned)
    return cleaned


HttpUrl = Annotated[str, AfterValidator(_validate_endpoint_url)]
