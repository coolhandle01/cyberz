"""HTTP wrappers that inject a traceable User-Agent on every outbound request.

Every tool that makes HTTP requests should call into this module rather than
``requests`` directly. The module-level wrappers (``get``, ``post``, etc.)
delegate to ``requests.<verb>`` underneath, so existing tests that patch
``requests.get`` continue to intercept calls without modification.

The User-Agent is built from operator config (platform, H1 username, contact
email) plus the optional per-run programme handle set via ``set_programme()``.
A SOC operator seeing this UA can verify the H1 username and programme handle
against their HackerOne dashboard and use the contact email to reach the
operator without having to ban the IP first. See issue #46.
"""

from __future__ import annotations

from typing import Any

import requests

from config import config

# Identifies the platform the squad operates against. Hardcoded for now;
# move to config when a second platform is supported.
_PLATFORM = "hackerone"

_current_programme: str | None = None


def set_programme(handle: str | None) -> None:
    """Set or clear the current programme handle for outbound UA attribution.

    Called by agent @tool wrappers that already deserialise a Programme or
    ReconResult. Subsequent HTTP calls in the same run - including from
    tools that only see Endpoint lists - inherit the programme context.
    """
    global _current_programme
    _current_programme = handle.strip() if handle else None


def get_programme() -> str | None:
    return _current_programme


def user_agent() -> str:
    """Build the current User-Agent string from operator + programme context."""
    parts = [f"platform: {_PLATFORM}"]
    if _current_programme:
        parts.append(f"programme: {_current_programme}")
    parts.append(f"researcher: {config.h1.api_username}")
    parts.append(f"contact: {config.contact_email}")
    return f"cybersquad (authorised research; {'; '.join(parts)})"


def _inject_headers(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Merge our User-Agent into the caller's headers dict.

    A caller-supplied User-Agent wins (test fixtures occasionally pin one),
    but the default for every request is our traceable UA.
    """
    headers = dict(kwargs.get("headers") or {})
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = user_agent()
    kwargs["headers"] = headers
    return kwargs


# Pass-through wrappers. Each delegates to requests.<verb> so existing test
# patches against ``requests.get`` and friends continue to intercept calls
# without modification. The timeout argument is part of the caller's contract
# (every call site we ship sets one), not the helper's job to default - hence
# the B113 suppression on each line.


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    return requests.request(method, url, **_inject_headers(kwargs))  # nosec B113


def get(url: str, **kwargs: Any) -> requests.Response:
    return requests.get(url, **_inject_headers(kwargs))  # nosec B113


def post(url: str, **kwargs: Any) -> requests.Response:
    return requests.post(url, **_inject_headers(kwargs))  # nosec B113


def put(url: str, **kwargs: Any) -> requests.Response:
    return requests.put(url, **_inject_headers(kwargs))  # nosec B113


def delete(url: str, **kwargs: Any) -> requests.Response:
    return requests.delete(url, **_inject_headers(kwargs))  # nosec B113


def head(url: str, **kwargs: Any) -> requests.Response:
    return requests.head(url, **_inject_headers(kwargs))  # nosec B113


def patch(url: str, **kwargs: Any) -> requests.Response:
    return requests.patch(url, **_inject_headers(kwargs))  # nosec B113


def options(url: str, **kwargs: Any) -> requests.Response:
    return requests.options(url, **_inject_headers(kwargs))  # nosec B113
