"""HTTP wrappers that inject a traceable User-Agent on every outbound request.

Every tool that makes HTTP requests should call into this module rather than
``requests`` directly. The module-level wrappers (``get``, ``post``, etc.)
delegate to ``requests.<verb>`` underneath, so existing tests that patch
``requests.get`` continue to intercept calls without modification.

The User-Agent is built from operator config (platform, H1 username, contact
email) plus the in-flight programme handle read from ``runtime.programme_handle``.
A SOC operator seeing this UA can verify the H1 username and programme handle
against their HackerOne dashboard and use the contact email to reach the
operator without having to ban the IP first. See issue #46.

There is no ``set_programme()`` registry: the Programme Manager has already
written ``runtime.programme_handle`` (and ``<run_dir>/programme.json``) before
any other tool fires an outbound request, so the UA builder reads workspace
state directly and every per-tool ``http.set_programme(...)`` call is gone.
"""

from __future__ import annotations

from typing import Any

import requests

import runtime
from config import config

# Identifies the platform the squad operates against. Hardcoded for now;
# move to config when a second platform is supported.
_PLATFORM = "hackerone"


def user_agent() -> str:
    """Build the current User-Agent string from operator + workspace context."""
    parts = [f"platform: {_PLATFORM}"]
    handle = runtime.programme_handle
    if handle:
        parts.append(f"programme: {handle}")
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
# without modification. Timeout is an explicit parameter so callers cannot
# accidentally omit it; the configured default applies when omitted.


def request(method: str, url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.request(method, url, timeout=_timeout, **_inject_headers(kwargs))


def get(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.get(url, timeout=_timeout, **_inject_headers(kwargs))


def post(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.post(url, timeout=_timeout, **_inject_headers(kwargs))


def put(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.put(url, timeout=_timeout, **_inject_headers(kwargs))


def delete(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.delete(url, timeout=_timeout, **_inject_headers(kwargs))


def head(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.head(url, timeout=_timeout, **_inject_headers(kwargs))


def patch(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.patch(url, timeout=_timeout, **_inject_headers(kwargs))


def options(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.options(url, timeout=_timeout, **_inject_headers(kwargs))
