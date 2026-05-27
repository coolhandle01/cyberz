"""HTML fetch-and-parse helper.

Wraps ``http.get`` and returns a ``Webpage`` that bundles the response,
parsed soup, framework-detection result, and form / cookie recipes
probes used to inline. Probes get a typed page object and ask it
questions; the soup mechanics stay here.

The framework-detection signals live next to the soup recipes (rather
than in ``tools/http.py`` or a separate ``tools/framework.py``)
because they operate on the (response, soup) pair this module owns.
The pure transport layer in ``tools/http.py`` stays free of model
knowledge.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from models.framework import Framework
from tools import http

# Name fragments that suggest a CSRF protection token. Lifted from
# tools/pentest/csrf.py at the framework-aware-PT refactor so the soup
# recipes live one layer up from probe code; the probe consumes Webpage.
_CSRF_NAME_FRAGMENTS = (
    "csrf",
    "token",
    "_token",
    "authenticity_token",
    "nonce",
    "xsrf",
)

# High-confidence framework signals from response cookies. Cookie-name
# match is exact, case-insensitive. Ambiguous signals (XSRF-TOKEN
# cookie matches both Angular and Laravel) are deliberately NOT mapped
# here - they still drive the generic page_protected boolean via the
# fragment-based check above, but the typed channel stays clean.
_FRAMEWORK_COOKIE_SIGNALS: tuple[tuple[Framework, str], ...] = (
    (Framework.django, "csrftoken"),
    (Framework.tornado, "_xsrf"),
)

# High-confidence framework signals from <meta> tags. Rails ships
# `<meta name="csrf-param">` alongside `csrf-token`, distinguishing it
# from Spring (csrf-token only) - so csrf-param is the Rails-specific
# tell. Plain `csrf-token` meta stays unmapped (Rails or Spring; cannot
# tell apart here).
_FRAMEWORK_META_SIGNALS: tuple[tuple[Framework, str], ...] = ((Framework.rails, "csrf-param"),)


@dataclass(frozen=True)
class Form:
    """One <form> element observed on a page.

    ``resolved_action`` is the form's action URL computed at parse time
    against the page URL so probes do not have to ``urljoin`` at every
    call site. ``has_csrf_input`` is True when the form contains a
    hidden input whose name matches any CSRF-pattern fragment.
    """

    action: str  # raw action attribute, may be empty
    resolved_action: str  # action resolved relative to the page URL
    method: str  # "get" / "post" / ... (lower-cased)
    has_csrf_input: bool


class Webpage:
    """One fetched HTML page wrapping response, soup, and derived recipes.

    Constructed via ``tools.html.fetch(url, ...)``. The underlying
    ``response`` and ``soup`` are exposed as attributes for probes
    that need raw access; derived page properties are
    ``cached_property`` so a probe asking for ``post_forms`` and
    ``frameworks`` only pays the parse cost once.

    Not a frozen dataclass: ``cached_property`` writes to the instance.
    Consumers should treat the instance as immutable - tests construct
    a fresh Webpage per case rather than mutating a shared one.
    """

    def __init__(self, response: requests.Response, soup: BeautifulSoup) -> None:
        self.response = response
        self.soup = soup

    @property
    def url(self) -> str:
        """The page URL (post-redirect, from the underlying response)."""
        return self.response.url

    @cached_property
    def frameworks(self) -> set[Framework]:
        """Frameworks detected from cookies + meta tags.

        Only high-confidence signals (see ``_FRAMEWORK_COOKIE_SIGNALS``
        / ``_FRAMEWORK_META_SIGNALS``) emit. Ambiguous signals drive
        ``page_protected`` but not this typed set.
        """
        return _detect_frameworks(self.response, self.soup)

    def has_csrf_cookie(self) -> bool:
        """True if the response sets a cookie with a CSRF-pattern name.

        The double-submit cookie pattern (Angular's XSRF-TOKEN,
        Django's csrftoken, Tornado's _xsrf) protects POSTs without
        hidden form inputs - JS reads the cookie and sends its value
        back as a custom request header.
        """
        for name in self.response.cookies.keys():
            if any(frag in name.lower() for frag in _CSRF_NAME_FRAGMENTS):
                return True
        return False

    def has_csrf_meta_tag(self) -> bool:
        """True if the page contains a <meta> tag carrying a CSRF token.

        Rails, Spring, and other frameworks place the CSRF token in a
        ``<meta name="csrf-token" content="...">`` element; the
        framework's JS reads it from the DOM and sends it as a request
        header. Forms on such pages are protected even without hidden
        inputs.
        """
        for meta in self.soup.find_all("meta"):
            name = (meta.get("name") or "").lower()
            if any(frag in name for frag in _CSRF_NAME_FRAGMENTS):
                return True
        return False

    @cached_property
    def page_protected(self) -> bool:
        """True if a CSRF-pattern cookie OR meta tag is present.

        Use this to suppress the "missing CSRF token in form" finding
        on pages where the framework provides JS-side CSRF protection
        without a hidden input. Per-view bypasses (Django ``@csrf_exempt``,
        Rails ``skip_before_action``, Spring ``csrf().disable()``,
        Laravel ``$except``) mean this signal cannot be trusted to
        cover every route - the Origin-validation probe must still
        fire even on protected pages.
        """
        return self.has_csrf_cookie() or self.has_csrf_meta_tag()

    @cached_property
    def forms(self) -> list[Form]:
        """All <form> elements on the page (any method)."""
        out: list[Form] = []
        for form_el in self.soup.find_all("form"):
            method = (form_el.get("method") or "get").lower()
            action = form_el.get("action") or ""
            resolved = urljoin(self.url, action) if action else self.url
            has_csrf = any(
                (inp.get("type") or "").lower() == "hidden"
                and any(frag in (inp.get("name") or "").lower() for frag in _CSRF_NAME_FRAGMENTS)
                for inp in form_el.find_all("input")
            )
            out.append(
                Form(
                    action=action,
                    resolved_action=resolved,
                    method=method,
                    has_csrf_input=has_csrf,
                )
            )
        return out

    @cached_property
    def post_forms(self) -> list[Form]:
        """All <form method="post"> elements on the page."""
        return [f for f in self.forms if f.method == "post"]

    @cached_property
    def get_forms(self) -> list[Form]:
        """All <form method="get"> elements on the page."""
        return [f for f in self.forms if f.method == "get"]


def _detect_frameworks(response: requests.Response, soup: BeautifulSoup) -> set[Framework]:
    """Detect frameworks from response cookies and HTML meta tags.

    Only the high-confidence signals in ``_FRAMEWORK_COOKIE_SIGNALS``
    and ``_FRAMEWORK_META_SIGNALS`` emit. Ambiguous CSRF-pattern
    signals (XSRF-TOKEN cookie, plain csrf-token meta) drive
    ``Webpage.page_protected`` but are deliberately not mapped to a
    specific Framework here - too many candidates per signal.
    """
    detected: set[Framework] = set()
    cookie_names = {name.lower() for name in response.cookies.keys()}
    for fw, signal in _FRAMEWORK_COOKIE_SIGNALS:
        if signal in cookie_names:
            detected.add(fw)
    meta_names = {(m.get("name") or "").lower() for m in soup.find_all("meta")}
    for fw, signal in _FRAMEWORK_META_SIGNALS:
        if signal in meta_names:
            detected.add(fw)
    return detected


def fetch(url: str, **kwargs: object) -> Webpage:
    """GET url and parse the response body as HTML, returning a Webpage.

    Use this instead of calling http.get + BeautifulSoup separately.
    Pass any http.get kwargs (timeout, allow_redirects, headers, etc.)
    through.

    The returned Webpage exposes ``response``, ``soup``, plus
    cached_property accessors for derived page properties
    (``frameworks``, ``page_protected``, ``forms``, ``post_forms``,
    ``get_forms``). When the Content-Type is not text/html the soup is
    empty and the derived properties return their natural empty values.
    """
    resp = http.get(url, **kwargs)  # type: ignore[arg-type]
    ct = resp.headers.get("Content-Type", "")
    body = resp.text if "text/html" in ct else ""
    return Webpage(response=resp, soup=BeautifulSoup(body, "html.parser"))
