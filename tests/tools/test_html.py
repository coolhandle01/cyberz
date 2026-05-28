"""tests/tools/test_html.py - unit tests for tools/html.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models.framework import Framework
from tools import html

pytestmark = pytest.mark.unit

_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
_JSON_CT = {"Content-Type": "application/json"}


@pytest.fixture
def make_page(make_response, target_apex):
    """Build a Webpage from a soup body + optional cookies / url overrides.

    Single source of truth across the Webpage test classes - avoids the
    "three slightly-different _page helpers" trap. ``body`` always lands
    on ``response.text`` AND is the HTML the soup is parsed from, so
    response and soup stay consistent. The default page URL derives from
    ``target_apex`` so the suite's single-knob retargeting still holds.
    """

    def _build(
        body: str = "",
        cookies: dict | None = None,
        url: str | None = None,
    ) -> html.Webpage:
        resolved_url = url if url is not None else f"https://{target_apex}/"
        resp = make_response(body=body, headers=_HTML_CT, cookies=cookies, url=resolved_url)
        return html.Webpage(response=resp)

    return _build


class TestFetch:
    def test_returns_webpage_with_response_and_soup(self, target_apex, make_response) -> None:
        from bs4 import BeautifulSoup

        resp = make_response(body="<html><body>hi</body></html>", headers=_HTML_CT)
        with patch("requests.get", return_value=resp):
            page = html.fetch(f"https://{target_apex}/")

        assert isinstance(page, html.Webpage)
        assert isinstance(page.response, MagicMock)
        assert isinstance(page.soup, BeautifulSoup)

    def test_soup_contains_parsed_html(self, target_apex, make_response) -> None:
        body = "<html><body><h1>Hello</h1></body></html>"
        with patch("requests.get", return_value=make_response(body=body, headers=_HTML_CT)):
            page = html.fetch(f"https://{target_apex}/")

        h1 = page.soup.find("h1")
        assert h1 is not None
        assert h1.text == "Hello"

    def test_empty_soup_for_non_html_content_type(self, target_apex, make_response) -> None:
        resp = make_response(body='{"key": "val"}', headers=_JSON_CT)
        with patch("requests.get", return_value=resp):
            page = html.fetch(f"https://{target_apex}/api")

        assert page.soup.find() is None

    def test_empty_soup_when_content_type_missing(self, target_apex, make_response) -> None:
        resp = make_response(body="<html><body>hi</body></html>", headers={})
        with patch("requests.get", return_value=resp):
            page = html.fetch(f"https://{target_apex}/")

        assert page.soup.find() is None

    def test_kwargs_forwarded_to_http_get(self, target_apex, make_response) -> None:
        with patch("requests.get", return_value=make_response()) as mock_get:
            html.fetch(f"https://{target_apex}/", allow_redirects=True)

        assert mock_get.call_args.kwargs.get("allow_redirects") is True

    def test_caller_timeout_forwarded(self, target_apex, make_response) -> None:
        with patch("requests.get", return_value=make_response()) as mock_get:
            html.fetch(f"https://{target_apex}/", timeout=5)

        assert mock_get.call_args.kwargs.get("timeout") == 5

    def test_response_is_returned_unchanged(self, target_apex, make_response) -> None:
        mock_resp = make_response(body="<p>content</p>", headers=_HTML_CT)
        with patch("requests.get", return_value=mock_resp):
            page = html.fetch(f"https://{target_apex}/")

        assert page.response is mock_resp


class TestWebpageCsrfSignals:
    """Cookie- and meta-tag-based CSRF protection detection."""

    @pytest.mark.parametrize(
        "cookies",
        [
            {"csrftoken": "abc"},  # Django
            {"XSRF-TOKEN": "abc"},  # Angular / Laravel
            {"_xsrf": "abc"},  # Tornado
            {"xsrf-token": "abc"},  # case-insensitive match
        ],
    )
    def test_has_csrf_cookie_true(self, make_page, cookies) -> None:
        assert make_page(cookies=cookies).has_csrf_cookie()

    @pytest.mark.parametrize(
        "cookies",
        [
            None,
            {"sessionid": "abc"},
            {"JSESSIONID": "abc"},
        ],
    )
    def test_has_csrf_cookie_false(self, make_page, cookies) -> None:
        assert not make_page(cookies=cookies).has_csrf_cookie()

    @pytest.mark.parametrize(
        "body",
        [
            '<meta name="csrf-token" content="abc">',  # Rails / Spring
            '<meta name="_csrf" content="abc">',
            '<meta name="xsrf-token" content="abc">',
            '<meta name="CSRF-Token" content="abc">',  # case-insensitive
        ],
    )
    def test_has_csrf_meta_tag_true(self, make_page, body) -> None:
        assert make_page(body=body).has_csrf_meta_tag()

    @pytest.mark.parametrize(
        "body",
        [
            "<html></html>",
            '<meta name="description" content="abc">',
            '<meta name="viewport" content="width=device-width">',
        ],
    )
    def test_has_csrf_meta_tag_false(self, make_page, body) -> None:
        assert not make_page(body=body).has_csrf_meta_tag()

    def test_page_protected_true_via_cookie(self, make_page) -> None:
        assert make_page(cookies={"csrftoken": "abc"}).page_protected

    def test_page_protected_true_via_meta(self, make_page) -> None:
        assert make_page(body='<meta name="csrf-token" content="abc">').page_protected

    def test_page_protected_false_when_neither(self, make_page) -> None:
        assert not make_page(body="<html></html>").page_protected


class TestWebpageFrameworks:
    """High-confidence Framework detection via cookies + meta tags."""

    @pytest.mark.parametrize(
        ("cookies", "body", "expected"),
        [
            # Unambiguous cookie signals
            ({"csrftoken": "abc"}, "", {Framework.django}),
            ({"_xsrf": "abc"}, "", {Framework.tornado}),
            # Unambiguous meta signal
            (None, '<meta name="csrf-param" content="auth_token">', {Framework.rails}),
            # Ambiguous - typed channel stays empty even though page_protected flips
            ({"XSRF-TOKEN": "abc"}, "", set()),
            (None, '<meta name="csrf-token" content="abc">', set()),
            # No signals
            (None, "<html></html>", set()),
        ],
    )
    def test_detection(self, make_page, cookies, body, expected) -> None:
        page = make_page(body=body, cookies=cookies)
        assert page.frameworks == expected

    def test_ambiguous_signals_still_drive_page_protected(self, make_page) -> None:
        # XSRF-TOKEN (Angular OR Laravel) emits no typed Framework but
        # still raises the page_protected flag - the suppression rule in
        # CSRF Tier 1 depends on this.
        page = make_page(cookies={"XSRF-TOKEN": "abc"})
        assert page.frameworks == set()
        assert page.page_protected


class TestWebpageForms:
    """Form parsing on the Webpage shape."""

    def test_post_forms_picks_only_post(self, make_page) -> None:
        page = make_page(
            body=(
                '<form method="get" action="/search"></form>'
                '<form method="post" action="/submit"></form>'
            ),
        )
        assert len(page.post_forms) == 1
        assert page.post_forms[0].action == "/submit"

    def test_get_forms_picks_only_get(self, make_page) -> None:
        page = make_page(
            body=(
                '<form method="get" action="/search"></form>'
                '<form method="post" action="/submit"></form>'
            ),
        )
        assert len(page.get_forms) == 1
        assert page.get_forms[0].action == "/search"

    def test_default_method_is_get(self, make_page) -> None:
        page = make_page(body='<form action="/x"></form>')
        assert page.forms[0].method == "get"
        assert page.get_forms == page.forms
        assert page.post_forms == []

    @pytest.mark.parametrize(
        ("action_attr", "expected_resolved_template"),
        [
            ("/submit", "https://{apex}/submit"),
            ("", "https://{apex}/page"),
            ("https://other.example.org/x", "https://other.example.org/x"),
        ],
    )
    def test_resolved_action(
        self, make_page, target_apex, action_attr, expected_resolved_template
    ) -> None:
        action_html = f' action="{action_attr}"' if action_attr else ""
        page = make_page(
            body=f'<form method="post"{action_html}></form>',
            url=f"https://{target_apex}/page",
        )
        assert page.post_forms[0].resolved_action == expected_resolved_template.format(
            apex=target_apex
        )

    @pytest.mark.parametrize(
        ("input_html", "expected_has_csrf"),
        [
            ('<input type="hidden" name="csrf_token" value="abc">', True),
            ('<input type="hidden" name="authenticity_token" value="abc">', True),
            ('<input type="text" name="csrf_token" value="abc">', False),
            ('<input type="hidden" name="user_id" value="abc">', False),
        ],
    )
    def test_has_csrf_input(self, make_page, input_html, expected_has_csrf) -> None:
        page = make_page(body=f'<form method="post" action="/x">{input_html}</form>')
        assert page.post_forms[0].has_csrf_input is expected_has_csrf

    def test_forms_cached(self, make_page) -> None:
        page = make_page(body='<form method="post" action="/x"></form>')
        first = page.forms
        second = page.forms
        assert first is second


class TestWebpageScripts:
    """<script src="..."> parsing on the Webpage shape."""

    def test_picks_up_scripts_with_src(self, make_page) -> None:
        page = make_page(
            body='<script src="/app.js"></script><script>inline()</script>',
        )
        assert len(page.scripts) == 1
        assert page.scripts[0].url == "/app.js"

    def test_resolved_url(self, make_page, target_apex) -> None:
        page = make_page(
            body='<script src="/app.js"></script>',
            url=f"https://{target_apex}/page",
        )
        assert page.scripts[0].resolved_url == f"https://{target_apex}/app.js"

    def test_absolute_url_unchanged(self, make_page) -> None:
        page = make_page(body='<script src="https://cdn.example.org/lib.js"></script>')
        assert page.scripts[0].resolved_url == "https://cdn.example.org/lib.js"

    @pytest.mark.parametrize(
        ("integrity_attr", "expected"),
        [
            (' integrity="sha384-abc"', True),
            ("", False),
            (' integrity=""', False),
        ],
    )
    def test_has_integrity(self, make_page, integrity_attr, expected) -> None:
        page = make_page(body=f'<script src="/a.js"{integrity_attr}></script>')
        assert page.scripts[0].has_integrity is expected

    def test_cached(self, make_page) -> None:
        page = make_page(body='<script src="/a.js"></script>')
        assert page.scripts is page.scripts


class TestWebpageJavascripts:
    """``.js``-filtered subset of ``page.scripts``."""

    def test_includes_js_extension(self, make_page) -> None:
        page = make_page(body='<script src="/app.js"></script>')
        assert len(page.javascripts) == 1

    def test_includes_mjs_extension(self, make_page) -> None:
        # ES modules - browsers serve these natively in production.
        page = make_page(body='<script src="/module.mjs"></script>')
        assert len(page.javascripts) == 1

    def test_includes_js_with_query_string(self, make_page) -> None:
        page = make_page(body='<script src="/app.js?v=2"></script>')
        assert len(page.javascripts) == 1

    def test_excludes_source_formats(self, make_page) -> None:
        # .jsx / .ts / .tsx get transpiled at build time - production
        # targets do not serve them, so they stay out of the filter.
        page = make_page(
            body=(
                '<script src="/app.jsx"></script>'
                '<script src="/app.ts"></script>'
                '<script src="/app.tsx"></script>'
            ),
        )
        assert page.javascripts == []

    def test_excludes_non_js(self, make_page) -> None:
        page = make_page(
            body=(
                '<script src="/app.js"></script>'
                '<script src="/widget.cgi"></script>'
                '<script src="/api/v1/widget"></script>'
            ),
        )
        assert len(page.javascripts) == 1
        assert page.javascripts[0].url == "/app.js"

    def test_scripts_still_includes_all(self, make_page) -> None:
        # The unfiltered set stays available for SRI's broader coverage.
        page = make_page(
            body='<script src="/app.js"></script><script src="/widget.cgi"></script>',
        )
        assert len(page.scripts) == 2


class TestWebpageStylesheets:
    """<link rel="stylesheet" href="..."> parsing on the Webpage shape."""

    def test_picks_up_stylesheets(self, make_page) -> None:
        page = make_page(body='<link rel="stylesheet" href="/style.css">')
        assert len(page.stylesheets) == 1
        assert page.stylesheets[0].url == "/style.css"

    def test_ignores_non_stylesheet_links(self, make_page) -> None:
        page = make_page(
            body=('<link rel="icon" href="/favicon.ico"><link rel="canonical" href="/canonical">'),
        )
        assert page.stylesheets == []

    def test_resolved_url(self, make_page, target_apex) -> None:
        page = make_page(
            body='<link rel="stylesheet" href="/style.css">',
            url=f"https://{target_apex}/page",
        )
        assert page.stylesheets[0].resolved_url == f"https://{target_apex}/style.css"

    @pytest.mark.parametrize(
        ("integrity_attr", "expected"),
        [
            (' integrity="sha384-abc"', True),
            ("", False),
        ],
    )
    def test_has_integrity(self, make_page, integrity_attr, expected) -> None:
        page = make_page(
            body=f'<link rel="stylesheet" href="/style.css"{integrity_attr}>',
        )
        assert page.stylesheets[0].has_integrity is expected

    def test_skips_link_without_href(self, make_page) -> None:
        page = make_page(body='<link rel="stylesheet">')
        assert page.stylesheets == []
