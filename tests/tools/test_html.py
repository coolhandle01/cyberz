"""tests/tools/test_html.py - unit tests for tools/html.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models.framework import Framework
from tools import html

pytestmark = pytest.mark.unit


_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}


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
        resp = make_response(body='{"key": "val"}', headers={"Content-Type": "application/json"})
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

    def _page(self, soup_html: str = "", cookies: dict | None = None) -> html.Webpage:
        from bs4 import BeautifulSoup

        resp = MagicMock()
        resp.cookies = cookies or {}
        resp.url = "https://example.com/"
        return html.Webpage(response=resp, soup=BeautifulSoup(soup_html, "html.parser"))

    def test_has_csrf_cookie_django(self) -> None:
        assert self._page(cookies={"csrftoken": "abc"}).has_csrf_cookie()

    def test_has_csrf_cookie_angular(self) -> None:
        assert self._page(cookies={"XSRF-TOKEN": "abc"}).has_csrf_cookie()

    def test_has_csrf_cookie_tornado(self) -> None:
        assert self._page(cookies={"_xsrf": "abc"}).has_csrf_cookie()

    def test_has_csrf_cookie_false_on_unrelated(self) -> None:
        assert not self._page(cookies={"sessionid": "abc"}).has_csrf_cookie()

    def test_has_csrf_meta_tag_rails(self) -> None:
        assert self._page('<meta name="csrf-token" content="abc">').has_csrf_meta_tag()

    def test_has_csrf_meta_tag_false_on_unrelated(self) -> None:
        assert not self._page('<meta name="description" content="abc">').has_csrf_meta_tag()

    def test_page_protected_true_via_cookie(self) -> None:
        assert self._page(cookies={"csrftoken": "abc"}).page_protected

    def test_page_protected_true_via_meta(self) -> None:
        assert self._page('<meta name="csrf-token" content="abc">').page_protected

    def test_page_protected_false_when_neither(self) -> None:
        assert not self._page("<html></html>").page_protected


class TestWebpageFrameworks:
    """High-confidence Framework detection via cookies + meta tags."""

    def _page(self, soup_html: str = "", cookies: dict | None = None) -> html.Webpage:
        from bs4 import BeautifulSoup

        resp = MagicMock()
        resp.cookies = cookies or {}
        resp.url = "https://example.com/"
        return html.Webpage(response=resp, soup=BeautifulSoup(soup_html, "html.parser"))

    def test_django_via_csrftoken_cookie(self) -> None:
        assert self._page(cookies={"csrftoken": "abc"}).frameworks == {Framework.django}

    def test_tornado_via_xsrf_cookie(self) -> None:
        assert self._page(cookies={"_xsrf": "abc"}).frameworks == {Framework.tornado}

    def test_rails_via_csrf_param_meta(self) -> None:
        soup_html = '<meta name="csrf-param" content="auth_token">'
        assert self._page(soup_html).frameworks == {Framework.rails}

    def test_xsrf_token_cookie_stays_unmapped(self) -> None:
        # Ambiguous between Angular and Laravel - the typed channel
        # stays empty even though page_protected still flips.
        page = self._page(cookies={"XSRF-TOKEN": "abc"})
        assert page.frameworks == set()
        assert page.page_protected

    def test_plain_csrf_token_meta_stays_unmapped(self) -> None:
        # Ambiguous between Rails and Spring - same rule.
        page = self._page('<meta name="csrf-token" content="abc">')
        assert page.frameworks == set()
        assert page.page_protected

    def test_empty_when_no_signals(self) -> None:
        assert self._page("<html></html>").frameworks == set()


class TestWebpageForms:
    """Form parsing on the Webpage shape."""

    def _page(self, soup_html: str, page_url: str = "https://example.com/") -> html.Webpage:
        from bs4 import BeautifulSoup

        resp = MagicMock()
        resp.cookies = {}
        resp.url = page_url
        return html.Webpage(response=resp, soup=BeautifulSoup(soup_html, "html.parser"))

    def test_post_forms_picks_only_post(self) -> None:
        soup_html = (
            '<form method="get" action="/search"></form>'
            '<form method="post" action="/submit"></form>'
        )
        page = self._page(soup_html)
        assert len(page.post_forms) == 1
        assert page.post_forms[0].action == "/submit"

    def test_get_forms_picks_only_get(self) -> None:
        soup_html = (
            '<form method="get" action="/search"></form>'
            '<form method="post" action="/submit"></form>'
        )
        page = self._page(soup_html)
        assert len(page.get_forms) == 1
        assert page.get_forms[0].action == "/search"

    def test_default_method_is_get(self) -> None:
        page = self._page('<form action="/x"></form>')
        assert page.forms[0].method == "get"
        assert page.get_forms == page.forms
        assert page.post_forms == []

    def test_resolved_action_relative(self) -> None:
        page = self._page(
            '<form method="post" action="/submit"></form>',
            page_url="https://example.com/page",
        )
        assert page.post_forms[0].resolved_action == "https://example.com/submit"

    def test_resolved_action_empty_uses_page_url(self) -> None:
        page = self._page(
            '<form method="post"></form>',
            page_url="https://example.com/page",
        )
        assert page.post_forms[0].resolved_action == "https://example.com/page"

    def test_resolved_action_absolute(self) -> None:
        page = self._page(
            '<form method="post" action="https://other.com/x"></form>',
        )
        assert page.post_forms[0].resolved_action == "https://other.com/x"

    def test_has_csrf_input_picks_hidden_csrf_name(self) -> None:
        soup_html = (
            '<form method="post" action="/x">'
            '<input type="hidden" name="csrf_token" value="abc">'
            "</form>"
        )
        page = self._page(soup_html)
        assert page.post_forms[0].has_csrf_input

    def test_has_csrf_input_picks_authenticity_token(self) -> None:
        soup_html = (
            '<form method="post" action="/x">'
            '<input type="hidden" name="authenticity_token" value="abc">'
            "</form>"
        )
        page = self._page(soup_html)
        assert page.post_forms[0].has_csrf_input

    def test_has_csrf_input_false_when_only_non_hidden(self) -> None:
        soup_html = (
            '<form method="post" action="/x">'
            '<input type="text" name="csrf_token" value="abc">'
            "</form>"
        )
        page = self._page(soup_html)
        assert not page.post_forms[0].has_csrf_input

    def test_has_csrf_input_false_when_unrelated_name(self) -> None:
        soup_html = (
            '<form method="post" action="/x">'
            '<input type="hidden" name="user_id" value="abc">'
            "</form>"
        )
        page = self._page(soup_html)
        assert not page.post_forms[0].has_csrf_input

    def test_forms_cached(self) -> None:
        page = self._page('<form method="post" action="/x"></form>')
        first = page.forms
        second = page.forms
        assert first is second
