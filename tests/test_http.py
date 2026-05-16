"""tests/test_http.py - unit tests for the traceable User-Agent helper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from config import config
from tools import http

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_programme():
    """Each test starts with no programme set and leaves it that way."""
    http.set_programme(None)
    yield
    http.set_programme(None)


class TestUserAgent:
    def test_includes_platform_researcher_and_contact(self):
        ua = http.user_agent()
        assert ua.startswith("cybersquad (authorised research;")
        assert "platform: hackerone" in ua
        # H1 username and contact email come from config (seeded by conftest)
        assert "researcher: ci-user" in ua
        assert "contact: ci@example.invalid" in ua

    def test_omits_programme_when_unset(self):
        assert "programme:" not in http.user_agent()

    def test_includes_programme_when_set(self):
        http.set_programme("acme-corp")
        assert "programme: acme-corp" in http.user_agent()

    def test_set_programme_strips_whitespace(self):
        http.set_programme("  acme-corp  ")
        assert "programme: acme-corp" in http.user_agent()

    def test_clearing_programme(self):
        http.set_programme("acme")
        http.set_programme(None)
        assert http.get_programme() is None
        assert "programme:" not in http.user_agent()


class TestInjectHeaders:
    def test_adds_user_agent_when_absent(self):
        kwargs: dict = {}
        out = http._inject_headers(kwargs)
        assert out["headers"]["User-Agent"] == http.user_agent()

    def test_preserves_existing_user_agent(self):
        kwargs = {"headers": {"User-Agent": "custom-ua"}}
        out = http._inject_headers(kwargs)
        assert out["headers"]["User-Agent"] == "custom-ua"

    def test_preserves_existing_user_agent_case_insensitive(self):
        kwargs = {"headers": {"user-agent": "custom-ua"}}
        out = http._inject_headers(kwargs)
        # No new User-Agent injected because lowercase one already there
        assert "User-Agent" not in out["headers"]
        assert out["headers"]["user-agent"] == "custom-ua"

    def test_merges_with_other_headers(self):
        kwargs = {"headers": {"Origin": "https://x"}}
        out = http._inject_headers(kwargs)
        assert out["headers"]["Origin"] == "https://x"
        assert "User-Agent" in out["headers"]

    def test_handles_no_headers_kwarg(self):
        kwargs: dict = {}
        out = http._inject_headers(kwargs)
        assert "User-Agent" in out["headers"]


class TestVerbWrappers:
    def test_get_calls_requests_get_with_ua(self):
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get("https://x.example.com/")
        kwargs = mock_get.call_args.kwargs
        assert kwargs["headers"]["User-Agent"] == http.user_agent()

    def test_default_timeout_applied_when_omitted(self):
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get("https://x.example.com/")
        assert mock_get.call_args.kwargs["timeout"] == config.recon.http_timeout

    def test_explicit_timeout_not_overridden(self):
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get("https://x.example.com/", timeout=999)
        assert mock_get.call_args.kwargs["timeout"] == 999

    def test_post_calls_requests_post_with_ua(self):
        with patch("requests.post", return_value=MagicMock()) as mock_post:
            http.post("https://x.example.com/", json={"a": 1})
        kwargs = mock_post.call_args.kwargs
        assert kwargs["headers"]["User-Agent"] == http.user_agent()
        assert kwargs["json"] == {"a": 1}

    @pytest.mark.parametrize("verb", ["put", "delete", "head", "patch", "options"])
    def test_other_verbs_inject_ua(self, verb):
        with patch(f"requests.{verb}", return_value=MagicMock()) as mock_call:
            getattr(http, verb)("https://x.example.com/")
        assert mock_call.call_args.kwargs["headers"]["User-Agent"] == http.user_agent()

    def test_request_passes_method(self):
        with patch("requests.request", return_value=MagicMock()) as mock_req:
            http.request("PATCH", "https://x.example.com/")
        args, kwargs = mock_req.call_args
        assert args[0] == "PATCH"
        assert kwargs["headers"]["User-Agent"] == http.user_agent()

    def test_programme_appears_in_outbound_ua(self):
        http.set_programme("acme-corp")
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get("https://x.example.com/")
        ua = mock_get.call_args.kwargs["headers"]["User-Agent"]
        assert "programme: acme-corp" in ua
