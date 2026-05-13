"""tests/test_open_redirect.py - unit tests for tools/pentest/open_redirect.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.open_redirect import (
    _PAYLOAD_HOST,
    _redirect_target,
    _redirects_to_canary,
    check_open_redirect,
)

pytestmark = pytest.mark.unit


def _resp(status: int = 302, headers: dict[str, str] | None = None, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = body
    return resp


class TestRedirectTarget:
    def test_picks_up_location_header(self):
        assert _redirect_target(_resp(headers={"Location": "https://x/"})) == "https://x/"

    def test_picks_up_refresh_header(self):
        target = _redirect_target(_resp(status=200, headers={"Refresh": "0; url=https://x/"}))
        assert target == "https://x/"

    def test_picks_up_meta_refresh(self):
        body = '<html><head><meta http-equiv="refresh" content="0;url=https://x/"></head></html>'
        assert _redirect_target(_resp(status=200, body=body)) == "https://x/"

    def test_returns_none_when_no_redirect(self):
        assert _redirect_target(_resp(status=200, body="<html>plain page</html>")) is None


class TestRedirectsToCanary:
    def test_matches_absolute_url(self):
        assert _redirects_to_canary(f"https://{_PAYLOAD_HOST}/")

    def test_matches_protocol_relative(self):
        assert _redirects_to_canary(f"//{_PAYLOAD_HOST}/some/path")

    def test_matches_subdomain_of_canary(self):
        assert _redirects_to_canary(f"https://sub.{_PAYLOAD_HOST}/")

    def test_does_not_match_when_canary_is_only_in_path(self):
        # Server safely placed our payload inside the path of the legitimate
        # host - browser would stay on-origin, so this is NOT a finding.
        assert not _redirects_to_canary(f"https://app.example.com/{_PAYLOAD_HOST}/")

    def test_does_not_match_unrelated_host(self):
        assert not _redirects_to_canary("https://app.example.com/dashboard")


class TestCheckOpenRedirect:
    def test_detects_30x_to_canary(self):
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["next"])

        def fake_get(url, **kwargs):
            payload = url.split("next=", 1)[1]
            return _resp(status=302, headers={"Location": payload})

        with patch("requests.get", side_effect=fake_get):
            results = check_open_redirect([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "OpenRedirect"
        assert results[0].severity_hint == Severity.MEDIUM
        assert "next" in results[0].evidence
        assert _PAYLOAD_HOST in results[0].evidence

    def test_detects_meta_refresh_redirect(self):
        ep = Endpoint(url="https://app.example.com/go", status_code=200, parameters=["dest"])

        def fake_get(url, **kwargs):
            payload = url.split("dest=", 1)[1]
            body = (
                f'<html><head><meta http-equiv="refresh" content="0;url={payload}"></head></html>'
            )
            return _resp(status=200, body=body)

        with patch("requests.get", side_effect=fake_get):
            results = check_open_redirect([ep])

        assert len(results) == 1
        assert "Redirect target" in results[0].evidence

    def test_no_finding_when_redirect_stays_on_origin(self):
        # Application sanitises by ignoring our payload and redirecting home
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["next"])

        def fake_get(url, **kwargs):
            return _resp(status=302, headers={"Location": "/dashboard"})

        with patch("requests.get", side_effect=fake_get):
            results = check_open_redirect([ep])

        assert results == []

    def test_no_finding_when_no_redirect_at_all(self):
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["next"])

        def fake_get(url, **kwargs):
            return _resp(status=200, body="<html>login form</html>")

        with patch("requests.get", side_effect=fake_get):
            results = check_open_redirect([ep])

        assert results == []

    def test_skips_endpoints_without_parameters(self):
        ep = Endpoint(url="https://app.example.com/about", status_code=200)
        with patch("requests.get") as mock_get:
            results = check_open_redirect([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=500, parameters=["url"])
        with patch("requests.get") as mock_get:
            results = check_open_redirect([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_one_finding_per_endpoint_even_with_multiple_vuln_params(self):
        ep = Endpoint(
            url="https://app.example.com/login",
            status_code=200,
            parameters=["next", "return_to"],
        )

        def fake_get(url, **kwargs):
            # Both params would redirect if probed
            for key in ("next=", "return_to="):
                if key in url:
                    payload = url.split(key, 1)[1]
                    return _resp(status=302, headers={"Location": payload})
            return _resp(status=200)

        with patch("requests.get", side_effect=fake_get):
            results = check_open_redirect([ep])

        assert len(results) == 1

    def test_protocol_relative_payload_in_location(self):
        # Server normalises a backslash payload to protocol-relative
        ep = Endpoint(url="https://app.example.com/r", status_code=200, parameters=["u"])

        def fake_get(url, **kwargs):
            return _resp(status=302, headers={"Location": f"//{_PAYLOAD_HOST}/"})

        with patch("requests.get", side_effect=fake_get):
            results = check_open_redirect([ep])

        assert len(results) == 1

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["next"])
        with patch("requests.get", side_effect=Exception("network error")):
            results = check_open_redirect([ep])
        assert results == []

    def test_payloads_use_a_reserved_canary_host(self):
        # Defence in depth: our payload host must be a reserved TLD so even
        # if a victim browser followed the redirect, no live service receives it.
        assert _PAYLOAD_HOST.endswith(".invalid")
