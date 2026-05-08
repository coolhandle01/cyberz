"""tests/test_xss.py - unit tests for tools/pentest/xss.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.xss import check_reflected_xss

pytestmark = pytest.mark.unit


class TestCheckReflectedXss:
    def test_detects_unescaped_reflection(self):
        ep = Endpoint(url="https://app.example.com/search", status_code=200, parameters=["q"])

        def fake_get(url, **kwargs):
            canary = url.split("q=")[1]
            resp = MagicMock()
            resp.text = f"<html><body>Results for {canary}</body></html>"
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_reflected_xss([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "ReflectedXSS"
        assert results[0].severity_hint == Severity.HIGH
        assert "q" in results[0].evidence

    def test_no_finding_when_canary_is_html_encoded(self):
        ep = Endpoint(url="https://app.example.com/search", status_code=200, parameters=["q"])

        def fake_get(url, **kwargs):
            resp = MagicMock()
            # Application HTML-encodes < and >
            resp.text = "<html><body>Results for &lt;bountysquad-xss-test&gt;</body></html>"
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_reflected_xss([ep])

        assert results == []

    def test_no_finding_when_canary_absent_from_response(self):
        ep = Endpoint(url="https://app.example.com/search", status_code=200, parameters=["q"])

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.text = "<html><body>No results found</body></html>"
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_reflected_xss([ep])

        assert results == []

    def test_skips_endpoints_without_parameters(self):
        ep = Endpoint(url="https://app.example.com/about", status_code=200)
        with patch("requests.get") as mock_get:
            results = check_reflected_xss([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=500, parameters=["id"])
        with patch("requests.get") as mock_get:
            results = check_reflected_xss([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_deduplicates_multiple_reflecting_params(self):
        ep = Endpoint(
            url="https://app.example.com/search",
            status_code=200,
            parameters=["q", "category"],
        )

        def fake_get(url, **kwargs):
            # Both params reflect the canary
            for key in ("q=", "category="):
                if key in url:
                    canary = url.split(key)[1]
                    resp = MagicMock()
                    resp.text = f"<html>{canary}</html>"
                    return resp
            resp = MagicMock()
            resp.text = "<html></html>"
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_reflected_xss([ep])

        # Only one finding per endpoint despite two reflecting params
        assert len(results) == 1

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/search", status_code=200, parameters=["q"])
        with patch("requests.get", side_effect=Exception("network error")):
            results = check_reflected_xss([ep])
        assert results == []

    def test_canary_includes_angle_brackets(self):
        """The canary must be a real tag to test for XSS, not just text."""
        ep = Endpoint(url="https://app.example.com/", status_code=200, parameters=["x"])

        seen_urls: list[str] = []

        def fake_get(url, **kwargs):
            seen_urls.append(url)
            resp = MagicMock()
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            check_reflected_xss([ep])

        assert seen_urls
        payload = seen_urls[0].split("x=")[1]
        assert payload.startswith("<") and payload.endswith(">")
