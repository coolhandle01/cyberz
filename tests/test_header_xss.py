"""tests/test_header_xss.py - unit tests for tools/pentest/header_xss.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.header_xss import _CANARY_PREFIX, _XSS_HEADERS, check_header_xss

pytestmark = pytest.mark.unit


def _resp(body: str = "", status: int = 200) -> MagicMock:
    r = MagicMock()
    r.text = body
    r.status_code = status
    return r


def _make_reflecting_fake(match_header: str | None = None):
    """Return a fake_get that reflects any canary injected into the given
    header (or into any header when match_header is None)."""

    def fake_get(url, headers=None, **kwargs):
        h = headers or {}
        for key, val in h.items():
            if _CANARY_PREFIX in str(val):
                if match_header is None or key == match_header:
                    return _resp(body=f"<html>Echoed: {val}</html>")
        return _resp(body="<html>Normal response</html>")

    return fake_get


class TestCheckHeaderXss:
    def test_detects_user_agent_reflection(self):
        ep = Endpoint(url="https://app.example.com/error", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake("User-Agent")):
            results = check_header_xss([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "HeaderXSS"
        assert results[0].severity_hint == Severity.HIGH
        assert "User-Agent" in results[0].evidence

    def test_detects_referer_reflection(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake("Referer")):
            results = check_header_xss([ep])

        assert len(results) == 1
        assert "Referer" in results[0].evidence

    def test_detects_x_forwarded_for_reflection(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake("X-Forwarded-For")):
            results = check_header_xss([ep])

        assert len(results) == 1
        assert "X-Forwarded-For" in results[0].evidence

    def test_no_finding_when_canary_is_html_encoded(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        def fake_get(url, headers=None, **kwargs):
            return _resp(body="<html>&lt;bountysquad-hxss-test&gt;</html>")

        with patch("requests.get", side_effect=fake_get):
            results = check_header_xss([ep])

        assert results == []

    def test_no_finding_when_canary_absent(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", return_value=_resp(body="<html>Normal</html>")):
            results = check_header_xss([ep])

        assert results == []

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=500)

        with patch("requests.get") as mock_get:
            results = check_header_xss([ep])

        mock_get.assert_not_called()
        assert results == []

    def test_one_finding_per_endpoint_even_when_multiple_headers_reflect(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake(None)):
            results = check_header_xss([ep])

        assert len(results) == 1

    def test_stops_after_first_reflecting_header(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        call_count = 0

        def fake_get(url, headers=None, **kwargs):
            nonlocal call_count
            call_count += 1
            return _resp(body=f"<html>Echoed: {list((headers or {}).values())[0]}</html>")

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert call_count == 1

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=OSError("connection refused")):
            results = check_header_xss([ep])

        assert results == []

    def test_canary_contains_angle_brackets(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        seen_canaries: list[str] = []

        def fake_get(url, headers=None, **kwargs):
            for val in (headers or {}).values():
                if _CANARY_PREFIX in str(val):
                    seen_canaries.append(str(val))
            return _resp()

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert seen_canaries, "No canary found in any request header"
        assert all(c.startswith("<") and c.endswith(">") for c in seen_canaries)

    def test_all_five_headers_probed_when_no_reflection(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        probed: set[str] = set()

        def fake_get(url, headers=None, **kwargs):
            for key, val in (headers or {}).items():
                if _CANARY_PREFIX in str(val):
                    probed.add(key)
            return _resp()

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert probed == set(_XSS_HEADERS)

    def test_deduplicates_same_url_across_endpoint_list(self):
        eps = [
            Endpoint(url="https://app.example.com/page", status_code=200),
            Endpoint(url="https://app.example.com/page", status_code=200),
        ]

        with patch("requests.get", side_effect=_make_reflecting_fake(None)):
            results = check_header_xss(eps)

        assert len(results) == 1

    def test_evidence_includes_header_payload_and_snippet(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake("Referer")):
            results = check_header_xss([ep])

        assert results
        ev = results[0].evidence
        assert "Referer" in ev
        assert _CANARY_PREFIX in ev
        assert "Response snippet" in ev

    def test_unique_canary_per_request(self):
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        canaries: list[str] = []

        def fake_get(url, headers=None, **kwargs):
            for val in (headers or {}).values():
                if _CANARY_PREFIX in str(val):
                    canaries.append(str(val))
            return _resp()

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert len(canaries) == len(_XSS_HEADERS)
        assert len(set(canaries)) == len(canaries), "canaries must be unique per request"
