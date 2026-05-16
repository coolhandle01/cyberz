"""tests/test_header_xss.py - unit tests for tools/pentest/header_xss.py"""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import patch

import pytest

from models import Endpoint, Severity
from tools.pentest.header_xss import _CANARY_PREFIX, XSSHeader, check_header_xss

pytestmark = pytest.mark.unit


def _make_reflecting_fake(
    make_response: Callable,
    match_header: str | None = None,
) -> Callable:
    """Return a fake requests.get that reflects any canary injected into the
    given header (or any header when match_header is None)."""

    def fake_get(url: str, headers: dict | None = None, **kwargs: object) -> object:
        h = headers or {}
        for key, val in h.items():
            if _CANARY_PREFIX in str(val):
                if match_header is None or key == match_header:
                    return make_response(body=f"<html>Echoed: {val}</html>")
        return make_response(body="<html>Normal response</html>")

    return fake_get


class TestCheckHeaderXss:
    def test_detects_user_agent_reflection(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/error", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake(make_response, "User-Agent")):
            results = check_header_xss([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "HeaderXSS"
        assert results[0].severity_hint == Severity.HIGH
        assert "User-Agent" in results[0].evidence

    def test_detects_referer_reflection(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake(make_response, "Referer")):
            results = check_header_xss([ep])

        assert len(results) == 1
        assert "Referer" in results[0].evidence

    def test_detects_x_forwarded_for_reflection(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch(
            "requests.get",
            side_effect=_make_reflecting_fake(make_response, "X-Forwarded-For"),
        ):
            results = check_header_xss([ep])

        assert len(results) == 1
        assert "X-Forwarded-For" in results[0].evidence

    def test_no_finding_when_canary_is_html_encoded(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch(
            "requests.get",
            return_value=make_response(body="<html>&lt;bountysquad-hxss-test&gt;</html>"),
        ):
            results = check_header_xss([ep])

        assert results == []

    def test_no_finding_when_canary_absent(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", return_value=make_response(body="<html>Normal</html>")):
            results = check_header_xss([ep])

        assert results == []

    def test_skips_server_error_endpoints(self) -> None:
        ep = Endpoint(url="https://app.example.com/", status_code=500)

        with patch("requests.get") as mock_get:
            results = check_header_xss([ep])

        mock_get.assert_not_called()
        assert results == []

    def test_one_finding_per_endpoint_even_when_multiple_headers_reflect(
        self, make_response: Callable
    ) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake(make_response)):
            results = check_header_xss([ep])

        assert len(results) == 1

    def test_stops_after_first_reflecting_header(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        call_count = 0

        def fake_get(url: str, headers: dict | None = None, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            first_val = next(iter((headers or {}).values()), "")
            return make_response(body=f"<html>Echoed: {first_val}</html>")

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert call_count == 1

    def test_network_exception_is_swallowed(self) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=OSError("connection refused")):
            results = check_header_xss([ep])

        assert results == []

    def test_canary_contains_angle_brackets(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        seen_canaries: list[str] = []

        def fake_get(url: str, headers: dict | None = None, **kwargs: object) -> object:
            for val in (headers or {}).values():
                if _CANARY_PREFIX in str(val):
                    seen_canaries.append(str(val))
            return make_response()

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert seen_canaries, "No canary found in any request header"
        assert all(c.startswith("<") and c.endswith(">") for c in seen_canaries)

    def test_all_five_headers_probed_when_no_reflection(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        probed: set[str] = set()

        def fake_get(url: str, headers: dict | None = None, **kwargs: object) -> object:
            for key, val in (headers or {}).items():
                if _CANARY_PREFIX in str(val):
                    probed.add(key)
            return make_response()

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert probed == set(XSSHeader)

    def test_deduplicates_same_url_across_endpoint_list(self, make_response: Callable) -> None:
        eps = [
            Endpoint(url="https://app.example.com/page", status_code=200),
            Endpoint(url="https://app.example.com/page", status_code=200),
        ]

        with patch("requests.get", side_effect=_make_reflecting_fake(make_response)):
            results = check_header_xss(eps)

        assert len(results) == 1

    def test_evidence_includes_header_payload_and_snippet(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)

        with patch("requests.get", side_effect=_make_reflecting_fake(make_response, "Referer")):
            results = check_header_xss([ep])

        assert results
        ev = results[0].evidence
        assert "Referer" in ev
        assert _CANARY_PREFIX in ev
        assert "Response snippet" in ev

    def test_unique_canary_per_request(self, make_response: Callable) -> None:
        ep = Endpoint(url="https://app.example.com/page", status_code=200)
        canaries: list[str] = []

        def fake_get(url: str, headers: dict | None = None, **kwargs: object) -> object:
            for val in (headers or {}).values():
                if _CANARY_PREFIX in str(val):
                    canaries.append(str(val))
            return make_response()

        with patch("requests.get", side_effect=fake_get):
            check_header_xss([ep])

        assert len(canaries) == len(XSSHeader)
        assert len(set(canaries)) == len(canaries), "canaries must be unique per request"
