"""Unit tests for tools/pentest/nosql.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.nosql import check_nosql_injection

pytestmark = pytest.mark.unit


def _mock_resp(status: int, body: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.text = body
    return m


class TestCheckNosqlInjection:
    def test_detects_auth_bypass_via_url_param(self):
        endpoint = Endpoint(
            url="https://api.example.com/login",
            status_code=401,
            parameters=["username"],
        )
        # baseline 401, injected 200 -> CRITICAL auth bypass
        with patch("requests.get", side_effect=[_mock_resp(401), _mock_resp(200, "welcome")]):
            results = check_nosql_injection([endpoint])

        assert len(results) == 1
        assert results[0].vuln_class == "NoSQLi"
        assert results[0].severity_hint == Severity.CRITICAL
        assert "[$ne]" in results[0].evidence

    def test_detects_data_leakage_via_url_param(self):
        endpoint = Endpoint(
            url="https://api.example.com/users",
            status_code=200,
            parameters=["id"],
        )
        # both 200 but body contains _id -> HIGH data leakage
        leak_body = '{"_id": "abc"}'
        side_effects = [_mock_resp(200, "normal"), _mock_resp(200, leak_body)]
        with patch("requests.get", side_effect=side_effects):
            results = check_nosql_injection([endpoint])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.HIGH

    def test_detects_auth_bypass_via_post_body(self):
        endpoint = Endpoint(
            url="https://api.example.com/auth",
            status_code=401,
            parameters=["email", "password"],
        )
        # URL probes all return baseline status, POST injection returns 200
        url_responses = [_mock_resp(401), _mock_resp(401)] * 6  # covers all URL_PAYLOADS * params
        post_responses = [_mock_resp(401), _mock_resp(200, "authenticated")]

        with (
            patch("requests.get", side_effect=url_responses + post_responses),
            patch("requests.post", return_value=_mock_resp(200, "authenticated")),
        ):
            results = check_nosql_injection([endpoint])

        assert any(r.vuln_class == "NoSQLi" for r in results)

    def test_skips_endpoints_without_parameters(self):
        endpoint = Endpoint(url="https://api.example.com/static", status_code=200)

        with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
            results = check_nosql_injection([endpoint])

        mock_get.assert_not_called()
        mock_post.assert_not_called()
        assert results == []

    def test_safe_response_produces_no_finding(self):
        endpoint = Endpoint(
            url="https://api.example.com/search",
            status_code=200,
            parameters=["query"],
        )
        safe_resp = _mock_resp(200, "<html>No results</html>")

        with (
            patch("requests.get", return_value=safe_resp),
            patch("requests.post", return_value=safe_resp),
        ):
            results = check_nosql_injection([endpoint])

        assert results == []

    def test_request_exception_is_swallowed(self):
        endpoint = Endpoint(
            url="https://api.example.com/login",
            status_code=200,
            parameters=["user"],
        )

        with (
            patch("requests.get", side_effect=Exception("timeout")),
            patch("requests.post", side_effect=Exception("timeout")),
        ):
            results = check_nosql_injection([endpoint])

        assert results == []

    def test_deduplicates_findings_per_endpoint(self):
        endpoint = Endpoint(
            url="https://api.example.com/login",
            status_code=401,
            parameters=["username", "password"],
        )
        # First probe triggers a finding; second should be skipped via deduplication
        bypass = _mock_resp(200, "ok")
        baseline = _mock_resp(401)

        with patch("requests.get", side_effect=[baseline, bypass]):
            results = check_nosql_injection([endpoint])

        assert len(results) == 1

    def test_prefers_doc_store_params_over_generic_ones(self):
        endpoint = Endpoint(
            url="https://api.example.com/find",
            status_code=200,
            parameters=["unrelated", "filter"],
        )
        safe = _mock_resp(200, "normal")

        called_urls: list[str] = []

        def capture_get(url: str, **kwargs: object) -> object:
            called_urls.append(url)
            return safe

        with (
            patch("requests.get", side_effect=capture_get),
            patch("requests.post", return_value=safe),
        ):
            check_nosql_injection([endpoint])

        # "filter" is in _DOC_STORE_PARAMS so it should be probed; "unrelated" should not
        assert any("filter" in u for u in called_urls)
        assert not any("unrelated" in u for u in called_urls)

    def test_nosqli_cvss_critical(self):
        from tools.pentest.triage import _lookup_cvss

        score, vector = _lookup_cvss("NoSQLi", Severity.CRITICAL)
        assert score == 9.8
        assert "CVSS:3.1" in vector

    def test_nosqli_cvss_high(self):
        from tools.pentest.triage import _lookup_cvss

        score, vector = _lookup_cvss("NoSQLi", Severity.HIGH)
        assert score == 8.8
        assert "CVSS:3.1" in vector
