"""
tests/test_sourcemaps.py - unit tests for tools/pentest/sourcemaps.py
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.sourcemaps import check_js_source_maps

pytestmark = pytest.mark.unit


def _html_with_script(js_url: str = "https://app.example.com/app.js") -> str:
    return f'<html><head><script src="{js_url}"></script></head></html>'


def _map_payload(sources: list[str], sources_content: list[str]) -> dict:
    return {
        "version": 3,
        "sources": sources,
        "sourcesContent": sources_content,
        "mappings": "AAAA",
    }


class TestCheckJsSourceMaps:
    def test_detects_exposed_map_with_internal_paths(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)

        map_data = _map_payload(
            sources=["/src/server/auth.ts", "/src/app/config.ts"],
            sources_content=["// auth code", "// config"],
        )

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            if url.endswith(".map"):
                resp.text = json.dumps(map_data)
                resp.json.return_value = map_data
            elif url.endswith(".js"):
                resp.text = "console.log('app')"
            else:
                resp.text = _html_with_script()
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_js_source_maps([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "SourceMapLeak"
        assert results[0].severity_hint == Severity.MEDIUM
        assert "/src/server/auth.ts" in results[0].evidence

    def test_detects_critical_finding_when_secrets_present(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)

        map_data = _map_payload(
            sources=["/src/app.ts"],
            sources_content=['const apiKey = "sk-AKIAIOSFODNN7EXAMPLE1234567890AB";'],
        )

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            if url.endswith(".map"):
                resp.text = json.dumps(map_data)
                resp.json.return_value = map_data
            elif url.endswith(".js"):
                resp.text = "//# sourceMappingURL=app.js.map"
            else:
                resp.text = _html_with_script()
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_js_source_maps([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL

    def test_detects_aws_access_key_in_sources(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)

        map_data = _map_payload(
            sources=["/src/config.ts"],
            sources_content=["const key = 'AKIAIOSFODNN7EXAMPLE';"],
        )

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            if url.endswith(".map"):
                resp.text = json.dumps(map_data)
                resp.json.return_value = map_data
            elif url.endswith(".js"):
                resp.text = ""
            else:
                resp.text = _html_with_script()
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_js_source_maps([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL

    def test_skips_non_200_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=404)
        with patch("requests.get") as mock_get:
            results = check_js_source_maps([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_skips_non_html_content_type(self):
        ep = Endpoint(url="https://app.example.com/api/data", status_code=200)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.text = '{"key": "value"}'

        with patch("requests.get", return_value=mock_resp):
            results = check_js_source_maps([ep])

        assert results == []

    def test_ignores_map_returning_non_200(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url.endswith(".map"):
                resp.status_code = 404
                resp.text = "Not Found"
            elif url.endswith(".js"):
                resp.status_code = 200
                resp.text = ""
            else:
                resp.status_code = 200
                resp.headers = {"Content-Type": "text/html"}
                resp.text = _html_with_script()
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_js_source_maps([ep])

        assert results == []

    def test_request_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", side_effect=Exception("network error")):
            results = check_js_source_maps([ep])
        assert results == []

    def test_deduplicates_same_map_url(self):
        endpoints = [
            Endpoint(url="https://app.example.com/page1", status_code=200),
            Endpoint(url="https://app.example.com/page2", status_code=200),
        ]
        map_data = _map_payload(
            sources=["/src/app.ts"],
            sources_content=["const x = 1;"],
        )

        map_fetch_count = 0

        def fake_get(url, **kwargs):
            nonlocal map_fetch_count
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            if url.endswith(".map"):
                map_fetch_count += 1
                resp.text = json.dumps(map_data)
                resp.json.return_value = map_data
            elif url.endswith(".js"):
                resp.text = ""
            else:
                resp.text = _html_with_script()
            return resp

        with patch("requests.get", side_effect=fake_get):
            check_js_source_maps(endpoints)

        assert map_fetch_count == 1
