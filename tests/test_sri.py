"""tests/test_sri.py - unit tests for tools/pentest/sri.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.sri import check_sri

pytestmark = pytest.mark.unit


def _html_resp(html: str, content_type: str = "text/html") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"Content-Type": content_type}
    resp.text = html
    return resp


class TestCheckSri:
    def test_flags_cross_origin_script_without_integrity(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        html = '<script src="https://cdn.example.net/lib.js"></script>'

        with patch("requests.get", return_value=_html_resp(html)):
            results = check_sri([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "MissingSRI"
        assert results[0].severity_hint == Severity.MEDIUM
        assert "cdn.example.net" in results[0].evidence

    def test_no_finding_when_integrity_present(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        html = (
            '<script src="https://cdn.example.net/lib.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>'
        )

        with patch("requests.get", return_value=_html_resp(html)):
            results = check_sri([ep])

        assert results == []

    def test_no_finding_for_same_origin_script(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        html = '<script src="/static/app.js"></script>'

        with patch("requests.get", return_value=_html_resp(html)):
            results = check_sri([ep])

        assert results == []

    def test_flags_cross_origin_stylesheet_without_integrity(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        html = '<link rel="stylesheet" href="https://fonts.example.net/style.css">'

        with patch("requests.get", return_value=_html_resp(html)):
            results = check_sri([ep])

        assert len(results) == 1
        assert "fonts.example.net" in results[0].evidence

    def test_no_finding_for_non_stylesheet_link(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        # rel="icon" - not a stylesheet, should be ignored
        html = '<link rel="icon" href="https://cdn.example.net/favicon.ico">'

        with patch("requests.get", return_value=_html_resp(html)):
            results = check_sri([ep])

        assert results == []

    def test_skips_non_200_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=404)
        with patch("requests.get") as mock_get:
            results = check_sri([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_skips_non_html_content_type(self):
        ep = Endpoint(url="https://app.example.com/api", status_code=200)
        resp = _html_resp("{}", content_type="application/json")
        with patch("requests.get", return_value=resp):
            results = check_sri([ep])
        assert results == []

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_sri([ep])
        assert results == []

    def test_multiple_missing_resources_in_one_finding(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        html = (
            '<script src="https://cdn1.example.net/a.js"></script>'
            '<script src="https://cdn2.example.net/b.js"></script>'
        )

        with patch("requests.get", return_value=_html_resp(html)):
            results = check_sri([ep])

        # Both resources reported in a single finding for the endpoint
        assert len(results) == 1
        assert "cdn1.example.net" in results[0].evidence
        assert "cdn2.example.net" in results[0].evidence

    def test_deduplicates_same_endpoint(self):
        endpoints = [
            Endpoint(url="https://app.example.com/page1", status_code=200),
            Endpoint(url="https://app.example.com/page1", status_code=200),
        ]
        html = '<script src="https://cdn.example.net/lib.js"></script>'

        with patch("requests.get", return_value=_html_resp(html)):
            results = check_sri(endpoints)

        assert len(results) == 1
