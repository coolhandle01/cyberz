"""tests/test_ssti.py - unit tests for tools/pentest/ssti.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.ssti import _EXPECTED, _PROBES, check_ssti

pytestmark = pytest.mark.unit


def _resp(status: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


class TestCheckSSTI:
    def test_detects_jinja_style_evaluation(self):
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **kwargs):
            # Server evaluates the Jinja-style payload to the product
            if "%7B%7B" in url or "{{" in url:
                return _resp(body=f"<html>Hello {_EXPECTED}</html>")
            return _resp(body="<html>Hello</html>")

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "SSTI"
        assert results[0].severity_hint == Severity.HIGH
        assert _EXPECTED in results[0].evidence
        assert "Jinja2" in results[0].evidence

    def test_detects_dollar_brace_engine(self):
        ep = Endpoint(url="https://app.example.com/render", status_code=200, parameters=["tpl"])

        def fake_get(url, **kwargs):
            # Only the ${...} payload triggers; the {{...}} one is echoed
            if "%24%7B" in url or url.endswith("${12345*67890}"):
                return _resp(body=f"Result: {_EXPECTED}")
            # Echo other payloads back literally
            payload = url.split("tpl=", 1)[1]
            return _resp(body=f"Submitted: {payload}")

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert len(results) == 1
        assert "Mako" in results[0].evidence or "FreeMarker" in results[0].evidence

    def test_no_finding_when_input_is_echoed_literally(self):
        # Page reflects the raw payload (input echo) but does not evaluate it.
        # Our guard requires literal absence, so this must NOT be a finding -
        # even if the product happens to appear in some unrelated text.
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **kwargs):
            payload = url.split("name=", 1)[1]
            return _resp(body=f"<html>You said: {payload}. Order #{_EXPECTED}.</html>")

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert results == []

    def test_no_finding_when_product_absent(self):
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **kwargs):
            return _resp(body="<html>Hello world</html>")

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert results == []

    def test_skips_endpoints_without_parameters(self):
        ep = Endpoint(url="https://app.example.com/about", status_code=200)
        with patch("requests.get") as mock_get:
            results = check_ssti([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=500, parameters=["q"])
        with patch("requests.get") as mock_get:
            results = check_ssti([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_one_finding_per_endpoint(self):
        ep = Endpoint(
            url="https://app.example.com/preview",
            status_code=200,
            parameters=["name", "title"],
        )

        def fake_get(url, **kwargs):
            return _resp(body=f"Hello {_EXPECTED}!")

        with patch("requests.get", side_effect=fake_get) as mock_get:
            results = check_ssti([ep])

        assert len(results) == 1
        # First param, first payload should trigger - only one request
        assert mock_get.call_count == 1

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])
        with patch("requests.get", side_effect=Exception("network error")):
            results = check_ssti([ep])
        assert results == []

    def test_probes_cover_major_template_engines(self):
        # Sanity check the payload list - one entry per major syntax family.
        engines = " ".join(label for _, label in _PROBES)
        assert "Jinja2" in engines
        assert "Mako" in engines or "FreeMarker" in engines
        assert "ERB" in engines
        assert "Ruby" in engines

    def test_expected_product_is_correct(self):
        # Guards against someone tweaking _A/_B but forgetting _EXPECTED.
        assert _EXPECTED == str(12345 * 67890)
        assert _EXPECTED == "838102050"
