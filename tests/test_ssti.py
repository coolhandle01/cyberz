"""tests/test_ssti.py - unit tests for tools/pentest/ssti.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.ssti import _EXPECTED, _PROBES, SstiPayload, check_ssti

pytestmark = pytest.mark.unit


def _resp(status: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def _echo(url: str) -> MagicMock:
    """Echo the URL parameter back literally - simulates naive reflection
    where no template engine is involved. Triggers the literal-absence
    guard so no probe should fire against this response."""
    payload = url.split("=", 1)[1] if "=" in url else ""
    return _resp(body=f"<html>Echo: {payload}</html>")


class TestCheckSSTI:
    def test_detects_jinja_style_evaluation(self):
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **kwargs):
            # Server evaluates {{x+y}} - Jinja2/Twig path. The Jinja2 probe
            # is first in the iteration order so it wins before any other
            # {{...}} payload (Liquid, Django) is even sent.
            if "{{" in url and "+" in url:
                return _resp(body=f"<html>Hello {_EXPECTED}</html>")
            return _echo(url)

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
            # Only Mako-style ${...} triggers; everything else is echoed.
            if "${" in url:
                return _resp(body=f"Result: {_EXPECTED}")
            return _echo(url)

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert len(results) == 1
        assert "Mako" in results[0].evidence or "FreeMarker" in results[0].evidence

    def test_detects_liquid_plus_filter(self):
        # Liquid has no infix arithmetic - it can only do `{{ x | plus: y }}`.
        # The probe must fire on that signature specifically (not the Jinja2/
        # Twig {{x+y}} form which Liquid would render literally).
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **kwargs):
            if "| plus:" in url:
                return _resp(body=f"<html>Total: {_EXPECTED}</html>")
            return _echo(url)

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert len(results) == 1
        assert "Liquid" in results[0].evidence
        assert _EXPECTED in results[0].evidence

    def test_detects_django_add_filter(self):
        # Django does not evaluate raw arithmetic in {{ }} but it does
        # evaluate its built-in filter chain - the |add: filter does integer
        # addition. Only fire when the Django payload signature shows up.
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **kwargs):
            if "|add:" in url:
                return _resp(body=f"<html>Total: {_EXPECTED}</html>")
            return _echo(url)

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert len(results) == 1
        assert "Django" in results[0].evidence
        assert _EXPECTED in results[0].evidence

    def test_no_finding_when_input_is_echoed_literally(self):
        # Page reflects the raw payload (input echo) but does not evaluate it.
        # The literal-absence guard must suppress detection even when the
        # expected sum happens to appear somewhere unrelated on the page.
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **kwargs):
            payload = url.split("name=", 1)[1]
            return _resp(body=f"<html>You said: {payload}. Total {_EXPECTED}.</html>")

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep])

        assert results == []

    def test_no_finding_when_expected_absent(self):
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
        # First param, first payload should trigger - only one request fired
        assert mock_get.call_count == 1

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])
        with patch("requests.get", side_effect=Exception("network error")):
            results = check_ssti([ep])
        assert results == []

    def test_probes_cover_major_template_engines(self):
        # Sanity check the payload list - one entry per major syntax family.
        engines = " ".join(label for _, label in _PROBES.values())
        assert "Jinja2" in engines
        assert "Mako" in engines or "FreeMarker" in engines
        assert "ERB" in engines
        assert "Ruby" in engines
        # The #{...} payload also covers Pug (Express) and Slim - make sure
        # the engine label flags that for the LLM consuming the evidence.
        assert "Pug" in engines
        # Filter-based engines that cannot share the operator form get their
        # own dedicated probe.
        assert "Liquid" in engines
        assert "Django" in engines

    def test_expected_value_is_correct(self):
        # Guards against someone tweaking the canary constants but
        # forgetting to update the expected output.
        assert _EXPECTED == str(123456789 + 987654321)
        assert _EXPECTED == "1111111110"

    def test_filter_based_probes_use_correct_syntax(self):
        # The Liquid and Django probes are the only ones with filter syntax;
        # if their pipe/colon shape regresses the engine never evaluates.
        payloads = [payload for payload, _label in _PROBES.values()]
        assert any("| plus:" in p for p in payloads)
        assert any("|add:" in p for p in payloads)

    def test_payload_filter_restricts_to_named_engines(self):
        # When the agent knows the stack is Jinja2 it should only fire that
        # one probe - five other engine probes must be skipped.
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        seen_urls: list[str] = []

        def record(url, **_):
            seen_urls.append(url)
            return _resp(body="<html>no eval</html>")

        with patch("requests.get", side_effect=record):
            check_ssti([ep], payload_names=[SstiPayload.jinja2])

        assert len(seen_urls) == 1
        # Confirm it was the Jinja2 form (curly-brace expression).
        joined = " ".join(seen_urls)
        assert "%7B%7B" in joined or "{{" in joined

    def test_payload_filter_finding_uses_engine_label_in_evidence(self):
        # The agent picked "django" by name; the finding evidence must still
        # carry the verbose engine label so reports name what was probed.
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        def fake_get(url, **_):
            if "|add:" in url:
                return _resp(body=f"<html>Total: {_EXPECTED}</html>")
            return _echo(url)

        with patch("requests.get", side_effect=fake_get):
            results = check_ssti([ep], payload_names=[SstiPayload.django])

        assert len(results) == 1
        assert "Django" in results[0].evidence

    def test_payload_filter_empty_list_is_a_noop(self):
        ep = Endpoint(url="https://app.example.com/preview", status_code=200, parameters=["name"])

        with patch("requests.get") as mock_get:
            results = check_ssti([ep], payload_names=[])

        assert results == []
        mock_get.assert_not_called()
