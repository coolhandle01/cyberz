"""tests/test_xxe.py - unit tests for tools/pentest/xxe.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.xxe import (
    _ERROR_PROBES,
    _FILE_READ_PROBES,
    _LINUX_MARKER,
    _WIN_MARKER,
    _XML_ERROR_MARKERS,
    check_xxe,
)

pytestmark = pytest.mark.unit


def _resp(status: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


class TestCheckXXE:
    def test_detects_linux_file_read_critical(self) -> None:
        ep = Endpoint(url="https://app.example.com/soap", status_code=200)

        with patch("requests.post", return_value=_resp(body=f"data: {_LINUX_MARKER} more")):
            results = check_xxe([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "XXE"
        assert results[0].severity_hint == Severity.CRITICAL
        assert _LINUX_MARKER in results[0].evidence

    def test_detects_windows_file_read_critical(self) -> None:
        ep = Endpoint(url="https://app.example.com/xml", status_code=200)

        def fake_post(url: str, **kw: object) -> MagicMock:
            body = kw.get("data", "")
            if "Windows" in str(body):
                return _resp(body=f"result {_WIN_MARKER} end")
            return _resp(body="")

        with patch("requests.post", side_effect=fake_post):
            results = check_xxe([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL
        assert _WIN_MARKER in results[0].evidence

    def test_detects_xml_parser_error_medium(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        def fake_post(url: str, **kw: object) -> MagicMock:
            body = str(kw.get("data", ""))
            # Only the error probe (undefined entity) triggers a parser error.
            if "cybersquad_xxe_probe" in body:
                return _resp(body="SAXParseException: undefined entity at line 1")
            return _resp(body="")

        with patch("requests.post", side_effect=fake_post):
            results = check_xxe([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.MEDIUM
        assert "SAXParseException" in results[0].evidence

    def test_file_read_takes_priority_over_error(self) -> None:
        # Both file marker and XML error present - CRITICAL should win because
        # file-read probes are tried first and stop before error probes run.
        ep = Endpoint(url="https://app.example.com/soap", status_code=200)
        body = f"{_LINUX_MARKER}\nSAXParseException: something"

        with patch("requests.post", return_value=_resp(body=body)):
            results = check_xxe([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL

    def test_no_finding_on_clean_response(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        with patch("requests.post", return_value=_resp(body="<response>ok</response>")):
            results = check_xxe([ep])

        assert results == []

    def test_skips_server_error_endpoints(self) -> None:
        ep = Endpoint(url="https://app.example.com/soap", status_code=500)

        with patch("requests.post") as mock_post:
            results = check_xxe([ep])

        mock_post.assert_not_called()
        assert results == []

    def test_endpoint_without_status_code_is_probed(self) -> None:
        # status_code=None means recon didn't record it - still worth trying.
        ep = Endpoint(url="https://app.example.com/soap")

        with patch("requests.post", return_value=_resp(body=_LINUX_MARKER)):
            results = check_xxe([ep])

        assert len(results) == 1

    def test_one_finding_per_endpoint(self) -> None:
        # Even though multiple probes would match, we stop at the first.
        ep = Endpoint(url="https://app.example.com/soap", status_code=200)

        with patch("requests.post", return_value=_resp(body=_LINUX_MARKER)):
            results = check_xxe([ep])

        assert len(results) == 1

    def test_deduplicates_same_url(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/soap", status_code=200)
        ep2 = Endpoint(url="https://app.example.com/soap", status_code=200)

        with patch("requests.post", return_value=_resp(body=_LINUX_MARKER)):
            results = check_xxe([ep1, ep2])

        assert len(results) == 1

    def test_multiple_distinct_endpoints_each_get_a_finding(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/soap", status_code=200)
        ep2 = Endpoint(url="https://app.example.com/xml-api", status_code=200)

        with patch("requests.post", return_value=_resp(body=_LINUX_MARKER)):
            results = check_xxe([ep1, ep2])

        assert len(results) == 2

    def test_network_exception_is_swallowed(self) -> None:
        ep = Endpoint(url="https://app.example.com/soap", status_code=200)

        with patch("requests.post", side_effect=OSError("connection refused")):
            results = check_xxe([ep])

        assert results == []

    def test_soap_envelope_probe_is_included(self) -> None:
        bodies = [body for body, _, _, _ in _FILE_READ_PROBES]
        soap_bodies = [b for b in bodies if "Envelope" in b]
        assert len(soap_bodies) >= 1

    def test_xmlrpc_probe_is_included(self) -> None:
        bodies = [body for body, _, _, _ in _FILE_READ_PROBES]
        xmlrpc_bodies = [b for b in bodies if "methodCall" in b]
        assert len(xmlrpc_bodies) >= 1

    def test_both_linux_and_windows_probes_included(self) -> None:
        markers = {marker for _, _, marker, _ in _FILE_READ_PROBES}
        assert _LINUX_MARKER in markers
        assert _WIN_MARKER in markers

    def test_error_probes_cover_both_content_types(self) -> None:
        content_types = {ct for _, ct, _ in _ERROR_PROBES}
        assert "application/xml" in content_types
        assert "text/xml; charset=utf-8" in content_types

    def test_xml_error_markers_cover_common_parsers(self) -> None:
        joined = " ".join(_XML_ERROR_MARKERS)
        assert "SAXParseException" in joined
        assert "ParseError" in joined
        assert "undefined entity" in joined
        assert "expat" in joined
