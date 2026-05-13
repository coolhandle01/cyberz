"""tests/test_path_traversal.py - unit tests for tools/pentest/path_traversal.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.path_traversal import _PROBES, check_path_traversal

pytestmark = pytest.mark.unit

_PASSWD_BODY = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"
_WIN_INI_BODY = "; for 16-bit app support\n[fonts]\n[extensions]\n"


def _resp(status: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


class TestCheckPathTraversal:
    def test_detects_linux_passwd_marker(self):
        ep = Endpoint(url="https://app.example.com/download", status_code=200, parameters=["file"])

        with patch("requests.get", return_value=_resp(body=_PASSWD_BODY)):
            results = check_path_traversal([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "PathTraversal"
        assert results[0].severity_hint == Severity.HIGH
        assert "file" in results[0].evidence
        assert "root:x:0:0:" in results[0].evidence

    def test_detects_windows_win_ini_marker(self):
        ep = Endpoint(url="https://app.example.com/view", status_code=200, parameters=["page"])

        def fake_get(url, **kwargs):
            # Only respond with win.ini content when the Windows payload is sent
            if "windows" in url.lower() and "win.ini" in url.lower():
                return _resp(body=_WIN_INI_BODY)
            return _resp(body="not found")

        with patch("requests.get", side_effect=fake_get):
            results = check_path_traversal([ep])

        assert len(results) == 1
        assert "for 16-bit app support" in results[0].evidence

    def test_detects_url_encoded_payload_only(self):
        # Server sanitises plain "../" but not "%2f" - the encoded variant
        # must still be tried so this is detected.
        ep = Endpoint(url="https://app.example.com/dl", status_code=200, parameters=["f"])

        def fake_get(url, **kwargs):
            # Plain "../" is stripped by the (fake) server's filter
            if "../" in url:
                return _resp(body="forbidden")
            if "%2f" in url.lower():
                return _resp(body=_PASSWD_BODY)
            return _resp(body="")

        with patch("requests.get", side_effect=fake_get):
            results = check_path_traversal([ep])

        assert len(results) == 1
        assert "%2f" in results[0].evidence.lower()

    def test_no_finding_when_marker_absent(self):
        ep = Endpoint(url="https://app.example.com/download", status_code=200, parameters=["file"])

        with patch("requests.get", return_value=_resp(body="<html>Not Found</html>")):
            results = check_path_traversal([ep])

        assert results == []

    def test_no_false_positive_when_only_word_root_present(self):
        # Body mentions "root" but not the unique "root:x:0:0:" prefix - the
        # marker check must be strict enough to skip this.
        ep = Endpoint(url="https://app.example.com/download", status_code=200, parameters=["file"])

        with patch("requests.get", return_value=_resp(body="Welcome, root admin user!")):
            results = check_path_traversal([ep])

        assert results == []

    def test_skips_endpoints_without_parameters(self):
        ep = Endpoint(url="https://app.example.com/about", status_code=200)
        with patch("requests.get") as mock_get:
            results = check_path_traversal([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=500, parameters=["file"])
        with patch("requests.get") as mock_get:
            results = check_path_traversal([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_one_finding_per_endpoint_even_with_multiple_vuln_params(self):
        ep = Endpoint(
            url="https://app.example.com/dl",
            status_code=200,
            parameters=["file", "path"],
        )

        with patch("requests.get", return_value=_resp(body=_PASSWD_BODY)):
            results = check_path_traversal([ep])

        assert len(results) == 1

    def test_stops_calling_after_first_match(self):
        # Once we have a finding for an endpoint we should not keep firing
        # additional payloads against later parameters.
        ep = Endpoint(
            url="https://app.example.com/dl",
            status_code=200,
            parameters=["file", "path", "page"],
        )

        with patch("requests.get", return_value=_resp(body=_PASSWD_BODY)) as mock_get:
            check_path_traversal([ep])

        # First param matches on the very first probe - only one request expected
        assert mock_get.call_count == 1

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/dl", status_code=200, parameters=["file"])
        with patch("requests.get", side_effect=Exception("network error")):
            results = check_path_traversal([ep])
        assert results == []

    def test_probes_cover_encoding_bypasses(self):
        # Sanity check that we ship the full set of encoding bypasses called
        # out in the issue: plain, single-encoded, double-encoded, null byte,
        # backslash for Windows.
        payloads = [p for p, _ in _PROBES]
        joined = "\n".join(payloads)
        assert "../" in joined
        assert "%2f" in joined
        assert "%252f" in joined
        assert "%00" in joined
        assert "\\" in joined
