"""tests/test_ldap_injection.py - unit tests for tools/pentest/ldap_injection.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.ldap_injection import (
    _BASELINE_VALUE,
    _LDAP_ERROR_MARKERS,
    _PAYLOADS,
    check_ldap_injection,
)

pytestmark = pytest.mark.unit


def _resp(status: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def _baseline_or_probe(
    url: str, baseline_resp: MagicMock, probe_resp: MagicMock, **_: object
) -> MagicMock:
    """Return baseline_resp for the baseline URL, probe_resp for everything else."""
    if _BASELINE_VALUE in url:
        return baseline_resp
    return probe_resp


class TestCheckLDAPInjection:
    def test_detects_auth_bypass_high(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["username"])

        with patch(
            "requests.get",
            side_effect=lambda url, **kw: _baseline_or_probe(
                url, _resp(401, "Invalid credentials"), _resp(200, "Welcome!")
            ),
        ):
            results = check_ldap_injection([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "LDAPInjection"
        assert results[0].severity_hint == Severity.HIGH
        assert "auth-bypass" in results[0].evidence or "bypass" in results[0].evidence.lower()
        assert "username" in results[0].evidence

    def test_detects_ldap_error_marker_medium(self) -> None:
        ep = Endpoint(url="https://app.example.com/search", status_code=200, parameters=["q"])

        with patch(
            "requests.get",
            side_effect=lambda url, **kw: _baseline_or_probe(
                url,
                _resp(200, "No results"),
                _resp(200, "javax.naming.NamingException: invalid attribute"),
            ),
        ):
            results = check_ldap_injection([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.MEDIUM
        assert "javax.naming" in results[0].evidence

    def test_detects_server_error_on_payload_medium(self) -> None:
        ep = Endpoint(url="https://app.example.com/auth", status_code=200, parameters=["user"])

        with patch(
            "requests.get",
            side_effect=lambda url, **kw: _baseline_or_probe(
                url, _resp(200, "ok"), _resp(500, "Internal Server Error")
            ),
        ):
            results = check_ldap_injection([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.MEDIUM
        assert "500" in results[0].evidence

    def test_no_finding_on_clean_response(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["username"])

        with patch("requests.get", return_value=_resp(401, "Invalid credentials")):
            results = check_ldap_injection([ep])

        assert results == []

    def test_skips_endpoints_without_parameters(self) -> None:
        ep = Endpoint(url="https://app.example.com/about", status_code=200)

        with patch("requests.get") as mock_get:
            results = check_ldap_injection([ep])

        mock_get.assert_not_called()
        assert results == []

    def test_skips_server_error_endpoints(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=500, parameters=["username"])

        with patch("requests.get") as mock_get:
            results = check_ldap_injection([ep])

        mock_get.assert_not_called()
        assert results == []

    def test_one_finding_per_endpoint_with_multiple_params(self) -> None:
        ep = Endpoint(
            url="https://app.example.com/login",
            status_code=200,
            parameters=["username", "email"],
        )

        with patch(
            "requests.get",
            side_effect=lambda url, **kw: _baseline_or_probe(
                url, _resp(401, "bad"), _resp(200, "Welcome!")
            ),
        ):
            results = check_ldap_injection([ep])

        assert len(results) == 1

    def test_stops_probing_after_first_match(self) -> None:
        ep = Endpoint(
            url="https://app.example.com/login",
            status_code=200,
            parameters=["username"],
        )

        with patch(
            "requests.get",
            side_effect=lambda url, **kw: _baseline_or_probe(
                url, _resp(401, "bad"), _resp(200, "Welcome!")
            ),
        ) as mock_get:
            check_ldap_injection([ep])

        # One baseline + one payload before match - should stop immediately.
        assert mock_get.call_count == 2

    def test_baseline_exception_skips_param(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["username"])

        def raise_on_baseline(url: str, **kw: object) -> MagicMock:
            if _BASELINE_VALUE in url:
                raise OSError("connection refused")
            return _resp(200, "Welcome!")

        with patch("requests.get", side_effect=raise_on_baseline):
            results = check_ldap_injection([ep])

        assert results == []

    def test_probe_exception_is_swallowed(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["username"])

        def raise_on_probe(url: str, **kw: object) -> MagicMock:
            if _BASELINE_VALUE in url:
                return _resp(401, "bad")
            raise OSError("timeout")

        with patch("requests.get", side_effect=raise_on_probe):
            results = check_ldap_injection([ep])

        assert results == []

    def test_deduplicates_across_multiple_endpoints_same_url(self) -> None:
        ep1 = Endpoint(
            url="https://app.example.com/login", status_code=200, parameters=["username"]
        )
        ep2 = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["email"])

        with patch(
            "requests.get",
            side_effect=lambda url, **kw: _baseline_or_probe(
                url, _resp(401, "bad"), _resp(200, "Welcome!")
            ),
        ):
            results = check_ldap_injection([ep1, ep2])

        assert len(results) == 1

    def test_high_takes_priority_over_medium(self) -> None:
        # Response triggers both a status-code bypass AND an error marker -
        # the finding should be HIGH, not MEDIUM.
        ep = Endpoint(url="https://app.example.com/login", status_code=200, parameters=["username"])

        with patch(
            "requests.get",
            side_effect=lambda url, **kw: _baseline_or_probe(
                url,
                _resp(401, "bad"),
                _resp(200, "Welcome! objectClass=person"),
            ),
        ):
            results = check_ldap_injection([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.HIGH

    def test_payload_list_covers_required_classes(self) -> None:
        payloads = [p for p, _ in _PAYLOADS]
        joined = " ".join(payloads)
        assert "uid=*" in joined
        assert "objectClass" in joined
        assert "*" in joined
        assert "admin" in joined
        assert "%00" in joined

    def test_error_markers_cover_required_strings(self) -> None:
        assert "javax.naming" in _LDAP_ERROR_MARKERS
        assert "ldap_search" in _LDAP_ERROR_MARKERS
        assert "objectClass" in _LDAP_ERROR_MARKERS
