"""tests/test_cmd_injection.py - unit tests for tools/pentest/cmd_injection.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.cmd_injection import _CANARY, _PAYLOADS, check_cmd_injection

pytestmark = pytest.mark.unit


def _resp(status: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


class TestCheckCmdInjection:
    def test_detects_canary_in_response(self) -> None:
        ep = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["host"])

        with patch("requests.get", return_value=_resp(body=f"PING output\n{_CANARY}\ndone")):
            results = check_cmd_injection([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "CommandInjection"
        assert results[0].severity_hint == Severity.CRITICAL
        assert "host" in results[0].evidence
        assert _CANARY in results[0].evidence

    def test_stops_after_first_matching_payload(self) -> None:
        ep = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["host"])

        with patch("requests.get", return_value=_resp(body=f"{_CANARY}")) as mock_get:
            check_cmd_injection([ep])

        assert mock_get.call_count == 1

    def test_no_finding_when_canary_absent(self) -> None:
        ep = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["host"])

        with patch("requests.get", return_value=_resp(body="PING 127.0.0.1: 56 data bytes")):
            results = check_cmd_injection([ep])

        assert results == []

    def test_partial_canary_match_is_not_a_finding(self) -> None:
        # A substring of the canary appearing coincidentally must not trigger.
        ep = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["host"])
        partial = _CANARY[:6]

        with patch("requests.get", return_value=_resp(body=f"result: {partial} ok")):
            results = check_cmd_injection([ep])

        assert results == []

    def test_skips_endpoints_without_parameters(self) -> None:
        ep = Endpoint(url="https://app.example.com/ping", status_code=200)

        with patch("requests.get") as mock_get:
            results = check_cmd_injection([ep])

        mock_get.assert_not_called()
        assert results == []

    def test_skips_server_error_endpoints(self) -> None:
        ep = Endpoint(url="https://app.example.com/ping", status_code=500, parameters=["host"])

        with patch("requests.get") as mock_get:
            results = check_cmd_injection([ep])

        mock_get.assert_not_called()
        assert results == []

    def test_one_finding_per_endpoint_multiple_params(self) -> None:
        ep = Endpoint(
            url="https://app.example.com/ping",
            status_code=200,
            parameters=["host", "port"],
        )

        with patch("requests.get", return_value=_resp(body=_CANARY)):
            results = check_cmd_injection([ep])

        assert len(results) == 1

    def test_deduplicates_same_url(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["host"])
        ep2 = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["ip"])

        with patch("requests.get", return_value=_resp(body=_CANARY)):
            results = check_cmd_injection([ep1, ep2])

        assert len(results) == 1

    def test_multiple_distinct_endpoints_each_get_a_finding(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["host"])
        ep2 = Endpoint(url="https://app.example.com/exec", status_code=200, parameters=["cmd"])

        with patch("requests.get", return_value=_resp(body=_CANARY)):
            results = check_cmd_injection([ep1, ep2])

        assert len(results) == 2

    def test_network_exception_is_swallowed(self) -> None:
        ep = Endpoint(url="https://app.example.com/ping", status_code=200, parameters=["host"])

        with patch("requests.get", side_effect=OSError("connection refused")):
            results = check_cmd_injection([ep])

        assert results == []

    def test_payload_list_covers_required_separators(self) -> None:
        payloads = [p for p, _ in _PAYLOADS]
        joined = " ".join(payloads)
        assert "; echo" in joined
        assert "| echo" in joined
        assert "&& echo" in joined
        assert "|| echo" in joined
        assert "`echo" in joined
        assert "$(echo" in joined
        assert "%0aecho" in joined
        assert "& echo" in joined

    def test_canary_is_embedded_in_all_payloads(self) -> None:
        for payload, label in _PAYLOADS:
            assert _CANARY in payload, f"canary missing from payload {label!r}"
