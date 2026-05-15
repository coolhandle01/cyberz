"""tests/test_prototype_pollution.py - unit tests for tools/pentest/prototype_pollution.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.prototype_pollution import (
    _CANARY,
    _JSON_PAYLOADS,
    _URL_PAYLOADS,
    check_prototype_pollution,
)

pytestmark = pytest.mark.unit


def _resp(status: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


class TestCheckPrototypePollution:
    def test_detects_canary_in_url_param_get_response(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        # Baseline GET returns clean body; second GET (URL param probe) reflects canary.
        responses = [
            _resp(body="normal response"),  # baseline
            _resp(body=f"response containing {_CANARY}"),  # first URL param vector
        ]
        with patch("requests.get", side_effect=responses):
            results = check_prototype_pollution([ep])

        assert len(results) == 1
        assert results[0].vuln_class == "PrototypePollution"
        assert results[0].severity_hint == Severity.CRITICAL
        assert _CANARY in results[0].evidence
        assert "URL parameter" in results[0].evidence

    def test_detects_canary_in_json_post_response(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        # All GETs return empty; first POST reflects canary.
        clean_get = _resp(body="")
        canary_post = _resp(body=f"echo: {_CANARY}")

        def fake_get(url: str, **kw: object) -> MagicMock:
            return clean_get

        def fake_post(url: str, **kw: object) -> MagicMock:
            return canary_post

        with (
            patch("requests.get", side_effect=fake_get),
            patch("requests.post", side_effect=fake_post),
        ):
            results = check_prototype_pollution([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL
        assert _CANARY in results[0].evidence
        assert "JSON body" in results[0].evidence

    def test_no_finding_when_canary_absent_and_no_500(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        with (
            patch("requests.get", return_value=_resp(body="nothing here")),
            patch("requests.post", return_value=_resp(body="still nothing")),
        ):
            results = check_prototype_pollution([ep])

        assert results == []

    def test_detects_server_error_after_injection_medium(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        baseline = _resp(status=200, body="ok")
        error_resp = _resp(status=500, body="Internal Server Error")

        # Baseline GET is 200; first URL param probe triggers 500.
        responses = [baseline, error_resp]
        with (
            patch("requests.get", side_effect=responses),
            patch("requests.post", return_value=_resp(body="")),
        ):
            results = check_prototype_pollution([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.MEDIUM
        assert "server error" in results[0].title.lower() or "injection" in results[0].title.lower()
        assert "500" in results[0].evidence

    def test_critical_takes_priority_over_medium(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        baseline = _resp(status=200, body="ok")

        # First URL param probe gives 500 (would be MEDIUM), but second gives canary (CRITICAL).
        url_probe_1 = _resp(status=500, body="err")
        url_probe_2 = _resp(body=f"reflected {_CANARY}")

        responses = [baseline, url_probe_1, url_probe_2]
        with (
            patch("requests.get", side_effect=responses),
            patch("requests.post", return_value=_resp(body="")),
        ):
            results = check_prototype_pollution([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL

    def test_skips_5xx_endpoints(self) -> None:
        ep = Endpoint(url="https://app.example.com/broken", status_code=503)

        with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
            results = check_prototype_pollution([ep])

        mock_get.assert_not_called()
        mock_post.assert_not_called()
        assert results == []

    def test_deduplicates_same_url(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/api", status_code=200)
        ep2 = Endpoint(url="https://app.example.com/api", status_code=200)

        responses_get = [
            _resp(body=""),  # baseline for ep1
            _resp(body=f"{_CANARY}"),  # first URL probe for ep1 -> CRITICAL
        ]
        with (
            patch("requests.get", side_effect=responses_get),
            patch("requests.post", return_value=_resp(body="")),
        ):
            results = check_prototype_pollution([ep1, ep2])

        # ep2 is a duplicate URL; only one finding expected.
        assert len(results) == 1

    def test_multiple_distinct_endpoints_each_get_a_finding(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/api/users", status_code=200)
        ep2 = Endpoint(url="https://app.example.com/api/posts", status_code=200)

        with (
            patch("requests.get", return_value=_resp(body=f"{_CANARY}")),
            patch("requests.post", return_value=_resp(body="")),
        ):
            results = check_prototype_pollution([ep1, ep2])

        assert len(results) == 2
        targets = {r.target for r in results}
        assert "https://app.example.com/api/users" in targets
        assert "https://app.example.com/api/posts" in targets

    def test_network_exception_is_swallowed(self) -> None:
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        with (
            patch("requests.get", side_effect=OSError("connection refused")),
            patch("requests.post", side_effect=OSError("connection refused")),
        ):
            results = check_prototype_pollution([ep])

        assert results == []

    def test_url_payloads_cover_proto_and_constructor(self) -> None:
        payloads = [qs for qs, _ in _URL_PAYLOADS]
        joined = " ".join(payloads)
        assert "__proto__" in joined
        assert "constructor" in joined
        assert _CANARY in joined

    def test_json_payloads_cover_proto_and_constructor(self) -> None:
        import json

        serialised = json.dumps([body for body, _ in _JSON_PAYLOADS])
        assert "__proto__" in serialised
        assert "constructor" in serialised
        assert _CANARY in serialised

    def test_endpoint_with_none_status_code_is_probed(self) -> None:
        # status_code=None means the endpoint was discovered but not yet probed.
        ep = Endpoint(url="https://app.example.com/api", status_code=None)

        with (
            patch("requests.get", return_value=_resp(body=f"{_CANARY}")),
            patch("requests.post", return_value=_resp(body="")),
        ):
            results = check_prototype_pollution([ep])

        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL

    def test_endpoint_with_400_status_is_probed(self) -> None:
        # Non-5xx error responses should still be probed.
        ep = Endpoint(url="https://app.example.com/api", status_code=400)

        with (
            patch("requests.get", return_value=_resp(body=f"{_CANARY}")),
            patch("requests.post", return_value=_resp(body="")),
        ):
            results = check_prototype_pollution([ep])

        assert len(results) == 1

    def test_medium_not_emitted_when_baseline_already_500(self) -> None:
        # If the baseline itself is 500, a 500 on injection is not evidence.
        ep = Endpoint(url="https://app.example.com/api", status_code=200)

        # Baseline returns 500 too, so server was already broken.
        with (
            patch("requests.get", return_value=_resp(status=500, body="")),
            patch("requests.post", return_value=_resp(status=500, body="")),
        ):
            results = check_prototype_pollution([ep])

        assert results == []
