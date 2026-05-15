"""tests/test_csrf.py - unit tests for tools/pentest/csrf.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.csrf import _parse_post_forms, check_csrf

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HTML_POST_NO_TOKEN = """
<html><body>
<form method="POST" action="/submit">
  <input type="text" name="username">
  <input type="submit" value="Go">
</form>
</body></html>
"""

_HTML_POST_WITH_TOKEN = """
<html><body>
<form method="POST" action="/submit">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="username">
  <input type="submit" value="Go">
</form>
</body></html>
"""

_HTML_GET_FORM_ONLY = """
<html><body>
<form method="GET" action="/search">
  <input type="text" name="q">
</form>
</body></html>
"""

_HTML_NO_FORM = "<html><body><p>Hello world</p></body></html>"


def _get_resp(
    status: int = 200,
    body: str = "",
    content_type: str = "text/html; charset=utf-8",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.headers = {"Content-Type": content_type}
    return resp


def _post_resp(status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = ""
    resp.headers = {}
    return resp


# ---------------------------------------------------------------------------
# _parse_post_forms unit tests
# ---------------------------------------------------------------------------


class TestParsePostForms:
    def test_finds_post_form_without_token(self) -> None:
        forms = _parse_post_forms(_HTML_POST_NO_TOKEN)
        assert len(forms) == 1
        assert forms[0]["has_csrf_input"] is False
        assert forms[0]["action"] == "/submit"

    def test_finds_post_form_with_csrf_token(self) -> None:
        forms = _parse_post_forms(_HTML_POST_WITH_TOKEN)
        assert len(forms) == 1
        assert forms[0]["has_csrf_input"] is True

    def test_ignores_get_form(self) -> None:
        assert _parse_post_forms(_HTML_GET_FORM_ONLY) == []

    def test_no_forms(self) -> None:
        assert _parse_post_forms(_HTML_NO_FORM) == []

    def test_case_insensitive_method_attribute(self) -> None:
        html = '<form method="post"><input type="text" name="x"></form>'
        forms = _parse_post_forms(html)
        assert len(forms) == 1

    def test_recognises_xsrf_token(self) -> None:
        html = '<form method="POST"><input type="hidden" name="xsrf_token" value="y"></form>'
        forms = _parse_post_forms(html)
        assert forms[0]["has_csrf_input"] is True

    def test_recognises_authenticity_token(self) -> None:
        html = (
            '<form method="POST"><input type="hidden" name="authenticity_token" value="z"></form>'
        )
        forms = _parse_post_forms(html)
        assert forms[0]["has_csrf_input"] is True

    def test_multiple_forms_tracked_independently(self) -> None:
        html = """
        <form method="POST" action="/a">
          <input type="hidden" name="csrf" value="x">
        </form>
        <form method="POST" action="/b">
          <input type="text" name="user">
        </form>
        """
        forms = _parse_post_forms(html)
        assert len(forms) == 2
        assert forms[0]["has_csrf_input"] is True
        assert forms[1]["has_csrf_input"] is False


# ---------------------------------------------------------------------------
# check_csrf integration tests
# ---------------------------------------------------------------------------


class TestCheckCSRF:
    # ------------------------------------------------------------------
    # Tier 1: missing CSRF token -> MEDIUM
    # ------------------------------------------------------------------

    def test_detects_missing_csrf_token_medium(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", return_value=_post_resp(status=400)),
        ):
            results = check_csrf([ep])

        tier1 = [r for r in results if r.severity_hint == Severity.MEDIUM]
        assert len(tier1) == 1
        assert tier1[0].vuln_class == "CSRF"
        assert "Missing CSRF Token" in tier1[0].title
        assert "/submit" in tier1[0].evidence

    def test_no_finding_when_csrf_token_present(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        with patch("requests.get", return_value=_get_resp(body=_HTML_POST_WITH_TOKEN)):
            results = check_csrf([ep])

        assert results == []

    def test_skips_non_html_responses(self) -> None:
        ep = Endpoint(url="https://app.example.com/api/data", status_code=200)

        with patch(
            "requests.get",
            return_value=_get_resp(body='{"key": "val"}', content_type="application/json"),
        ) as mock_get:
            results = check_csrf([ep])

        mock_get.assert_called_once()
        assert results == []

    def test_skips_5xx_endpoints(self) -> None:
        ep = Endpoint(url="https://app.example.com/broken", status_code=500)

        with patch("requests.get") as mock_get:
            results = check_csrf([ep])

        mock_get.assert_not_called()
        assert results == []

    def test_skips_endpoints_with_get_forms_only(self) -> None:
        ep = Endpoint(url="https://app.example.com/search", status_code=200)

        with patch("requests.get", return_value=_get_resp(body=_HTML_GET_FORM_ONLY)):
            results = check_csrf([ep])

        assert results == []

    def test_no_finding_on_page_with_no_forms(self) -> None:
        ep = Endpoint(url="https://app.example.com/about", status_code=200)

        with patch("requests.get", return_value=_get_resp(body=_HTML_NO_FORM)):
            results = check_csrf([ep])

        assert results == []

    def test_network_exception_is_swallowed(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        with patch("requests.get", side_effect=OSError("connection refused")):
            results = check_csrf([ep])

        assert results == []

    # ------------------------------------------------------------------
    # Tier 2: origin not validated -> HIGH
    # ------------------------------------------------------------------

    def test_detects_origin_not_validated_high(self) -> None:
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", return_value=_post_resp(status=200)),
        ):
            results = check_csrf([ep])

        tier2 = [r for r in results if r.severity_hint == Severity.HIGH]
        assert len(tier2) == 1
        assert "Origin Header Not Validated" in tier2[0].title
        assert "evil.example.com" in tier2[0].evidence

    def test_no_high_finding_when_origin_validated(self) -> None:
        # Evil origin gets 403, correct origin gets 200 -> origin is validated.
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        def fake_post(url: str, **kw: object) -> MagicMock:
            headers = kw.get("headers", {})
            assert isinstance(headers, dict)
            if "evil.example.com" in headers.get("Origin", ""):
                return _post_resp(status=403)
            return _post_resp(status=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", side_effect=fake_post),
        ):
            results = check_csrf([ep])

        tier2 = [r for r in results if r.severity_hint == Severity.HIGH]
        assert tier2 == []

    def test_no_high_finding_when_both_non_2xx(self) -> None:
        # Both origins rejected -> no HIGH finding (not exploitable).
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", return_value=_post_resp(status=403)),
        ):
            results = check_csrf([ep])

        tier2 = [r for r in results if r.severity_hint == Severity.HIGH]
        assert tier2 == []

    def test_tier2_not_run_when_tier1_no_finding(self) -> None:
        # Page with CSRF token -> Tier 1 passes -> Tier 2 should not run.
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_WITH_TOKEN)),
            patch("requests.post") as mock_post,
        ):
            results = check_csrf([ep])

        mock_post.assert_not_called()
        assert results == []

    def test_tier2_exception_is_swallowed(self) -> None:
        # GET succeeds and Tier 1 fires, but Tier 2 POST raises.
        ep = Endpoint(url="https://app.example.com/login", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", side_effect=OSError("timeout")),
        ):
            results = check_csrf([ep])

        # Tier 1 MEDIUM should still be present, Tier 2 HIGH should not.
        assert len(results) == 1
        assert results[0].severity_hint == Severity.MEDIUM

    # ------------------------------------------------------------------
    # One finding per endpoint per tier
    # ------------------------------------------------------------------

    def test_one_tier1_finding_per_endpoint(self) -> None:
        # Page has two unprotected POST forms; still only one Tier-1 finding.
        html = """
        <form method="POST" action="/a"><input type="text" name="u"></form>
        <form method="POST" action="/b"><input type="text" name="v"></form>
        """
        ep = Endpoint(url="https://app.example.com/multi", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=html)),
            patch("requests.post", return_value=_post_resp(status=400)),
        ):
            results = check_csrf([ep])

        tier1 = [r for r in results if r.severity_hint == Severity.MEDIUM]
        assert len(tier1) == 1

    def test_deduplicates_same_url(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/login", status_code=200)
        ep2 = Endpoint(url="https://app.example.com/login", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", return_value=_post_resp(status=400)),
        ):
            results = check_csrf([ep1, ep2])

        tier1 = [r for r in results if r.severity_hint == Severity.MEDIUM]
        assert len(tier1) == 1

    def test_multiple_distinct_endpoints_each_get_findings(self) -> None:
        ep1 = Endpoint(url="https://app.example.com/login", status_code=200)
        ep2 = Endpoint(url="https://app.example.com/register", status_code=200)

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", return_value=_post_resp(status=400)),
        ):
            results = check_csrf([ep1, ep2])

        tier1 = [r for r in results if r.severity_hint == Severity.MEDIUM]
        assert len(tier1) == 2

    def test_endpoint_without_status_code_is_probed(self) -> None:
        # status_code=None means recon did not record it - still probe.
        ep = Endpoint(url="https://app.example.com/login")

        with (
            patch("requests.get", return_value=_get_resp(body=_HTML_POST_NO_TOKEN)),
            patch("requests.post", return_value=_post_resp(status=400)),
        ):
            results = check_csrf([ep])

        assert len([r for r in results if r.severity_hint == Severity.MEDIUM]) == 1
