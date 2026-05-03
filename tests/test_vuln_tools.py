"""
tests/test_vuln_tools.py - unit tests for tools/vuln_tools.py
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity, VerifiedVulnerability
from tools.vuln_tools import (
    _lookup_cvss,
    check_cors_misconfiguration,
    is_in_scope,
    run_nuclei,
    triage_findings,
)

pytestmark = pytest.mark.unit


# _above_floor
class TestAboveFloor:
    def test_medium_above_medium_floor(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "medium")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.MEDIUM) is True

    def test_low_below_medium_floor(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "medium")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.LOW) is False

    def test_critical_always_above(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "high")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.CRITICAL) is True

    def test_informational_below_low_floor(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "low")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.INFORMATIONAL) is False


# _lookup_cvss
class TestLookupCvss:
    def test_sqli_critical(self):
        score, vector = _lookup_cvss("SQLi", Severity.CRITICAL)
        assert score == 9.8
        assert "CVSS:3.1" in vector

    def test_cors_high(self):
        score, vector = _lookup_cvss("CORS", Severity.HIGH)
        assert score == 7.4

    def test_unknown_class_falls_back_to_default(self):
        score, vector = _lookup_cvss("UnknownVulnType", Severity.HIGH)
        assert score == 7.5

    def test_returns_tuple(self):
        result = _lookup_cvss("XSS", Severity.MEDIUM)
        assert isinstance(result, tuple)
        assert len(result) == 2


# is_in_scope
class TestIsInScope:
    def test_in_scope_finding(self, raw_finding_high, programme):
        assert is_in_scope(raw_finding_high, programme) is True

    def test_out_of_scope_finding(self, raw_finding_oos, programme):
        assert is_in_scope(raw_finding_oos, programme) is False


# triage_findings
class TestTriageFindings:
    def test_filters_out_of_scope(self, raw_finding_high, raw_finding_oos, programme):
        results = triage_findings([raw_finding_high, raw_finding_oos], programme)
        targets = [v.target for v in results]
        assert raw_finding_oos.target not in targets

    def test_filters_below_severity_floor(
        self, raw_finding_high, raw_finding_low, programme, monkeypatch
    ):
        monkeypatch.setenv("MIN_SEVERITY", "medium")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        results = vt.triage_findings([raw_finding_high, raw_finding_low], programme)
        severities = [v.severity for v in results]
        assert Severity.LOW not in severities

    def test_assigns_cvss_score(self, raw_finding_high, programme):
        results = triage_findings([raw_finding_high], programme)
        assert len(results) == 1
        assert results[0].cvss_score > 0
        assert results[0].cvss_vector.startswith("CVSS:3.1")

    def test_returns_verified_vulnerability_objects(self, raw_finding_high, programme):
        results = triage_findings([raw_finding_high], programme)
        for r in results:
            assert isinstance(r, VerifiedVulnerability)

    def test_empty_input_returns_empty(self, programme):
        assert triage_findings([], programme) == []

    def test_all_filtered_returns_empty(self, raw_finding_oos, programme):
        assert triage_findings([raw_finding_oos], programme) == []

    def test_preserves_title_and_target(self, raw_finding_high, programme):
        results = triage_findings([raw_finding_high], programme)
        assert results[0].title == raw_finding_high.title
        assert results[0].target == raw_finding_high.target


# run_nuclei
class TestRunNuclei:
    def test_parses_nuclei_json_output(self):
        import json

        mock_result = MagicMock()
        mock_result.stdout = json.dumps(
            {
                "info": {"name": "Test Finding", "severity": "high", "tags": ["xss"]},
                "matched-at": "https://api.example.com/search",
                "extracted-results": ["payload"],
            }
        )
        mock_result.returncode = 0

        endpoints = [Endpoint(url="https://api.example.com/search", status_code=200)]

        with (
            patch("shutil.which", return_value="/usr/bin/nuclei"),
            patch("subprocess.run", return_value=mock_result),
        ):
            results = run_nuclei(endpoints)

        assert len(results) == 1
        assert results[0].tool == "nuclei"
        assert results[0].severity_hint == Severity.HIGH

    def test_empty_endpoints_returns_empty(self):
        results = run_nuclei([])
        assert results == []

    def test_raises_if_binary_missing(self):
        endpoints = [Endpoint(url="https://example.com", status_code=200)]
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="nuclei"):
                run_nuclei(endpoints)


# check_cors_misconfiguration
class TestCheckCorsMisconfiguration:
    def test_detects_wildcard_cors(self):
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "false",
        }

        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", return_value=mock_response):
            results = check_cors_misconfiguration(endpoints)

        assert len(results) == 1
        assert results[0].vuln_class == "CORS"

    def test_detects_reflected_origin_with_credentials(self):
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil.example.com",
            "Access-Control-Allow-Credentials": "true",
        }

        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", return_value=mock_response):
            results = check_cors_misconfiguration(endpoints)

        assert len(results) == 1
        assert results[0].severity_hint == Severity.HIGH

    def test_safe_cors_produces_no_finding(self):
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://example.com",
            "Access-Control-Allow-Credentials": "false",
        }

        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", return_value=mock_response):
            results = check_cors_misconfiguration(endpoints)

        assert results == []

    def test_request_exception_is_swallowed(self):
        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_cors_misconfiguration(endpoints)

        assert results == []


# check_ssrf
class TestCheckSsrf:
    def test_detects_aws_metadata_in_response(self):
        from tools.vuln_tools import check_ssrf

        endpoint = Endpoint(
            url="https://api.example.com/fetch",
            status_code=200,
            parameters=["url"],
        )
        mock_resp = MagicMock()
        mock_resp.text = "ami-id: ami-12345678\ninstance-id: i-abc"

        with patch("requests.get", return_value=mock_resp):
            results = check_ssrf([endpoint])

        assert len(results) == 1
        assert results[0].vuln_class == "SSRF"
        assert results[0].severity_hint == Severity.CRITICAL

    def test_skips_endpoints_without_parameters(self):
        from tools.vuln_tools import check_ssrf

        endpoint = Endpoint(url="https://api.example.com/static", status_code=200)

        with patch("requests.get") as mock_get:
            results = check_ssrf([endpoint])

        mock_get.assert_not_called()
        assert results == []

    def test_safe_response_produces_no_finding(self):
        from tools.vuln_tools import check_ssrf

        endpoint = Endpoint(
            url="https://api.example.com/fetch",
            status_code=200,
            parameters=["url"],
        )
        mock_resp = MagicMock()
        mock_resp.text = "<html>Normal page</html>"

        with patch("requests.get", return_value=mock_resp):
            results = check_ssrf([endpoint])

        assert results == []

    def test_request_exception_is_swallowed(self):
        from tools.vuln_tools import check_ssrf

        endpoint = Endpoint(
            url="https://api.example.com/fetch",
            status_code=200,
            parameters=["url"],
        )

        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_ssrf([endpoint])

        assert results == []


# check_header_injection
class TestCheckHeaderInjection:
    def test_detects_reflected_canary_in_headers(self):
        from tools.vuln_tools import check_header_injection

        endpoint = Endpoint(url="https://api.example.com/", status_code=200)
        mock_resp = MagicMock()
        mock_resp.headers = {"BountySquadCanary": "yes"}
        mock_resp.text = ""

        with patch("requests.get", return_value=mock_resp):
            results = check_header_injection([endpoint])

        assert len(results) == 1
        assert results[0].vuln_class == "HeaderInjection"

    def test_detects_canary_in_response_body(self):
        from tools.vuln_tools import check_header_injection

        endpoint = Endpoint(url="https://api.example.com/", status_code=200)
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.text = "bountysquadcanary injected"

        with patch("requests.get", return_value=mock_resp):
            results = check_header_injection([endpoint])

        assert len(results) == 1

    def test_clean_response_produces_no_finding(self):
        from tools.vuln_tools import check_header_injection

        endpoint = Endpoint(url="https://api.example.com/", status_code=200)
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "<html>Normal</html>"

        with patch("requests.get", return_value=mock_resp):
            results = check_header_injection([endpoint])

        assert results == []

    def test_request_exception_is_swallowed(self):
        from tools.vuln_tools import check_header_injection

        endpoint = Endpoint(url="https://api.example.com/", status_code=200)

        with patch("requests.get", side_effect=Exception("conn error")):
            results = check_header_injection([endpoint])

        assert results == []


# lookup_cve
class TestLookupCve:
    def _nvd_response(self):
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "vectorString": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                                        ),
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }

    def test_returns_parsed_cve_results(self):
        from tools.vuln_tools import lookup_cve

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = self._nvd_response()

        with patch("requests.get", return_value=mock_resp):
            results = lookup_cve("log4shell")

        assert len(results) == 1
        assert results[0]["id"] == "CVE-2021-44228"
        assert results[0]["cvss_score"] == 10.0
        assert results[0]["description"] == "Log4Shell RCE"

    def test_returns_empty_list_on_network_error(self):
        from tools.vuln_tools import lookup_cve

        with patch("requests.get", side_effect=Exception("network down")):
            results = lookup_cve("sqli")

        assert results == []

    def test_sends_api_key_header_when_configured(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "test-key-123")
        import importlib

        import config as cfg_module

        importlib.reload(cfg_module)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("requests.get", return_value=mock_resp) as mock_get:
            import tools.vuln_tools as vt_module

            importlib.reload(vt_module)
            vt_module.lookup_cve("xss")

        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs.get("headers", {}).get("apiKey") == "test-key-123"
