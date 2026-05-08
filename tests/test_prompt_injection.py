"""Unit tests for LLM endpoint detection and prompt injection probe."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.prompt_injection import check_prompt_injection
from tools.pentest.triage import _lookup_cvss
from tools.recon.llm import detect_llm_endpoints

pytestmark = pytest.mark.unit


# --- helpers -----------------------------------------------------------------


def _mock_resp(status: int, body: str = "", headers: dict | None = None) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.text = body
    m.headers = headers or {}
    return m


# --- detect_llm_endpoints ----------------------------------------------------


class TestDetectLlmEndpoints:
    def test_detects_by_url_path_token(self):
        ep = Endpoint(url="https://example.com/chat", status_code=200)
        with patch("requests.get", return_value=_mock_resp(200)):
            results = detect_llm_endpoints([ep])
        assert len(results) == 1
        assert "LLM" in results[0].technologies

    def test_detects_by_openai_header(self):
        ep = Endpoint(url="https://example.com/api/v1", status_code=200)
        headers = {"x-openai-organization": "org-abc123"}
        with patch("requests.get", return_value=_mock_resp(200, headers=headers)):
            results = detect_llm_endpoints([ep])
        assert len(results) == 1

    def test_detects_by_sse_content_type(self):
        ep = Endpoint(url="https://example.com/stream", status_code=200)
        headers = {"content-type": "text/event-stream"}
        with patch("requests.get", return_value=_mock_resp(200, headers=headers)):
            results = detect_llm_endpoints([ep])
        assert len(results) == 1

    def test_detects_by_openai_response_json(self):
        ep = Endpoint(url="https://example.com/api", status_code=200)
        body = '{"choices": [{"message": {"content": "hello"}}], "model": "gpt-4"}'
        with patch("requests.get", return_value=_mock_resp(200, body=body)):
            results = detect_llm_endpoints([ep])
        assert len(results) == 1

    def test_detects_by_body_phrase(self):
        ep = Endpoint(url="https://example.com/support", status_code=200)
        body = "I'm an AI assistant and I can help you with that."
        with patch("requests.get", return_value=_mock_resp(200, body=body)):
            results = detect_llm_endpoints([ep])
        assert len(results) == 1

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://example.com/chat", status_code=500)
        with patch("requests.get") as mock_get:
            results = detect_llm_endpoints([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_clean_endpoint_produces_no_result(self):
        ep = Endpoint(url="https://example.com/products", status_code=200)
        body = "<html><body>Product listing</body></html>"
        with patch("requests.get", return_value=_mock_resp(200, body=body)):
            results = detect_llm_endpoints([ep])
        assert results == []

    def test_preserves_existing_technologies(self):
        ep = Endpoint(url="https://example.com/chat", status_code=200, technologies=["React"])
        with patch("requests.get", return_value=_mock_resp(200)):
            results = detect_llm_endpoints([ep])
        assert "React" in results[0].technologies
        assert "LLM" in results[0].technologies

    def test_request_exception_does_not_raise(self):
        # URL has no LLM path token so detection relies solely on the HTTP probe.
        ep = Endpoint(url="https://example.com/support/widget", status_code=200)
        with patch("requests.get", side_effect=Exception("timeout")):
            results = detect_llm_endpoints([ep])
        assert results == []


# --- check_prompt_injection --------------------------------------------------


class TestCheckPromptInjection:
    def test_detects_canary_reflection(self):
        ep = Endpoint(url="https://example.com/chat", status_code=200)
        with patch("requests.post", return_value=_mock_resp(200, "CYBERSQUADCANARY")):
            results = check_prompt_injection([ep])
        assert len(results) == 1
        assert results[0].vuln_class == "PromptInjection"
        assert results[0].severity_hint == Severity.CRITICAL

    def test_detects_system_prompt_leakage(self):
        ep = Endpoint(url="https://example.com/chat", status_code=200)
        body = "You are a helpful customer service assistant. Your role is to help users."
        with patch("requests.post", return_value=_mock_resp(200, body)):
            results = check_prompt_injection([ep])
        assert len(results) == 1
        assert results[0].severity_hint == Severity.HIGH

    def test_safe_response_produces_no_finding(self):
        ep = Endpoint(url="https://example.com/chat", status_code=200)
        body = "I can help you with that! What would you like to know?"
        with patch("requests.post", return_value=_mock_resp(200, body)):
            results = check_prompt_injection([ep])
        assert results == []

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://example.com/chat", status_code=500)
        with patch("requests.post") as mock_post:
            results = check_prompt_injection([ep])
        mock_post.assert_not_called()
        assert results == []

    def test_request_exception_is_swallowed(self):
        ep = Endpoint(url="https://example.com/chat", status_code=200)
        with patch("requests.post", side_effect=Exception("timeout")):
            results = check_prompt_injection([ep])
        assert results == []

    def test_deduplicates_per_endpoint(self):
        ep = Endpoint(url="https://example.com/chat", status_code=200)
        with patch("requests.post", return_value=_mock_resp(200, "CYBERSQUADCANARY")):
            results = check_prompt_injection([ep])
        assert len(results) == 1

    def test_prompt_injection_cvss_critical(self):
        score, vector = _lookup_cvss("PromptInjection", Severity.CRITICAL)
        assert score == 9.1
        assert "CVSS:3.1" in vector

    def test_prompt_injection_cvss_high(self):
        score, vector = _lookup_cvss("PromptInjection", Severity.HIGH)
        assert score == 7.2
        assert "CVSS:3.1" in vector
