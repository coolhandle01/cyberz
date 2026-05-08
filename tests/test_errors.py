"""tests/test_errors.py - unit tests for tools/pentest/errors.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.errors import check_error_disclosure

pytestmark = pytest.mark.unit

_PYTHON_TRACEBACK = "Traceback (most recent call last):\n  File 'app.py', line 42\nValueError"
_DJANGO_ERROR = "django.core.exceptions.ObjectDoesNotExist at /api/users"
_PHP_ERROR = "Fatal error: Uncaught TypeError in /var/www/html/index.php on line 99"
_JAVA_TRACE = "at com.example.app.Controller.handle(Controller.java:55)"
_MYSQL_ERROR = "You have an error in your SQL syntax; check the manual"
_ORACLE_ERROR = "ORA-00942: table or view does not exist"
_PG_ERROR = "PG::UndefinedTable: ERROR: relation 'users' does not exist"
_ASPNET_ERROR = "Server Error in '/' Application. Runtime Error"


def _resp(body: str, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = body
    return r


class TestCheckErrorDisclosure:
    def test_detects_python_traceback(self):
        ep = Endpoint(url="https://app.example.com/api", status_code=200, parameters=["id"])
        with patch("requests.get", return_value=_resp(_PYTHON_TRACEBACK)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert results[0].vuln_class == "ErrorDisclosure"
        assert results[0].severity_hint == Severity.INFORMATIONAL
        assert "Python traceback" in results[0].evidence

    def test_detects_django_debug(self):
        ep = Endpoint(url="https://app.example.com/api", status_code=200, parameters=["id"])
        with patch("requests.get", return_value=_resp(_DJANGO_ERROR)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert "Django debug" in results[0].evidence

    def test_detects_php_fatal_error(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", return_value=_resp(_PHP_ERROR)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert "PHP fatal error" in results[0].evidence

    def test_detects_java_stack_trace(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", return_value=_resp(_JAVA_TRACE)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert "Java stack trace" in results[0].evidence

    def test_detects_mysql_error(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200, parameters=["q"])
        with patch("requests.get", return_value=_resp(_MYSQL_ERROR)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert "MySQL error" in results[0].evidence

    def test_detects_oracle_error(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", return_value=_resp(_ORACLE_ERROR)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert "Oracle SQL error" in results[0].evidence

    def test_detects_postgresql_error(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", return_value=_resp(_PG_ERROR)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert "PostgreSQL error" in results[0].evidence

    def test_detects_aspnet_error(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", return_value=_resp(_ASPNET_ERROR)):
            results = check_error_disclosure([ep])
        assert len(results) == 1
        assert "ASP.NET" in results[0].evidence

    def test_no_finding_for_clean_response(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", return_value=_resp("<html><body>Not Found</body></html>")):
            results = check_error_disclosure([ep])
        assert results == []

    def test_skips_server_error_endpoints(self):
        ep = Endpoint(url="https://app.example.com/", status_code=500)
        with patch("requests.get") as mock_get:
            results = check_error_disclosure([ep])
        mock_get.assert_not_called()
        assert results == []

    def test_network_exception_is_swallowed(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_error_disclosure([ep])
        assert results == []

    def test_deduplicates_multiple_probe_hits(self):
        """Only one finding per endpoint even if both probe URLs trigger errors."""
        ep = Endpoint(url="https://app.example.com/api", status_code=200, parameters=["id"])
        with patch("requests.get", return_value=_resp(_PYTHON_TRACEBACK)):
            results = check_error_disclosure([ep])
        assert len(results) == 1

    def test_probes_404_path_even_without_parameters(self):
        ep = Endpoint(url="https://app.example.com/", status_code=200)
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            return _resp("")

        with patch("requests.get", side_effect=recording_get):
            check_error_disclosure([ep])

        assert any("bountysquad-404probe" in u for u in seen_urls)
