"""
tests/tools/recon/test_recon_tools.py - unit tests for tools/recon_tools.py

Focuses on the scope guard (security-critical) and domain extraction.
Subprocess calls are mocked so tests run without binaries installed.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint
from models.h1 import Programme, ScopeType
from tools.recon import (
    _ACTIVE_RECON_TYPES,
    _CODE_HOSTS,
    cert_transparency,
    discover_paths,
    enumerate_subdomains,
    filter_in_scope,
    historical_urls,
    host_of,
    port_scan,
    probe_endpoints,
)

pytestmark = pytest.mark.unit


# host_of - thin stdlib urlparse wrapper. Returns the URL's hostname
# or "" when the input has no host (a bare hostname rather than a URL).
class TestHostOf:
    def test_url_with_scheme(self, target_apex):
        assert host_of(f"https://{target_apex}") == "example.com"

    def test_url_with_path(self, target_apex):
        assert host_of(f"https://api.{target_apex}/v1/search") == "api.example.com"

    def test_url_with_port(self, target_apex):
        assert host_of(f"https://{target_apex}:8443") == "example.com"

    def test_bare_hostname_returns_empty(self):
        """No scheme means urlparse cannot identify a netloc; the helper
        is intentionally URL-only and returns "" rather than guessing."""
        assert host_of("example.com") == ""


class TestSeedingConstants:
    """
    Regression: URL-type scope items pointing into third-party code hosting infra
    (e.g. github.com/cloudflare) must not be used as subfinder seeds.
    H1 returns URL for both bare domains and wildcard patterns; OTHER for products.
    """

    def test_url_type_is_active_recon(self):
        assert ScopeType.URL in _ACTIVE_RECON_TYPES

    def test_wildcard_type_is_active_recon(self):
        assert ScopeType.WILDCARD in _ACTIVE_RECON_TYPES

    def test_other_type_is_not_active_recon(self):
        assert ScopeType.OTHER not in _ACTIVE_RECON_TYPES

    def test_code_hosts_blocks_github(self):
        assert "github.com" in _CODE_HOSTS

    def test_code_hosts_blocks_gitlab(self):
        assert "gitlab.com" in _CODE_HOSTS


# filter_in_scope
class TestFilterInScope:
    """
    The scope guard is security-critical - an out-of-scope false positive
    would cause us to test targets we're not authorised to touch.
    """

    def test_exact_domain_match(self, programme):
        assert filter_in_scope(["example.com"], programme) == ["example.com"]

    def test_genuine_subdomain_passes(self, programme):
        result = filter_in_scope(["api.example.com"], programme)
        assert "api.example.com" in result

    def test_deep_subdomain_passes(self, programme):
        result = filter_in_scope(["deep.api.example.com"], programme)
        assert "deep.api.example.com" in result

    def test_out_of_scope_domain_blocked(self, programme):
        result = filter_in_scope(["other.com"], programme)
        assert result == []

    def test_boundary_spoofing_blocked(self, programme):
        """evil.notexample.com must NOT pass as in-scope for example.com."""
        result = filter_in_scope(["evil.notexample.com"], programme)
        assert result == [], "Scope guard boundary bug: evil.notexample.com matched example.com"

    def test_suffix_spoofing_blocked(self, programme):
        """attackerexample.com must NOT match *.example.com."""
        result = filter_in_scope(["attackerexample.com"], programme)
        assert result == []

    def test_mixed_batch(self, programme):
        hosts = ["api.example.com", "evil.notexample.com", "admin.example.com", "other.io"]
        result = filter_in_scope(hosts, programme)
        assert "api.example.com" in result
        assert "admin.example.com" in result
        assert "evil.notexample.com" not in result
        assert "other.io" not in result

    def test_empty_input(self, programme):
        assert filter_in_scope([], programme) == []

    def test_no_scope_items(self):
        bare_programme = Programme(
            handle="bare",
            name="Bare",
            url="https://hackerone.com/bare",
            bounty_table={},
            in_scope=[],
            out_of_scope=[],
        )
        assert filter_in_scope(["example.com"], bare_programme) == []

    def test_non_url_wildcard_scope_items_are_skipped(self, target_apex):
        """``filter_in_scope`` only consults URL / WILDCARD scope items.
        A programme whose in-scope catalogue mixes other ``ScopeType``
        members (``IP_ADDRESS``, ``CIDR``, ``OTHER``, mobile-app IDs)
        skips those entries entirely - they do not match hostnames.
        Pins the branch that would otherwise silently treat a CIDR
        ``asset_identifier`` as a hostname pattern."""
        from models.h1 import ScopeItem, ScopeType

        prog = Programme(
            handle="mixed",
            name="Mixed Scope",
            url="https://hackerone.com/mixed",
            bounty_table={},
            in_scope=[
                ScopeItem(asset_identifier="10.0.0.0/8", asset_type=ScopeType.CIDR),
                ScopeItem(asset_identifier="192.0.2.1", asset_type=ScopeType.IP_ADDRESS),
                ScopeItem(asset_identifier="com.example.app", asset_type=ScopeType.OTHER),
                ScopeItem(asset_identifier=f"*.{target_apex}", asset_type=ScopeType.WILDCARD),
            ],
            out_of_scope=[],
        )
        # Only the WILDCARD entry matches; the IP / CIDR / OTHER entries
        # are skipped per the ``continue`` branch.
        assert filter_in_scope([f"api.{target_apex}"], prog) == [f"api.{target_apex}"]
        assert filter_in_scope(["10.0.0.5"], prog) == []
        assert filter_in_scope(["com.example.app"], prog) == []


class TestInScopeTypedAliases:
    """The ``TargetHostnames`` / ``TargetEndpoints`` typed aliases run
    a Pydantic ``AfterValidator`` at ``args_schema.model_validate(...)``
    time - that is the scope guard. List variants filter silently
    (mixed candidate lists pass survivors); single variants
    (``TargetHostname`` / ``TargetEndpoint``) raise ``ValueError`` on
    an OOS pick. The aliases are exercised end-to-end via a small
    args_schema stub that mirrors what the cloud / probe / OSINT
    wrappers declare in production.
    """

    def test_list_hostnames_filters_oos(self, programme_in_workspace, target_apex):
        from pydantic import BaseModel

        from tools.recon.scope import TargetHostnames

        class _Args(BaseModel):
            hostnames: TargetHostnames

        parsed = _Args.model_validate(
            {"hostnames": [f"api.{target_apex}", "bystander.example.org"]}
        )
        assert parsed.hostnames == [f"api.{target_apex}"]

    def test_list_endpoints_filters_oos(self, programme_in_workspace, target_apex, bystander_url):
        from pydantic import BaseModel

        from tools.recon.scope import TargetEndpoints

        class _Args(BaseModel):
            endpoints: TargetEndpoints

        parsed = _Args.model_validate(
            {
                "endpoints": [
                    {"url": f"https://api.{target_apex}", "status_code": 200},
                    {"url": bystander_url, "status_code": 200},
                ]
            }
        )
        assert len(parsed.endpoints) == 1
        assert parsed.endpoints[0].url == f"https://api.{target_apex}"

    def test_single_hostname_rejects_oos(self, programme_in_workspace):
        from pydantic import BaseModel, ValidationError

        from tools.recon.scope import TargetHostname

        class _Args(BaseModel):
            hostname: TargetHostname

        with pytest.raises(ValidationError, match="not in the selected programme's scope"):
            _Args.model_validate({"hostname": "bystander.example.org"})

    def test_single_endpoint_rejects_oos(self, programme_in_workspace, bystander_url):
        from pydantic import BaseModel, ValidationError

        from tools.recon.scope import TargetEndpoint

        class _Args(BaseModel):
            endpoint: TargetEndpoint

        with pytest.raises(ValidationError, match="not in the selected programme's scope"):
            _Args.model_validate({"endpoint": {"url": bystander_url, "status_code": 200}})

    def test_single_url_accepts_in_scope(self, programme_in_workspace, target_apex):
        """``TargetUrl`` parses the host out of a URL string and rejects
        out-of-scope hosts loudly. Sibling of ``TargetEndpoint`` for
        callers that have a bare URL string rather than an ``Endpoint``
        (the MCP-shipped tools that take URLs as plain strings are the
        canonical case)."""
        from pydantic import BaseModel

        from tools.recon.scope import TargetUrl

        class _Args(BaseModel):
            url: TargetUrl

        parsed = _Args.model_validate({"url": f"https://api.{target_apex}/login"})
        assert parsed.url == f"https://api.{target_apex}/login"

    def test_single_url_rejects_oos(self, programme_in_workspace, bystander_url):
        from pydantic import BaseModel, ValidationError

        from tools.recon.scope import TargetUrl

        class _Args(BaseModel):
            url: TargetUrl

        with pytest.raises(ValidationError, match="not in the selected programme's scope"):
            _Args.model_validate({"url": bystander_url})

    def test_single_url_rejects_unparseable(self, programme_in_workspace):
        """A URL string with no parseable host is refused: the filter
        cannot vouch for what it cannot parse."""
        from pydantic import BaseModel, ValidationError

        from tools.recon.scope import TargetUrl

        class _Args(BaseModel):
            url: TargetUrl

        with pytest.raises(ValidationError, match="cannot parse a host"):
            _Args.model_validate({"url": "not-a-real-url"})

    def test_empty_list_skips_programme_lookup(self):
        """An empty list short-circuits the validator - no
        ``current_programme()`` lookup. No ``programme_in_workspace``
        fixture is taken, so the lookup would raise if it ran."""
        from pydantic import BaseModel

        from tools.recon.scope import TargetHostnames

        class _Args(BaseModel):
            hostnames: TargetHostnames

        parsed = _Args.model_validate({"hostnames": []})
        assert parsed.hostnames == []


# enumerate_subdomains
class TestEnumerateSubdomains:
    def test_returns_parsed_subdomains(self):
        mock_result = MagicMock()
        mock_result.stdout = "api.example.com\nadmin.example.com\n"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = enumerate_subdomains("example.com")

        assert "api.example.com" in result
        assert "admin.example.com" in result

    def test_deduplicates_results(self):
        mock_result = MagicMock()
        mock_result.stdout = "api.example.com\napi.example.com\nadmin.example.com\n"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = enumerate_subdomains("example.com")

        assert result.count("api.example.com") == 1

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="subfinder"):
                enumerate_subdomains("example.com")

    def test_empty_output(self):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = enumerate_subdomains("example.com")

        assert result == []


# probe_endpoints
class TestProbeEndpoints:
    def test_parses_httpx_json_output(self, target_apex):
        import json

        mock_result = MagicMock()
        mock_result.stdout = "\n".join(
            [
                json.dumps(
                    {"url": f"https://api.{target_apex}", "status_code": 200, "tech": ["nginx"]}
                ),
                json.dumps({"url": f"https://admin.{target_apex}", "status_code": 403, "tech": []}),
            ]
        )
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/httpx"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = probe_endpoints(["api.example.com", "admin.example.com"])

        assert len(result) == 2
        assert result[0].url == f"https://api.{target_apex}"
        assert result[0].status_code == 200
        assert "nginx" in result[0].technologies

    def test_skips_malformed_json_lines(self, target_apex):
        mock_result = MagicMock()
        mock_result.stdout = (
            f'not json\n{{"url": "https://api.{target_apex}", "status_code": 200, "tech": []}}'
        )
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/httpx"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = probe_endpoints(["api.example.com"])

        assert len(result) == 1

    def test_stdin_receives_host_list(self):
        """Regression: probe_endpoints previously discarded the host list entirely."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/httpx"),
            patch("subprocess.run", return_value=mock_result) as mock_run,
        ):
            probe_endpoints(["api.example.com", "admin.example.com"])

        call_kwargs = mock_run.call_args.kwargs
        assert "input" in call_kwargs, "host list must be passed via stdin (input=)"
        assert "api.example.com" in call_kwargs["input"]
        assert "admin.example.com" in call_kwargs["input"]

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="httpx"):
                probe_endpoints(["example.com"])


# port_scan
class TestPortScan:
    def test_parses_open_ports(self):
        mock_result = MagicMock()
        mock_result.stdout = (
            "# Nmap scan\n"
            "Host: 93.184.216.34 (example.com)\tStatus: Up\n"
            "Host: 93.184.216.34 (example.com)\tPorts: 80/open/tcp, 443/open/tcp\n"
        )
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = port_scan(["example.com"])

        assert 80 in result["example.com"]
        assert 443 in result["example.com"]

    def test_empty_host_list(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = port_scan([])
        assert result == {}

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="nmap"):
                port_scan(["example.com"])


# cert_transparency
class TestCertTransparency:
    def _crtsh_response(self):
        return [
            {"name_value": "api.example.com\nstage.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "other.notexample.com"},
        ]

    def test_returns_subdomains_ending_in_domain(self, make_response):
        mock_resp = make_response(json=self._crtsh_response())

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert "api.example.com" in result
        assert "stage.example.com" in result

    def test_strips_wildcard_prefix(self, make_response):
        mock_resp = make_response(json=[{"name_value": "*.example.com"}])

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert all(not n.startswith("*.") for n in result)

    def test_filters_off_domain_names(self, make_response):
        mock_resp = make_response(json=[{"name_value": "other.notexample.com"}])

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert result == []

    def test_deduplicates_results(self, make_response):
        mock_resp = make_response(
            json=[
                {"name_value": "api.example.com"},
                {"name_value": "api.example.com"},
            ]
        )

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert result.count("api.example.com") == 1


# historical_urls
class TestHistoricalUrls:
    def test_returns_urls_from_binary_output(self, target_apex):
        mock_proc = MagicMock()
        mock_proc.stdout = f"https://{target_apex}/old-path\nhttps://example.com/another\n"
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/waybackurls"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = historical_urls("example.com")

        assert f"https://{target_apex}/old-path" in result
        assert f"https://{target_apex}/another" in result

    def test_missing_binary_raises(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(OSError, match="waybackurls"):
                historical_urls("example.com")

    def test_empty_output_returns_empty_list(self):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/waybackurls"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = historical_urls("example.com")

        assert result == []


# discover_paths
class TestDiscoverPaths:
    def _ffuf_side_effect(self, results):
        """Return a subprocess.run side effect that writes ffuf JSON to the -o path."""

        def fake_run(cmd, *args, **kwargs):
            out_path = cmd[cmd.index("-o") + 1]
            with open(out_path, "w") as fh:
                json.dump({"results": results}, fh)
            return MagicMock(returncode=0, stdout="", stderr="")

        return fake_run

    def test_returns_discovered_endpoints(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        hits = [
            {"url": f"https://{target_apex}/admin", "status": 200},
            {"url": f"https://{target_apex}/api", "status": 200},
        ]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect(hits)),
        ):
            result = discover_paths(endpoints)

        urls = [ep.url for ep in result]
        assert f"https://{target_apex}/admin" in urls
        assert f"https://{target_apex}/api" in urls

    def test_deduplicates_known_urls(self, target_apex):
        endpoints = [
            Endpoint(url=f"https://{target_apex}/", status_code=200),
            Endpoint(url=f"https://{target_apex}/admin", status_code=200),
        ]
        hits = [
            {"url": f"https://{target_apex}/admin", "status": 200},
            {"url": f"https://{target_apex}/new-path", "status": 200},
        ]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect(hits)),
        ):
            result = discover_paths(endpoints)

        urls = [ep.url for ep in result]
        assert f"https://{target_apex}/admin" not in urls
        assert f"https://{target_apex}/new-path" in urls

    def test_empty_endpoints_returns_empty(self):
        assert discover_paths([]) == []

    def test_skips_endpoints_with_500_status(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=500)]
        with patch("shutil.which", return_value="/usr/bin/ffuf"):
            result = discover_paths(endpoints)
        assert result == []

    def test_missing_binary_raises_oserror(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        with patch("shutil.which", return_value=None):
            with pytest.raises(OSError, match="ffuf"):
                discover_paths(endpoints)

    def test_ffuf_exception_is_swallowed(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=Exception("connection refused")),
        ):
            result = discover_paths(endpoints)
        assert result == []

    def test_respects_status_codes_from_results(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        hits = [{"url": f"https://{target_apex}/protected", "status": 403}]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect(hits)),
        ):
            result = discover_paths(endpoints)

        assert len(result) == 1
        assert result[0].status_code == 403

    def test_empty_ffuf_results_returns_empty(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect([])),
        ):
            result = discover_paths(endpoints)
        assert result == []
