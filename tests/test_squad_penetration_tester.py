"""
tests/test_squad_penetration_tester.py - exercise the @tool wrappers on
the Penetration Tester.

Roughly 55 tools live on this agent; the bodies are near-identical thin
wrappers, so the per-wrapper bespoke tests at the top cover the unique
shapes (probes that mock specific helpers) and the parametrize tables
further down (``TestHostnameWrapperPassThrough`` and
``TestEndpointWrapperPassThrough``) cover every typed cloud wrapper for
the wrapper-level scope-filter + helper-forwarding contract at once.
The underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestPenetrationTesterTools:
    def test_nuclei_scan_tool(self, programme_in_workspace, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import nuclei_scan_tool

        with patch(
            "squad.penetration_tester.probes.external.run_nuclei",
            return_value=[raw_finding_low],
        ):
            result = nuclei_scan_tool.func([endpoint.model_dump(mode="json")], ["wordpress"])

        assert result == [raw_finding_low]

    def test_sqlmap_tool(self, programme_in_workspace, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import sqlmap_tool

        with patch(
            "squad.penetration_tester.probes.injection.run_sqlmap",
            return_value=[raw_finding_low],
        ):
            result = sqlmap_tool.func([endpoint.model_dump(mode="json")])

        assert result == [raw_finding_low]

    def test_cookie_check_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import cookie_check_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch(
            "squad.penetration_tester.probes.headers.check_cookies",
            return_value=[raw_finding_low],
        ):
            result = cookie_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_cors_check_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import cors_check_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch(
            "squad.penetration_tester.probes.headers.check_cors_misconfiguration",
            return_value=[raw_finding_low],
        ):
            result = cors_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_csrf_check_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import csrf_check_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch(
            "squad.penetration_tester.probes.headers.check_csrf",
            return_value=[raw_finding_low],
        ):
            result = csrf_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_ssrf_probe_tool(self, programme_in_workspace, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import ssrf_probe_tool

        with patch(
            "squad.penetration_tester.probes.network.check_ssrf",
            return_value=[raw_finding_low],
        ):
            result = ssrf_probe_tool.func([endpoint.model_dump(mode="json")], None)

        assert result == [raw_finding_low]

    def test_header_injection_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import header_injection_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch(
            "squad.penetration_tester.probes.headers.check_header_injection",
            return_value=[raw_finding_low],
        ):
            result = header_injection_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_host_header_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import host_header_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch(
            "squad.penetration_tester.probes.headers.check_host_headers",
            return_value=[raw_finding_low],
        ):
            result = host_header_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_save_findings_tool(self, raw_finding_low, run_dir) -> None:
        from models import RawFinding
        from squad.penetration_tester import save_findings_tool

        result = save_findings_tool.func([raw_finding_low.model_dump(mode="json")])

        assert result == "findings.json"
        persisted = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        assert [RawFinding.model_validate(f) for f in persisted] == [raw_finding_low]

    def test_recon_subdomains_tool(self, recon_result, run_dir) -> None:
        from squad.penetration_tester import recon_subdomains_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        result = recon_subdomains_tool.func("recon.json")
        assert result == recon_result.subdomains

    def test_recon_endpoints_tool(self, recon_result, run_dir) -> None:
        from squad.penetration_tester import recon_endpoints_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        result = recon_endpoints_tool.func("recon.json", status=200)
        from models import EndpointPage

        assert isinstance(result, EndpointPage)
        assert result.total == 1
        assert result.endpoints[0].url == recon_result.endpoints[0].url

    def test_recon_open_ports_tool(self, recon_result, run_dir) -> None:
        from squad.penetration_tester import recon_open_ports_tool

        (run_dir / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")
        from models import OpenPortsMap

        result = recon_open_ports_tool.func("recon.json")
        assert isinstance(result, OpenPortsMap)
        assert result.hosts == recon_result.open_ports


# Hostname-passing cloud wrappers split by body shape: each takes
# ``list[Hostname]`` and scope-filters at the wrapper, but the body
# differs in how it forwards to ``check_X``.
#
# - Iterating: the databases call ``check_X(host)`` per host inside a
#   loop. When the filtered list is empty, ``check_X`` is never called.
# - List-passing: panels / dashboards / consul / storage call
#   ``check_X(hostnames)`` once with the whole list. The downstream
#   helper handles empty internally - the per-hostname HTTP probe
#   never fires - but ``check_X`` itself IS called with ``[]``.
#
# Splitting per body shape lets each parametrize assert exactly what
# the body does, rather than a both-shapes "or" assertion.
_HOSTNAME_PASSING_ITERATING_WRAPPERS: list[tuple[str, str]] = [
    ("elasticsearch_tool", "squad.penetration_tester.cloud.databases.check_elasticsearch"),
    ("couchdb_tool", "squad.penetration_tester.cloud.databases.check_couchdb"),
    ("redis_tool", "squad.penetration_tester.cloud.databases.check_redis"),
    ("mongodb_tool", "squad.penetration_tester.cloud.databases.check_mongodb"),
    ("postgresql_tool", "squad.penetration_tester.cloud.databases.check_postgresql"),
    ("mysql_tool", "squad.penetration_tester.cloud.databases.check_mysql"),
]

_HOSTNAME_PASSING_LIST_WRAPPERS: list[tuple[str, str]] = [
    ("s3_check_tool", "squad.penetration_tester.cloud.storage.check_s3_buckets"),
    (
        "azure_blob_container_check_tool",
        "squad.penetration_tester.cloud.storage.check_azure_blob_containers",
    ),
    ("cpanel_tool", "squad.penetration_tester.cloud.panels.check_cpanel"),
    ("plesk_tool", "squad.penetration_tester.cloud.panels.check_plesk"),
    ("directadmin_tool", "squad.penetration_tester.cloud.panels.check_directadmin"),
    ("webmin_tool", "squad.penetration_tester.cloud.panels.check_webmin"),
    ("grafana_port_check_tool", "squad.penetration_tester.cloud.dashboards.check_grafana_ports"),
    ("kibana_port_check_tool", "squad.penetration_tester.cloud.dashboards.check_kibana_ports"),
    (
        "portainer_port_check_tool",
        "squad.penetration_tester.cloud.dashboards.check_portainer_ports",
    ),
    (
        "consul_vault_port_check_tool",
        "squad.penetration_tester.cloud.service_discovery.check_consul_vault_ports",
    ),
]


def _resolve_check_fn(check_fn_path: str) -> tuple[object, str]:
    import importlib

    module_path, attr = check_fn_path.rsplit(".", 1)
    return importlib.import_module(module_path), attr


class TestHostnameIteratingWrappers:
    """Databases iterate the supplied hostnames and call
    ``check_X(host)`` per host. The wrapper-level scope_filter drops
    OOS hosts before the loop body runs, so on an empty filtered list
    the loop is a no-op and ``check_X`` is never called."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_ITERATING_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_ITERATING_WRAPPERS],
    )
    def test_wrapper_calls_check_fn_per_in_scope_host(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        raw_finding_low,
        target_apex: str,
    ) -> None:
        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        in_scope_host = f"api.{target_apex}"

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck:
            result = wrapper.func([in_scope_host])

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(in_scope_host)

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_ITERATING_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_ITERATING_WRAPPERS],
    )
    def test_wrapper_skips_check_fn_when_all_hosts_out_of_scope(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        bystander_url: str,
        invoke_tool,
    ) -> None:
        from urllib.parse import urlparse

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_host = urlparse(bystander_url).hostname

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = invoke_tool(wrapper, hostnames=[oos_host])

        assert result == []
        mcheck.assert_not_called()


class TestHostnameListPassingWrappers:
    """Panels / dashboards / consul / storage call ``check_X(hostnames)``
    once with the filtered list. When everything filters out, the
    wrapper calls ``check_X([])`` - the helper handles empty internally
    and no per-hostname HTTP probe fires."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_LIST_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_LIST_WRAPPERS],
    )
    def test_wrapper_forwards_in_scope_hostnames_to_check_fn(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        raw_finding_low,
        target_apex: str,
    ) -> None:
        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        in_scope_host = f"api.{target_apex}"

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck:
            result = wrapper.func([in_scope_host])

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with([in_scope_host])

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_LIST_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_LIST_WRAPPERS],
    )
    def test_wrapper_calls_check_fn_with_empty_list_when_out_of_scope(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        bystander_url: str,
        invoke_tool,
    ) -> None:
        from urllib.parse import urlparse

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_host = urlparse(bystander_url).hostname

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = invoke_tool(wrapper, hostnames=[oos_host])

        assert result == []
        mcheck.assert_called_once_with([])
        # Sanity-check: the OOS host never reached the helper.
        passed = mcheck.call_args[0][0]
        assert oos_host not in passed, (
            f"{tool_name}: scope_filter let the OOS host reach check_X; got {passed!r}"
        )


_ENDPOINT_DRIVEN_CLOUD_WRAPPERS: list[tuple[str, str]] = [
    ("sensitive_files_tool", "squad.penetration_tester.cloud.web_content.check_sensitive_files"),
    ("admin_panels_tool", "squad.penetration_tester.cloud.web_content.check_admin_panels"),
    (
        "azure_sas_token_check_tool",
        "squad.penetration_tester.cloud.storage.check_azure_sas_tokens",
    ),
    ("grafana_path_check_tool", "squad.penetration_tester.cloud.dashboards.check_grafana_paths"),
    ("kibana_path_check_tool", "squad.penetration_tester.cloud.dashboards.check_kibana_paths"),
    (
        "portainer_path_check_tool",
        "squad.penetration_tester.cloud.dashboards.check_portainer_paths",
    ),
    (
        "consul_vault_path_check_tool",
        "squad.penetration_tester.cloud.service_discovery.check_consul_vault_paths",
    ),
]


class TestEndpointWrapperPassThrough:
    """Each endpoint-passing cloud wrapper takes ``list[Endpoint]``,
    scope-filters via ``filter_endpoints_in_scope`` on the URL host,
    and forwards the survivors to ``check_X``. Pins the wrapper-level
    pass-through and the scope-filter guard for all 6 at once."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _ENDPOINT_DRIVEN_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _ENDPOINT_DRIVEN_CLOUD_WRAPPERS],
    )
    def test_wrapper_passes_in_scope_endpoints_to_check_fn(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        endpoint,
        raw_finding_low,
    ) -> None:
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck:
            result = wrapper.func([endpoint.model_dump(mode="json")])

        assert result == [raw_finding_low]
        # The wrapper re-validated the dict back into an Endpoint instance
        # before handing it to check_X.
        mcheck.assert_called_once()
        passed_endpoints = mcheck.call_args[0][0]
        assert len(passed_endpoints) == 1
        assert passed_endpoints[0].url == endpoint.url

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _ENDPOINT_DRIVEN_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _ENDPOINT_DRIVEN_CLOUD_WRAPPERS],
    )
    def test_wrapper_drops_out_of_scope_endpoints(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        bystander_url: str,
        invoke_tool,
    ) -> None:
        """The args_schema's ``InScopeEndpoints`` validator drops
        endpoints whose host is outside the programme's structured
        scope before the wrapper body runs; ``check_X`` still receives
        the (empty) filtered list but the per-endpoint HTTP probe
        never fires."""
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_endpoint = {"url": bystander_url, "status_code": 200}

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = invoke_tool(wrapper, endpoints=[oos_endpoint])

        assert result == []
        for call in mcheck.call_args_list:
            args = call.args[0] if call.args else None
            assert args == [], (
                f"{tool_name}: scope_filter let the OOS endpoint reach check_X; "
                f"got call args {args!r}"
            )
