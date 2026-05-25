"""
tests/test_squad_penetration_tester.py - exercise a representative sample of
the @tool wrappers on the Penetration Tester.

42 tools live on this agent; the bodies are near-identical thin wrappers, so a
representative sample is enough for regression value without inflating the
test suite to no benefit. The wrappers unmarshal JSON, call into tools/*
helpers, and serialise the result; the underlying helpers are exercised in
their own dedicated test files.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestPenetrationTesterTools:
    def test_nuclei_scan_tool(self, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import nuclei_scan_tool

        with patch(
            "squad.penetration_tester.probes.external.run_nuclei",
            return_value=[raw_finding_low],
        ):
            result = nuclei_scan_tool.func([endpoint.model_dump(mode="json")], ["wordpress"])

        assert result == [raw_finding_low]

    def test_sqlmap_tool(self, endpoint, raw_finding_low) -> None:
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

    def test_ssrf_probe_tool(self, endpoint, raw_finding_low) -> None:
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


# Hostname-passing cloud wrappers (Path B): the wrapper-level
# ``scope_filter`` runs against the supplied hostnames, then the body
# either iterates (databases call ``check_X(host)`` per host) or
# forwards the list (panels / dashboards / consul / storage call
# ``check_X(hostnames)`` once). Both shapes are covered here; the
# pass-through assertion below accepts either positional shape.
_HOSTNAME_PASSING_CLOUD_WRAPPERS: list[tuple[str, str]] = [
    ("s3_check_tool", "squad.penetration_tester.cloud.storage.check_s3_buckets"),
    (
        "azure_blob_container_check_tool",
        "squad.penetration_tester.cloud.storage.check_azure_blob_containers",
    ),
    ("elasticsearch_tool", "squad.penetration_tester.cloud.databases.check_elasticsearch"),
    ("couchdb_tool", "squad.penetration_tester.cloud.databases.check_couchdb"),
    ("redis_tool", "squad.penetration_tester.cloud.databases.check_redis"),
    ("mongodb_tool", "squad.penetration_tester.cloud.databases.check_mongodb"),
    ("postgresql_tool", "squad.penetration_tester.cloud.databases.check_postgresql"),
    ("mysql_tool", "squad.penetration_tester.cloud.databases.check_mysql"),
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


class TestHostnameWrapperPassThrough:
    """Each hostname-passing cloud wrapper scope-filters the typed
    ``list[Hostname]`` and forwards the survivors to ``check_X``. The
    body shape is one of two: panels / dashboards / consul call the
    helper once with the whole list; databases iterate per-host. This
    class pins the wrapper-level pass-through and the scope-filter
    guard for all 14 at once."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_CLOUD_WRAPPERS],
    )
    def test_wrapper_forwards_in_scope_hostnames_to_check_fn(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        raw_finding_low,
        target_apex: str,
    ) -> None:
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        in_scope_host = f"api.{target_apex}"

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck:
            result = wrapper.func([in_scope_host])

        assert result == [raw_finding_low]
        mcheck.assert_called()
        # The body either iterates per-host (databases) or passes the
        # list (panels / dashboards / consul); both shapes carry the
        # in-scope host as the first positional arg.
        call_arg = mcheck.call_args[0][0]
        if isinstance(call_arg, list):
            assert call_arg == [in_scope_host]
        else:
            assert call_arg == in_scope_host

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_CLOUD_WRAPPERS],
    )
    def test_wrapper_drops_out_of_scope_hostnames(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        bystander_url: str,
    ) -> None:
        """The wrapper-level ``scope_filter`` empties the list before the
        body fires. Two body shapes here:

        - Iterating bodies (databases) never call ``check_X`` once the
          filtered list is empty.
        - List-passing bodies (panels / dashboards / consul) still call
          ``check_X([])`` because the helper accepts a hostname list and
          handles empty internally - the per-hostname HTTP probe never
          fires.

        The contract being tested is the same in both shapes: no probe
        fires against the OOS host. Asserts on the result and on the
        absence of an OOS-carrying call.
        """
        import importlib
        from urllib.parse import urlparse

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_host = urlparse(bystander_url).hostname

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = wrapper.func([oos_host])

        assert result == []
        for call in mcheck.call_args_list:
            args = call.args[0] if call.args else None
            assert args in ([], None), (
                f"{tool_name}: scope_filter let the OOS host reach check_X; got call args {args!r}"
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
    ) -> None:
        """The wrapper-level scope filter drops endpoints whose host is
        outside the programme's structured scope; ``check_X`` still
        receives the (empty) filtered list but the per-endpoint HTTP
        probe never fires. Same shape as the hostname-side OOS test
        above."""
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_endpoint = {"url": bystander_url, "status_code": 200}

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = wrapper.func([oos_endpoint])

        assert result == []
        for call in mcheck.call_args_list:
            args = call.args[0] if call.args else None
            assert args == [], (
                f"{tool_name}: scope_filter let the OOS endpoint reach check_X; "
                f"got call args {args!r}"
            )
