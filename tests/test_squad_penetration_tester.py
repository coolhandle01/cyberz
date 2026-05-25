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

    def test_cookie_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import cookie_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme") as mhttp,
            patch(
                "squad.penetration_tester.probes.headers.check_cookies",
                return_value=[raw_finding_low],
            ),
        ):
            result = cookie_check_tool.func("recon.json")

        assert result == [raw_finding_low]
        mhttp.assert_called_once_with(recon_result.programme.handle)

    def test_cors_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import cors_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme"),
            patch(
                "squad.penetration_tester.probes.headers.check_cors_misconfiguration",
                return_value=[raw_finding_low],
            ),
        ):
            result = cors_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_csrf_check_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import csrf_check_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme"),
            patch(
                "squad.penetration_tester.probes.headers.check_csrf",
                return_value=[raw_finding_low],
            ),
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

    def test_header_injection_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import header_injection_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme"),
            patch(
                "squad.penetration_tester.probes.headers.check_header_injection",
                return_value=[raw_finding_low],
            ),
        ):
            result = header_injection_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_host_header_tool(self, recon_result, raw_finding_low, tmp_path) -> None:
        from squad.penetration_tester import host_header_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme"),
            patch(
                "squad.penetration_tester.probes.headers.check_host_headers",
                return_value=[raw_finding_low],
            ),
        ):
            result = host_header_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_save_findings_tool(self, raw_finding_low, tmp_path) -> None:
        from models import RawFinding
        from squad.penetration_tester import save_findings_tool

        with patch("runtime.run_dir", return_value=tmp_path):
            result = save_findings_tool.func([raw_finding_low.model_dump(mode="json")])

        assert result == "findings.json"
        persisted = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
        assert [RawFinding.model_validate(f) for f in persisted] == [raw_finding_low]

    def test_recon_subdomains_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_subdomains_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = recon_subdomains_tool.func("recon.json")
        assert result == recon_result.subdomains

    def test_recon_endpoints_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_endpoints_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = recon_endpoints_tool.func("recon.json", status=200)
        from models import EndpointPage

        assert isinstance(result, EndpointPage)
        assert result.total == 1
        assert result.endpoints[0].url == recon_result.endpoints[0].url

    def test_recon_open_ports_tool(self, recon_result, tmp_path) -> None:
        from squad.penetration_tester import recon_open_ports_tool

        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")
        from models import OpenPortsMap

        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = recon_open_ports_tool.func("recon.json")
        assert isinstance(result, OpenPortsMap)
        assert result.hosts == recon_result.open_ports


# The 10 recon-driven cloud / infra wrappers that just forward the
# loaded ReconResult to their ``check_X`` callable:
# ``_recon_from_path(recon_path)`` -> ``check_X(recon)`` -> return its
# findings. Per-wrapper behavioural tests would all look identical, so
# this parametrize covers them in one place - the cloud sub-modules were
# at 33-87% line coverage post-split because only a representative
# sample was hit individually in the class above; this lifts them to
# 100% without 10 near-duplicate test methods.
_RECON_PASSING_CLOUD_WRAPPERS: list[tuple[str, str]] = [
    ("s3_check_tool", "squad.penetration_tester.cloud.storage.check_s3_buckets"),
    ("azure_storage_check_tool", "squad.penetration_tester.cloud.storage.check_azure_storage"),
    ("cpanel_tool", "squad.penetration_tester.cloud.panels.check_cpanel"),
    ("plesk_tool", "squad.penetration_tester.cloud.panels.check_plesk"),
    ("directadmin_tool", "squad.penetration_tester.cloud.panels.check_directadmin"),
    ("webmin_tool", "squad.penetration_tester.cloud.panels.check_webmin"),
    ("grafana_tool", "squad.penetration_tester.cloud.dashboards.check_grafana"),
    ("kibana_tool", "squad.penetration_tester.cloud.dashboards.check_kibana"),
    ("portainer_tool", "squad.penetration_tester.cloud.dashboards.check_portainer"),
    (
        "consul_vault_tool",
        "squad.penetration_tester.cloud.service_discovery.check_consul_vault",
    ),
]


class TestCloudWrapperPassThrough:
    """Each recon-passing cloud / infra wrapper loads the recon and
    forwards to its ``check_X`` callable. The body is mechanical; this
    class pins the pass-through shape (recon resolved, check_fn invoked,
    findings returned, http programme context set) for every wrapper at
    once."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _RECON_PASSING_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _RECON_PASSING_CLOUD_WRAPPERS],
    )
    def test_wrapper_loads_recon_and_returns_check_fn_output(
        self,
        tool_name: str,
        check_fn_path: str,
        recon_result,
        raw_finding_low,
        tmp_path,
    ) -> None:
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        recon_path = tmp_path / "recon.json"
        recon_path.write_text(recon_result.model_dump_json(), encoding="utf-8")

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme") as mhttp,
            patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck,
        ):
            result = wrapper.func("recon.json")

        assert result == [raw_finding_low]
        # The wrapper loaded recon.json and passed the typed ReconResult to
        # check_X (rather than the raw path string).
        mcheck.assert_called_once()
        passed_recon = mcheck.call_args[0][0]
        assert passed_recon.programme.handle == recon_result.programme.handle
        # The http programme context was set from the recon's programme
        # handle so outbound User-Agent headers carry the right tag.
        mhttp.assert_called_once_with(recon_result.programme.handle)


# The 6 database wrappers share a different shape from the rest of the
# cloud package: they iterate ``recon.open_ports`` and only call
# ``check_X(host)`` when the engine's signature port is in the open list.
# Parametrise per-engine + signature-port so the test mutates the
# ``recon_result`` fixture's open_ports map to include the right port via
# ``model_copy`` (per the cybersquad-tool skill's "derive variants with
# model_copy" rule), exercises the iteration branch, and asserts the
# wrapper passes only the matching host to ``check_X``.
_DATABASE_WRAPPERS: list[tuple[str, str, int]] = [
    (
        "elasticsearch_tool",
        "squad.penetration_tester.cloud.databases.check_elasticsearch",
        9200,
    ),
    ("couchdb_tool", "squad.penetration_tester.cloud.databases.check_couchdb", 5984),
    ("redis_tool", "squad.penetration_tester.cloud.databases.check_redis", 6379),
    ("mongodb_tool", "squad.penetration_tester.cloud.databases.check_mongodb", 27017),
    (
        "postgresql_tool",
        "squad.penetration_tester.cloud.databases.check_postgresql",
        5432,
    ),
    ("mysql_tool", "squad.penetration_tester.cloud.databases.check_mysql", 3306),
]


class TestDatabaseWrapperPassThrough:
    """Each database wrapper checks for its engine's signature port in
    ``recon.open_ports`` and forwards the matching host to ``check_X``.
    Pins the iteration branch (port present -> findings forwarded; port
    absent -> empty list returned without firing check_X) for every
    engine at once."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path", "port"),
        _DATABASE_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _, _ in _DATABASE_WRAPPERS],
    )
    def test_wrapper_fires_check_fn_when_port_is_open(
        self,
        tool_name: str,
        check_fn_path: str,
        port: int,
        recon_result,
        raw_finding_low,
        tmp_path,
    ) -> None:
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        # Mutate the conftest fixture's open_ports to include this
        # engine's signature port on the in-scope host.
        target_host = "api.example.com"
        recon_with_port = recon_result.model_copy(update={"open_ports": {target_host: [port]}})
        (tmp_path / "recon.json").write_text(recon_with_port.model_dump_json(), encoding="utf-8")

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme"),
            patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck,
        ):
            result = wrapper.func("recon.json")

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(target_host)

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path", "port"),
        _DATABASE_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _, _ in _DATABASE_WRAPPERS],
    )
    def test_wrapper_skips_check_fn_when_port_is_absent(
        self,
        tool_name: str,
        check_fn_path: str,
        port: int,  # noqa: ARG002 - parametrize value unused, kept for symmetry / id derivation
        recon_result,
        tmp_path,
    ) -> None:
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        # Fixture's default open_ports is {"api.example.com": [80, 443]} -
        # none of the DB signature ports. The wrapper should skip
        # check_X entirely and return [].
        (tmp_path / "recon.json").write_text(recon_result.model_dump_json(), encoding="utf-8")

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with (
            patch("tools.workspace.runtime.run_dir", return_value=tmp_path),
            patch("squad.penetration_tester._decorator.http.set_programme"),
            patch.object(check_module, check_attr) as mcheck,
        ):
            result = wrapper.func("recon.json")

        assert result == []
        mcheck.assert_not_called()


_ENDPOINT_DRIVEN_CLOUD_WRAPPERS: list[tuple[str, str]] = [
    ("sensitive_files_tool", "squad.penetration_tester.cloud.web_content.check_sensitive_files"),
    ("admin_panels_tool", "squad.penetration_tester.cloud.web_content.check_admin_panels"),
]


class TestEndpointDrivenCloudWrapperPassThrough:
    """The two cloud wrappers that take ``list[Endpoint]`` rather than a
    recon path. Same pass-through shape as the recon-driven ones, just
    fed the agent's endpoint pick directly."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _ENDPOINT_DRIVEN_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _ENDPOINT_DRIVEN_CLOUD_WRAPPERS],
    )
    def test_wrapper_passes_validated_endpoints_to_check_fn(
        self,
        tool_name: str,
        check_fn_path: str,
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
