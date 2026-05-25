"""
tests/test_pt_args_schemas.py - contract tests for the explicit Pydantic
``args_schema`` every Penetration Tester ``@cyber_tool`` / ``@pentest_tool``
wrapper carries.

Started life under #143/#146 covering the 25 ``@pentest_tool`` probes;
#147 extended it to cover the 18 cloud / infra ``@cyber_tool`` wrappers on
the same agent. Both decorators go through the same ``cyber_tool`` helper
so the contract is identical: the schema class is hand-written, every
field carries a non-empty ``description``, and ``args_schema`` on the
registered ``Tool`` ``is`` (identity) the explicit class - not the
title-cased one CrewAI synthesises from the function signature.

The PT agent's tools hit live programmes; a mis-call costs money and
noise. The ``args_schema`` is the per-tool contract the LLM is shown when
picking the tool, so the rules below enforce three things in CI:

  1. Every PT tool with a hand-written schema is in ``_PT_SCHEMAS``, and
     every entry in ``_PT_SCHEMAS`` resolves to a registered tool with the
     expected schema. Closed-world check: a new PT typed-tool added
     without a mapping entry fires this test before review.
  2. Every field on every schema carries a non-empty ``description`` -
     the explicit path can address fields individually and the inferred
     path cannot, so we make sure the new capability is actually used.
  3. Schemas with StrEnum filter parameters reject unknown values;
     required-field schemas reject missing fields. The contract is
     enforced upstream of any HTTP request.

The existing behavioural tests (``test_ssrf.py``, ``test_idor.py`` etc.)
cover probe behaviour separately and are unchanged.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad import SquadTool
from squad.penetration_tester import (
    MEMBER,
    _AdminPanelsArgs,
    _AzureStorageCheckArgs,
    _CmdInjectionArgs,
    _ConsulVaultArgs,
    _CookieCheckArgs,
    _CorsCheckArgs,
    _CouchdbCheckArgs,
    _CpanelArgs,
    _CsrfCheckArgs,
    _DirectadminArgs,
    _ElasticsearchCheckArgs,
    _ErrorDisclosureArgs,
    _GrafanaArgs,
    _HeaderInjectionArgs,
    _HeaderXssArgs,
    _HostHeaderArgs,
    _HppArgs,
    _IdorArgs,
    _JwtCheckArgs,
    _KibanaArgs,
    _LdapInjectionArgs,
    _MongodbCheckArgs,
    _MysqlCheckArgs,
    _NosqliArgs,
    _NucleiScanArgs,
    _OpenRedirectArgs,
    _PathTraversalArgs,
    _PleskArgs,
    _PortainerArgs,
    _PostgresqlCheckArgs,
    _PromptInjectionArgs,
    _PrototypePollutionArgs,
    _PtReconEndpointsArgs,
    _PtReconOpenPortsArgs,
    _PtReconSubdomainsArgs,
    _RedisCheckArgs,
    _S3CheckArgs,
    _SaveFindingsArgs,
    _SensitiveFilesArgs,
    _SourceMapsArgs,
    _SqlmapArgs,
    _SriCheckArgs,
    _SsrfArgs,
    _SstiArgs,
    _WebminArgs,
    _XssArgs,
    _XxeArgs,
)
from squad.workspace_tools import (
    _ListRunFilesArgs,
    _ReadAttackPlanArgs,
    _ReadRunFileArgs,
)

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every PT @cyber_tool /
# @pentest_tool wrapper, including the four recon / save tools and the
# three shared workspace readers swept in #150 (the final-pass sweep
# that completed the args_schema discipline started in #143 / #146).
_PT_SCHEMAS: dict[str, type[BaseModel]] = {
    # @pentest_tool probes (#143 / #146)
    "Nuclei Scan": _NucleiScanArgs,
    "SQLMap Injection Scan": _SqlmapArgs,
    "Cookie Security Check": _CookieCheckArgs,
    "CORS Misconfiguration Check": _CorsCheckArgs,
    "CSRF Detection": _CsrfCheckArgs,
    "SSRF Probe": _SsrfArgs,
    "Header Injection Check": _HeaderInjectionArgs,
    "Host Header Attack Check": _HostHeaderArgs,
    "Header XSS Probe": _HeaderXssArgs,
    "JS Source Map Scan": _SourceMapsArgs,
    "Path Traversal Probe": _PathTraversalArgs,
    "HTTP Parameter Pollution Probe": _HppArgs,
    "Server-Side Template Injection Probe": _SstiArgs,
    "Open Redirect Probe": _OpenRedirectArgs,
    "Reflected XSS Probe": _XssArgs,
    "Subresource Integrity Check": _SriCheckArgs,
    "Error and Stack Trace Disclosure Check": _ErrorDisclosureArgs,
    "NoSQL Injection Scan": _NosqliArgs,
    "Prompt Injection Probe": _PromptInjectionArgs,
    "LDAP Injection Probe": _LdapInjectionArgs,
    "Command Injection Probe": _CmdInjectionArgs,
    "XXE Probe": _XxeArgs,
    "Prototype Pollution Check": _PrototypePollutionArgs,
    "IDOR Probe": _IdorArgs,
    "JWT Vulnerability Check": _JwtCheckArgs,
    # @cyber_tool cloud / infra wrappers (#147)
    "S3 Bucket Check": _S3CheckArgs,
    "Azure Blob Storage Check": _AzureStorageCheckArgs,
    "Unauthenticated Elasticsearch Check": _ElasticsearchCheckArgs,
    "Unauthenticated CouchDB Check": _CouchdbCheckArgs,
    "Unauthenticated Redis Check": _RedisCheckArgs,
    "Unauthenticated MongoDB Check": _MongodbCheckArgs,
    "Exposed PostgreSQL Check": _PostgresqlCheckArgs,
    "Exposed MySQL/MariaDB Check": _MysqlCheckArgs,
    "Sensitive Files Check": _SensitiveFilesArgs,
    "Admin Panels Check": _AdminPanelsArgs,
    "cPanel/WHM Check": _CpanelArgs,
    "Plesk Check": _PleskArgs,
    "DirectAdmin Check": _DirectadminArgs,
    "Webmin Check": _WebminArgs,
    "Grafana Check": _GrafanaArgs,
    "Kibana Check": _KibanaArgs,
    "Portainer Check": _PortainerArgs,
    "Consul/Vault Check": _ConsulVaultArgs,
    # PT recon / save wrappers (#150 - final-pass sweep)
    "Recon Subdomains": _PtReconSubdomainsArgs,
    "Recon Endpoints": _PtReconEndpointsArgs,
    "Recon Open Ports": _PtReconOpenPortsArgs,
    "Save Findings": _SaveFindingsArgs,
    # Shared workspace wrappers (#150 - re-exported via squad.workspace_tools)
    "List Run Files": _ListRunFilesArgs,
    "Read Run File": _ReadRunFileArgs,
    "Read Attack Plan": _ReadAttackPlanArgs,
}

# Cloud / infra wrappers that take ``recon_path: str``. Used by the
# missing-required-field parametrize below.
_RECON_PATH_CLOUD_SCHEMAS: list[type[BaseModel]] = [
    _S3CheckArgs,
    _AzureStorageCheckArgs,
    _ElasticsearchCheckArgs,
    _CouchdbCheckArgs,
    _RedisCheckArgs,
    _MongodbCheckArgs,
    _PostgresqlCheckArgs,
    _MysqlCheckArgs,
    _CpanelArgs,
    _PleskArgs,
    _DirectadminArgs,
    _WebminArgs,
    _GrafanaArgs,
    _KibanaArgs,
    _PortainerArgs,
    _ConsulVaultArgs,
]


def _tools_by_name() -> dict[str, SquadTool]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


class TestPtArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_PT_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every PT typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _PT_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"
        )

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(_PT_SCHEMAS.items()),
        ids=sorted(_PT_SCHEMAS),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        """Per #143 / #147: every field on every PT typed-tool schema carries a description."""
        for field_name, field_info in schema_cls.model_fields.items():
            desc = field_info.description
            assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
            assert isinstance(desc, str) and desc.strip(), (
                f"{tool_name}::{field_name} description is blank"
            )

    def test_every_pt_cyber_tool_has_schema_mapping(self) -> None:
        """The mapping above must cover every PT ``@cyber_tool`` / ``@pentest_tool``.

        Closed-world structural check: every PT tool whose Tool exposes a
        private (``_*``) args_schema class name is in ``_PT_SCHEMAS``;
        every entry in ``_PT_SCHEMAS`` resolves to a registered tool.
        A new typed tool added without a mapping entry fires this test
        before reviewers see the PR.
        """
        tools = _tools_by_name()
        private_schema_tools = {
            name
            for name, t in tools.items()
            if getattr(getattr(t, "args_schema", None), "__name__", "").startswith("_")
        }
        assert private_schema_tools == set(_PT_SCHEMAS), (
            "Mismatch between PT typed-tool wrappers and _PT_SCHEMAS: "
            f"in registry but not mapping = {private_schema_tools - set(_PT_SCHEMAS)}; "
            f"in mapping but not registry = {set(_PT_SCHEMAS) - private_schema_tools}"
        )


class TestSchemaAcceptReject:
    # Schemas with a StrEnum filter parameter get a known-good acceptance
    # and an unknown-value rejection. Required-field schemas get a missing-
    # field rejection. Endpoint-taking schemas get a wrong-shape rejection.

    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            # @pentest_tool acceptance cases
            (_SsrfArgs, {"endpoints": [], "payloads": ["aws-imds"]}),
            (_SsrfArgs, {"endpoints": []}),
            (_HeaderXssArgs, {"endpoints": [], "header_names": ["User-Agent"]}),
            (_PathTraversalArgs, {"endpoints": [], "payloads": ["unix-basic"]}),
            (_SstiArgs, {"endpoints": [], "payloads": ["jinja2"]}),
            (_OpenRedirectArgs, {"endpoints": [], "payloads": ["protocol-relative"]}),
            (_PromptInjectionArgs, {"endpoints": [], "payloads": ["override"]}),
            (_LdapInjectionArgs, {"endpoints": [], "payloads": ["auth-bypass"]}),
            (_CmdInjectionArgs, {"endpoints": [], "payloads": ["semicolon"]}),
            (_XxeArgs, {"endpoints": [], "payloads": ["linux-generic"]}),
            (
                _PrototypePollutionArgs,
                {"endpoints": [], "payloads": ["proto-dot"]},
            ),
            (_IdorArgs, {"endpoints": [], "attacks": ["boundary"]}),
            (
                _JwtCheckArgs,
                {
                    "token": "eyJ.x.y",
                    # endpoint is typed Endpoint; minimum shape is the URL
                    "endpoint": {"url": "https://victim.example.com/api/me"},
                    "attacks": ["alg-none"],
                },
            ),
            (_NucleiScanArgs, {"endpoints": [], "tech_tags": ["wordpress"]}),
            (_SqlmapArgs, {"endpoints": []}),
            (_NosqliArgs, {"endpoints": []}),
            (_XssArgs, {"endpoints": []}),
            (_HppArgs, {"endpoints": []}),
            (_ErrorDisclosureArgs, {"endpoints": []}),
            (_CookieCheckArgs, {"recon_path": "recon.json"}),
            (_CorsCheckArgs, {"recon_path": "recon.json"}),
            (_CsrfCheckArgs, {"recon_path": "recon.json"}),
            (_HeaderInjectionArgs, {"recon_path": "recon.json"}),
            (_HostHeaderArgs, {"recon_path": "recon.json"}),
            (_SourceMapsArgs, {"recon_path": "recon.json"}),
            (_SriCheckArgs, {"recon_path": "recon.json"}),
            # @cyber_tool cloud / infra acceptance cases (#147)
            (_S3CheckArgs, {"recon_path": "recon.json"}),
            (_AzureStorageCheckArgs, {"recon_path": "recon.json"}),
            (_ElasticsearchCheckArgs, {"recon_path": "recon.json"}),
            (_CouchdbCheckArgs, {"recon_path": "recon.json"}),
            (_RedisCheckArgs, {"recon_path": "recon.json"}),
            (_MongodbCheckArgs, {"recon_path": "recon.json"}),
            (_PostgresqlCheckArgs, {"recon_path": "recon.json"}),
            (_MysqlCheckArgs, {"recon_path": "recon.json"}),
            (_SensitiveFilesArgs, {"endpoints": []}),
            (_AdminPanelsArgs, {"endpoints": []}),
            (_CpanelArgs, {"recon_path": "recon.json"}),
            (_PleskArgs, {"recon_path": "recon.json"}),
            (_DirectadminArgs, {"recon_path": "recon.json"}),
            (_WebminArgs, {"recon_path": "recon.json"}),
            (_GrafanaArgs, {"recon_path": "recon.json"}),
            (_KibanaArgs, {"recon_path": "recon.json"}),
            (_PortainerArgs, {"recon_path": "recon.json"}),
            (_ConsulVaultArgs, {"recon_path": "recon.json"}),
            # PT recon / save acceptance cases (#150)
            (_PtReconSubdomainsArgs, {"recon_path": "recon.json"}),
            (_PtReconSubdomainsArgs, {"recon_path": "recon.json", "host_filter": "api"}),
            (_PtReconEndpointsArgs, {"recon_path": "recon.json"}),
            (
                _PtReconEndpointsArgs,
                {
                    "recon_path": "recon.json",
                    "status": 200,
                    "tech": "wordpress",
                    "host_contains": "admin",
                    "offset": 0,
                    "limit": 25,
                },
            ),
            (_PtReconOpenPortsArgs, {"recon_path": "recon.json"}),
            # The host-restricted ``Recon Open Ports`` acceptance case lives
            # in a dedicated test method below (``test_recon_open_ports_*``)
            # because the ``host`` field is now ``Hostname``-typed and the
            # fixture-derived hostname makes test intent ("in-scope target")
            # readable at the call site rather than via an opaque literal.
            (_SaveFindingsArgs, {"findings": []}),
            # Shared workspace acceptance cases (#150). List Run Files and
            # Read Attack Plan take no parameters - the empty payload is the
            # canonical call.
            (_ListRunFilesArgs, {}),
            (_ReadAttackPlanArgs, {}),
            (_ReadRunFileArgs, {"relative_path": "recon.json"}),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    # StrEnum-filtered probes - unknown payload / attack value must reject.
    @pytest.mark.parametrize(
        ("schema_cls", "field_name"),
        [
            (_SsrfArgs, "payloads"),
            (_HeaderXssArgs, "header_names"),
            (_PathTraversalArgs, "payloads"),
            (_SstiArgs, "payloads"),
            (_OpenRedirectArgs, "payloads"),
            (_PromptInjectionArgs, "payloads"),
            (_LdapInjectionArgs, "payloads"),
            (_CmdInjectionArgs, "payloads"),
            (_XxeArgs, "payloads"),
            (_PrototypePollutionArgs, "payloads"),
            (_IdorArgs, "attacks"),
            (_JwtCheckArgs, "attacks"),
        ],
    )
    def test_unknown_strenum_value_rejected(
        self, schema_cls: type[BaseModel], field_name: str
    ) -> None:
        """An unknown StrEnum member must fail validation, not silently coerce."""
        base: dict[str, object] = {field_name: ["this-is-not-a-real-variant"]}
        if "endpoints" in schema_cls.model_fields:
            base["endpoints"] = []
        if "token" in schema_cls.model_fields:
            base["token"] = "eyJ.x.y"
        if "endpoint" in schema_cls.model_fields:
            # _JwtCheckArgs takes the typed ``Endpoint`` shape (not a bare
            # URL string); pass the minimum dict that validates so the test
            # stays focused on the unknown-StrEnum reject.
            base["endpoint"] = {"url": "https://victim.example.com/api/me"}
        with pytest.raises(ValidationError):
            schema_cls.model_validate(base)

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _NucleiScanArgs,
            _SqlmapArgs,
            _SsrfArgs,
            _HeaderXssArgs,
            _PathTraversalArgs,
            _SstiArgs,
            _OpenRedirectArgs,
            _PromptInjectionArgs,
            _LdapInjectionArgs,
            _CmdInjectionArgs,
            _XxeArgs,
            _PrototypePollutionArgs,
            _IdorArgs,
            _NosqliArgs,
            _XssArgs,
            _HppArgs,
            _ErrorDisclosureArgs,
            # @cyber_tool cloud wrappers that take endpoints (#147)
            _SensitiveFilesArgs,
            _AdminPanelsArgs,
        ],
    )
    def test_missing_required_endpoints_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``endpoints`` is required on every endpoint-taking PT typed-tool schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _CookieCheckArgs,
            _CorsCheckArgs,
            _CsrfCheckArgs,
            _HeaderInjectionArgs,
            _HostHeaderArgs,
            _SourceMapsArgs,
            _SriCheckArgs,
            *_RECON_PATH_CLOUD_SCHEMAS,
            # PT recon wrappers (#150) - all take a required ``recon_path``
            _PtReconSubdomainsArgs,
            _PtReconEndpointsArgs,
            _PtReconOpenPortsArgs,
        ],
    )
    def test_missing_required_recon_path_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``recon_path`` is required on every recon-path-taking PT typed-tool schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_jwt_requires_both_token_and_endpoint(self, endpoint) -> None:
        """JWT check needs the raw token and the validating endpoint.

        Uses the conftest ``endpoint`` fixture for the typed-Endpoint
        payload so test intent ("a real, in-scope target endpoint") is
        readable at the call site rather than via a hand-rolled URL
        literal.
        """
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"token": "eyJ.x.y"})
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"endpoint": endpoint.model_dump(mode="json")})

    def test_jwt_rejects_malformed_endpoint(self, endpoint) -> None:
        """The typed ``Endpoint`` validates URL well-formedness upstream of
        the JWT replay - a string where an Endpoint dict is required
        rejects, as does an Endpoint dict whose URL is malformed."""
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate(
                {"token": "eyJ.x.y", "endpoint": "https://victim.example.com/api"}
            )
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"token": "eyJ.x.y", "endpoint": {"url": "not-a-url"}})
        # The conftest endpoint fixture is intentionally valid; this asserts
        # the happy path stays accepting alongside the rejects above.
        _JwtCheckArgs.model_validate(
            {"token": "eyJ.x.y", "endpoint": endpoint.model_dump(mode="json")}
        )

    def test_save_findings_requires_findings(self) -> None:
        """``Save Findings`` rejects an empty payload - ``findings`` has no default."""
        with pytest.raises(ValidationError):
            _SaveFindingsArgs.model_validate({})

    def test_read_run_file_requires_relative_path(self) -> None:
        """``Read Run File`` rejects an empty payload - ``relative_path`` is required."""
        with pytest.raises(ValidationError):
            _ReadRunFileArgs.model_validate({})

    def test_save_findings_rejects_mis_shaped_finding(self) -> None:
        """A dict that does not validate as ``RawFinding`` rejects upstream of
        the wrapper - the whole point of the typed ``list[RawFinding]``
        parameter is the schema reject before findings.json is written."""
        with pytest.raises(ValidationError):
            _SaveFindingsArgs.model_validate({"findings": [{"not_a_real_field": "x"}]})

    def test_recon_open_ports_accepts_victim_host(self, victim_url: str) -> None:
        """``Recon Open Ports`` accepts a bare hostname filter.

        The ``host`` field is ``Hostname``-typed; using the ``victim_url``
        fixture (the conftest's in-scope-target handle) and stripping the
        scheme keeps the test intent readable at the call site rather than
        via an opaque ``api.example.com`` literal.
        """
        from urllib.parse import urlparse

        host = urlparse(victim_url).hostname
        _PtReconOpenPortsArgs.model_validate({"recon_path": "recon.json", "host": host})

    def test_recon_open_ports_rejects_url_in_host(self, victim_url: str) -> None:
        """The ``Hostname`` primitive rejects a URL where a bare hostname
        is expected - ``victim_url`` carries the ``https://`` scheme, so
        passing it directly trips the validator upstream of the wrapper."""
        with pytest.raises(ValidationError):
            _PtReconOpenPortsArgs.model_validate({"recon_path": "recon.json", "host": victim_url})
