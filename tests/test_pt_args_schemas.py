"""
tests/test_pt_args_schemas.py - contract tests for the explicit Pydantic
``args_schema`` every Penetration Tester ``@typed_tool`` / ``@pentest_tool``
wrapper carries.

Started life under #143/#146 covering the 25 ``@pentest_tool`` probes;
#147 extended it to cover the 18 cloud / infra ``@typed_tool`` wrappers on
the same agent. Both decorators go through the same ``typed_tool`` helper
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
    _RedisCheckArgs,
    _S3CheckArgs,
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

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every PT @typed_tool /
# @pentest_tool wrapper. Recon / write / workspace tools that intentionally
# keep the signature-inferred schema (Recon Subdomains, Recon Endpoints,
# Recon Open Ports, Save Findings, plus the three workspace readers) are
# absent: they are out of scope for #143 / #147, and #150 covers them.
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
    # @typed_tool cloud / infra wrappers (#147)
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


def _tools_by_name() -> dict[str, object]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


class TestPtArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_PT_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every PT typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _PT_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (  # type: ignore[attr-defined]
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"  # type: ignore[attr-defined]
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

    def test_every_pt_typed_tool_has_schema_mapping(self) -> None:
        """The mapping above must cover every PT ``@typed_tool`` / ``@pentest_tool``.

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
                    "endpoint": "https://victim.example.com/api/me",
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
            # @typed_tool cloud / infra acceptance cases (#147)
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
            base["endpoint"] = "https://victim.example.com/api/me"
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
            # @typed_tool cloud wrappers that take endpoints (#147)
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
        ],
    )
    def test_missing_required_recon_path_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``recon_path`` is required on every recon-path-taking PT typed-tool schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_jwt_requires_both_token_and_endpoint(self) -> None:
        """JWT check needs the raw token and the validating endpoint."""
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"token": "eyJ.x.y"})
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"endpoint": "https://victim.example.com/api"})
