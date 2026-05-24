"""
tests/test_osint_args_schemas.py - contract tests for the explicit Pydantic
``args_schema`` every OSINT Analyst ``@cyber_tool`` wrapper carries.

Sibling of ``test_pt_args_schemas.py``: same shape of structural and
accept/reject checks, scoped to the OSINT Analyst's tool surface. Closes
#148.

OSINT tools fire external recon (subfinder, httpx, nmap, testssl.sh,
ffuf, crt.sh, waybackurls, dnsx, LLM endpoint detection) against in-scope
hosts. The "live programmes, mis-call costs money" framing that motivated
#143 / #146 / #147 applies identically here, plus a scope-leak risk that
is specific to recon: a mis-targeted ``host_filter`` or wrong
``host_contains`` substring can pull a sibling programme's endpoints
into the run and silently corrupt every downstream stage. Filter-
parameter discipline is the bulk of what the per-field descriptions are
doing.

The workspace tools on the OSINT Analyst (``List Run Files``, ``Read Run
File``) intentionally keep the signature-inferred schema and are out of
scope here - #150 covers them.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad.osint_analyst import (
    MEMBER,
    _AnnotateHostArgs,
    _CertTransparencyArgs,
    _DetectTakeoverCandidatesArgs,
    _FinaliseReconArgs,
    _HistoricalUrlsArgs,
    _LlmDetectionArgs,
    _OsintLookupCweArgs,
    _OsintLookupOwaspArgs,
    _ProbeHostnamesArgs,
    _ReconEndpointsArgs,
    _ReconOpenPortsArgs,
    _ReconSubdomainsArgs,
    _RunInitialSweepArgs,
    _UncoveredHostsArgs,
)

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every OSINT @cyber_tool
# wrapper. The workspace readers (List Run Files, Read Run File) on the
# OSINT Analyst keep the inferred schema and are out of scope - #150 owns
# them.
_OSINT_SCHEMAS: dict[str, type[BaseModel]] = {
    "Run Initial Sweep": _RunInitialSweepArgs,
    "Recon Subdomains": _ReconSubdomainsArgs,
    "Recon Endpoints": _ReconEndpointsArgs,
    "Recon Open Ports": _ReconOpenPortsArgs,
    "Certificate Transparency Lookup": _CertTransparencyArgs,
    "Historical URL Discovery": _HistoricalUrlsArgs,
    "LLM Endpoint Detection": _LlmDetectionArgs,
    "Probe Hostnames": _ProbeHostnamesArgs,
    "Detect Takeover Candidates": _DetectTakeoverCandidatesArgs,
    "Lookup CWE": _OsintLookupCweArgs,
    "Lookup OWASP Guidance": _OsintLookupOwaspArgs,
    "Annotate Host": _AnnotateHostArgs,
    "Uncovered Hosts": _UncoveredHostsArgs,
    "Finalise Recon": _FinaliseReconArgs,
}


def _tools_by_name() -> dict[str, object]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


class TestOsintArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_OSINT_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every OSINT typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _OSINT_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (  # type: ignore[attr-defined]
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"  # type: ignore[attr-defined]
        )

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(_OSINT_SCHEMAS.items()),
        ids=sorted(_OSINT_SCHEMAS),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        """Per #148: every field on every OSINT typed-tool schema carries a description."""
        for field_name, field_info in schema_cls.model_fields.items():
            desc = field_info.description
            assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
            assert isinstance(desc, str) and desc.strip(), (
                f"{tool_name}::{field_name} description is blank"
            )

    def test_every_osint_cyber_tool_has_schema_mapping(self) -> None:
        """The mapping above must cover every OSINT ``@cyber_tool`` wrapper.

        Closed-world structural check: every OSINT tool whose Tool exposes
        a private (``_*``) args_schema class name is in ``_OSINT_SCHEMAS``;
        every entry in ``_OSINT_SCHEMAS`` resolves to a registered tool.
        A new typed tool added without a mapping entry fires this test
        before reviewers see the PR.
        """
        tools = _tools_by_name()
        private_schema_tools = {
            name
            for name, t in tools.items()
            if getattr(getattr(t, "args_schema", None), "__name__", "").startswith("_")
        }
        assert private_schema_tools == set(_OSINT_SCHEMAS), (
            "Mismatch between OSINT typed-tool wrappers and _OSINT_SCHEMAS: "
            f"in registry but not mapping = {private_schema_tools - set(_OSINT_SCHEMAS)}; "
            f"in mapping but not registry = {set(_OSINT_SCHEMAS) - private_schema_tools}"
        )


class TestSchemaAcceptReject:
    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            (_RunInitialSweepArgs, {"programme_handle": "example"}),
            (_ReconSubdomainsArgs, {}),
            (_ReconSubdomainsArgs, {"sweep_path": "sweep.json", "host_filter": "api"}),
            (_ReconEndpointsArgs, {}),
            (
                _ReconEndpointsArgs,
                {"status": 200, "tech": "wordpress", "host_contains": "admin", "limit": 25},
            ),
            (_ReconOpenPortsArgs, {}),
            (_ReconOpenPortsArgs, {"host": "victim.example.com"}),
            (_CertTransparencyArgs, {"domain": "example.com"}),
            (_HistoricalUrlsArgs, {"domain": "example.com"}),
            (_LlmDetectionArgs, {"endpoints": []}),
            (
                _ProbeHostnamesArgs,
                {"hostnames": ["api.example.com"], "programme_handle": "example"},
            ),
            (
                _DetectTakeoverCandidatesArgs,
                {"hostnames": ["legacy.example.com"], "programme_handle": "example"},
            ),
            (_OsintLookupCweArgs, {"query": "xss"}),
            (_OsintLookupOwaspArgs, {"query": "csrf"}),
            (
                _AnnotateHostArgs,
                {
                    "hostname": "api.example.com",
                    "role": "api",
                    "priority": "high",
                    "notes": "Production REST API surface; warrants careful probing.",
                    "detected_tech": ["nginx"],
                    "programme_handle": "example",
                },
            ),
            (_UncoveredHostsArgs, {}),
            (_FinaliseReconArgs, {"programme_handle": "example"}),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    # Required-field rejections. Each schema below has at least one
    # required field; missing it must fail validation.
    @pytest.mark.parametrize(
        "schema_cls",
        [
            _RunInitialSweepArgs,  # programme_handle required
            _CertTransparencyArgs,  # domain required
            _HistoricalUrlsArgs,  # domain required
            _LlmDetectionArgs,  # endpoints required
            _ProbeHostnamesArgs,  # hostnames + programme_handle required
            _DetectTakeoverCandidatesArgs,  # hostnames + programme_handle required
            _OsintLookupCweArgs,  # query required
            _OsintLookupOwaspArgs,  # query required
            _AnnotateHostArgs,  # hostname / role / priority / notes required
            _FinaliseReconArgs,  # programme_handle required
        ],
    )
    def test_missing_required_field_rejected(self, schema_cls: type[BaseModel]) -> None:
        """At least one required field is missing: model_validate must fail."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_probe_hostnames_requires_both_hostnames_and_handle(self) -> None:
        """Both hostnames and programme_handle are required - one alone fails."""
        with pytest.raises(ValidationError):
            _ProbeHostnamesArgs.model_validate({"hostnames": ["api.example.com"]})
        with pytest.raises(ValidationError):
            _ProbeHostnamesArgs.model_validate({"programme_handle": "example"})

    def test_annotate_host_requires_core_fields(self) -> None:
        """hostname / role / priority / notes are all required for Annotate Host."""
        base: dict[str, object] = {
            "hostname": "api.example.com",
            "role": "api",
            "priority": "high",
            "notes": "Production REST API surface; warrants careful probing.",
        }
        for missing in ("hostname", "role", "priority", "notes"):
            kwargs = {k: v for k, v in base.items() if k != missing}
            with pytest.raises(ValidationError):
                _AnnotateHostArgs.model_validate(kwargs)
