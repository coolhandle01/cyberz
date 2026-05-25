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

The two shared workspace readers re-exported into the OSINT Analyst's
registry (``List Run Files``, ``Read Run File``) gained explicit
schemas via ``squad.workspace_tools`` in #150 (the final-pass sweep);
they are now part of the closed-world check below.
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest
from pydantic import BaseModel, ValidationError

from squad import SquadTool
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
from squad.workspace_tools import (
    _ListRunFilesArgs,
    _ReadRunFileArgs,
)

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every OSINT @cyber_tool
# wrapper plus the two shared workspace readers swept in #150 (the
# final-pass sweep that completed the args_schema discipline started
# in #143 / #146).
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
    # Shared workspace wrappers (#150 - re-exported via squad.workspace_tools)
    "List Run Files": _ListRunFilesArgs,
    "Read Run File": _ReadRunFileArgs,
}


def _tools_by_name() -> dict[str, SquadTool]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


def _annotate_host_base(hostname: str) -> dict[str, object]:
    """Minimal valid kwargs for _AnnotateHostArgs, parameterised by hostname.

    Centralised so the fixture-derived hostname flows in from one place and
    each rejection test stays focused on the field it is exercising.
    """
    return {
        "hostname": hostname,
        "role": "api",
        "priority": "high",
        "notes": "Production REST API surface; warrants careful probing.",
    }


class TestOsintArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_OSINT_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every OSINT typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _OSINT_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"
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
    """Accept / reject contract per schema.

    The parametrize below carries cases that do not involve a hostname or
    URL - those use the conftest ``victim_url`` / ``bystander_url`` /
    ``callback_url`` domain fixtures via the dedicated test methods further
    down, so test intent ("this is the in-scope target") is readable at the
    call site rather than via opaque ``example.com`` literals.
    """

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
            (_OsintLookupCweArgs, {"query": "xss"}),
            (_OsintLookupOwaspArgs, {"query": "csrf"}),
            (_UncoveredHostsArgs, {}),
            (_FinaliseReconArgs, {"programme_handle": "example"}),
            # Shared workspace acceptance cases (#150). List Run Files takes
            # no parameters; Read Run File needs a relative path.
            (_ListRunFilesArgs, {}),
            (_ReadRunFileArgs, {"relative_path": "recon.json"}),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    # URL / hostname-taking schemas use the conftest domain fixtures so test
    # intent is readable at the call site. Each schema below has a dedicated
    # method rather than a parametrize entry because parametrize literals
    # cannot consume fixtures.

    def test_recon_open_ports_accepts_victim_host(self, victim_url: str) -> None:
        """Recon Open Ports accepts a real hostname filter."""
        host = urlparse(victim_url).hostname
        _ReconOpenPortsArgs.model_validate({"host": host})

    def test_cert_transparency_accepts_victim_apex(self, victim_url: str) -> None:
        """Certificate Transparency takes the apex domain of the in-scope target."""
        host = urlparse(victim_url).hostname or ""
        apex = host.split(".", 1)[-1] if "." in host else host
        _CertTransparencyArgs.model_validate({"domain": apex})

    def test_historical_urls_accepts_victim_apex(self, victim_url: str) -> None:
        """Historical URL Discovery takes the apex domain of the in-scope target."""
        host = urlparse(victim_url).hostname or ""
        apex = host.split(".", 1)[-1] if "." in host else host
        _HistoricalUrlsArgs.model_validate({"domain": apex})

    def test_probe_hostnames_accepts_victim_hostname(self, victim_url: str) -> None:
        """Probe Hostnames takes a list of hostnames plus the programme handle."""
        _ProbeHostnamesArgs.model_validate(
            {
                "hostnames": [urlparse(victim_url).hostname],
                "programme_handle": "example",
            }
        )

    def test_detect_takeover_candidates_accepts_bystander_hostname(
        self, bystander_url: str
    ) -> None:
        """Detect Takeover Candidates models the case where a CNAME dangles to a
        bystander - the ``bystander_url`` fixture is the conventional handle
        for an out-of-scope target."""
        _DetectTakeoverCandidatesArgs.model_validate(
            {
                "hostnames": [urlparse(bystander_url).hostname],
                "programme_handle": "example",
            }
        )

    def test_annotate_host_accepts_victim_hostname(self, victim_url: str) -> None:
        """Annotate Host takes a hostname plus role / priority / notes / tech."""
        host = urlparse(victim_url).hostname or ""
        _AnnotateHostArgs.model_validate(
            {
                **_annotate_host_base(host),
                "detected_tech": ["nginx"],
                "programme_handle": "example",
            }
        )

    def test_llm_detection_accepts_populated_endpoint_list(self, endpoint) -> None:
        """LLM Endpoint Detection accepts the realistic ``Endpoint`` shape.

        The conftest ``endpoint`` fixture is the canonical Endpoint instance;
        using it here exercises the Endpoint model's own validation path as
        part of the schema contract.
        """
        instance = _LlmDetectionArgs.model_validate(
            {"endpoints": [endpoint.model_dump(mode="json")]}
        )
        assert len(instance.endpoints) == 1
        assert instance.endpoints[0].url == endpoint.url

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

    def test_probe_hostnames_requires_both_hostnames_and_handle(self, victim_url: str) -> None:
        """Both hostnames and programme_handle are required - one alone fails."""
        host = urlparse(victim_url).hostname
        with pytest.raises(ValidationError):
            _ProbeHostnamesArgs.model_validate({"hostnames": [host]})
        with pytest.raises(ValidationError):
            _ProbeHostnamesArgs.model_validate({"programme_handle": "example"})

    def test_annotate_host_requires_core_fields(self, victim_url: str) -> None:
        """hostname / role / priority / notes are all required for Annotate Host."""
        base = _annotate_host_base(urlparse(victim_url).hostname or "")
        for missing in ("hostname", "role", "priority", "notes"):
            kwargs = {k: v for k, v in base.items() if k != missing}
            with pytest.raises(ValidationError):
                _AnnotateHostArgs.model_validate(kwargs)

    def test_annotate_host_rejects_unknown_role_and_priority(self, victim_url: str) -> None:
        """role and priority are typed as HostRole / HostPriority StrEnums.

        Unknown values reject upstream of the wrapper rather than in the
        body's ``HostRole(role)`` / ``HostPriority(priority)`` coercion.
        """
        base = _annotate_host_base(urlparse(victim_url).hostname or "")
        with pytest.raises(ValidationError):
            _AnnotateHostArgs.model_validate({**base, "role": "not-a-real-role"})
        with pytest.raises(ValidationError):
            _AnnotateHostArgs.model_validate({**base, "priority": "urgent"})

    # Hostname-typed fields (#148 review feedback). Every schema below
    # carries at least one ``Hostname`` field; passing a URL / port / path
    # rejects upstream, before the scope filter sees the value.
    # test_models.py's TestHostname covers the validator exhaustively;
    # this method asserts the OSINT schemas actually wire it, with each
    # malformed case derived from ``victim_url`` so the deliberately broken
    # input is recognisably "the in-scope target, mis-shaped" rather than
    # an opaque literal.
    def test_hostname_field_rejects_malformed_input(self, victim_url: str) -> None:
        host = urlparse(victim_url).hostname or ""
        cases: list[tuple[type[BaseModel], str, object, dict[str, object]]] = [
            (_CertTransparencyArgs, "domain", f"https://{host}", {}),
            (_HistoricalUrlsArgs, "domain", f"{host}:8080", {}),
            (_ReconOpenPortsArgs, "host", f"{host}/path", {}),
            (
                _ProbeHostnamesArgs,
                "hostnames",
                [f"https://{host}"],
                {"programme_handle": "example"},
            ),
            (
                _DetectTakeoverCandidatesArgs,
                "hostnames",
                [f"{host}:9000"],
                {"programme_handle": "example"},
            ),
        ]
        for schema_cls, field, value, base in cases:
            with pytest.raises(ValidationError):
                schema_cls.model_validate({**base, field: value})

    def test_annotate_host_hostname_rejects_url(self, victim_url: str) -> None:
        """Annotate Host's hostname is Hostname-typed; passing the full URL fails."""
        with pytest.raises(ValidationError):
            _AnnotateHostArgs.model_validate(_annotate_host_base(victim_url))

    def test_hostname_fields_lowercase_input(self, victim_url: str) -> None:
        """Hostname validator lowercases - the schema returns the normalised form."""
        host = (urlparse(victim_url).hostname or "").upper()
        validated = _AnnotateHostArgs.model_validate(_annotate_host_base(host))
        assert validated.hostname == host.lower()
