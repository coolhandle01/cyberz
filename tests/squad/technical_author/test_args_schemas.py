"""
Contract tests for the Technical Author's explicit Pydantic
``args_schema`` classes - one of the per-agent test pairs (sibling
under ``tests/squad/<agent>/test_args_schemas.py``).

The TA is internal-effect (it does not fire requests at live
programmes), but ``Draft Vulnerability Report`` is the longest
authored contract on any agent and its quality gate is exactly what
keeps unfilled / under-validated drafts out of the Disclosure
Coordinator's submission path. The per-field descriptions enforced
here are what teaches the LLM the gate's grammar upstream of any
draft being written.

Structural / accept / reject pattern mirrors
``tests/test_pt_args_schemas.py`` so the same closed-world guarantee
holds for the TA agent.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad import SquadTool
from squad.technical_author import (
    MEMBER,
    _DraftReportArgs,
    _FinaliseReportsArgs,
    _SanitiseEvidenceArgs,
    _TaCalculateCvssArgs,
    _TaListProgrammeReportsArgs,
    _TaLookupCweArgs,
    _TaLookupOwaspArgs,
)
from squad.workspace_tools import (
    _ListRunFilesArgs,
    _ReadRunFileArgs,
)

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every TA @cyber_tool wrapper
# plus the two shared workspace readers re-exported via
# ``squad.workspace_tools``. The shared ``Lookup CWE`` / ``Lookup OWASP
# Guidance`` / ``Calculate CVSS Score`` / ``List Programme Reports``
# wrappers are declared per-agent (each gets its own ``_Ta*`` class) -
# consolidating the duplicated lookup tools is a separate refactor, not
# this one.
_TA_SCHEMAS: dict[str, type[BaseModel]] = {
    "Sanitise Evidence": _SanitiseEvidenceArgs,
    "Lookup CWE": _TaLookupCweArgs,
    "Lookup OWASP Guidance": _TaLookupOwaspArgs,
    "Calculate CVSS Score": _TaCalculateCvssArgs,
    "List Programme Reports": _TaListProgrammeReportsArgs,
    "Draft Vulnerability Report": _DraftReportArgs,
    "Finalise Reports": _FinaliseReportsArgs,
    # Shared workspace wrappers
    "List Run Files": _ListRunFilesArgs,
    "Read Run File": _ReadRunFileArgs,
}


def _tools_by_name() -> dict[str, SquadTool]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


def _good_authored_draft() -> dict[str, object]:
    """Minimal valid kwargs for ``AuthoredDraft``.

    Returned as a dict so the args_schema accept / reject tests can
    mutate one authored field at a time without restating the full
    shape, and so the wrapper-side wraps it under ``authored`` via
    ``_good_draft_kwargs`` below.
    """
    return {
        "title": "SQL Injection in /search?q allows full database extraction",
        "summary": (
            "The /search endpoint concatenates user input into a SELECT "
            "statement. An attacker can dump the entire users table."
        ),
        "description": (
            "The handler concatenates the q parameter directly into the "
            "SQL statement with no parameterisation. UNION-based "
            "injection extracts arbitrary rows."
        ),
        "steps_to_reproduce": [
            "Issue GET https://api.example.com/search?q=test' UNION SELECT 1,2,3-- ",
            "Observe the response body contains the union'd rows.",
        ],
        "evidence": 'HTTP/1.1 200 OK\n\n[{"username":"alice"}]',
        "impact": (
            "An attacker dumps the users table including bcrypt hashes "
            "and emails, enabling offline cracking and account takeover."
        ),
        "remediation": (
            "Use parameterised queries throughout the ORM. See "
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": 89,
    }


def _good_draft_kwargs() -> dict[str, object]:
    """Minimal valid kwargs for ``_DraftReportArgs``.

    Wraps the authored shape (``_good_authored_draft``) in the
    ``authored`` field the args_schema expects.
    """
    return {
        "finding_index": 0,
        "authored": _good_authored_draft(),
    }


class TestTaArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_TA_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every TA typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _TA_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"
        )

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(_TA_SCHEMAS.items()),
        ids=sorted(_TA_SCHEMAS),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        """Every field on every TA typed-tool schema carries a description."""
        for field_name, field_info in schema_cls.model_fields.items():
            desc = field_info.description
            assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
            assert isinstance(desc, str) and desc.strip(), (
                f"{tool_name}::{field_name} description is blank"
            )

    def test_every_ta_cyber_tool_has_schema_mapping(self) -> None:
        """The mapping above must cover every TA ``@cyber_tool`` wrapper.

        Closed-world structural check: every TA tool whose Tool exposes a
        private (``_*``) args_schema class name is in ``_TA_SCHEMAS``;
        every entry in ``_TA_SCHEMAS`` resolves to a registered tool.
        A new typed tool added without a mapping entry fires this test
        before reviewers see the PR.
        """
        tools = _tools_by_name()
        private_schema_tools = {
            name
            for name, t in tools.items()
            if getattr(getattr(t, "args_schema", None), "__name__", "").startswith("_")
        }
        assert private_schema_tools == set(_TA_SCHEMAS), (
            "Mismatch between TA typed-tool wrappers and _TA_SCHEMAS: "
            f"in registry but not mapping = {private_schema_tools - set(_TA_SCHEMAS)}; "
            f"in mapping but not registry = {set(_TA_SCHEMAS) - private_schema_tools}"
        )

    def test_calculate_cvss_description_names_vector_format(self) -> None:
        """The CVSS vector format is documented in the field description.

        The issue body called out ``Calculate CVSS Score`` as the
        field-description sweet spot. Mirrors the equivalent test on the
        VR's copy of the schema.
        """
        desc = _TaCalculateCvssArgs.model_fields["vector"].description or ""
        assert "CVSS:3.1" in desc, (
            f"Calculate CVSS Score vector description must name the canonical"
            f" vector format (CVSS:3.1/...): got {desc!r}"
        )

    def test_draft_report_evidence_description_names_sanitisation(self) -> None:
        """The ``evidence`` field on ``AuthoredDraft`` (referenced by
        ``Draft Vulnerability Report``'s args_schema) must carry the
        upstream-sanitisation warning.

        The Disclosure Coordinator submits whatever the TA drafts to a
        public-by-default H1 report. ``Sanitise Evidence`` exists for
        this reason, and the ``evidence`` field description is the
        load-bearing place to remind the LLM to run it. Test the
        wording rather than just the presence of *any* description; a
        sibling test enforces the latter.
        """
        from models import AuthoredDraft

        desc = AuthoredDraft.model_fields["evidence"].description or ""
        lower = desc.lower()
        assert "sanitis" in lower, (
            f"AuthoredDraft.evidence description must call out Sanitise"
            f" Evidence as the upstream step: got {desc!r}"
        )


class TestSchemaAcceptReject:
    """Accept / reject contract per schema.

    Uses the conftest ``programme`` and ``disclosure_report`` fixtures
    where possible so test intent ("the selected programme",
    "a Technical-Author-shaped report") is readable at the call site.
    """

    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            (_SanitiseEvidenceArgs, {"text": "Authorization: Bearer abc.def.ghi"}),
            (_TaLookupCweArgs, {"query": "SQLi"}),
            (_TaLookupOwaspArgs, {"query": "sql injection"}),
            (_TaCalculateCvssArgs, {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}),
            # Shared workspace acceptance cases.
            (_ListRunFilesArgs, {}),
            (_ReadRunFileArgs, {"relative_path": "verified.json"}),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    def test_list_programme_reports_accepts_empty_payload(self) -> None:
        """``List Programme Reports`` takes no required parameters - the
        programme is sourced from the workspace at runtime."""
        instance = _TaListProgrammeReportsArgs.model_validate({})
        assert instance.page_size == 25  # default

    def test_draft_report_accepts_full_authored_shape(self) -> None:
        """``Draft Vulnerability Report`` accepts the canonical authored payload.

        The authored content is the typed ``AuthoredDraft`` (in
        ``models.report``) nested under the args_schema's ``authored``
        field; the wrapper-side plumbing (finding_index,
        verified_path) stays top-level.
        """
        instance = _DraftReportArgs.model_validate(_good_draft_kwargs())
        assert instance.finding_index == 0
        assert instance.authored.cwe_id == 89
        assert instance.verified_path == "verified.json"  # default

    def test_finalise_reports_accepts_summary(self) -> None:
        """``Finalise Reports`` takes an executive summary attached to
        every consolidated report. The programme is sourced from the
        workspace at runtime."""
        instance = _FinaliseReportsArgs.model_validate(
            {
                "summary": (
                    "Tested the API surface and found one Critical SQLi at "
                    "/search. No other findings cleared the floor."
                ),
            }
        )
        assert "SQLi" in instance.summary

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _SanitiseEvidenceArgs,  # text required
            _TaLookupCweArgs,  # query required
            _TaLookupOwaspArgs,  # query required
            _TaCalculateCvssArgs,  # vector required
            _DraftReportArgs,  # every authored field required
            _FinaliseReportsArgs,  # summary required
            _ReadRunFileArgs,  # relative_path required
        ],
    )
    def test_missing_required_field_rejected(self, schema_cls: type[BaseModel]) -> None:
        """At least one required field is missing: model_validate must fail."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_draft_report_rejects_partial_authored_payload(self) -> None:
        """Each field on ``AuthoredDraft`` is required - dropping any one
        rejects upstream of the wrapper body. Spot-check the four
        most-frequently-missed fields rather than parametrize over the
        full nine: every required field is structurally identical."""
        full_authored = _good_authored_draft()
        for missing in ("title", "evidence", "cvss_vector", "cwe_id"):
            partial_authored = {k: v for k, v in full_authored.items() if k != missing}
            kwargs = {"finding_index": 0, "authored": partial_authored}
            with pytest.raises(ValidationError):
                _DraftReportArgs.model_validate(kwargs)

    def test_draft_report_rejects_non_numeric_cwe_id(self) -> None:
        """``AuthoredDraft.cwe_id`` is typed ``int`` - a non-numeric
        string rejects.

        Pydantic v2's lax mode coerces numeric strings ("89") to int, so
        this test only pins the case the validator actually catches: a
        non-numeric string for ``cwe_id``.
        """
        authored = {**_good_authored_draft(), "cwe_id": "not-a-number"}
        with pytest.raises(ValidationError):
            _DraftReportArgs.model_validate({"finding_index": 0, "authored": authored})
