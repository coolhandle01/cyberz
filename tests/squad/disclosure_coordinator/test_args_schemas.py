"""
Contract tests for the Disclosure Coordinator's explicit Pydantic
``args_schema`` classes - one of the per-agent test pairs (sibling
under ``tests/squad/<agent>/test_args_schemas.py``).

The DC is the only agent whose tools have an irreversible public
side-effect - ``Submit Report`` files a report on hackerone.com that the
programme's triage team sees and the operator cannot silently retract.
The per-field description for ``report`` names the consequence; the
contract test ensures the description is present and that the
irreversibility wording survives any future rewording.

The two shared workspace readers re-exported into the DC's registry
(``List Run Files``, ``Read Run File``) are part of the closed-world
check below.

The wrappers do not call the H1 API at validation time - the existing
H1 behavioural tests in ``test_tools.py`` keep their mocking; this
file only exercises the schema contract.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad import SquadTool
from squad.disclosure_coordinator import (
    MEMBER,
    _CheckDuplicateArgs,
    _SubmitReportArgs,
)
from squad.workspace_tools import (
    _ListRunFilesArgs,
    _ReadRunFileArgs,
)

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every DC @cyber_tool
# wrapper plus the two shared workspace readers.
_DC_SCHEMAS: dict[str, type[BaseModel]] = {
    "Submit Report": _SubmitReportArgs,
    "Check H1 Duplicate": _CheckDuplicateArgs,
    # Shared workspace wrappers (re-exported via squad.workspace_tools)
    "List Run Files": _ListRunFilesArgs,
    "Read Run File": _ReadRunFileArgs,
}


def _tools_by_name() -> dict[str, SquadTool]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


class TestDcArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_DC_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every DC typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _DC_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"
        )

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(_DC_SCHEMAS.items()),
        ids=sorted(_DC_SCHEMAS),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        """Every field on every DC typed-tool schema carries a description."""
        for field_name, field_info in schema_cls.model_fields.items():
            desc = field_info.description
            assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
            assert isinstance(desc, str) and desc.strip(), (
                f"{tool_name}::{field_name} description is blank"
            )

    def test_every_dc_cyber_tool_has_schema_mapping(self) -> None:
        """The mapping above must cover every DC ``@cyber_tool`` wrapper.

        Closed-world structural check: every DC tool whose Tool exposes a
        private (``_*``) args_schema class name is in ``_DC_SCHEMAS``;
        every entry in ``_DC_SCHEMAS`` resolves to a registered tool.
        A new typed tool added without a mapping entry fires this test
        before reviewers see the PR.
        """
        tools = _tools_by_name()
        private_schema_tools = {
            name
            for name, t in tools.items()
            if getattr(getattr(t, "args_schema", None), "__name__", "").startswith("_")
        }
        assert private_schema_tools == set(_DC_SCHEMAS), (
            "Mismatch between DC typed-tool wrappers and _DC_SCHEMAS: "
            f"in registry but not mapping = {private_schema_tools - set(_DC_SCHEMAS)}; "
            f"in mapping but not registry = {set(_DC_SCHEMAS) - private_schema_tools}"
        )

    def test_submit_report_description_names_irreversibility(self) -> None:
        """The irreversible operation's field description must name the
        consequence of a mis-call.

        The agent reading ``Submit Report``'s schema needs to know that a
        wrong ``programme_handle`` inside the payload publishes a report
        to the wrong target - the schema description is the load-bearing
        place to say that out loud. Test the wording rather than just
        the presence of *any* description; a sibling test (
        ``test_every_field_has_description`` above) already enforces the
        latter.
        """
        desc = _SubmitReportArgs.model_fields["report"].description or ""
        # "Irreversible" is the framing the issue body uses; we look for
        # the broader semantic signal (irreversible + programme_handle
        # warning) rather than a single literal so the description can be
        # reworded without breaking the test.
        lower = desc.lower()
        assert "irreversible" in lower or "cannot" in lower, (
            f"Submit Report description must name the irreversible nature: got {desc!r}"
        )
        assert "programme_handle" in lower or "programme handle" in lower, (
            "Submit Report description must call out the programme_handle "
            f"mis-call risk: got {desc!r}"
        )


class TestSchemaAcceptReject:
    """Accept / reject contract per schema.

    URL / hostname-taking schemas don't apply here - the DC's tools take
    a serialised report payload or a programme handle, both of which are
    well served by the ``disclosure_report`` and ``programme`` fixtures.
    """

    def test_submit_report_accepts_dict_payload(self, disclosure_report) -> None:
        """CrewAI hands the args_schema a dict shaped like DisclosureReport.

        Uses the ``disclosure_report`` conftest fixture so test intent
        ("a real, in-scope report") is readable at the call site rather
        than a hand-rolled dict literal.
        """
        instance = _SubmitReportArgs.model_validate({"report": disclosure_report.model_dump()})
        assert instance.report.programme_handle == disclosure_report.programme_handle
        assert instance.report.title == disclosure_report.title

    def test_submit_report_accepts_typed_model(self, disclosure_report) -> None:
        """Direct test invocations pass a DisclosureReport instance; the
        schema must accept that too (the both-shapes adapter pattern)."""
        instance = _SubmitReportArgs.model_validate({"report": disclosure_report})
        assert instance.report.programme_handle == disclosure_report.programme_handle

    def test_submit_report_rejects_mis_shaped_report(self) -> None:
        """A dict that doesn't validate as DisclosureReport rejects
        upstream of the wrapper - the whole point of the typed
        parameter is the schema reject."""
        with pytest.raises(ValidationError):
            _SubmitReportArgs.model_validate({"report": {"not_a_real_field": "x"}})

    def test_check_duplicate_accepts_title(self, disclosure_report) -> None:
        """Check Duplicate takes the draft title - the programme is
        sourced from the workspace at runtime."""
        instance = _CheckDuplicateArgs.model_validate({"title": disclosure_report.title})
        assert instance.title == disclosure_report.title

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _SubmitReportArgs,
            _CheckDuplicateArgs,
        ],
    )
    def test_missing_required_fields_rejected(self, schema_cls: type[BaseModel]) -> None:
        """Every DC typed-tool schema rejects an empty payload - all fields are required."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})
