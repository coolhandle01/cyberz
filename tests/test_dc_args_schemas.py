"""
tests/test_dc_args_schemas.py - contract tests for the explicit Pydantic
``args_schema`` every Disclosure Coordinator ``@cyber_tool`` wrapper
carries.

Sibling of ``test_pt_args_schemas.py``, ``test_osint_args_schemas.py``,
and ``test_pm_args_schemas.py``: same shape of structural and
accept/reject checks, scoped to the DC's tool surface. Closes #149 for DC.

The DC is the only agent whose tools have an irreversible public
side-effect - ``Submit Report`` files a report on hackerone.com that the
programme's triage team sees and the operator cannot silently retract.
The per-field descriptions for ``report_json`` name the consequence; the
contract test ensures the description is present and non-empty.

The two workspace tools on the DC (``List Run Files``, ``Read Run
File``) intentionally keep the signature-inferred schema and are out of
scope here - #150 covers them.

The wrappers do not call the H1 API at validation time - the existing
H1 behavioural tests in test_squad_disclosure_coordinator.py keep their
mocking; this file only exercises the schema contract.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad.disclosure_coordinator import (
    MEMBER,
    _CheckDuplicateArgs,
    _SubmitReportArgs,
)

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every DC @cyber_tool wrapper.
# The two workspace readers (``List Run Files``, ``Read Run File``) on
# the DC keep the inferred schema and are out of scope - #150 owns them.
_DC_SCHEMAS: dict[str, type[BaseModel]] = {
    "Submit Report": _SubmitReportArgs,
    "Check H1 Duplicate": _CheckDuplicateArgs,
}


def _tools_by_name() -> dict[str, object]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


class TestDcArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_DC_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every DC typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _DC_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (  # type: ignore[attr-defined]
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"  # type: ignore[attr-defined]
        )

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(_DC_SCHEMAS.items()),
        ids=sorted(_DC_SCHEMAS),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        """Per #149: every field on every DC typed-tool schema carries a description."""
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
        """Per the #149 acceptance criterion: the irreversible operation's
        field description must name the consequence of a mis-call.

        The agent reading ``Submit Report``'s schema needs to know that a
        wrong ``programme_handle`` inside the payload publishes a report
        to the wrong target - the schema description is the load-bearing
        place to say that out loud. Test the wording rather than just
        the presence of *any* description; a sibling test (
        ``test_every_field_has_description`` above) already enforces the
        latter.
        """
        desc = _SubmitReportArgs.model_fields["report_json"].description or ""
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

    def test_submit_report_accepts_serialised_report(self, disclosure_report) -> None:
        """The Technical Author's serialised DisclosureReport must validate.

        Uses the ``disclosure_report`` conftest fixture so test intent
        ("a real, in-scope report") is readable at the call site rather
        than a hand-rolled JSON literal.
        """
        instance = _SubmitReportArgs.model_validate(
            {"report_json": disclosure_report.model_dump_json()}
        )
        assert instance.report_json == disclosure_report.model_dump_json()

    def test_check_duplicate_accepts_programme_and_title(
        self, programme, disclosure_report
    ) -> None:
        """Check Duplicate takes the selected programme's handle and the draft title."""
        instance = _CheckDuplicateArgs.model_validate(
            {
                "programme_handle": programme.handle,
                "title": disclosure_report.title,
            }
        )
        assert instance.programme_handle == programme.handle
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

    def test_check_duplicate_requires_both_handle_and_title(self, programme) -> None:
        """Both ``programme_handle`` and ``title`` are required - one alone fails."""
        with pytest.raises(ValidationError):
            _CheckDuplicateArgs.model_validate({"programme_handle": programme.handle})
        with pytest.raises(ValidationError):
            _CheckDuplicateArgs.model_validate({"title": "Some report title"})
