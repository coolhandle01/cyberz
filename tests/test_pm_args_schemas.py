"""
tests/test_pm_args_schemas.py - contract tests for the explicit Pydantic
``args_schema`` every Programme Manager ``@cyber_tool`` wrapper carries.

Sibling of ``test_pt_args_schemas.py`` and ``test_osint_args_schemas.py``:
same shape of structural and accept/reject checks, scoped to the
Programme Manager's tool surface. Closes #149 for PM.

The PM's tools are the highest-stakes targeting surface in the squad: a
mis-call picks the wrong programme, and downstream every probe runs
against the wrong target. The ``handle`` field in particular is the
most-mis-called field type in the codebase, so the per-field
descriptions enforced here are the primary signal the LLM reads.

The wrappers do not call the H1 API at validation time - the existing
H1 behavioural tests in test_squad_programme_manager.py keep their
mocking; this file only exercises the schema contract.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from models.h1 import ScopeType, SubmissionState
from squad.programme_manager import (
    MEMBER,
    _BrowseProgrammesArgs,
    _HydrateProgrammeArgs,
    _SaveProgrammeArgs,
)

pytestmark = pytest.mark.unit


# Tool-name -> explicit schema class. Covers every PM @cyber_tool wrapper.
_PM_SCHEMAS: dict[str, type[BaseModel]] = {
    "Browse HackerOne Programmes": _BrowseProgrammesArgs,
    "Hydrate HackerOne Programme": _HydrateProgrammeArgs,
    "Save Selected Programme": _SaveProgrammeArgs,
}


def _tools_by_name() -> dict[str, object]:
    """Look up MEMBER.tools by display name once, share across tests."""
    return {t.name: t for t in MEMBER.tools}


class TestPmArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(_PM_SCHEMAS))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        """Every PM typed tool registers the explicit schema class on its Tool."""
        tool_obj = _tools_by_name()[tool_name]
        expected = _PM_SCHEMAS[tool_name]
        assert tool_obj.args_schema is expected, (  # type: ignore[attr-defined]
            f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"  # type: ignore[attr-defined]
        )

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(_PM_SCHEMAS.items()),
        ids=sorted(_PM_SCHEMAS),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        """Per #149: every field on every PM typed-tool schema carries a description."""
        for field_name, field_info in schema_cls.model_fields.items():
            desc = field_info.description
            assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
            assert isinstance(desc, str) and desc.strip(), (
                f"{tool_name}::{field_name} description is blank"
            )

    def test_every_pm_cyber_tool_has_schema_mapping(self) -> None:
        """The mapping above must cover every PM ``@cyber_tool`` wrapper.

        Closed-world structural check: every PM tool whose Tool exposes a
        private (``_*``) args_schema class name is in ``_PM_SCHEMAS``;
        every entry in ``_PM_SCHEMAS`` resolves to a registered tool.
        A new typed tool added without a mapping entry fires this test
        before reviewers see the PR.
        """
        tools = _tools_by_name()
        private_schema_tools = {
            name
            for name, t in tools.items()
            if getattr(getattr(t, "args_schema", None), "__name__", "").startswith("_")
        }
        assert private_schema_tools == set(_PM_SCHEMAS), (
            "Mismatch between PM typed-tool wrappers and _PM_SCHEMAS: "
            f"in registry but not mapping = {private_schema_tools - set(_PM_SCHEMAS)}; "
            f"in mapping but not registry = {set(_PM_SCHEMAS) - private_schema_tools}"
        )


class TestSchemaAcceptReject:
    """Accept / reject contract per schema.

    The parametrize below carries cases that do not need a fixture-derived
    programme handle. Hydrate / Save take a ``handle`` and use the
    ``programme`` fixture via dedicated test methods so test intent
    ("the selected programme") is readable at the call site.
    """

    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            # Browse: every field defaults to None, so the empty kwargs case
            # is the canonical "let H1 apply defaults" call.
            (_BrowseProgrammesArgs, {}),
            (
                _BrowseProgrammesArgs,
                {
                    # StrEnum values are lowercase Python-side; the
                    # wrapper uppercases asset_type before sending it to
                    # H1.
                    "asset_type": "wildcard",
                    "bookmarked": True,
                    "offers_bounties": True,
                    "submission_state": "open",
                    "sort": "-launched_at",
                    "limit": 50,
                },
            ),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    def test_browse_rejects_unknown_asset_type(self) -> None:
        """Per #149 review: ``asset_type`` is a StrEnum; H1's documented
        types are the only acceptable values."""
        with pytest.raises(ValidationError):
            _BrowseProgrammesArgs.model_validate({"asset_type": "not-a-real-type"})

    def test_browse_rejects_unknown_submission_state(self) -> None:
        """Per #149 review: ``submission_state`` is a StrEnum scoped to
        the documented H1 filter values (open / disabled / paused)."""
        with pytest.raises(ValidationError):
            _BrowseProgrammesArgs.model_validate({"submission_state": "closed"})

    def test_browse_accepts_strenum_members_directly(self) -> None:
        """Passing the StrEnum members (rather than their string values)
        also validates - the wrapper is happy with either."""
        instance = _BrowseProgrammesArgs.model_validate(
            {
                "asset_type": ScopeType.WILDCARD,
                "submission_state": SubmissionState.OPEN,
            }
        )
        assert instance.asset_type is ScopeType.WILDCARD
        assert instance.submission_state is SubmissionState.OPEN

    def test_hydrate_accepts_programme_handle(self, programme) -> None:
        """Hydrate takes the exact handle of the selected programme."""
        instance = _HydrateProgrammeArgs.model_validate({"handle": programme.handle})
        assert instance.handle == programme.handle

    def test_save_accepts_programme_handle(self, programme) -> None:
        """Save takes the exact handle of the selected programme."""
        instance = _SaveProgrammeArgs.model_validate({"handle": programme.handle})
        assert instance.handle == programme.handle

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _HydrateProgrammeArgs,
            _SaveProgrammeArgs,
        ],
    )
    def test_missing_required_handle_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``handle`` is required on every handle-taking PM typed-tool schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_browse_ignores_unknown_fields(self) -> None:
        """Browse's filter fields are all optional - extras silently drop.

        Pydantic's default is ``extra='ignore'`` and we keep that here:
        H1's wire layer ignores unknown ``filter[*]`` keys silently
        anyway, so additional strictness would only confuse agents that
        pass through an extra key the wrapper would happily forward.
        """
        instance = _BrowseProgrammesArgs.model_validate(
            {"offers_bounties": True, "nope": "ignored"}
        )
        assert instance.offers_bounties is True
        assert not hasattr(instance, "nope")

    def test_browse_rejects_non_numeric_limit(self) -> None:
        """``limit`` is typed ``int | None`` - a non-numeric string rejects.

        Pydantic v2's lax mode coerces numeric strings ("50") to int and
        accepts boolish strings ("yes") for bool fields, so this test
        only pins the case the validator actually catches: a non-numeric
        string for ``limit``.
        """
        with pytest.raises(ValidationError):
            _BrowseProgrammesArgs.model_validate({"limit": "not-a-number"})
