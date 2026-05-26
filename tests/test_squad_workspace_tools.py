"""
tests/test_squad_workspace_tools.py - exercise the shared workspace @tool
wrappers (``read_run_filelist_tool`` / ``read_run_file_tool`` /
``read_attack_plan_tool``) plus the ``current_programme()`` reader and the
``@cyber_tool`` auto-detected scope-filter mechanism that builds on it.

The wrappers are thin: unmarshal JSON, call into tools/workspace helpers,
serialise the result. Coverage here is regression coverage of the wrapping
itself; the underlying helpers are exercised in ``tests/test_workspace.py``.

The ``args_schema`` contract for the same three wrappers lives in
``TestWorkspaceArgsSchemas`` below - aligned with the per-agent
``test_args_schemas.py`` shape used elsewhere, but co-located with the
behavioural tests because the workspace tools are shared rather than
agent-scoped.
"""

import pytest
from pydantic import BaseModel, Field, ValidationError

pytestmark = pytest.mark.unit


class TestSharedWorkspaceTools:
    def test_read_run_filelist_tool(self, run_dir) -> None:
        from models import RunFile
        from squad import read_run_filelist_tool

        (run_dir / "recon.json").write_text("{}", encoding="utf-8")
        result = read_run_filelist_tool.func()
        assert result == [RunFile(name="recon.json", size_bytes=2)]

    def test_read_run_file_tool(self, run_dir) -> None:
        from models import RunFileContent
        from squad import read_run_file_tool

        (run_dir / "recon.json").write_text("hello", encoding="utf-8")
        result = read_run_file_tool.func("recon.json")
        assert isinstance(result, RunFileContent)
        assert result.content == "hello"
        assert result.size_bytes == 5

    def test_read_run_file_tool_refuses_escape(self, run_dir) -> None:
        from squad import read_run_file_tool

        with pytest.raises(ValueError, match=r"must not contain '\.\.'"):
            read_run_file_tool.func("../etc/passwd")

    def test_read_attack_plan_tool_returns_typed_plan(self, attack_plan, run_dir) -> None:
        from models.attack import AttackPlan
        from squad import read_attack_plan_tool

        (run_dir / "attack_plan.json").write_text(attack_plan.model_dump_json(), encoding="utf-8")
        result = read_attack_plan_tool.func()
        assert isinstance(result, AttackPlan)
        assert result.programme_handle == attack_plan.programme_handle
        assert len(result.items) == len(attack_plan.items)
        assert result.items[0].probe == attack_plan.items[0].probe
        assert result.items[0].expected_ceiling == attack_plan.items[0].expected_ceiling

    def test_read_attack_plan_tool_raises_when_missing(self, run_dir) -> None:
        from squad import read_attack_plan_tool

        with pytest.raises(FileNotFoundError, match="attack plan not found"):
            read_attack_plan_tool.func()


class TestCurrentProgramme:
    """``current_programme()`` reads the PM's run-dir snapshot.

    The PM's Save Selected Programme writes ``programme.json`` to the
    run directory at run start. Every downstream agent and every
    ``@cyber_tool(scope_filter=...)`` wrapper sources its Programme
    through ``current_programme()``; no second H1 API call.
    """

    def test_returns_programme_from_run_dir(self, programme, run_dir) -> None:
        from squad.workspace_tools import current_programme

        (run_dir / "programme.json").write_text(programme.model_dump_json(), encoding="utf-8")
        result = current_programme()
        assert result.handle == programme.handle
        assert result.in_scope == programme.in_scope

    def test_raises_when_programme_json_missing(self, run_dir) -> None:
        from squad.workspace_tools import current_programme

        with pytest.raises(FileNotFoundError):
            current_programme()


# Module-scope stub args_schema classes for the auto-detection tests.
# ``from __future__ import annotations`` makes every field annotation a
# forward-ref string; Pydantic resolves those via the class's enclosing
# module namespace when CrewAI's ``tool()`` triggers ``model_rebuild``.
# A class defined inside a test method has no module namespace
# ``Hostname`` lives in, so model_rebuild fails. Defining them here -
# alongside the canonical ``Hostname`` import - keeps the resolver
# happy and lets the test bodies stay narrow. Deferred-import context
# documented at https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file/
from models import Hostname  # noqa: E402 - deferred so the stub args_schemas resolve forward refs


class _StubHostnamesArgs(BaseModel):
    """Stub args_schema with a typed-target hostname list - the
    auto-detection's primary trigger."""

    hostnames: list[Hostname] = Field(description="Targets the wrapper filters.")


class _StubReconPathArgs(BaseModel):
    """Stub args_schema with no typed-target fields - the
    auto-detection skips wrapping entirely for this shape."""

    recon_path: str = Field(description="Workspace artefact handle.")


class TestCyberToolScopeFilter:
    """``@cyber_tool`` auto-detects typed-target fields and runs the
    matching scope filter before the body.

    The typed parameter IS the opt-in signal - any ``args_schema``
    field annotated ``Hostname`` / ``list[Hostname]`` /
    ``Endpoint`` / ``list[Endpoint]`` is auto-scope-filtered against
    ``<run_dir>/programme.json``; no per-tool parameter to forget.
    Fields with any other annotation pass through unchanged.
    """

    def test_filter_runs_before_body(self, programme_in_workspace, target_apex) -> None:
        """The auto-detected scope filter rewrites the typed-target field
        before the body sees it."""
        from squad import cyber_tool

        seen_values: list[list[str]] = []

        @cyber_tool("Stub Hostname Tool", args_schema=_StubHostnamesArgs)
        def stub_tool(hostnames: list[Hostname]) -> list[Hostname]:
            """Stub body that records what it was handed and returns it."""
            seen_values.append(hostnames)
            return hostnames

        result = stub_tool.func(hostnames=[f"api.{target_apex}", "bystander.example.org"])

        assert result == [f"api.{target_apex}"]
        assert seen_values == [[f"api.{target_apex}"]]

    def test_empty_input_skips_programme_lookup(self) -> None:
        """An empty typed-target field short-circuits the wrapper - no
        ``current_programme()`` lookup, no run-dir read, body receives
        the empty list verbatim."""
        from squad import cyber_tool

        @cyber_tool("Stub Empty-Skip Tool", args_schema=_StubHostnamesArgs)
        def stub_tool(hostnames: list[Hostname]) -> list[Hostname]:
            """Stub body that returns the input verbatim."""
            return hostnames

        # No ``runtime.run_dir`` patch is required - the wrapper must
        # not reach for the workspace when the field is empty.
        assert stub_tool.func(hostnames=[]) == []

    def test_no_typed_target_fields_skips_wrapping(self) -> None:
        """When ``args_schema`` has no typed-target fields, the wrapper
        does not wrap the body at all - no Programme lookup, no
        rewriting, the body sees its kwargs verbatim. The
        ``recon_path: str`` shape lives on tools that read workspace
        artefacts; their input is a filename, not an agent-supplied
        target, so scope-filtering is not the contract."""
        from squad import cyber_tool

        @cyber_tool("Stub Recon Reader", args_schema=_StubReconPathArgs)
        def stub_tool(recon_path: str) -> str:
            """Stub body that returns the input verbatim."""
            return recon_path

        # No ``programme_in_workspace`` / ``run_dir`` fixture - the
        # wrapper must not reach for the workspace at all.
        assert stub_tool.func(recon_path="recon.json") == "recon.json"


# Tool-name -> explicit schema class. The workspace wrappers are shared
# rather than agent-scoped, so the closed-world structural check in each
# consuming agent's ``test_args_schemas.py`` covers the registry side;
# this block holds the schema-side contract.
def _load_workspace_schemas() -> dict[str, type[BaseModel]]:
    """Resolve the schemas lazily so the module imports without the env vars."""
    from squad.workspace_tools import (
        _ListRunFilesArgs,
        _ReadAttackPlanArgs,
        _ReadRunFileArgs,
    )

    return {
        "List Run Files": _ListRunFilesArgs,
        "Read Run File": _ReadRunFileArgs,
        "Read Attack Plan": _ReadAttackPlanArgs,
    }


class TestWorkspaceArgsSchemas:
    """Contract tests for the shared workspace tools' explicit
    ``args_schema`` classes.

    The workspace wrappers are reachable from every agent's ``MEMBER.tools``;
    a mis-call costs a wrong artefact loaded (or the wrong agent reasoning
    over the wrong inputs). The per-field description on ``Read Run File``'s
    ``relative_path`` is the load-bearing signal that says "prefer the typed
    slicer when one exists".
    """

    def test_every_field_has_description(self) -> None:
        """Every field on every workspace schema carries a description.

        ``List Run Files`` and ``Read Attack Plan`` have no fields (the
        run directory and attack plan path are resolved from runtime
        state), so the loop trivially passes for them.
        """
        for tool_name, schema_cls in _load_workspace_schemas().items():
            for field_name, field_info in schema_cls.model_fields.items():
                desc = field_info.description
                assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
                assert isinstance(desc, str) and desc.strip(), (
                    f"{tool_name}::{field_name} description is blank"
                )

    def test_list_run_files_accepts_empty_payload(self) -> None:
        """``List Run Files`` takes no parameters; the empty payload is canonical."""
        from squad.workspace_tools import _ListRunFilesArgs

        instance = _ListRunFilesArgs.model_validate({})
        assert isinstance(instance, _ListRunFilesArgs)

    def test_read_attack_plan_accepts_empty_payload(self) -> None:
        """``Read Attack Plan`` takes no parameters; the empty payload is canonical."""
        from squad.workspace_tools import _ReadAttackPlanArgs

        instance = _ReadAttackPlanArgs.model_validate({})
        assert isinstance(instance, _ReadAttackPlanArgs)

    def test_read_run_file_accepts_relative_path(self) -> None:
        """``Read Run File`` accepts a bare relative-path string."""
        from squad.workspace_tools import _ReadRunFileArgs

        instance = _ReadRunFileArgs.model_validate({"relative_path": "recon.json"})
        assert instance.relative_path == "recon.json"

    def test_read_run_file_rejects_missing_relative_path(self) -> None:
        """``relative_path`` is required - the wrapper has no default."""
        from squad.workspace_tools import _ReadRunFileArgs

        with pytest.raises(ValidationError):
            _ReadRunFileArgs.model_validate({})
