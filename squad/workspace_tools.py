"""squad/workspace_tools.py - shared run-workspace surface.

Two halves:

- ``@cyber_tool`` wrappers around the workspace artefact IO (``List
  Run Files``, ``Read Run File``, ``Read Attack Plan``).
- ``load_programme(programme_handle)`` - the shared programme-loader
  helper used by every agent that needs a parsed ``Programme`` to
  reason against (OSINT's curation + active-probe tools, VR triage).
  Lives here because it is the workspace's other authoritative
  context: the run directory tells us what we wrote, and this loader
  tells us who we wrote it about.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models import RunFile, RunFileContent
from models.attack import AttackPlan
from models.h1 import Programme
from squad import cyber_tool
from tools import http, workspace
from tools.h1_api import h1
from tools.research_tools import attack_plan_path, load_attack_plan


def load_programme(programme_handle: str | None) -> Programme:
    """Fetch and parse the Programme for the current run.

    Centralised here (rather than duplicated as a private helper in
    each agent's package) because the programme is workspace-level
    state - every agent that needs to scope-check against the
    selected programme calls this. ``programme_handle`` is required:
    a None / empty handle is a hard error rather than a silent fall-
    through to the run directory's metadata, because the scope guard
    needs the parsed ``Programme`` model and the H1 API is the
    authoritative source for it.
    """
    if not programme_handle:
        raise ValueError("programme_handle is required")
    http.set_programme(programme_handle)
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    return h1.parse_programme(policy["data"], scope)


class _ListRunFilesArgs(BaseModel):
    """Explicit args_schema for the List Run Files tool.

    The tool takes no parameters - the run directory is resolved from
    ``runtime.run_dir()`` at call time. The empty schema is still
    declared so the closed-world contract test in each consuming
    agent's ``test_args_schemas.py`` accounts for the tool, and so
    every shared workspace wrapper goes through ``@cyber_tool``.
    """


@cyber_tool("List Run Files", args_schema=_ListRunFilesArgs)
def read_run_filelist_tool() -> list[RunFile]:
    """List the artefacts written to the current run directory by the squad
    so far, each with its name and byte size. Use this to discover what an
    upstream teammate has produced before deciding which file to sample with
    Read Run File."""
    return [RunFile(**entry) for entry in workspace.list_run_files()]


class _ReadRunFileArgs(BaseModel):
    """Explicit args_schema for the Read Run File tool."""

    relative_path: str = Field(
        description=(
            "Path of the artefact to read, relative to the current run"
            " directory (e.g. ``recon.json``, ``findings.json``,"
            " ``attack_plan.json``). Absolute paths and any segment"
            " containing ``..`` are rejected by the workspace layer; the"
            " agent should pass the bare filename a finalise tool returned"
            " (or one List Run Files surfaced). A wrong ``relative_path``"
            " here loads the wrong artefact and the agent reasons over the"
            " wrong inputs - prefer the typed slicers (``Recon Endpoints``"
            " / ``Read Attack Plan`` / ``List Raw Findings``) when one"
            " exists for the artefact you want."
        ),
    )


@cyber_tool("Read Run File", args_schema=_ReadRunFileArgs)
def read_run_file_tool(relative_path: str) -> RunFileContent:
    """Read a file from the current run directory and return its full contents.
    ``relative_path`` is a path relative to the run directory (e.g.
    "recon.json") - the only kind of path this tool accepts."""
    return RunFileContent(**workspace.read_run_file(relative_path))


class _ReadAttackPlanArgs(BaseModel):
    """Explicit args_schema for the Read Attack Plan tool.

    The tool takes no parameters - the attack plan path is resolved
    from ``runtime.run_dir()`` via ``attack_plan_path()`` at call
    time. The empty schema is still declared so the closed-world
    contract test in each consuming agent's ``test_args_schemas.py``
    accounts for the tool.
    """


@cyber_tool("Read Attack Plan", args_schema=_ReadAttackPlanArgs)
def read_attack_plan_tool() -> AttackPlan:
    """Load the Vulnerability Researcher's typed attack plan from
    ``attack_plan.json`` in the current run directory.

    Returns the typed ``AttackPlan`` with ``programme_handle``, ``drafted_at``,
    and ``items`` - each item carrying ``probe``, ``target``,
    ``expected_ceiling``, ``rationale``, and ``recon_evidence``. Use this in
    preference to Read Run File on the same artefact: this tool deserialises
    the typed plan, so the agent works against the schema the VR wrote rather
    than a raw JSON blob.

    Raises if no attack plan exists yet for the current run.
    """
    return load_attack_plan(attack_plan_path())
