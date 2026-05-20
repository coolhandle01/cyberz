"""squad/workspace_tools.py - CrewAI @tool wrappers for the shared run workspace."""

from __future__ import annotations

from crewai.tools import tool

from tools import workspace
from tools.research_tools import attack_plan_path, load_attack_plan


@tool("List Run Files")
def read_run_filelist_tool() -> list[dict]:
    """List the artefacts written to the current run directory by the squad
    so far, each with its name and byte size. Use this to discover what an
    upstream teammate has produced before deciding which file to sample with
    Read Run File."""
    return workspace.list_run_files()


@tool("Read Run File")
def read_run_file_tool(relative_path: str) -> dict:
    """Read a file from the current run directory and return its full contents.
    ``relative_path`` is a path relative to the run directory (e.g.
    "recon.json") - the only kind of path this tool accepts. Returns
    {name, size_bytes, content}."""
    return workspace.read_run_file(relative_path)


@tool("Read Attack Plan")
def read_attack_plan_tool() -> dict:
    """Load the Vulnerability Researcher's typed attack plan from
    ``attack_plan.json`` in the current run directory.

    Returns a dict with ``programme_handle``, ``drafted_at``, and ``items`` -
    each item carrying ``probe``, ``target``, ``expected_ceiling``,
    ``rationale``, and ``recon_evidence``. Use this in preference to Read
    Run File on the same artefact: this tool deserialises the typed plan,
    so the agent works against the schema the VR wrote rather than a raw
    JSON blob.

    Raises if no attack plan exists yet for the current run.
    """
    return load_attack_plan(attack_plan_path()).model_dump(mode="json")
