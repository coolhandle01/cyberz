"""squad/workspace_tools.py - CrewAI @tool wrappers for the shared run workspace."""

from __future__ import annotations

from crewai.tools import tool

from tools import workspace


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
