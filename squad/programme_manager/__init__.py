"""Programme Manager - selects the highest-value H1 programme."""

from __future__ import annotations

import shutil
from pathlib import Path

from crewai.tools import tool

import runtime
from squad import SquadMember
from tools.h1_api import h1


@tool("Find HackerOne Programmes")
def find_programmes_tool(open_only: bool = True, bounty_only: bool = True) -> list[dict]:
    """
    Retrieve all accessible HackerOne programmes, fully hydrated with scope,
    bounty table, triage stats, and policy text in a single call.

    open_only: skip programmes that are not currently accepting reports
    bounty_only: skip programmes that do not offer bounties (VDPs)

    Each programme is cached locally so save_selected_programme can copy
    it into the run directory. Returns a list of Programme dicts ready for
    scoring; the agent reads policy_text before authorising any work.
    """
    programmes = h1.find_programmes(open_only=open_only, bounty_only=bounty_only)
    for prog in programmes:
        cache_path = runtime.programme_cache_path(prog.handle)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(prog.model_dump_json(), encoding="utf-8")
    return [p.model_dump() for p in programmes]


@tool("Save Selected Programme")
def save_programme_tool(handle: str) -> str:
    """
    Record the selected programme for downstream agents. Sets
    runtime.programme_handle, creates the run directory, and copies the
    cached programme.json into it. Returns the absolute path to the run
    directory.
    """
    runtime.programme_handle = handle
    run_dir = runtime.run_dir()
    run_dir.mkdir(parents=True, exist_ok=True)
    cache = runtime.programme_cache_path(handle)
    if cache.exists():
        shutil.copy(cache, run_dir / "programme.json")
    return str(run_dir)


MEMBER = SquadMember(
    slug="programme_manager",
    dir=Path(__file__).parent,
    tools=[find_programmes_tool, save_programme_tool],
    task="Select Program",
)
