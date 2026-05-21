"""Programme Manager - selects the highest-value H1 programme."""

from __future__ import annotations

import shutil
from pathlib import Path

from crewai.tools import tool

import runtime
from squad import SquadMember
from tools.h1_api import h1


@tool("Browse HackerOne Programmes")
# CrewAI builds the tool's JSON schema from this signature; each filter has
# to be a named parameter so the LLM can discover and pass it. Collapsing
# into a single dict argument would force the agent to guess valid filter
# keys.
# pylint: disable=R0913,R0917
def browse_programmes_tool(
    asset_type: str | None = None,
    bookmarked: bool | None = None,
    offers_bounties: bool | None = None,
    submission_state: str | None = None,
    sort: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """
    Survey the accessible H1 catalog with lightweight previews - one HTTP
    call per page, no per-programme detail fetch. Cheap, so use this first
    to see what is out there before deciding which programmes are worth
    paying to hydrate.

    Each preview carries handle, name, offers_bounties, submission_state,
    state, and bookmarked - enough to narrow on access mode and bounty
    posture before pulling policy_text and scope.

    Filter kwargs map to H1 filter[*] query params on /hackers/programs and
    are sent to the server; the H1 default applies when a kwarg is omitted.
      - asset_type: e.g. "URL", "WILDCARD"
      - bookmarked: True for programmes you have bookmarked
      - offers_bounties: True to exclude VDPs
      - submission_state: "open" to exclude paused/disabled programmes
      - sort: e.g. "-launched_at" for newest first
      - limit: cap on total previews (default config.h1.max_programmes)

    Returns a list of ProgrammePreview dicts. Hydrate shortlisted handles
    with hydrate_programme_tool.
    """
    previews = h1.browse_programmes(
        asset_type=asset_type,
        bookmarked=bookmarked,
        offers_bounties=offers_bounties,
        submission_state=submission_state,
        sort=sort,
        limit=limit,
    )
    return [p.model_dump() for p in previews]


@tool("Hydrate HackerOne Programme")
def hydrate_programme_tool(handle: str) -> dict:
    """
    Fetch full programme detail for one handle - bounty_table, structured
    scope, policy text, response/payout stats. One HTTP call.

    Expensive relative to browse_programmes_tool, so reserve for candidates
    the browse step has already shortlisted. The hydrated programme is
    cached so save_programme_tool can copy it into the run directory.
    """
    prog = h1.hydrate_programme(handle)
    cache_path = runtime.programme_cache_path(prog.handle)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(prog.model_dump_json(), encoding="utf-8")
    return prog.model_dump()


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
    dir=Path(__file__).parent,
    tools=[browse_programmes_tool, hydrate_programme_tool, save_programme_tool],
)
