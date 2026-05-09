"""Programme Manager - selects the highest-value H1 programme."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from squad import SquadMember
from tools.h1_api import h1
from tools.ledger import read_recent_retros, write_retro
from tools.suggestion_box import get_suggestions, make_suggestion_tool


@tool("List HackerOne Programmes")
def list_programmes_tool(page_size: int = 25) -> list[dict]:
    """Fetch and return a list of active HackerOne bug bounty programmes."""
    return h1.list_programmes(page_size=page_size)


@tool("Get Programme Scope")
def get_scope_tool(handle: str) -> dict:
    """Fetch the structured in-scope and out-of-scope assets for a programme."""
    policy = h1.get_programme_policy(handle)
    scope = h1.get_structured_scope(handle)
    return {"policy": policy, "scope": scope}


@tool("Get Programme Stats")
def get_programme_stats_tool(handle: str) -> dict:
    """
    Fetch response efficiency, average triage time, and total bounties paid for a
    programme. Use this to rank programmes by actual payout likelihood.
    """
    return h1.get_programme_stats(handle)


@tool("Read Suggestion Box")
def read_suggestions_tool() -> str:
    """
    Read all suggestions logged by squad agents during this pipeline run.
    Call this as part of the retrospective task to compile the operator summary.
    Returns a formatted list, or a message confirming nothing was logged.
    """
    suggestions = get_suggestions()
    if not suggestions:
        return "No suggestions logged during this pipeline run."
    return "\n".join(f"[{s.agent}/{s.category}] {s.message}" for s in suggestions)


@tool("Write Retrospective")
def write_retro_tool(handle: str, content: str) -> str:
    """
    Persist the retrospective for a programme campaign to disk.

    Call this at the end of the retrospective task after drafting the summary.
    Writes to reports/programs/<handle>/campaigns/<today>/retrospective.md so
    future runs of the same programme can read it as institutional memory.

    handle: the HackerOne programme handle (e.g. "acme")
    content: the full retrospective text in Markdown
    """
    path = write_retro(handle, content)
    return f"Retrospective saved to {path}"


@tool("Read Previous Retrospectives")
def read_recent_retros_tool(handle: str) -> str:
    """
    Read the retrospectives from the last three campaigns against a programme.

    Use this when selecting or re-evaluating a programme the squad has worked
    before - retros capture unexplored surface, programme policy quirks,
    tooling gaps, and what the squad should do differently next time.

    Returns formatted retro text, newest first, or a note if none exist.
    handle: the HackerOne programme handle (e.g. "acme")
    """
    retros = read_recent_retros(handle)
    if not retros:
        return f"No previous retrospectives found for {handle}."
    sections = [f"## {date}\n\n{content.strip()}" for date, content in retros]
    return "\n\n---\n\n".join(sections)


MEMBER = SquadMember(
    slug="programme_manager",
    dir=Path(__file__).parent,
    tools=[
        list_programmes_tool,
        get_scope_tool,
        get_programme_stats_tool,
        make_suggestion_tool("programme_manager"),
        read_suggestions_tool,
        write_retro_tool,
        read_recent_retros_tool,
    ],
)
