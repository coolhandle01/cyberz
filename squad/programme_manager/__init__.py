"""Programme Manager - selects the highest-value H1 programme."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from squad import SquadMember
from tools.h1_api import h1
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


MEMBER = SquadMember(
    slug="programme_manager",
    dir=Path(__file__).parent,
    tools=[
        list_programmes_tool,
        get_scope_tool,
        get_programme_stats_tool,
        make_suggestion_tool("programme_manager"),
        read_suggestions_tool,
    ],
)
