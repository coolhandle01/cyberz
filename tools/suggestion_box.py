"""Shared suggestion box for in-pipeline agent feedback.

Agents log friction, limitations, and hallucination urges here instead of
guessing or fabricating results. The Programme Manager reads the accumulated
suggestions at pipeline end and reports them to the operator.

Usage in agent tools:
    from tools.suggestion_box import make_suggestion_tool
    suggestion_box = make_suggestion_tool("osint_analyst")

    MEMBER = SquadMember(..., tools=[..., suggestion_box])
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from crewai.tools import tool

logger = logging.getLogger(__name__)

VALID_CATEGORIES = frozenset(
    {
        "missing_tool",
        "scope_limitation",
        "false_positive_risk",
        "hallucination_urge",
        "tooling_feedback",
    }
)


@dataclass
class Suggestion:
    agent: str
    category: str
    message: str


_suggestions: list[Suggestion] = []


def log_suggestion(agent: str, category: str, message: str) -> None:
    _suggestions.append(Suggestion(agent=agent, category=category, message=message))
    logger.warning("suggestion_box [%s/%s]: %s", agent, category, message)


def get_suggestions() -> list[Suggestion]:
    return list(_suggestions)


def clear() -> None:
    """Clear all logged suggestions. Call between pipeline runs and in tests."""
    _suggestions.clear()


def make_suggestion_tool(agent_slug: str) -> Any:  # noqa: ANN401
    """Return a Suggestion Box @tool pre-bound to agent_slug."""

    @tool("Suggestion Box")
    def suggestion_box_tool(category: str, message: str) -> str:
        """
        Log a limitation, friction point, or hallucination urge for the developer.

        Call this tool whenever you would otherwise guess, fabricate, or skip
        silently:
          - A required binary is missing or returned no output
          - You lack sufficient evidence to support a finding you feel pressure
            to include
          - A tooling gap would materially improve your output
          - You are about to produce a result you cannot independently verify

        This never blocks your task - it records the issue so the developer can
        improve the pipeline. After logging, continue with what you can verify.

        category: missing_tool | scope_limitation | false_positive_risk |
                  hallucination_urge | tooling_feedback
        message: one or two sentences describing the specific issue
        """
        from tools.suggestion_box import log_suggestion as _log

        _log(agent_slug, category, message)
        return f"Logged [{category}]: {message}"

    return suggestion_box_tool
