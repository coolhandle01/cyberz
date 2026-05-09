"""
squad/__init__.py - shared SquadMember dataclass + agent/task builders.

Each sub-package declares one module-level ``MEMBER = SquadMember(...)`` constant.
Prose lives in five single-purpose markdown files alongside it:

    role.md             goal.md             backstory.md
    description.md      expected_output.md

Assembly (LLM wiring, pipeline order, approval gates) lives in crew.py / tasks.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crewai import Agent, Task


@dataclass(frozen=True)
class SquadMember:
    """A single Bounty Squad member: identity, tools, and prose location."""

    slug: str
    dir: Path
    tools: list[Any] = field(default_factory=list)

    def read(self, name: str) -> str:
        """Read ``<dir>/<name>.md`` and return its stripped contents."""
        return (self.dir / f"{name}.md").read_text(encoding="utf-8").strip()


def build_agent(member: SquadMember, llm: object, verbose: bool = False) -> Agent:
    """Construct a CrewAI Agent from the member's role/goal/backstory files."""
    return Agent(
        role=member.read("role"),
        goal=member.read("goal"),
        backstory=member.read("backstory"),
        tools=member.tools,
        allow_delegation=False,
        llm=llm,
        verbose=verbose,
    )


def build_task(
    member: SquadMember,
    agent: Agent,
    context: list[Task] | None = None,
    human_input: bool = False,
    description_name: str = "description",
    expected_output_name: str = "expected_output",
) -> Task:
    """Create a Task from the member's prose files.

    description_name / expected_output_name let callers point at non-default
    .md files (e.g. retrospective_description.md) without duplicating the
    Task construction logic.
    """
    return Task(
        description=member.read(description_name),
        expected_output=member.read(expected_output_name),
        agent=agent,
        context=context or [],
        human_input=human_input,
    )
