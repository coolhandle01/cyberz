"""
squad/__init__.py - shared SquadMember dataclass + agent/task builders.

Each sub-package declares one module-level ``MEMBER = SquadMember(...)`` constant.
Agent prose lives in three markdown files alongside it:

    role.md   goal.md   backstory.md

Task-specific prose lives in named subdirectories:

    <task_name>/description.md    <task_name>/expected_output.md

A squad member that appears in more than one pipeline task (e.g. the
Vulnerability Researcher runs as both attack-planner and findings-triager)
has one subdir per task:

    research/description.md   triage/description.md

Member-specialist skills live alongside the prose in a ``skills/`` subdirectory;
each skill is its own folder containing a ``SKILL.md`` with frontmatter, per the
crewai.skills loader contract. Squad-wide skills live at ``squad/skills/`` and
are attached at Crew construction in crew.py.

Assembly (LLM wiring, pipeline order, approval gates) lives in crew.py / tasks.py.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from crewai import Agent, Task
from crewai.tools import tool
from crewai.tools.base_tool import Tool

from squad.workspace_tools import (
    read_attack_plan_tool,
    read_run_file_tool,
    read_run_filelist_tool,
)

R = TypeVar("R")

SQUAD_SKILLS_DIR = Path(__file__).parent / "skills"


def cached_tool(name: str) -> Callable[[Callable[..., R]], Tool[..., R]]:
    """Drop-in replacement for ``@tool`` for deterministic data lookups.

    Wraps the underlying function in ``functools.cache`` so repeated calls
    with the same arguments skip recomputation, then registers it as a
    CrewAI tool. Use this for pure functions whose return depends only on
    their arguments and never mutates state (the CWE / OWASP cheat-sheet
    lookups are the canonical case). Do not apply to tools that hit the
    network, read or write the workspace, or otherwise depend on time-
    varying state - those would silently return stale results.

    The cache lives on the Tool's ``.func`` attribute and can be cleared
    via ``tool_obj.func.cache_clear()``.
    """

    def decorator(fn: Callable[..., R]) -> Tool[..., R]:
        return tool(name)(functools.cache(fn))

    return decorator


@dataclass(frozen=True)
class SquadMember:
    """A single Bounty Squad member: identity, tools, and prose location.

    ``slug`` is derived from ``dir.name`` rather than stored separately - the
    two were always required to match (the dir name is the package path on
    disk) so the explicit field was just a place to introduce inconsistency.
    """

    dir: Path
    tools: list[Any] = field(default_factory=list)

    @property
    def slug(self) -> str:
        """Snake-case identifier (the on-disk package name)."""
        return self.dir.name

    def read(self, *parts: str) -> str:
        """Read a markdown file under this member's directory.

        read("role")                   -> <dir>/role.md
        read("triage", "description")  -> <dir>/triage/description.md
        """
        return (self.dir.joinpath(*parts).with_suffix(".md")).read_text(encoding="utf-8").strip()

    @property
    def skills_dir(self) -> Path:
        """Directory containing this member's specialist SKILL.md folders."""
        return self.dir / "skills"


def build_agent(member: SquadMember, llm: object, verbose: bool = False) -> Agent:
    """Construct a CrewAI Agent from the member's role/goal/backstory files.

    Member-specialist skills are passed as a directory path; crewai.skills
    discovers each ``SKILL.md`` subfolder and loads at METADATA disclosure
    (frontmatter only) so the agent sees a cheap menu of what is available
    and pays the body cost only on activation. Squad-wide skills are merged
    in at Crew construction (crew.py) so they are discovered once per run.
    """
    skills: list[Path] = [member.skills_dir] if member.skills_dir.is_dir() else []
    return Agent(
        role=member.read("role"),
        goal=member.read("goal"),
        backstory=member.read("backstory"),
        tools=member.tools,
        skills=skills,
        allow_delegation=False,
        llm=llm,
        verbose=verbose,
    )


def build_task(
    task_name: str,
    member: SquadMember,
    agent: Agent,
    context: list[Task] | None = None,
    human_input: bool = False,
) -> Task:
    """Create a Task from the member's task-specific prose files.

    Reads description and expected_output from ``<member.dir>/<task_name>/``.
    """
    return Task(
        description=member.read(task_name, "description"),
        expected_output=member.read(task_name, "expected_output"),
        agent=agent,
        context=context or [],
        human_input=human_input,
    )


__all__ = [
    "SquadMember",
    "build_agent",
    "build_task",
    "cached_tool",
    "read_attack_plan_tool",
    "read_run_filelist_tool",
    "read_run_file_tool",
]
