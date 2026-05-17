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
from crewai.tools import tool

from tools import workspace


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
) -> Task:
    """Create a Task from the member's description/expected_output files."""
    return Task(
        description=member.read("description"),
        expected_output=member.read("expected_output"),
        agent=agent,
        context=context or [],
        human_input=human_input,
    )


# Shared workspace tools - added to every downstream squad member so the
# squad can use the per-run directory as a common scratch space. Read-only:
# writes remain typed via each agent's domain tool (recon_tool,
# save_findings_tool, triage_tool, create_report_tool).


@tool("List Run Files")
def read_run_filelist_tool() -> list[dict]:
    """List the artefacts written to the current run directory by the squad
    so far, each with its name and byte size. Use this to discover what an
    upstream teammate has produced before deciding which file to sample with
    Read Run File."""
    return workspace.list_run_files()


@tool("Read Run File")
def read_run_file_tool(
    name: str,
    offset: int = 0,
    limit_bytes: int = workspace.DEFAULT_READ_BYTES,
) -> dict:
    """Read a byte slice of a file in the current run directory. ``name`` is
    a relative path (e.g. "recon.json"); paths outside the run directory are
    refused. Returns {name, offset, end, size_bytes, truncated, content}.
    Default limit_bytes is small (8 KiB) so you can sample large files
    cheaply - re-call with a larger offset to paginate."""
    return workspace.read_run_file(name, offset=offset, limit_bytes=limit_bytes)
