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
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast, get_args, get_origin, runtime_checkable

from crewai import Agent, Task
from crewai.tools import tool
from pydantic import BaseModel

SQUAD_SKILLS_DIR = Path(__file__).parent / "skills"


@runtime_checkable
class SquadTool(Protocol):
    """The shape every ``MEMBER.tools`` entry conforms to.

    Project-specific name (rather than e.g. ``CrewAITool``) so the squad's
    public surface stays decoupled from the underlying agent framework:
    today this Protocol matches the runtime shape ``crewai.tools.tool``
    produces, but the registry is "the tools the bounty squad uses", not
    "the tools CrewAI happens to produce". The Protocol stays a real
    abstraction: ``SquadMember.tools: list[SquadTool]`` and the specialist
    Protocols (``_PentestTool``, ``_ResearchBriefTool``) inherit from it
    so the cross-agent contract test in
    ``tests/test_squad_tool_contracts.py`` has a typed handle to walk.

    The decorators in use - the bare ``@tool``, ``@cyber_tool``,
    ``@pentest_tool``, ``@research_brief_tool`` - all produce CrewAI
    ``Tool`` instances that carry ``name``, ``description``, ``func``,
    and ``args_schema``. ``args_schema`` is part of the Protocol because
    every cybersquad wrapper carries an explicit Pydantic schema; the
    contract tests in ``tests/squad/<agent>/test_args_schemas.py`` walk
    it on every registered tool. ``func`` is declared via ``@property``
    (rather than as a plain class attribute) so the Protocol is
    satisfied by CrewAI's ``Tool`` model - its ``func`` field is typed
    ``Callable[P, R | Awaitable[R]]`` for the concrete wrapped function
    and would otherwise fail Protocol variance against
    ``Callable[..., object]``.
    """

    name: str
    description: str
    args_schema: type[BaseModel]

    @property
    def func(self) -> Callable[..., object]: ...


def cyber_tool(
    name: str,
    *,
    args_schema: type[BaseModel],
) -> Callable[[Callable[..., object]], SquadTool]:
    """The blessed cybersquad replacement for bare ``@crewai.tools.tool``.

    Equivalent to ``tool(name)`` except that ``args_schema`` is keyword-
    required: the explicit Pydantic class overrides the signature-inferred
    schema CrewAI would otherwise build. Every cybersquad ``@tool``
    wrapper carries one - the inferred path is not reachable anywhere
    in the squad. Per-field ``Field(description=...)`` is the
    targeting guidance the agent reads when picking the tool.

    ``pentest_tool`` and ``research_brief_tool`` compose on top of this
    helper: they call ``cyber_tool`` underneath and then layer their own
    docstring-injection (OWASP categories for the pentest wrapper, brief
    formatting for the research one). Anything that does not need a
    specialist wrapper uses ``@cyber_tool`` directly.

    Scope safety is built in. Any ``args_schema`` field typed as a
    cybersquad target primitive - ``Hostname`` / ``list[Hostname]`` or
    ``Endpoint`` / ``list[Endpoint]`` - is automatically scope-filtered
    against ``<run_dir>/programme.json`` before the body sees it. The
    typed parameter IS the opt-in signal; there is no per-tool
    parameter to forget. Fields typed as anything else (``str``,
    StrEnum filters, recon paths, ...) pass through unchanged.
    """

    def decorator(fn: Callable[..., object]) -> SquadTool:
        target = _apply_scope_filter(fn, args_schema)
        wrapped = tool(name)(target)
        wrapped.args_schema = args_schema
        return cast(SquadTool, wrapped)

    return decorator


def _scope_filter_for_field(annotation: object) -> Callable[..., object] | None:
    """Pick the scope filter for an args_schema field's annotation.

    Returns ``filter_in_scope`` for ``Hostname`` / ``list[Hostname]``,
    ``filter_endpoints_in_scope`` for ``Endpoint`` / ``list[Endpoint]``,
    or ``None`` for any other annotation. The cybersquad target
    primitives are identity-comparable (``Hostname`` is a single
    ``Annotated[...]`` alias imported by every consumer) so ``is``
    checks work without unwrapping the ``Annotated`` machinery.

    Lazy imports break the import cycle: ``models`` and ``tools``
    import nothing from ``squad``; we resolve them at decoration time.
    """
    from models import Endpoint, Hostname
    from tools.recon.scope import filter_endpoints_in_scope, filter_in_scope

    if annotation is Hostname:
        return filter_in_scope
    if annotation is Endpoint:
        return filter_endpoints_in_scope

    if get_origin(annotation) is list:
        inner_args = get_args(annotation)
        if inner_args:
            inner = inner_args[0]
            if inner is Hostname:
                return filter_in_scope
            if inner is Endpoint:
                return filter_endpoints_in_scope

    return None


def _apply_scope_filter(
    fn: Callable[..., object], args_schema: type[BaseModel]
) -> Callable[..., object]:
    """Wrap ``fn`` so every typed-target field is scope-filtered first.

    Auto-detects ``Hostname`` / ``list[Hostname]`` / ``Endpoint`` /
    ``list[Endpoint]`` fields on ``args_schema`` and wraps ``fn`` so
    each runs through the matching filter
    (``filter_in_scope`` / ``filter_endpoints_in_scope``) against
    ``current_programme()`` before the body sees it. Fields with any
    other annotation pass through unchanged. The wrapper returns ``fn``
    unchanged when ``args_schema`` has no typed-target fields, so the
    Programme lookup is paid for only when something actually needs
    filtering.

    ``inspect.signature.bind_partial`` resolves the named field whether
    the caller passes it positionally or by keyword - CrewAI's runtime
    path uses kwargs (built from ``args_schema``), but direct
    ``tool.func(value)`` test invocations pass positionally and the
    wrapper has to cover both shapes.
    """
    target_fields: dict[str, Callable[..., object]] = {}
    for field_name, field_info in args_schema.model_fields.items():
        filter_fn = _scope_filter_for_field(field_info.annotation)
        if filter_fn is not None:
            target_fields[field_name] = filter_fn

    if not target_fields:
        return fn

    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def guarded(*args: object, **kwargs: object) -> object:
        bound = sig.bind_partial(*args, **kwargs)
        programme = None
        for field_name, filter_fn in target_fields.items():
            values = bound.arguments.get(field_name)
            if values:
                if programme is None:
                    from squad.workspace_tools import current_programme

                    programme = current_programme()
                bound.arguments[field_name] = filter_fn(values, programme)
        return fn(*bound.args, **bound.kwargs)

    return guarded


# Shared workspace wrappers are imported after ``cyber_tool`` is defined,
# because ``squad/workspace_tools.py`` decorates with ``@cyber_tool`` and
# would hit a circular import if pulled in alongside the top-of-module
# imports.
from squad.workspace_tools import (  # noqa: E402
    read_attack_plan_tool,
    read_run_file_tool,
    read_run_filelist_tool,
)


@dataclass(frozen=True)
class SquadMember:
    """A single Bounty Squad member: identity, tools, and prose location.

    ``slug`` is derived from ``dir.name`` rather than stored separately - the
    two were always required to match (the dir name is the package path on
    disk) so the explicit field was just a place to introduce inconsistency.
    """

    dir: Path
    tools: list[SquadTool] = field(default_factory=list)

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
    "SquadTool",
    "SquadMember",
    "build_agent",
    "build_task",
    "read_attack_plan_tool",
    "read_run_filelist_tool",
    "read_run_file_tool",
    "cyber_tool",
]
