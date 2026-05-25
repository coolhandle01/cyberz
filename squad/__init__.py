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
import types
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Union, cast, get_args, get_origin, runtime_checkable

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
        _assert_scope_safety_complete(args_schema)
        target = _apply_scope_filter(fn, args_schema)
        wrapped = tool(name)(target)
        wrapped.args_schema = args_schema
        return cast(SquadTool, wrapped)

    return decorator


def _scope_filter_for_field(annotation: object) -> Callable[..., object] | None:
    """Pick the scope filter for an args_schema field's annotation.

    Returns ``filter_in_scope`` for ``list[Hostname]``,
    ``filter_endpoints_in_scope`` for ``list[Endpoint]``, the same
    filters for their ``| None`` / ``Optional[...]`` variants, or
    ``None`` for any other annotation.

    Deliberately narrow to list shapes: the auto-detection treats the
    typed list as the canonical "agent's attack-target pick", which is
    where scope-safety bites. Single-value ``Hostname`` / ``Endpoint``
    fields are slicer-filter parameters operating on already-scope-
    filtered workspace artefacts (e.g. ``host: Hostname | None`` on
    ``Recon Open Ports``); applying the scope guard at that layer
    would re-filter data that ``Finalise Recon`` already filtered.
    The loud-fail in ``_assert_scope_safety_complete`` catches any
    Hostname / Endpoint appearance in shapes this function does not
    cover, so the slicer-filter carve-out has to be expressed by the
    field type itself - use ``list[Hostname]`` (zero-or-one or many)
    if you want the wrapper-level scope guard.

    Lazy imports break the import cycle: ``models`` and ``tools``
    import nothing from ``squad``; we resolve them at decoration time.
    """
    from models import Endpoint, Hostname
    from tools.recon.scope import filter_endpoints_in_scope, filter_in_scope

    # Unwrap Optional[list[X]] / list[X] | None to the inner list shape -
    # an optional list-of-targets is the same scope-safety contract as
    # the bare list, just with None meaning "no targets supplied".
    if get_origin(annotation) in (Union, types.UnionType):
        non_none = [a for a in get_args(annotation) if a is not type(None)]
        if len(non_none) == 1:
            return _scope_filter_for_field(non_none[0])
        return None

    if get_origin(annotation) is list:
        inner_args = get_args(annotation)
        if inner_args:
            inner = inner_args[0]
            if inner is Hostname:
                return filter_in_scope
            if inner is Endpoint:
                return filter_endpoints_in_scope

    return None


def _walk_for_targets(
    annotation: object, path: tuple[object, ...]
) -> list[tuple[object, tuple[object, ...]]]:
    """Recurse through an annotation, returning every ``Hostname`` or
    ``Endpoint`` occurrence with the container chain that wraps it.

    The chain is the ``get_origin`` of each container the recursion
    descended through (``list``, ``dict``, ``set``, ``tuple``,
    ``types.UnionType``, ``typing.Union``, or a ``BaseModel`` subclass
    for nested models). Top-level appearance has an empty chain.
    """
    from models import Endpoint, Hostname

    if annotation is Hostname or annotation is Endpoint:
        return [(annotation, path)]

    origin = get_origin(annotation)
    if origin is None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            found: list[tuple[object, tuple[object, ...]]] = []
            for field_info in annotation.model_fields.values():
                found.extend(_walk_for_targets(field_info.annotation, (*path, annotation)))
            return found
        return []

    found = []
    for arg in get_args(annotation):
        if arg is type(None):
            continue
        found.extend(_walk_for_targets(arg, (*path, origin)))
    return found


def _assert_scope_safety_complete(args_schema: type[BaseModel]) -> None:
    """Refuse to wrap ``args_schema`` if a typed-target primitive hides
    inside a container the auto-detection does not cover.

    Cross-check: for every field, walk the annotation tree for
    ``Hostname`` / ``Endpoint`` occurrences. If any occurrence is in a
    shape ``_scope_filter_for_field`` covers (a ``list[X]`` or
    ``Optional[list[X]]``), or is a bare single-value ``Hostname`` /
    ``Endpoint`` (the slicer-filter carve-out documented on
    ``_scope_filter_for_field``), allow it through. Anything else
    (``dict[Hostname, ...]``, ``set[Hostname]``, a nested model with
    a ``Hostname`` field, ...) trips this guard with ``TypeError`` at
    decoration time so a new unsupported shape fails the build the
    moment it lands rather than the moment an agent triggers it.
    """
    from models import Endpoint, Hostname

    # Shapes the loud-fail considers handled. ``()`` = the field IS
    # the target (single ``Hostname`` / ``Endpoint`` slicer-filter);
    # ``(list,)`` = ``list[Hostname]`` / ``list[Endpoint]``;
    # union-prefixed variants cover ``| None`` / ``Optional[...]``.
    HANDLED_PATHS: tuple[tuple[object, ...], ...] = (
        (),
        (list,),
        (Union,),
        (types.UnionType,),
        (Union, list),
        (types.UnionType, list),
    )

    for field_name, field_info in args_schema.model_fields.items():
        for target, path in _walk_for_targets(field_info.annotation, ()):
            if path in HANDLED_PATHS:
                continue
            target_name = (
                "Hostname"
                if target is Hostname
                else "Endpoint"
                if target is Endpoint
                else repr(target)
            )
            chain = (
                " -> ".join(c.__name__ if hasattr(c, "__name__") else repr(c) for c in path)
                or "<direct>"
            )
            raise TypeError(
                f"{args_schema.__name__}.{field_name}: {target_name} "
                f"appears inside {chain} - the auto-detected scope "
                f"filter does not cover this container shape. Either "
                f"refactor the field to {target_name} / "
                f"list[{target_name}] / Optional thereof, or extend "
                f"_scope_filter_for_field in squad/__init__.py with "
                f"explicit handling for the new shape."
            )


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
