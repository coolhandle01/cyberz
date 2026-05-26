"""
crew.py - Assembles the Bounty Squad into a CrewAI Pipeline.

Call build_crew() to get a fully wired crew, then crew.kickoff() to run it.
"""

from __future__ import annotations

from pathlib import Path

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.memory import Memory
from crewai.tools import BaseTool

from config import config
from mcp_servers import ProvisionedMCPTools
from squad import SQUAD_SKILLS_DIR, SquadMember, build_agent
from squad.disclosure_coordinator import MEMBER as DISCLOSURE_COORDINATOR
from squad.osint_analyst import MEMBER as OSINT_ANALYST
from squad.penetration_tester import MEMBER as PENETRATION_TESTER
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER
from squad.technical_author import MEMBER as TECHNICAL_AUTHOR
from squad.vulnerability_researcher import MEMBER as VULNERABILITY_RESEARCHER
from tasks import build_tasks

_SQUAD: list[SquadMember] = [
    PROGRAMME_MANAGER,
    OSINT_ANALYST,
    PENETRATION_TESTER,
    VULNERABILITY_RESEARCHER,
    TECHNICAL_AUTHOR,
    DISCLOSURE_COORDINATOR,
]


def _build_llm() -> LLM:
    """Construct the squad LLM, honouring extended-thinking config.

    Per the cybersquad-agent-llm skill, model / temperature / max_tokens
    are passed explicitly. reasoning_effort is also passed explicitly when
    enabled so litellm forwards Anthropic extended thinking; when disabled
    we omit it so the default path is unchanged.
    """
    if config.llm.reasoning_enabled:
        return LLM(
            model=config.llm.model,
            temperature=config.llm.temperature,
            max_tokens=config.llm.max_tokens,
            reasoning_effort=config.llm.reasoning_effort,
        )
    return LLM(
        model=config.llm.model,
        temperature=config.llm.temperature,
        max_tokens=config.llm.max_tokens,
    )


def _build_long_term_memory() -> Memory | None:
    """Construct CrewAI long-term memory when enabled in config.

    Returns the Memory instance to pass to ``Crew(memory=...)``, or None
    when long-term memory is disabled (the default).
    """
    if not config.memory.long_term_enabled:
        return None
    storage_path = Path(config.memory.storage_path)
    storage_path.parent.mkdir(parents=True, exist_ok=True)
    return Memory(storage="lancedb", root_scope="/long_term")


def build_crew(
    verbose: bool | None = None,
    mcp_tools: ProvisionedMCPTools | None = None,
) -> Crew:
    """
    Instantiate agents and tasks, then wire them into a sequential Crew.

    Args:
        verbose: Override config.verbose for this run.
                 Defaults to the value in config.py.
        mcp_tools: The provisioned-MCP tool registry produced by
                 ``mcp_servers.provisioned_mcp_tools()``. ``None`` means
                 no MCP tools (the dry-run path, and the default for tests
                 that do not exercise MCP wiring). Per the
                 ``cybersquad-mcp`` skill, this is the only injection
                 point for MCP-sourced tools - agents cannot attach an
                 ``MCPServerAdapter`` at runtime. ``crew_wide`` reaches
                 every agent; ``penetration_tester`` reaches only the PT
                 (e.g. Playwright, #23).
    """
    be_verbose = verbose if verbose is not None else config.verbose
    crew_wide_mcp_tools = mcp_tools.crew_wide if mcp_tools is not None else ()
    # Per-member MCP routing: only the explicitly-listed role receives
    # the role-specific MCP bucket; every other agent's
    # ``member_specific_mcp_tools`` resolves to ``()`` via the lookup
    # below. Adding a new role-scoped MCP is: extend
    # ``ProvisionedMCPTools`` with a sibling field, add a line here, and
    # the rest of the squad stays unchanged.
    pt_mcp_tools = mcp_tools.penetration_tester if mcp_tools is not None else ()
    member_specific_by_slug: dict[str, tuple[BaseTool, ...]] = {
        PENETRATION_TESTER.slug: tuple(pt_mcp_tools),
    }

    llm: LLM = _build_llm()
    agents_by_slug: dict[str, Agent] = {
        m.slug: build_agent(
            m,
            llm,
            be_verbose,
            crew_wide_mcp_tools=crew_wide_mcp_tools,
            member_specific_mcp_tools=member_specific_by_slug.get(m.slug, ()),
        )
        for m in _SQUAD
    }
    # Crew(agents=...) wants list[BaseAgent]; list[Agent] is invariant
    # against it, so widen on construction.
    agents: list[BaseAgent] = list(agents_by_slug.values())
    tasks: list[Task] = build_tasks(agents_by_slug)
    memory: Memory | None = _build_long_term_memory()

    return Crew(
        agents=agents,
        tasks=tasks,
        process=Process.sequential,
        verbose=be_verbose,
        memory=memory,
        embedder=None,
        skills=[SQUAD_SKILLS_DIR] if SQUAD_SKILLS_DIR.is_dir() else None,
    )
