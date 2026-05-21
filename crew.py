"""
crew.py - Assembles the Bounty Squad into a CrewAI Pipeline.

Call build_crew() to get a fully wired crew, then crew.kickoff() to run it.
"""

from __future__ import annotations

from pathlib import Path

from crewai import LLM, Crew, Process
from crewai.memory.memory import Memory

from config import config
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
    """Construct the squad LLM, honouring extended-thinking config."""
    kwargs: dict[str, object] = {
        "model": config.llm.model,
        "temperature": config.llm.temperature,
        "max_tokens": config.llm.max_tokens,
    }
    if config.llm.reasoning_enabled:
        kwargs["reasoning_effort"] = config.llm.reasoning_effort
    return LLM(**kwargs)


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


def build_crew(verbose: bool | None = None) -> Crew:
    """
    Instantiate agents and tasks, then wire them into a sequential Crew.

    Args:
        verbose: Override config.verbose for this run.
                 Defaults to the value in config.py.
    """
    be_verbose = verbose if verbose is not None else config.verbose

    llm = _build_llm()
    agents = {m.slug: build_agent(m, llm, be_verbose) for m in _SQUAD}
    tasks = build_tasks(agents)

    memory = _build_long_term_memory()

    return Crew(
        agents=list(agents.values()),
        tasks=tasks,
        process=Process.sequential,
        verbose=be_verbose,
        memory=memory,
        embedder=None,
        skills=[SQUAD_SKILLS_DIR] if SQUAD_SKILLS_DIR.is_dir() else None,
    )
