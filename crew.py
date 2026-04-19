"""
crew.py — Assembles the Bounty Squad into a CrewAI Pipeline.

Call build_crew() to get a fully wired crew, then crew.kickoff() to run it.
"""

from __future__ import annotations

from crewai import Crew, Process

from agents import build_agents
from config import config
from tasks import CHECKPOINT_INDICES, build_tasks
from tools.approval import configure_gate, get_gate, make_approval_callback


def build_crew(verbose: bool | None = None) -> Crew:
    """
    Instantiate agents and tasks, then wire them into a sequential Crew.

    Args:
        verbose: Override config.verbose for this run.
                 Defaults to the value in config.py.
    """
    be_verbose = verbose if verbose is not None else config.verbose

    configure_gate(config.approval_mode)

    agents = build_agents(verbose=be_verbose)
    tasks = build_tasks(agents)

    approval_callback = make_approval_callback(get_gate(), CHECKPOINT_INDICES)

    return Crew(
        agents=list(agents.values()),
        tasks=tasks,
        process=Process.sequential,
        verbose=be_verbose,
        memory=False,
        embedder=None,
        task_callback=approval_callback,
    )
