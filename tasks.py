"""
tasks.py — Task definitions for the Bounty Squad pipeline.

Each task maps to one agent and produces an output that feeds the next.
Context chaining (context=[prev_task]) gives downstream agents access
to upstream results without manual passing.

Task descriptions and expected outputs live in prompts/*.md.
Each file is split on a '---' line: description above, expected output below.
"""

from __future__ import annotations

from pathlib import Path

from crewai import Task

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load(filename: str) -> tuple[str, str]:
    """Return (description, expected_output) from a prompts/*.md file."""
    text = (_PROMPTS_DIR / filename).read_text(encoding="utf-8")
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:  # noqa: PLR2004
        raise ValueError(f"prompts/{filename} must contain a '---' separator")
    return parts[0].strip(), parts[1].strip()


def build_tasks(agents: dict) -> list[Task]:
    """
    Build and return the ordered list of pipeline tasks.
    Each task is wired to its agent and declares context dependencies.
    """

    desc, out = _load("programme-manager.md")
    task_select_programme = Task(
        description=desc,
        expected_output=out,
        agent=agents["programme_manager"],
    )

    desc, out = _load("osint-analyst.md")
    task_recon = Task(
        description=desc,
        expected_output=out,
        agent=agents["osint_analyst"],
        context=[task_select_programme],
    )

    desc, out = _load("penetration-tester.md")
    task_pentest = Task(
        description=desc,
        expected_output=out,
        agent=agents["penetration_tester"],
        context=[task_recon],
    )

    desc, out = _load("vulnerability-researcher.md")
    task_triage = Task(
        description=desc,
        expected_output=out,
        agent=agents["vulnerability_researcher"],
        context=[task_pentest, task_select_programme],
    )

    desc, out = _load("technical-author.md")
    task_write_report = Task(
        description=desc,
        expected_output=out,
        agent=agents["technical_author"],
        context=[task_triage, task_select_programme],
    )

    desc, out = _load("disclosure-coordinator.md")
    task_submit = Task(
        description=desc,
        expected_output=out,
        agent=agents["disclosure_coordinator"],
        context=[task_write_report],
    )

    return [
        task_select_programme,
        task_recon,
        task_pentest,
        task_triage,
        task_write_report,
        task_submit,
    ]
