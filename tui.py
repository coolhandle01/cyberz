"""
tui.py - Cybersquad Textual TUI.

Wraps the generic CrewAIPipelineTUI with cybersquad-specific crew and task map.
Launch with: python main.py  (default) or python main.py --headless to skip the TUI.
"""

from __future__ import annotations

from tools.tui import CrewAIPipelineTUI


class CybersquadTUI(CrewAIPipelineTUI):
    CSS_PATH = "tui.tcss"

    def __init__(self, verbose: bool = False, dry_run: bool = False) -> None:
        from crew import build_crew, crew_tasks

        super().__init__(
            crew=build_crew(verbose=verbose),
            task_map=crew_tasks(),
            record_prefix="cybersquad",
            verbose=verbose,
            dry_run=dry_run,
        )
