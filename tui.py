"""
tui.py - Textual TUI for the cybersquad pipeline.

Launch with: python main.py  (default) or python main.py --headless to skip the TUI.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Input, Label, RichLog, Static

logger = logging.getLogger(__name__)


class CybersquadTUI(App):
    # Textual loads this file automatically via the CSS_PATH class attribute.
    # TODO: feat(themes-and-fonts)
    CSS_PATH = "tui.tcss"

    def __init__(self, verbose: bool = False) -> None:
        super().__init__()
        self._verbose = verbose
        # (name_label, status_label) per task, in task order
        self._task_widgets: list[tuple[Label, Label]] = []
        from crew import build_crew, squad_phases

        self._crew = build_crew(verbose=verbose)
        self._phase_map = squad_phases()
        self._task_names = [t.agent.role for t in self._crew.tasks if t.agent is not None]

        self._crew.step_callback = _make_step_callback(self)

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("cybersquad", id="sidebar-title")

                seen_phases: set[str] = set()
                for name in self._task_names:
                    phase = self._phase_map.get(name, name)
                    if phase not in seen_phases:
                        seen_phases.add(phase)
                        yield Label(phase, classes="phase-heading")
                    name_lbl = Label(name, classes="task-name")
                    status_lbl = Label("Waiting", classes="task-status")
                    self._task_widgets.append((name_lbl, status_lbl))
                    yield name_lbl
                    yield status_lbl

                yield Static("", id="metrics")

            with Vertical(id="main"):
                with Vertical(id="messages-pane"):
                    yield Label("Agent Output", classes="pane-title")
                    yield RichLog(id="agent-log", highlight=True, markup=True, wrap=True)
                    yield Input(
                        placeholder="Human review input (not yet implemented)",
                        disabled=True,
                        id="human-input",
                    )
                with Vertical(id="logs-pane"):
                    yield Label("Pipeline Logs", id="logs-title", classes="pane-title")
                    yield RichLog(id="crew-log", highlight=True, markup=True)

    def on_mount(self) -> None:
        logging.getLogger().addHandler(_TUILogHandler(self))
        self._start_run()

    @work(thread=True)
    def _start_run(self) -> None:
        import runtime

        run_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
        runtime.run_id = run_id
        started_at = datetime.now(UTC)

        crew = self._crew

        for i, task in enumerate(crew.tasks):
            orig: Callable[..., None] | None = task.callback
            task.callback = _make_task_callback(self, i, orig)

        self.call_from_thread(self._set_task_running, 0)

        try:
            result = crew.kickoff()
            self.call_from_thread(self._on_done, result, run_id, started_at)
        except Exception as exc:
            self.call_from_thread(self._write_agent, f"[bold red]Pipeline error: {exc}[/bold red]")
            self.call_from_thread(self._write_crew, f"[bold red]Pipeline error: {exc}[/bold red]")

    def _set_task_running(self, idx: int) -> None:
        if idx < len(self._task_widgets):
            name_lbl, status_lbl = self._task_widgets[idx]
            name_lbl.add_class("running")
            status_lbl.add_class("running")
            status_lbl.update("Running...")

    def _set_task_done(self, idx: int) -> None:
        if idx < len(self._task_widgets):
            name_lbl, status_lbl = self._task_widgets[idx]
            name_lbl.remove_class("running")
            name_lbl.add_class("done")
            status_lbl.remove_class("running")
            status_lbl.add_class("done")
            status_lbl.update("Done")
        next_idx = idx + 1
        if next_idx < len(self._task_widgets):
            self._set_task_running(next_idx)

    def _on_done(self, result: object, run_id: str, started_at: datetime) -> None:
        from config import config
        from tools.metrics import build_run_metrics, save_metrics

        raw = getattr(result, "raw", str(result))
        self._write_agent("[bold green]Pipeline complete.[/bold green]")
        self._write_agent(raw[:2000] if len(raw) > 2000 else raw)

        usage = getattr(result, "token_usage", None)
        if usage is None:
            return

        try:
            metrics = build_run_metrics(
                run_id=run_id,
                started_at=started_at,
                llm_model=config.llm.model,
                input_tokens=getattr(usage, "prompt_tokens", 0),
                output_tokens=getattr(usage, "completion_tokens", 0),
            )
            save_metrics(metrics, config.reports_dir)
            self.query_one("#metrics", Static).update(
                f" Tokens:  {metrics.total_tokens:,}\n"
                f" Cost:    ${metrics.estimated_cost_usd:.4f}\n"
                f" Run:     {run_id}\n"
                f" Status:  done"
            )
        except OSError as exc:
            self._write_crew(f"[yellow]Metrics error: {exc}[/yellow]")
        except NoMatches:
            logger.debug("metrics widget not mounted")

    def _write_agent(self, msg: str) -> None:
        try:
            self.query_one("#agent-log", RichLog).write(msg)
        except NoMatches:
            logger.debug("agent-log widget not mounted, dropping message")

    def _write_crew(self, msg: str) -> None:
        try:
            self.query_one("#crew-log", RichLog).write(msg)
        except NoMatches:
            logger.debug("crew-log widget not mounted, dropping message")


def _make_task_callback(
    app: CybersquadTUI, idx: int, orig: Callable[..., None] | None
) -> Callable[..., None]:
    def _cb(output: object) -> None:
        app.call_from_thread(app._set_task_done, idx)
        if orig is not None:
            orig(output)

    return _cb


def _make_step_callback(app: CybersquadTUI) -> Callable[[object], None]:
    def _cb(step: object) -> None:
        try:
            from crewai.agents.parser import AgentAction, AgentFinish

            if isinstance(step, AgentAction):
                tool_call = f"[cyan]> {step.tool}[/cyan]({step.tool_input[:120]})"
                msg = f"[yellow]Thought:[/yellow] {step.thought}\n{tool_call}"
                if step.result:
                    msg += f"\n[dim]{step.result[:300]}[/dim]"
            elif isinstance(step, AgentFinish):
                out = str(step.output)
                msg = f"[bold green]Answer:[/bold green] {out[:500]}"
            else:
                msg = str(step)[:300]
            app.call_from_thread(app._write_agent, msg)
        except (AttributeError, ImportError, TypeError) as exc:
            logger.debug("step callback error: %s", exc)

    return _cb


class _TUILogHandler(logging.Handler):
    def __init__(self, app: CybersquadTUI) -> None:
        super().__init__()
        self._app = app

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        if record.name.startswith("cybersquad"):
            self._app.call_from_thread(self._app._write_agent, msg)
        else:
            self._app.call_from_thread(self._app._write_crew, msg)
