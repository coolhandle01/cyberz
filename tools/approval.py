"""tools/approval.py — Pluggable approval gate for pipeline checkpoints.

Swap the active gate in tests via set_gate() to control approval decisions
without touching stdin. Set APPROVAL_MODE=auto for CI / automated pipelines.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass


class PipelineHalted(RuntimeError):
    """Raised when an approval checkpoint rejects continuation."""


@dataclass
class ApprovalDecision:
    approved: bool
    reason: str


class ApprovalGate(ABC):
    @abstractmethod
    def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
        """Block until the operator approves or rejects this checkpoint."""


class CliApprovalGate(ApprovalGate):
    """Interactive gate: rich-formatted panel + stdin prompts."""

    def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
        from rich.console import Console
        from rich.panel import Panel
        from rich.prompt import Confirm, Prompt
        from rich.text import Text

        console = Console()
        console.print()
        console.print(
            Panel(
                Text(summary[:1000]),
                title=f"[bold yellow]  {checkpoint}  [/bold yellow]",
                subtitle="[dim]approve to continue · reject to halt[/dim]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()
        try:
            approved = Confirm.ask("[bold]Approve and continue?[/bold]", default=False)
        except EOFError:
            return ApprovalDecision(approved=False, reason="Non-interactive stdin — rejected")
        if approved:
            reason = Prompt.ask("Reason [dim](optional — Enter to skip)[/dim]", default="")
            return ApprovalDecision(approved=True, reason=reason or "Approved by operator")
        reason = Prompt.ask("Rejection reason")
        return ApprovalDecision(approved=False, reason=reason or "Rejected by operator")


class AutoApprovalGate(ApprovalGate):
    """Non-blocking gate: always approves. Use for CI / automated pipelines."""

    def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
        return ApprovalDecision(approved=True, reason=f"auto-approved ({checkpoint})")


_gate: ApprovalGate


def configure_gate(mode: str) -> None:
    """Select gate implementation by mode name ('interactive' or 'auto')."""
    global _gate
    _gate = AutoApprovalGate() if mode == "auto" else CliApprovalGate()


def set_gate(gate: ApprovalGate) -> None:
    """Override the active gate — for use in tests."""
    global _gate
    _gate = gate


def get_gate() -> ApprovalGate:
    return _gate


def make_approval_callback(
    gate: ApprovalGate,
    checkpoints: dict[int, str],
) -> Callable[[object], None]:
    """Return a task_callback that triggers approval at specified task indices.

    Each call to the returned function advances an internal counter; when the
    counter matches a key in *checkpoints*, the gate is consulted. Raises
    PipelineHalted if the operator rejects.
    """
    completed = [0]

    def _callback(output: object) -> None:  # noqa: ANN401
        idx = completed[0]
        completed[0] += 1
        checkpoint = checkpoints.get(idx)
        if checkpoint is None:
            return
        decision = gate.request(checkpoint, str(output)[:800])
        if not decision.approved:
            raise PipelineHalted(f"Pipeline halted at '{checkpoint}': {decision.reason}")

    return _callback


# Initialise from env at module load
configure_gate(os.getenv("APPROVAL_MODE", "interactive"))
