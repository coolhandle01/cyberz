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
    """Interactive gate: prints context and reads y/N from stdin."""

    def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
        print(f"\n{'=' * 60}")
        print(f"  CHECKPOINT: {checkpoint}")
        print("=" * 60)
        print(summary[:1000])
        print()
        try:
            answer = input("Approve and continue? [y/N] ").strip().lower()
        except EOFError:
            return ApprovalDecision(approved=False, reason="Non-interactive stdin — rejected")
        if answer == "y":
            reason = input("Reason (optional): ").strip()
            return ApprovalDecision(approved=True, reason=reason or "Approved by operator")
        reason = input("Rejection reason: ").strip()
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
