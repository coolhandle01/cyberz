"""tests/test_approval.py — unit tests for the approval gate and callback."""

from __future__ import annotations

import pytest

from tools.approval import (
    ApprovalDecision,
    ApprovalGate,
    AutoApprovalGate,
    CliApprovalGate,
    PipelineHalted,
    configure_gate,
    get_gate,
    make_approval_callback,
    set_gate,
)

pytestmark = pytest.mark.unit


class TestAutoApprovalGate:
    def test_always_approves(self) -> None:
        gate = AutoApprovalGate()
        decision = gate.request("test-checkpoint", "some summary")
        assert decision.approved is True

    def test_includes_checkpoint_name_in_reason(self) -> None:
        gate = AutoApprovalGate()
        decision = gate.request("scan-approval", "summary")
        assert "scan-approval" in decision.reason


class TestCliApprovalGate:
    def test_approves_on_y(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()
        responses = iter(["y", "looks good"])
        monkeypatch.setattr("builtins.input", lambda *_: next(responses))
        decision = gate.request("test", "summary")
        assert decision.approved is True
        assert "looks good" in decision.reason

    def test_approves_with_empty_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()
        responses = iter(["y", ""])
        monkeypatch.setattr("builtins.input", lambda *_: next(responses))
        decision = gate.request("test", "summary")
        assert decision.approved is True
        assert decision.reason  # falls back to default text

    def test_rejects_on_n(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()
        responses = iter(["n", "too risky"])
        monkeypatch.setattr("builtins.input", lambda *_: next(responses))
        decision = gate.request("test", "summary")
        assert decision.approved is False
        assert "too risky" in decision.reason

    def test_rejects_on_eof(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()

        def _raise(*_: object) -> str:
            raise EOFError

        monkeypatch.setattr("builtins.input", _raise)
        decision = gate.request("test", "summary")
        assert decision.approved is False


class TestGateSingleton:
    def test_configure_auto_sets_auto_gate(self) -> None:
        configure_gate("auto")
        assert isinstance(get_gate(), AutoApprovalGate)

    def test_configure_interactive_sets_cli_gate(self) -> None:
        configure_gate("interactive")
        assert isinstance(get_gate(), CliApprovalGate)

    def test_set_gate_replaces_instance(self) -> None:
        custom = AutoApprovalGate()
        set_gate(custom)
        assert get_gate() is custom


class TestMakeApprovalCallback:
    def test_non_checkpoint_tasks_pass_silently(self) -> None:
        gate = AutoApprovalGate()
        cb = make_approval_callback(gate, {2: "check"})
        cb("output0")  # task 0 — no checkpoint
        cb("output1")  # task 1 — no checkpoint
        # no exception raised

    def test_triggers_gate_at_checkpoint_index(self) -> None:
        hit: list[str] = []

        class _RecordingGate(AutoApprovalGate):
            def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
                hit.append(checkpoint)
                return super().request(checkpoint, summary)

        cb = make_approval_callback(_RecordingGate(), {1: "scan-approval"})
        cb("task0")
        cb("task1")  # triggers checkpoint
        assert hit == ["scan-approval"]

    def test_raises_pipeline_halted_on_rejection(self) -> None:
        class _RejectGate(ApprovalGate):
            def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
                return ApprovalDecision(approved=False, reason="denied")

        cb = make_approval_callback(_RejectGate(), {0: "scan-approval"})
        with pytest.raises(PipelineHalted, match="scan-approval"):
            cb("output")

    def test_passes_after_rejection_position_if_not_checkpoint(self) -> None:
        gate = AutoApprovalGate()
        cb = make_approval_callback(gate, {1: "check"})
        cb("task0")
        # task 1 passes via auto gate
        cb("task1")
        # task 2 — not a checkpoint, should not raise
        cb("task2")

    def test_multiple_checkpoints(self) -> None:
        hit: list[str] = []

        class _RecordingGate(AutoApprovalGate):
            def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
                hit.append(checkpoint)
                return super().request(checkpoint, summary)

        cb = make_approval_callback(
            _RecordingGate(), {0: "scan-approval", 4: "submission-approval"}
        )
        for i in range(6):
            cb(f"task{i}")
        assert hit == ["scan-approval", "submission-approval"]
