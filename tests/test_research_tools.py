"""
tests/test_research_tools.py - unit tests for tools/research_tools.py.

Coverage targets the two primitive layers the Vulnerability Researcher's
research pass depends on:

* Per-plan validation (validate_attack_plan) - the refusal branches that
  guard the LLM's output before it hits the workspace.
* Finalisation (finalise_research) - happy path writes attack_plan.json,
  refusal path raises with every error listed.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from models import AttackPlan, AttackPlanItem, Severity
from tools.research_tools import (
    AttackPlanFinalisationError,
    attack_plan_path,
    finalise_research,
    validate_attack_plan,
)

pytestmark = pytest.mark.unit


# Validation


class TestValidateAttackPlan:
    def test_clean_plan_passes(self, attack_plan):
        report = validate_attack_plan(attack_plan)
        assert report.ok is True
        assert report.issues == []

    def test_rejects_empty_items(self, attack_plan):
        plan = attack_plan.model_copy(update={"items": []})
        report = validate_attack_plan(plan)
        assert report.ok is False
        assert any(i.section == "items" for i in report.issues)

    def test_rejects_item_missing_probe(self, attack_plan, attack_plan_item):
        plan = attack_plan.model_copy(
            update={"items": [attack_plan_item.model_copy(update={"probe": "   "})]}
        )
        report = validate_attack_plan(plan)
        assert report.ok is False
        assert any(i.section == "items[1].probe" for i in report.issues)

    def test_rejects_item_missing_target(self, attack_plan, attack_plan_item):
        plan = attack_plan.model_copy(
            update={"items": [attack_plan_item.model_copy(update={"target": ""})]}
        )
        report = validate_attack_plan(plan)
        assert report.ok is False
        assert any(i.section == "items[1].target" for i in report.issues)

    def test_rejects_item_missing_rationale(self, attack_plan, attack_plan_item):
        plan = attack_plan.model_copy(
            update={"items": [attack_plan_item.model_copy(update={"rationale": ""})]}
        )
        report = validate_attack_plan(plan)
        assert report.ok is False
        assert any(i.section == "items[1].rationale" for i in report.issues)

    def test_rejects_item_with_empty_recon_evidence(self, attack_plan, attack_plan_item):
        plan = attack_plan.model_copy(
            update={"items": [attack_plan_item.model_copy(update={"recon_evidence": []})]}
        )
        report = validate_attack_plan(plan)
        assert report.ok is False
        assert any(i.section == "items[1].recon_evidence" for i in report.issues)

    def test_reports_per_item_index(self, attack_plan, attack_plan_item):
        # Two items, second one bad - issue should reference items[2]
        good = attack_plan_item
        bad = attack_plan_item.model_copy(update={"probe": ""})
        plan = attack_plan.model_copy(update={"items": [good, bad]})
        report = validate_attack_plan(plan)
        assert report.ok is False
        assert any(i.section == "items[2].probe" for i in report.issues)


# Finalisation


class TestFinaliseResearch:
    def test_writes_attack_plan_json_for_clean_plan(self, attack_plan, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.research_tools.runtime.run_dir", lambda: tmp_path)
        path = finalise_research(attack_plan)
        assert path == tmp_path / "attack_plan.json"
        loaded = AttackPlan.model_validate_json(path.read_text(encoding="utf-8"))
        assert loaded.programme_handle == attack_plan.programme_handle
        assert len(loaded.items) == 1
        assert loaded.items[0].probe == "CVE-2022-22965"

    def test_refuses_empty_plan(self, attack_plan, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.research_tools.runtime.run_dir", lambda: tmp_path)
        plan = attack_plan.model_copy(update={"items": []})
        with pytest.raises(AttackPlanFinalisationError, match="no items"):
            finalise_research(plan)
        assert not (tmp_path / "attack_plan.json").exists()

    def test_refuses_on_validation_errors(
        self, attack_plan, attack_plan_item, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("tools.research_tools.runtime.run_dir", lambda: tmp_path)
        plan = attack_plan.model_copy(
            update={"items": [attack_plan_item.model_copy(update={"recon_evidence": []})]}
        )
        with pytest.raises(AttackPlanFinalisationError, match="recon_evidence"):
            finalise_research(plan)

    def test_creates_run_dir_if_missing(self, attack_plan, tmp_path, monkeypatch):
        # run_dir() may point to a directory that does not yet exist (the
        # finaliser is the first thing to write into it). The finaliser must
        # mkdir parents.
        nested = tmp_path / "nested" / "run"
        monkeypatch.setattr("tools.research_tools.runtime.run_dir", lambda: nested)
        path = finalise_research(attack_plan)
        assert path.exists()
        assert path.parent == nested


# Path helper


class TestAttackPlanPath:
    def test_returns_attack_plan_json_under_run_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.research_tools.runtime.run_dir", lambda: tmp_path)
        assert attack_plan_path() == tmp_path / "attack_plan.json"


# Round-trip


class TestAttackPlanModel:
    def test_serialises_round_trip(self, attack_plan):
        again = AttackPlan.model_validate_json(attack_plan.model_dump_json())
        assert again.programme_handle == attack_plan.programme_handle
        assert again.items[0].expected_ceiling == Severity.CRITICAL

    def test_attack_plan_item_accepts_all_required_fields(self):
        item = AttackPlanItem(
            probe="reflected XSS",
            target="https://admin.example.com/?q=test",
            expected_ceiling=Severity.MEDIUM,
            rationale="parameterised endpoint reflects q into response without escaping",
            recon_evidence=["admin.example.com hosts a Vue 2 SPA"],
        )
        assert item.expected_ceiling == Severity.MEDIUM
        assert datetime.now(UTC)  # ensures the import is reachable in tests
