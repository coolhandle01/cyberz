"""
tests/tools/test_research_tools.py - unit tests for tools/research_tools.py.

Coverage targets the two primitive layers the Vulnerability Researcher's
research pass depends on:

* Per-plan validation (validate_attack_graph) - the refusal branches that
  guard the LLM's output before it hits the workspace.
* Finalisation (finalise_research) - happy path writes attack_graph.json,
  refusal path raises with every error listed.
"""

from __future__ import annotations

import pytest

from models.attack import AttackGraph, AttackGraphFinalisationError
from tools.research_tools import (
    attack_graph_path,
    finalise_research,
    load_attack_graph,
    validate_attack_graph,
)

pytestmark = pytest.mark.unit


# Validation


class TestValidateAttackGraph:
    def test_clean_plan_passes(self, attack_graph):
        report = validate_attack_graph(attack_graph)
        assert report.ok is True
        assert report.issues == []

    def test_rejects_empty_items(self, attack_graph):
        plan = attack_graph.model_copy(update={"nodes": []})
        report = validate_attack_graph(plan)
        assert report.ok is False
        assert any(i.section == "nodes" for i in report.issues)

    def test_rejects_item_missing_probe(self, attack_graph, attack_graph_node):
        plan = attack_graph.model_copy(
            update={"nodes": [attack_graph_node.model_copy(update={"probe": "   "})]}
        )
        report = validate_attack_graph(plan)
        assert report.ok is False
        assert any(i.section == "nodes[1].probe" for i in report.issues)

    def test_rejects_item_missing_target(self, attack_graph, attack_graph_node):
        plan = attack_graph.model_copy(
            update={"nodes": [attack_graph_node.model_copy(update={"target": ""})]}
        )
        report = validate_attack_graph(plan)
        assert report.ok is False
        assert any(i.section == "nodes[1].target" for i in report.issues)

    def test_rejects_item_missing_rationale(self, attack_graph, attack_graph_node):
        plan = attack_graph.model_copy(
            update={"nodes": [attack_graph_node.model_copy(update={"rationale": ""})]}
        )
        report = validate_attack_graph(plan)
        assert report.ok is False
        assert any(i.section == "nodes[1].rationale" for i in report.issues)

    def test_rejects_item_with_empty_recon_evidence(self, attack_graph, attack_graph_node):
        plan = attack_graph.model_copy(
            update={"nodes": [attack_graph_node.model_copy(update={"recon_evidence": []})]}
        )
        report = validate_attack_graph(plan)
        assert report.ok is False
        assert any(i.section == "nodes[1].recon_evidence" for i in report.issues)

    def test_reports_per_item_index(self, attack_graph, attack_graph_node):
        # Two items, second one bad - issue should reference items[2]
        good = attack_graph_node
        bad = attack_graph_node.model_copy(update={"probe": ""})
        plan = attack_graph.model_copy(update={"nodes": [good, bad]})
        report = validate_attack_graph(plan)
        assert report.ok is False
        assert any(i.section == "nodes[2].probe" for i in report.issues)


# Finalisation


class TestFinaliseResearch:
    def test_writes_attack_graph_json_for_clean_plan(self, attack_graph, run_dir):
        path = finalise_research(attack_graph)
        assert path == run_dir / "attack_graph.json"
        loaded = AttackGraph.model_validate_json(path.read_text(encoding="utf-8"))
        assert loaded.programme_handle == attack_graph.programme_handle
        assert len(loaded.nodes) == 1
        assert loaded.nodes[0].probe == "CVE-2022-22965"

    def test_refuses_empty_plan(self, attack_graph, run_dir):
        plan = attack_graph.model_copy(update={"nodes": []})
        with pytest.raises(AttackGraphFinalisationError, match="no nodes"):
            finalise_research(plan)
        assert not (run_dir / "attack_graph.json").exists()

    def test_refuses_on_validation_errors(self, attack_graph, attack_graph_node, run_dir):
        plan = attack_graph.model_copy(
            update={"nodes": [attack_graph_node.model_copy(update={"recon_evidence": []})]}
        )
        with pytest.raises(AttackGraphFinalisationError, match="recon_evidence"):
            finalise_research(plan)

    def test_creates_run_dir_if_missing(self, attack_graph, tmp_path, monkeypatch):
        # run_dir() may point to a directory that does not yet exist (the
        # finaliser is the first thing to write into it). The finaliser must
        # mkdir parents. The shared ``run_dir`` fixture always returns an
        # existing path, so this test stays on the explicit monkeypatch.
        nested = tmp_path / "nested" / "run"
        monkeypatch.setattr("runtime.run_dir", lambda: nested)
        path = finalise_research(attack_graph)
        assert path.exists()
        assert path.parent == nested


# Path helper


class TestAttackGraphPath:
    def test_returns_attack_graph_json_under_run_dir(self, run_dir):
        assert attack_graph_path() == run_dir / "attack_graph.json"


# Loading


class TestLoadAttackGraph:
    def test_round_trips_a_persisted_plan(self, attack_graph, run_dir):
        path = finalise_research(attack_graph)
        loaded = load_attack_graph(path)
        assert isinstance(loaded, AttackGraph)
        assert loaded.programme_handle == attack_graph.programme_handle
        assert len(loaded.nodes) == len(attack_graph.nodes)
        assert loaded.nodes[0].probe == attack_graph.nodes[0].probe

    def test_raises_when_file_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="attack plan not found"):
            load_attack_graph(tmp_path / "attack_graph.json")
