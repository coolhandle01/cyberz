"""
tools/research_tools.py - Attack-plan authoring primitives for the
Vulnerability Researcher.

The VR's research pass turns the OSINT Analyst's recon brief into a typed
attack plan: a list of probe-target hypotheses with expected severity
ceilings and the recon signals that justified each one. The agent does the
thinking; this module provides the supporting primitives:

* ``AttackGraph`` / ``AttackGraphItem`` (from ``models.attack``) - the
  artefact the agent composes.
* ``validate_attack_graph(plan)`` - quality gate. Returns the issue list
  (``AttackGraphValidationReport`` from ``models.attack``). Hard errors
  block ``finalise_research``.
* ``finalise_research(plan)`` - validate, persist ``attack_graph.json`` for
  the Penetration Tester and re-read at triage time. Raises
  ``AttackGraphFinalisationError`` (from ``models.attack``) on hard errors.
* ``load_attack_graph(path)`` - reverse direction. Deserialise
  ``attack_graph.json`` into a typed ``AttackGraph`` so downstream agents
  (PT, VR at triage) consume a Pydantic model rather than a raw blob.

Mirrors the ``finalise_recon`` / ``finalise_triage`` pattern so the VR's
research artefact is a first-class workspace file alongside ``recon.json``
and ``verified.json``.
"""

from __future__ import annotations

from pathlib import Path

import runtime
from models.attack import (
    AttackGraph,
    AttackGraphFinalisationError,
    AttackGraphValidationIssue,
    AttackGraphValidationReport,
)

_ATTACK_GRAPH_FILENAME = "attack_graph.json"


# Validation


def validate_attack_graph(plan: AttackGraph) -> AttackGraphValidationReport:
    """Apply quality heuristics to an AttackGraph. Returns the issue list.

    Hard errors:
      * empty ``items`` (no plan is not a plan)
      * any item missing one of probe / target / rationale (empty after strip)
      * any item whose ``recon_evidence`` is empty - the plan is supposed
        to be grounded in the OSINT Analyst's signals; an unevidenced
        hypothesis is the agent skipping the research pass.
    """
    issues: list[AttackGraphValidationIssue] = []

    if not plan.items:
        issues.append(
            AttackGraphValidationIssue(
                section="items",
                severity="error",
                message=(
                    "attack plan has no items; produce at least one "
                    "probe-target hypothesis or explain in the briefing "
                    "why no probes are warranted"
                ),
            )
        )

    for n, item in enumerate(plan.items, 1):
        if not item.probe.strip():
            issues.append(
                AttackGraphValidationIssue(
                    section=f"items[{n}].probe",
                    severity="error",
                    message="probe is required (CVE id or vulnerability-class name)",
                )
            )
        if not item.target.strip():
            issues.append(
                AttackGraphValidationIssue(
                    section=f"items[{n}].target",
                    severity="error",
                    message="target is required (hostname or URL drawn from recon)",
                )
            )
        if not item.rationale.strip():
            issues.append(
                AttackGraphValidationIssue(
                    section=f"items[{n}].rationale",
                    severity="error",
                    message="rationale is required (1-2 sentence why and what to look for)",
                )
            )
        if not item.recon_evidence:
            issues.append(
                AttackGraphValidationIssue(
                    section=f"items[{n}].recon_evidence",
                    severity="error",
                    message=(
                        "recon_evidence must not be empty; cite the recon signals "
                        "(host, tech, port, endpoint pattern) that justified this probe"
                    ),
                )
            )

    ok = not any(i.severity == "error" for i in issues)
    return AttackGraphValidationReport(ok=ok, issues=issues)


# Persistence / finalisation


def attack_graph_path() -> Path:
    """Return the on-disk path of attack_graph.json for the current run."""
    return runtime.run_dir() / _ATTACK_GRAPH_FILENAME


def finalise_research(plan: AttackGraph) -> Path:
    """Validate ``plan`` and write ``attack_graph.json`` to the run dir.

    Refuses on any hard validation error (see ``validate_attack_graph``).
    Returns the path to the written file.
    """
    report = validate_attack_graph(plan)
    if not report.ok:
        # validate_attack_graph only emits errors today, so no filter; if a
        # warning level is added later, surface it the same way.
        lines = ["attack plan has unresolved errors:"]
        for issue in report.issues:
            lines.append(f"  - {issue.section}: {issue.message}")
        raise AttackGraphFinalisationError("\n".join(lines))

    out_path = attack_graph_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    return out_path


def load_attack_graph(path: Path) -> AttackGraph:
    """Deserialise ``attack_graph.json`` from ``path`` into a typed AttackGraph.

    The reader half of the ``finalise_research`` contract: PT loads the plan
    before running probes, and the VR re-loads it at triage time to map
    findings back to the hypotheses that justified them. Raises
    ``FileNotFoundError`` if the file is missing - the caller surfaces a
    workflow error rather than silently reverting to a free-form briefing.
    """
    if not path.is_file():
        raise FileNotFoundError(f"attack plan not found at {path}")
    return AttackGraph.model_validate_json(path.read_text(encoding="utf-8"))


__all__ = [
    "attack_graph_path",
    "finalise_research",
    "load_attack_graph",
    "validate_attack_graph",
]
