"""
tools/research_tools.py - Attack-plan authoring primitives for the
Vulnerability Researcher.

The VR's research pass turns the OSINT Analyst's recon brief into a typed
attack plan: a list of probe-target hypotheses with expected severity
ceilings and the recon signals that justified each one. The agent does the
thinking; this module provides the supporting primitives:

* ``AttackPlan`` / ``AttackPlanItem`` (from ``models.attack``) - the
  artefact the agent composes.
* ``validate_attack_plan(plan)`` - quality gate. Returns the issue list
  (``AttackPlanValidationReport`` from ``models.attack``). Hard errors
  block ``finalise_research``.
* ``finalise_research(plan)`` - validate, persist ``attack_plan.json`` for
  the Penetration Tester and re-read at triage time. Raises
  ``AttackPlanFinalisationError`` (from ``models.attack``) on hard errors.

Mirrors the ``finalise_recon`` / ``finalise_triage`` pattern so the VR's
research artefact is a first-class workspace file alongside ``recon.json``
and ``verified.json``.
"""

from __future__ import annotations

from pathlib import Path

import runtime
from models.attack import (
    AttackPlan,
    AttackPlanFinalisationError,
    AttackPlanValidationIssue,
    AttackPlanValidationReport,
)

_ATTACK_PLAN_FILENAME = "attack_plan.json"


# Validation


def validate_attack_plan(plan: AttackPlan) -> AttackPlanValidationReport:
    """Apply quality heuristics to an AttackPlan. Returns the issue list.

    Hard errors:
      * empty ``items`` (no plan is not a plan)
      * any item missing one of probe / target / rationale (empty after strip)
      * any item whose ``recon_evidence`` is empty - the plan is supposed
        to be grounded in the OSINT Analyst's signals; an unevidenced
        hypothesis is the agent skipping the research pass.
    """
    issues: list[AttackPlanValidationIssue] = []

    if not plan.items:
        issues.append(
            AttackPlanValidationIssue(
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
                AttackPlanValidationIssue(
                    section=f"items[{n}].probe",
                    severity="error",
                    message="probe is required (CVE id or vulnerability-class name)",
                )
            )
        if not item.target.strip():
            issues.append(
                AttackPlanValidationIssue(
                    section=f"items[{n}].target",
                    severity="error",
                    message="target is required (hostname or URL drawn from recon)",
                )
            )
        if not item.rationale.strip():
            issues.append(
                AttackPlanValidationIssue(
                    section=f"items[{n}].rationale",
                    severity="error",
                    message="rationale is required (1-2 sentence why and what to look for)",
                )
            )
        if not item.recon_evidence:
            issues.append(
                AttackPlanValidationIssue(
                    section=f"items[{n}].recon_evidence",
                    severity="error",
                    message=(
                        "recon_evidence must not be empty; cite the recon signals "
                        "(host, tech, port, endpoint pattern) that justified this probe"
                    ),
                )
            )

    ok = not any(i.severity == "error" for i in issues)
    return AttackPlanValidationReport(ok=ok, issues=issues)


# Persistence / finalisation


def attack_plan_path() -> Path:
    """Return the on-disk path of attack_plan.json for the current run."""
    return runtime.run_dir() / _ATTACK_PLAN_FILENAME


def finalise_research(plan: AttackPlan) -> Path:
    """Validate ``plan`` and write ``attack_plan.json`` to the run dir.

    Refuses on any hard validation error (see ``validate_attack_plan``).
    Returns the path to the written file.
    """
    report = validate_attack_plan(plan)
    if not report.ok:
        # validate_attack_plan only emits errors today, so no filter; if a
        # warning level is added later, surface it the same way.
        lines = ["attack plan has unresolved errors:"]
        for issue in report.issues:
            lines.append(f"  - {issue.section}: {issue.message}")
        raise AttackPlanFinalisationError("\n".join(lines))

    out_path = attack_plan_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    return out_path


__all__ = [
    "attack_plan_path",
    "finalise_research",
    "validate_attack_plan",
]
