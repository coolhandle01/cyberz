"""
models/attack.py - The Vulnerability Researcher's typed attack plan.

Lives in its own submodule so that the agent boundary the data crosses (VR
research pass -> PT, then re-loaded by VR at triage) is legible from the
import line. Future per-agent fixtures (#121) and the typed Exploit
interface (#88) attach here too.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from models import Severity


class AttackPlanItem(BaseModel):
    """One probe-target hypothesis from the VR's research pass."""

    probe: str  # CVE id or vulnerability-class name, e.g. "CVE-2022-22965" or "reflected XSS"
    target: str  # hostname or URL drawn from recon
    expected_ceiling: Severity  # CRITICAL / HIGH / MEDIUM / LOW the probe could reach
    rationale: str  # 1-2 sentence "why and what to look for"
    recon_evidence: list[str]  # references to recon signals that justified this hypothesis

    @field_validator("recon_evidence")
    @classmethod
    def _strip_and_filter_evidence(cls, value: list[str]) -> list[str]:
        """Strip whitespace from every entry and drop empties.

        Lives on the model so every constructor (CrewAI args_schema
        validation, ``model_validate_json`` on a re-loaded attack plan,
        a direct ``AttackPlanItem(...)`` call) sees the same cleaned
        list. Pairs with ``validate_attack_plan``'s
        ``if not item.recon_evidence:`` hard error - an item that was
        passed whitespace-only entries ends up with an empty list and
        the validator catches it, instead of the persisted artefact
        carrying junk the PT then has to reason around.
        """
        return [entry.strip() for entry in value if entry.strip()]


class AttackPlan(BaseModel):
    """The VR's attack plan, handed to the PT and re-read at triage time."""

    programme_handle: str
    drafted_at: datetime
    items: list[AttackPlanItem]


class AttackPlanValidationIssue(BaseModel):
    """One issue produced by attack-plan validation."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class AttackPlanValidationReport(BaseModel):
    """Result of validating an AttackPlan."""

    ok: bool
    issues: list[AttackPlanValidationIssue] = Field(default_factory=list)


class AttackPlanFinalisationError(RuntimeError):
    """Raised when an AttackPlan cannot be persisted to attack_plan.json."""


__all__ = [
    "AttackPlan",
    "AttackPlanFinalisationError",
    "AttackPlanItem",
    "AttackPlanValidationIssue",
    "AttackPlanValidationReport",
]
