"""
models/attack.py - The Vulnerability Researcher's typed attack plan.

Lives in its own submodule so that the agent boundary the data crosses (VR
research pass -> PT, then re-loaded by VR at triage) is legible from the
import line. Future per-agent fixtures (#121) and the typed Exploit
interface (#88) attach here too.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from models import Severity


class AttackPlanItem(BaseModel):
    """One probe-target hypothesis from the VR's research pass."""

    probe: str  # CVE id or vulnerability-class name, e.g. "CVE-2022-22965" or "reflected XSS"
    target: str  # hostname or URL drawn from recon
    expected_ceiling: Severity  # CRITICAL / HIGH / MEDIUM / LOW the probe could reach
    rationale: str  # 1-2 sentence "why and what to look for"
    recon_evidence: list[str]  # references to recon signals that justified this hypothesis


class AttackPlan(BaseModel):
    """The VR's attack plan, handed to the PT and re-read at triage time."""

    programme_handle: str
    drafted_at: datetime
    items: list[AttackPlanItem]


__all__ = ["AttackPlan", "AttackPlanItem"]
