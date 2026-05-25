"""
models/insight.py - typed shapes for the OSINT Analyst's recon
finalisation pipeline.

Carries the per-host annotation return shape (``HostAnnotation``), the
quality-gate validation report (``InsightValidationIssue`` /
``InsightValidationReport``) the OA's ``Annotate Host`` tool produces,
and the ``ReconFinalisationError`` ``finalise_recon`` raises when the
sweep + per-host insights cannot be consolidated into ``recon.json``.

Lives in models/ rather than tools/ because these are typed contracts
the OA wrapper functions return / raise - the kind of shape consumers
import to type-check against rather than to invoke. The data (sweep
loaders, insight persistence, scope guards) stays in
``tools/recon_insights.py``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class InsightValidationIssue(BaseModel):
    """One issue produced by validate_insight."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class InsightValidationReport(BaseModel):
    """Result of validating one insight."""

    ok: bool
    issues: list[InsightValidationIssue] = Field(default_factory=list)


class HostAnnotation(BaseModel):
    """Return shape of the Annotate Host tool.

    ``path`` is the workspace-relative location of the persisted insight
    (e.g. ``host_insights/api.example.com.json``); ``validation`` is the
    quality-gate report for the insight that was just authored.
    """

    path: str
    validation: InsightValidationReport


class ReconFinalisationError(RuntimeError):
    """Raised when finalise_recon cannot consolidate the sweep + insights."""


__all__ = [
    "HostAnnotation",
    "InsightValidationIssue",
    "InsightValidationReport",
    "ReconFinalisationError",
]
