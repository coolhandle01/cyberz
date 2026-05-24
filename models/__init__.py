"""
models - Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
The package is split into per-domain modules; this ``__init__`` is the
public re-export surface so ``from models import X`` continues to work
across every consumer.

| Module | Contents |
|---|---|
| ``models.primitives`` | ``Severity``, ``Hostname``, ``HttpUrl`` |
| ``models.finding`` | ``RawFinding``, ``VerifiedVulnerability``, ``RawFindingSummary`` |
| ``models.asset`` | ``Endpoint``, ``EndpointPage``, ``HostRole``, ``HostPriority``, |
|                  | ``HostInsight``, ``OpenPortsMap``, ``LlmEndpoint``, ``ReconResult`` |
| ``models.workspace`` | ``RunFile``, ``RunFileContent`` |
| ``models.cve`` | ``CveEntry`` |
| ``models.metrics`` | ``RunMetrics`` |
| ``models.h1`` | HackerOne shapes incl. ``ProgrammeReportSummary`` |
| ``models.attack`` | ``AttackPlan``, ``AttackPlanItem`` |

The per-domain modules import only from layers below them in the
dependency graph: primitives -> finding -> h1 -> asset. No module imports
from this ``__init__`` to avoid the partially-initialised-package gotcha
that the pre-split layout had to dance around.
"""

from __future__ import annotations

from models.asset import (
    Endpoint,
    EndpointPage,
    HostInsight,
    HostPriority,
    HostRole,
    LlmEndpoint,
    OpenPortsMap,
    ReconResult,
)
from models.cve import CveEntry
from models.finding import RawFinding, RawFindingSummary, VerifiedVulnerability
from models.h1 import ProgrammeReportSummary
from models.metrics import RunMetrics
from models.primitives import Hostname, HttpUrl, Severity
from models.workspace import RunFile, RunFileContent

__all__ = [
    "CveEntry",
    "Endpoint",
    "EndpointPage",
    "HostInsight",
    "HostPriority",
    "HostRole",
    "Hostname",
    "HttpUrl",
    "LlmEndpoint",
    "OpenPortsMap",
    "ProgrammeReportSummary",
    "RawFinding",
    "RawFindingSummary",
    "ReconResult",
    "RunFile",
    "RunFileContent",
    "RunMetrics",
    "Severity",
    "VerifiedVulnerability",
]
