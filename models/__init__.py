"""
models - Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
The package is split into per-domain modules; this ``__init__`` is the
public re-export surface so ``from models import X`` continues to work
across every consumer.

| Module | Contents |
|---|---|
| ``models.primitives`` | ``Severity``, ``Hostname``, ``HttpUrl``, ``IPAddress`` |
| ``models.finding`` | ``RawFinding``, ``VerifiedVulnerability``, ``RawFindingSummary`` |
| ``models.asset`` | ``Endpoint``, ``EndpointPage``, ``HostRole``, ``HostPriority``, |
|                  | ``HostInsight``, ``OpenPortsMap``, ``LlmEndpoint``, ``ReconResult`` |
| ``models.workspace`` | ``RunFile``, ``RunFileContent`` |
| ``models.cve`` | ``CveEntry`` |
| ``models.cwe`` | ``CWEEntry`` |
| ``models.owasp`` | ``OWASPEntry`` |
| ``models.dns`` | ``TakeoverCandidate`` |
| ``models.insight`` | ``HostAnnotation``, ``InsightValidationIssue``, |
|                    | ``InsightValidationReport``, ``ReconFinalisationError`` |
| ``models.metrics`` | ``RunMetrics`` |
| ``models.network`` | ``AsnRecord`` |
| ``models.h1`` | HackerOne shapes incl. ``ProgrammeReportSummary`` |
| ``models.attack`` | ``AttackPlan``, ``AttackPlanItem``, |
|                   | ``AttackPlanValidationIssue``, ``AttackPlanValidationReport``, |
|                   | ``AttackPlanFinalisationError`` |
| ``models.triage`` | ``AuthoredAssessment``, ``SeverityDecision`` |
| ``models.report`` | ``AuthoredDraft`` |
| ``models.technology`` | ``Technology``, ``TechnologyCategory`` |

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
from models.attack import (
    AttackPlan,
    AttackPlanFinalisationError,
    AttackPlanItem,
    AttackPlanValidationIssue,
    AttackPlanValidationReport,
)
from models.cve import CveEntry
from models.cwe import CWEEntry
from models.dns import TakeoverCandidate
from models.finding import RawFinding, RawFindingSummary, VerifiedVulnerability
from models.h1 import ProgrammeReportSummary
from models.insight import (
    HostAnnotation,
    InsightValidationIssue,
    InsightValidationReport,
    ReconFinalisationError,
)
from models.metrics import RunMetrics
from models.network import AsnRecord
from models.owasp import OWASPEntry
from models.primitives import Hostname, HttpUrl, IPAddress, Severity
from models.report import AuthoredDraft
from models.technology import Technology, TechnologyCategory
from models.triage import AuthoredAssessment, SeverityDecision
from models.workspace import RunFile, RunFileContent

__all__ = [
    "AsnRecord",
    "AttackPlan",
    "AttackPlanFinalisationError",
    "AttackPlanItem",
    "AttackPlanValidationIssue",
    "AttackPlanValidationReport",
    "AuthoredAssessment",
    "AuthoredDraft",
    "CWEEntry",
    "CveEntry",
    "Endpoint",
    "EndpointPage",
    "HostAnnotation",
    "HostInsight",
    "HostPriority",
    "HostRole",
    "Hostname",
    "HttpUrl",
    "IPAddress",
    "InsightValidationIssue",
    "InsightValidationReport",
    "LlmEndpoint",
    "OWASPEntry",
    "OpenPortsMap",
    "ProgrammeReportSummary",
    "RawFinding",
    "RawFindingSummary",
    "ReconFinalisationError",
    "ReconResult",
    "RunFile",
    "RunFileContent",
    "RunMetrics",
    "Severity",
    "SeverityDecision",
    "TakeoverCandidate",
    "Technology",
    "TechnologyCategory",
    "VerifiedVulnerability",
]
