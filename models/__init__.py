"""
models - Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
The package is split into per-domain modules; this ``__init__`` is the
public re-export surface so ``from models import X`` continues to work
across every consumer.

| Module | Contents |
|---|---|
| ``models.primitives`` | ``Severity``, ``FQDN``, ``HttpUrl``, ``IPAddress`` |
| ``models.finding`` | ``RawFinding``, ``VerifiedVulnerability``, ``RawFindingSummary`` |
| ``models.asset`` | ``Endpoint``, ``EndpointPage``, ``HostRole``, ``HostPriority``, |
|                  | ``HostInsight``, ``OpenPortsMap``, ``LlmEndpoint``, ``AttackGraph`` |
| ``models.workspace`` | ``RunFile``, ``RunFileContent`` |
| ``models.cve`` | ``CveEntry`` |
| ``models.cwe`` | ``CWEEntry`` |
| ``models.owasp`` | ``OWASPEntry`` |
| ``models.dns`` | ``TakeoverCandidate`` |
| ``models.insight`` | ``HostAnnotation``, ``InsightValidationIssue``, |
|                    | ``InsightValidationReport``, ``ReconFinalisationError`` |
| ``models.metrics`` | ``RunMetrics`` |
| ``models.network`` | ``AsnRecord`` |
| ``models.scanner`` | ``NmapMode``, ``NmapBanner``, ``NmapScripts``, ``NmapService``, |
|                    | ``NmapHostResult``, ``NmapScanResult``, ``HttpxMode`` |
| ``models.h1`` | HackerOne shapes incl. ``ProgrammeReportSummary`` |
| ``models.attack`` | ``AttackForest``, ``AttackTree``, |
|                   | ``AttackForestValidationIssue``, ``AttackForestValidationReport``, |
|                   | ``AttackForestFinalisationError`` |
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
    AttackGraph,
    Endpoint,
    EndpointPage,
    HostInsight,
    HostPriority,
    HostRole,
    LlmEndpoint,
    OpenPortsMap,
)
from models.attack import (
    AttackForest,
    AttackForestFinalisationError,
    AttackForestValidationIssue,
    AttackForestValidationReport,
    AttackTree,
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
from models.primitives import FQDN, HttpUrl, IPAddress, Severity
from models.report import AuthoredDraft
from models.scanner import (
    HttpxMode,
    NmapBanner,
    NmapHostResult,
    NmapMode,
    NmapScanResult,
    NmapScripts,
    NmapService,
)
from models.technology import Technology, TechnologyCategory
from models.triage import AuthoredAssessment, SeverityDecision
from models.workspace import RunFile, RunFileContent

__all__ = [
    "FQDN",
    "AsnRecord",
    "AttackForest",
    "AttackForestFinalisationError",
    "AttackForestValidationIssue",
    "AttackForestValidationReport",
    "AttackGraph",
    "AttackTree",
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
    "HttpUrl",
    "HttpxMode",
    "IPAddress",
    "InsightValidationIssue",
    "InsightValidationReport",
    "LlmEndpoint",
    "NmapBanner",
    "NmapHostResult",
    "NmapMode",
    "NmapScanResult",
    "NmapScripts",
    "NmapService",
    "OWASPEntry",
    "OpenPortsMap",
    "ProgrammeReportSummary",
    "RawFinding",
    "RawFindingSummary",
    "ReconFinalisationError",
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
