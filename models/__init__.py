"""
models - Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
The package is split into per-domain modules; this ``__init__`` is the
public re-export surface so ``from models import X`` continues to work
across every consumer.

| Module | Contents |
|---|---|
| ``models.primitives`` | ``Severity``, ``FQDN``, ``HttpUrl``, ``IPAddress``, ``Email`` |
| ``models.finding`` | ``RawFinding``, ``VerifiedVulnerability``, ``RawFindingSummary`` |
| ``models.asset`` | ``Endpoint``, ``EndpointPage``, ``HostRole``, ``HostPriority``, |
|                  | ``HostInsight``, ``HostScore``, ``IpAsset``, ``OpenPortsMap``, |
|                  | ``Service``, ``TLSCertificate``, ``VulnProperty``, ``Product``, |
|                  | ``ProductRelease``, ``LlmEndpoint`` |
| ``models.asset.network`` | ``AsnRecord``, ``Contact``, ``ContactRole``, |
|                          | ``DomainRecord``, ``RdapRecord`` |
| ``models.workspace`` | ``RunFile``, ``RunFileContent`` |
| ``models.cve`` | ``CveEntry`` |
| ``models.cwe`` | ``CWEEntry`` |
| ``models.owasp`` | ``OWASPEntry`` |
| ``models.dns`` | ``PtrRecord``, ``TakeoverCandidate`` |
| ``models.insight`` | ``HostAnnotation``, ``InsightValidationIssue``, |
|                    | ``InsightValidationReport``, ``ReconFinalisationError`` |
| ``models.metrics`` | ``RunMetrics`` |
| ``models.scanner`` | ``NmapMode``, ``NmapBanner``, ``NmapScripts``, ``NmapService``, |
|                    | ``NmapHostResult``, ``NmapScanResult``, ``HttpxMode`` |
| ``models.h1`` | HackerOne shapes incl. ``ProgrammeReportSummary`` |
| ``models.attack`` | ``AttackGraph``, ``AttackForest``, ``AttackTree``, |
|                   | ``AttackForestValidationIssue``, ``AttackForestValidationReport``, |
|                   | ``AttackForestFinalisationError`` |
| ``models.triage`` | ``AuthoredAssessment``, ``SeverityDecision`` |
| ``models.report`` | ``AuthoredDraft`` |

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
    HostScore,
    IpAsset,
    LlmEndpoint,
    OpenPortsMap,
    Product,
    ProductRelease,
    Service,
    TLSCertificate,
    VulnProperty,
)
from models.asset.network import AsnRecord, Contact, ContactRole, DomainRecord, RdapRecord
from models.attack import (
    AttackForest,
    AttackForestFinalisationError,
    AttackForestValidationIssue,
    AttackForestValidationReport,
    AttackGraph,
    AttackTree,
)
from models.cve import CveEntry
from models.cwe import CWEEntry
from models.dns import PtrRecord, TakeoverCandidate
from models.finding import RawFinding, RawFindingSummary, VerifiedVulnerability
from models.h1 import ProgrammeReportSummary
from models.insight import (
    HostAnnotation,
    InsightValidationIssue,
    InsightValidationReport,
    ReconFinalisationError,
)
from models.metrics import RunMetrics
from models.owasp import OWASPEntry
from models.primitives import FQDN, Email, HttpUrl, IPAddress, Severity
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
    "Contact",
    "ContactRole",
    "CveEntry",
    "DomainRecord",
    "Email",
    "Endpoint",
    "EndpointPage",
    "HostAnnotation",
    "HostInsight",
    "HostPriority",
    "HostRole",
    "HostScore",
    "HttpUrl",
    "HttpxMode",
    "IPAddress",
    "InsightValidationIssue",
    "InsightValidationReport",
    "IpAsset",
    "LlmEndpoint",
    "NmapBanner",
    "NmapHostResult",
    "NmapMode",
    "NmapScanResult",
    "NmapScripts",
    "NmapService",
    "OWASPEntry",
    "OpenPortsMap",
    "Product",
    "ProductRelease",
    "ProgrammeReportSummary",
    "PtrRecord",
    "RawFinding",
    "RawFindingSummary",
    "RdapRecord",
    "ReconFinalisationError",
    "RunFile",
    "RunFileContent",
    "RunMetrics",
    "Service",
    "Severity",
    "SeverityDecision",
    "TLSCertificate",
    "TakeoverCandidate",
    "VerifiedVulnerability",
    "VulnProperty",
]
