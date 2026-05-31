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
| ``models.asset`` | assets ``Endpoint``, ``EndpointPage``, ``IpAsset``, |
|                  | ``Service``, ``Product``, ``ProductRelease``, ``Url``, |
|                  | ``TLSCertificate``, ``LlmEndpoint``; properties |
|                  | ``SimpleProperty``, ``SourceProperty``, ``VulnProperty``; |
|                  | relations ``RelationType``, ``RRHeader``, ``SimpleRelation``, |
|                  | ``PortRelation``, ``BasicDNSRelation``, ``PrefDNSRelation``, |
|                  | ``SRVDNSRelation`` |
| ``models.asset.network`` | ``AsnRecord``, ``Contact``, ``ContactRole``, |
|                          | ``DomainRecord``, ``RdapRecord`` |
| ``models.workspace`` | ``RunFile``, ``RunFileContent`` |
| ``models.cve`` | ``CveEntry`` |
| ``models.cwe`` | ``CWEEntry`` |
| ``models.owasp`` | ``OWASPEntry`` |
| ``models.dns`` | ``PtrRecord``, ``TakeoverCandidate`` |
| ``models.insight`` | ``HostRole``, ``HostPriority``, ``HostInsight``, ``HostScore``, |
|                    | ``OpenPortsMap``, ``HostAnnotation``, ``InsightValidationIssue``, |
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
    BasicDNSRelation,
    Endpoint,
    EndpointPage,
    IpAsset,
    LlmEndpoint,
    PortRelation,
    PrefDNSRelation,
    Product,
    ProductRelease,
    RelationType,
    RRHeader,
    Service,
    SimpleProperty,
    SimpleRelation,
    SourceProperty,
    SRVDNSRelation,
    TLSCertificate,
    Url,
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
    HostInsight,
    HostPriority,
    HostRole,
    HostScore,
    InsightValidationIssue,
    InsightValidationReport,
    OpenPortsMap,
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
    "BasicDNSRelation",
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
    "PortRelation",
    "PrefDNSRelation",
    "Product",
    "ProductRelease",
    "ProgrammeReportSummary",
    "PtrRecord",
    "RRHeader",
    "RawFinding",
    "RawFindingSummary",
    "RdapRecord",
    "ReconFinalisationError",
    "RelationType",
    "RunFile",
    "RunFileContent",
    "RunMetrics",
    "SRVDNSRelation",
    "Service",
    "Severity",
    "SeverityDecision",
    "SimpleProperty",
    "SimpleRelation",
    "SourceProperty",
    "TLSCertificate",
    "TakeoverCandidate",
    "Url",
    "VerifiedVulnerability",
    "VulnProperty",
]
