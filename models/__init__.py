"""
models - Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
H1-specific shapes (programme catalog, scope, submission payloads) live in
models.h1; everything else stays here until a similar size/concern split is
warranted.

Declaration order is tweaked from the natural pipeline order (recon ->
findings -> report) so that the types models.h1 depends on (Severity,
VerifiedVulnerability) are defined before the `from models.h1 import ...`
line. Without this, h1 hits a partially-initialised package and the import
fails.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

# Enumerations


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Vulnerability findings (Penetration Tester -> Vulnerability Researcher)
#
# Defined ahead of the H1 import below because models.h1 needs
# VerifiedVulnerability for DisclosureReport.vulnerability, and RawFinding is
# referenced by ReconResult further down.


class RawFinding(BaseModel):
    """An unverified potential vulnerability from automated tooling."""

    title: str
    vuln_class: str
    target: str
    evidence: str
    tool: str
    severity_hint: Severity = Severity.MEDIUM


class VerifiedVulnerability(BaseModel):
    """A confirmed, in-scope vulnerability after Vulnerability Researcher triage."""

    title: str
    vuln_class: str
    target: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    description: str
    steps_to_reproduce: list[str]
    evidence: str
    impact: str
    remediation: str
    in_scope: bool = True
    confirmed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# H1 import - models.h1 imports Severity and VerifiedVulnerability from above;
# Programme is referenced by ReconResult below as a pydantic field type, which
# pydantic resolves against this module's globals at class-definition time.
from models.h1 import Programme  # noqa: E402

# Recon (OSINT Analyst -> Penetration Tester)


class Endpoint(BaseModel):
    """A discovered HTTP/S endpoint."""

    url: str
    status_code: int | None = None
    technologies: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)


class EndpointPage(BaseModel):
    """Paginated slice of Endpoint results from a recon query."""

    total: int
    offset: int
    returned: int
    endpoints: list[Endpoint]


class HostRole(StrEnum):
    """The role a host plays in the programme's attack surface.

    Drives priority decisions downstream: an ``ADMIN`` host with a known
    framework is a higher-value pentest target than a ``CDN`` host that
    serves static assets.
    """

    ADMIN = "admin"  # admin / control-plane UIs
    API = "api"  # REST / GraphQL / SOAP endpoints
    AUTH = "auth"  # SSO, OAuth, login, password reset
    APP = "app"  # main user-facing application
    CDN = "cdn"  # static asset delivery, edge caches
    STATIC = "static"  # purely static content (marketing, blog, docs)
    MAIL = "mail"  # SMTP / IMAP / MX hosts
    INFRA = "infra"  # name servers, monitoring, IaaS
    DEV = "dev"  # dev / staging / beta surfaces
    UNKNOWN = "unknown"


class HostPriority(StrEnum):
    """The OSINT Analyst's curation signal for downstream agents.

    The Penetration Tester biases probe budget toward ``HIGH`` hosts; the
    Vulnerability Researcher prioritises CVE / report-history research for
    them. ``SKIP`` is a hard signal not to probe (third-party-managed, known
    decoy, etc.)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SKIP = "skip"


class HostInsight(BaseModel):
    """One OSINT Analyst-authored annotation for a single host.

    The sweep produces ``subdomains`` / ``endpoints`` / ``open_ports`` /
    ``technologies`` as raw inventory; ``HostInsight`` is the agent's
    curation layer that tells downstream agents WHERE to look first and
    WHY.
    """

    hostname: str
    role: HostRole
    priority: HostPriority
    notes: str  # agent-authored, >= 30 chars
    detected_tech: list[str] = Field(default_factory=list)  # ideally with versions
    annotated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReconResult(BaseModel):
    """Everything the OSINT Analyst found about a programme's attack surface."""

    programme: Programme
    subdomains: list[str] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    notes: str = ""
    # Findings collected passively during recon (TLS issues, DNS misconfigs, etc.)
    # Available to all downstream agents without requiring a separate pentest pass.
    passive_findings: list[RawFinding] = Field(default_factory=list)
    # hostname -> ordered list of public hop IPs from traceroute.
    # Useful for identifying origin IPs behind CDNs/WAFs (CDN bypass vector).
    network_hops: dict[str, list[str]] = Field(default_factory=dict)
    # Per-host curation the OSINT Analyst authors via Annotate Host. Empty on
    # the OA's internal sweep.json; populated on the final recon.json.
    host_insights: list[HostInsight] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# Operational metrics (emitted after every pipeline run)


class RunMetrics(BaseModel):
    """Token usage, cost, and effectiveness summary for one pipeline run."""

    run_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    llm_model: str
    programme_handle: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    findings_raw: int = 0
    findings_verified: int = 0
    submitted: bool = False
