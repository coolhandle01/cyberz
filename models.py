"""
models.py - Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
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


class ScopeType(StrEnum):
    URL = "url"
    WILDCARD = "wildcard"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    DOWNLOADABLE_EXECUTABLES = "downloadable_executables"
    GOOGLE_PLAY_APP_ID = "google_play_app_id"
    APPLE_STORE_APP_ID = "apple_store_app_id"
    WINDOWS_APP_STORE_APP_ID = "windows_app_store_app_id"
    OTHER_APK = "other_apk"
    OTHER_IPA = "other_ipa"
    TESTFLIGHT = "testflight"
    OTHER = "other"


class SubmissionStatus(StrEnum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    INFORMATIVE = "informative"


# Programme selection (Programme Manager -> everyone)


class ScopeItem(BaseModel):
    """A single in-scope or out-of-scope asset."""

    asset_identifier: str
    asset_type: ScopeType
    eligible_for_bounty: bool = True
    instruction: str | None = None
    max_severity: Severity | None = None


class Programme(BaseModel):
    """A HackerOne bug bounty programme selected by the Programme Manager."""

    handle: str
    name: str
    url: str
    bounty_table: dict[Severity, int]
    in_scope: list[ScopeItem]
    out_of_scope: list[ScopeItem]
    offers_bounties: bool = True
    accepts_new_reports: bool = True
    response_efficiency_pct: float | None = None
    avg_time_to_bounty_days: float | None = None
    avg_time_to_first_response_days: float | None = None
    total_bounties_paid_usd: int | None = None
    triage_active: bool | None = None
    last_updated_at: datetime | None = None
    policy_text: str = ""
    priority_score: float = 0.0
    selected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


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


# Attack plan (Vulnerability Researcher -> Penetration Tester)


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


# Vulnerability findings (Penetration Tester -> Vulnerability Researcher)


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


# Report (Technical Author -> Disclosure Coordinator)


class DisclosureReport(BaseModel):
    """A complete, submission-ready vulnerability report in H1 format."""

    programme_handle: str
    title: str
    vulnerability: VerifiedVulnerability
    summary: str
    body_markdown: str
    weakness_id: int | None = None
    structured_scope_id: str | None = None
    impact_statement: str
    attachments: list[str] = Field(default_factory=list)
    authored_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# Submission (Disclosure Coordinator)


class SubmissionResult(BaseModel):
    """Result of a HackerOne report submission."""

    report_id: str | None = None
    status: SubmissionStatus = SubmissionStatus.PENDING
    h1_url: str | None = None
    submitted_at: datetime | None = None
    error: str | None = None


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
