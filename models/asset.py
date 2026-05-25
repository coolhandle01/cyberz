"""
models.asset - the recon-output inventory shapes (OSINT Analyst -> PT).

What the OSINT Analyst's sweep / annotation / finalisation produces:
endpoints discovered, hostnames classified by role and priority, open
ports per host, LLM-backed endpoint flags, and the bundled ``ReconResult``
that wraps the lot for downstream agents.

Hostname-typed fields compose the ``Hostname`` primitive so mis-
shaped hostnames reject upstream of any downstream consumer rather
than silently flowing through the scope filter.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from models.finding import RawFinding
from models.h1 import Programme
from models.primitives import Hostname, HttpUrl


class Endpoint(BaseModel):
    """A discovered HTTP/S endpoint.

    ``url`` is validated as a parseable HTTP / HTTPS URL with a valid
    ``Hostname`` underneath; the runtime type stays ``str`` so existing
    consumers that ``.startswith(...)`` / compare against literals keep
    working. FIXME(#152 follow-up): migrate to Pydantic ``HttpUrl`` once
    every call site is ready for the ``Url`` runtime type.
    """

    url: HttpUrl
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

    hostname: Hostname
    role: HostRole
    priority: HostPriority
    notes: str  # agent-authored, >= 30 chars
    detected_tech: list[str] = Field(default_factory=list)  # ideally with versions
    annotated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OpenPortsMap(BaseModel):
    """The recon-derived port map keyed by host.

    Lives as its own model rather than ``dict[Hostname, list[int]]`` so the
    Penetration Tester sees a documented shape it can pattern-match on
    when deciding which port-specific probes to run.
    """

    hosts: dict[Hostname, list[int]] = Field(default_factory=dict)


class LlmEndpoint(BaseModel):
    """An endpoint flagged as LLM-backed by ``detect_llm_endpoints``.

    A thin wrapper over ``Endpoint`` so the OSINT Analyst tool surface
    carries the LLM-detection intent at the type level (the field set is
    identical, but the model name marks the contract).

    FIXME(#144 / #83): this class is on the way to becoming ``DiscoveredMCP``.
    The intent the original author was reaching for - "this endpoint
    exposes an LLM" - has a more useful concrete shape now that the MCP
    threat model is clear: MCP servers advertise tool lists, capability
    bits, init handshakes, and schemas, and that structured surface is
    what the PT would actually probe against. The right move is to
    promote this into ``models/framework.py`` (per #83) as
    ``DiscoveredMCP`` carrying the advertised tool inventory, the
    suspicious-docstring flags, and the schema-laxness markers that the
    #144 MCP-discipline conversation called out. Until then this class
    exists as an intent marker and a placeholder; do not extend it as a
    generic LLM endpoint shape.
    """

    url: HttpUrl
    status_code: int | None = None
    technologies: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)


class ReconResult(BaseModel):
    """Everything the OSINT Analyst found about a programme's attack surface."""

    programme: Programme
    subdomains: list[Hostname] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    open_ports: dict[Hostname, list[int]] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    notes: str = ""
    # Findings collected passively during recon (TLS issues, DNS misconfigs, etc.)
    # Available to all downstream agents without requiring a separate pentest pass.
    passive_findings: list[RawFinding] = Field(default_factory=list)
    # hostname -> ordered list of public hop IPs from traceroute.
    # Useful for identifying origin IPs behind CDNs/WAFs (CDN bypass vector).
    network_hops: dict[Hostname, list[str]] = Field(default_factory=dict)
    # Per-host curation the OSINT Analyst authors via Annotate Host. Empty on
    # the OA's internal sweep.json; populated on the final recon.json.
    host_insights: list[HostInsight] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
