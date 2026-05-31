"""
models.asset.host - host role / priority enums and the OA curation shapes.

The OSINT Analyst's per-host curation layer: ``HostRole`` / ``HostPriority``
classify a host; ``HostInsight`` / ``HostScore`` carry the annotation; and
``OpenPortsMap`` is the documented port-map shape the PT pattern-matches on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from models.asset.vuln import VulnProperty
from models.primitives import FQDN


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

    hostname: FQDN
    role: HostRole
    priority: HostPriority
    notes: str  # agent-authored, >= 30 chars
    detected_tech: list[str] = Field(default_factory=list)  # ideally with versions
    # OAM ``VulnProperty`` annotations hung off this host (FQDN asset) - the
    # known vulnerabilities the OA / VR attributed to it from its detected
    # tech. Additive and default-empty.
    vulns: list[VulnProperty] = Field(default_factory=list)
    annotated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HostScore(BaseModel):
    """The OSINT Analyst's scoring of one host - the score/priority half of
    ``HostInsight``, split out from the prose.

    Pure machine-actionable curation: WHERE a host sits in the attack
    surface (``role``) and how hard downstream agents should lean on it
    (``priority``). The WHY - the agent's prose rationale - lives beside it
    as ``notes.md`` rather than shoehorned into this data shape, so the PT
    can filter on ``priority`` / ``role`` without parsing free text.

    Materialised per host at ``hosts/<fqdn>/host.json`` - the typed header
    of that host's OAM-asset directory. Maps toward amass's FQDN asset,
    with role / priority as ``SimpleProperty`` values when #45 lands.
    """

    hostname: FQDN
    role: HostRole
    priority: HostPriority
    annotated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OpenPortsMap(BaseModel):
    """The recon-derived port map keyed by host.

    Lives as its own model rather than ``dict[FQDN, list[int]]`` so the
    Penetration Tester sees a documented shape it can pattern-match on
    when deciding which port-specific probes to run.
    """

    hosts: dict[FQDN, list[int]] = Field(default_factory=dict)
