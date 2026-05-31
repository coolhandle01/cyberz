"""
models.attack.graph - the OSINT Analyst's recon-output bundle.

The Sheyner-style attack graph: everything the OA *describes* about a
programme's attack surface, composing the OAM asset shapes from
``models.asset``. Not itself an OAM asset - the bundle that wraps them, the
root of the OA -> VR -> PT handoff.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from models.asset import Endpoint, IpAsset, TLSCertificate
from models.finding import RawFinding
from models.h1 import Programme
from models.insight import HostInsight
from models.primitives import FQDN


class AttackGraph(BaseModel):
    """Everything the OSINT Analyst found about a programme's attack surface."""

    programme: Programme
    subdomains: list[FQDN] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    open_ports: dict[FQDN, list[int]] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    notes: str = ""
    # Findings collected passively during recon (TLS issues, DNS misconfigs, etc.)
    # Available to all downstream agents without requiring a separate pentest pass.
    passive_findings: list[RawFinding] = Field(default_factory=list)
    # hostname -> ordered list of public hop IPs from traceroute.
    # Useful for identifying origin IPs behind CDNs/WAFs (CDN bypass vector).
    network_hops: dict[FQDN, list[str]] = Field(default_factory=dict)
    # Per-host curation the OSINT Analyst authors via Annotate Host. Empty on
    # the OA's internal attack_graph.json; populated on the final recon.json.
    host_insights: list[HostInsight] = Field(default_factory=list)
    # IP-rooted enrichment: one IpAsset per unique IP observed across the
    # in-scope hosts' A records. Composes Cymru ASN data, RDAP registrant
    # data, and dnsx PTR hostnames into the cybersquad equivalent of an
    # amass IPAddress asset + its hanging SimpleProperty values. Empty when
    # the resolve / enrichment pass did not run.
    ip_assets: list[IpAsset] = Field(default_factory=list)
    # Leaf TLS certificates observed during the httpx WEB_INVENTORY pass,
    # lifted off the endpoints by ``run_recon`` - one per HTTPS endpoint
    # that presented a cert. The cybersquad equivalent of amass's
    # TLSCertificate asset nodes; the per-host copy lives at
    # ``hosts/<fqdn>/tls.json``. Populated OA-side, read by the PT/VR
    # (additive: empty when the WEB_INVENTORY pass did not run).
    tls_certificates: list[TLSCertificate] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
