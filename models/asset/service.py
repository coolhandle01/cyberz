"""
models.asset.service - the OAM ``Service`` / ``Product`` / ``ProductRelease``
assets.

The open-network-service asset the OA's deep-scan pass emits, plus the
product line and version-specific release the ``Service.product_used`` edge
points at (and the spec-proper anchor a ``VulnProperty`` hangs off).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.asset.vuln import VulnProperty
from models.primitives import FQDN, IPAddress


class Service(BaseModel):
    """The cybersquad shape that maps to amass's ``Service`` asset.

    One open network service on a single host:port, as the OSINT
    Analyst's deep-scan pass (a focused nmap ``-sC -sV`` against a host's
    known-open ports) observes it. The OAM-vernacular counterpart to the
    scanner-internal ``NmapService`` (``models/scanner.py``): where
    ``NmapService`` mirrors nmap's raw ``<port>`` / ``<service>`` XML,
    ``Service`` is the asset-graph shape the OA emits for downstream
    agents - the rich sibling of ``OpenPortsMap``, which carries bare
    port numbers only.

    When amass lands (#45), each ``Service`` becomes one amass
    ``Service`` asset node related to its host's ``FQDN`` / ``IPAddress``
    asset:

    * ``host`` + ``port`` -> the Service asset's identity and the
      ``port`` edge from the host asset.
    * ``name`` / ``product`` / ``version`` / ``extra_info`` ->
      ``SimpleProperty`` values on the Service node (the service-banner
      detail ``-sV`` recovered).
    * ``cpe`` -> a ``SimpleProperty`` carrying the NIST CPE 2.3 identifier
      nmap matched - the authoritative product key (it encodes
      vendor:product:version directly) the VR's CVE lookup queries NVD with.
    * ``detected_by`` -> a ``SourceProperty`` naming the tool that observed
      the service. Provenance is OAM's source-attribution slot, stamped on
      every asset we upsert.

    There is deliberately no separate ``Technology`` rows on a Service: the
    service's own ``product`` / ``version`` / ``cpe`` *is* the technology.
    Classification is not our job (we maintain no catalogue); the CPE is the
    authoritative identity.

    OAM is a *presence* graph: a ``Service`` exists in the model only
    when the scan actually observed an open service. A host that is down,
    or alive with nothing listening, contributes zero ``Service`` nodes -
    absence carries "nothing here", so there is deliberately no
    down / filtered / closed state on this shape (that lives in the
    scanner layer's ``NmapService.state``, below the OA boundary).
    """

    host: FQDN | IPAddress
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(max_length=8)  # "tcp" / "udp"

    # Tool-captured from nmap's service-version (-sV) output, translated
    # from the scanner layer's ``NmapService`` at the OA tool boundary.
    # Defence: each field carries the same boundary length cap as its
    # ``NmapService`` source so a malformed banner cannot smuggle a large
    # injection across the OA -> PT handoff.
    name: str | None = Field(default=None, max_length=64)  # nmap "service" field
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    extra_info: str | None = Field(default=None, max_length=255)

    # CPE 2.3 identifier nmap matched for this service (normalised from its
    # ``<cpe>`` 2.2 URI output via ``tools.cpe``). The authoritative product
    # key: it encodes vendor:product:version and is what the VR's CVE lookup
    # queries NVD against. ``None`` when nmap matched no CPE. A cybersquad
    # extension to the OAM Service asset, persisted as a ``SimpleProperty``.
    #
    # FIXME(#45 / amass-integration): promote to a typed ``Cpe`` primitive in
    # ``models.primitives`` once the CVE-lookup workflow lands - cpe sits on
    # two fields (here + ``NmapService.cpe``), the multi-field threshold the
    # cybersquad-models skill sets for a primitive; deferred alongside the
    # existing ``CvssVector`` / ``CweId`` primitive plans.
    cpe: str | None = Field(default=None, max_length=255)

    # The tool that observed this service ("nmap"). OAM's ``SourceProperty``:
    # provenance stamped on every asset we upsert. A tool-named closed
    # vocabulary (not free text from an external source), so no injection
    # guard needed; length-capped defensively. Mirrors the existing
    # ``RawFinding.tool`` provenance field - a shared ``DetectionTool``
    # StrEnum is the natural promotion once this lands on more asset types.
    detected_by: str | None = Field(default=None, max_length=32)

    # OAM ``VulnProperty`` annotations hung off this service asset - the
    # known vulnerabilities the VR / OA attributed to it, typically an NVD
    # CVE matched against the service's ``cpe`` (the authoritative product
    # key) or product / version. Additive and default-empty.
    vulns: list[VulnProperty] = Field(default_factory=list)


class Product(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Product`` asset.

    A product line / vendor offering observed on the surface - "WordPress",
    "nginx", "Spring Framework". In OAM a ``Service`` relates to a
    ``Product`` via the ``product_used`` edge; the version-specific instance
    is ``ProductRelease`` below. Mirrors amass's ``Product`` field for field
    (OAM json tag in parentheses).
    """

    name: str = Field(min_length=1, max_length=128)  # product_name
    product_id: str = Field(default="", max_length=128)  # unique_id
    type: str = Field(default="", max_length=64)  # product_type
    category: str = Field(default="", max_length=128)  # category
    # Agent- / feed-authored descriptive text; length-capped at the boundary.
    description: str = Field(default="", max_length=2000)  # description
    country_of_origin: str = Field(default="", max_length=64)  # country_of_origin


class ProductRelease(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``ProductRelease`` asset.

    A specific released version of a ``Product`` - "WordPress 5.8.1". In OAM
    this is the spec-proper anchor a ``VulnProperty`` hangs off (a CVE is
    carried by the *release*, not the product line), and the target of a
    ``Service`` ``product_used`` edge. Mirrors amass's ``ProductRelease``
    (OAM json tag in parentheses).
    """

    name: str = Field(min_length=1, max_length=128)  # name (e.g. "WordPress 5.8.1")
    release_date: str = Field(default="", max_length=64)  # release_date (verbatim)

    # OAM ``VulnProperty`` annotations hung off this release - the
    # spec-proper home for a CVE the VR matched against this exact version.
    # Additive and default-empty.
    vulns: list[VulnProperty] = Field(default_factory=list)
