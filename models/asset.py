"""
models.asset - the recon-output inventory shapes (OSINT Analyst -> PT).

What the OSINT Analyst's sweep / annotation / finalisation produces:
endpoints discovered, hostnames classified by role and priority, open
ports per host, LLM-backed endpoint flags, and the bundled ``AttackGraph``
that wraps the lot for downstream agents.

FQDN-typed fields compose the ``FQDN`` primitive so mis-
shaped hostnames reject upstream of any downstream consumer rather
than silently flowing through the scope filter.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from models.finding import RawFinding
from models.h1 import Programme
from models.network import AsnRecord, RdapRecord
from models.primitives import FQDN, HttpUrl, IPAddress


class Endpoint(BaseModel):
    """A discovered HTTP/S endpoint.

    ``url`` is validated through Pydantic's built-in ``HttpUrl``
    (canonical RFC-3986 parser) with the host component running through
    the ``FQDN`` validator for RFC 1123 strictness; runtime stays
    ``str`` so consumers that ``.startswith(...)`` / ``.lower()`` /
    ``urlparse(ep.url)`` / dict-key / f-string keep working with no
    audit. See ``models/primitives._validate_endpoint_url`` for the
    full contract.

    ``technologies`` is the raw httpx ``-tech-detect`` output
    (Wappalyzer-shape strings like ``"Django:4.2"``) - the detecting
    tool's own vocabulary, kept verbatim. We classify nothing and
    maintain no catalogue: the tool's string is the identifier. The
    raw strings populate at probe time in ``tools.recon.httpx.httpx_scan``.

    (Web technologies carry no CPE - httpx emits names, not CPEs - so
    they stay as strings here. nmap-discovered services carry their
    NIST CPE on the ``Service`` asset instead.)
    """

    url: HttpUrl
    status_code: int | None = None
    technologies: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)

    # Favicon hash (MMH3 of the favicon bytes) emitted by httpx's
    # ``-favicon`` flag when ``HttpxMode.WEB_INVENTORY`` runs. Used as
    # the join key for Shodan / Censys ``http.favicon.hash:`` searches -
    # one in-scope asset's favicon pivots into every other host serving
    # the same icon. Tool-captured: defence is coerce-time normalise +
    # length cap (MMH3 is a signed 32-bit int rendered as decimal; 12
    # chars including the sign is the realistic ceiling, capped loose).
    favicon_hash: str | None = Field(default=None, max_length=32)
    # TLS Subject Alternative Names extracted from the leaf cert by
    # httpx's ``-tls-grab`` flag when ``HttpxMode.WEB_INVENTORY`` runs.
    # Each entry is an FQDN-shaped string (the FQDN primitive validates
    # at construction). Useful in-scope-FQDN discovery: a multi-SAN cert
    # leaks every hostname the server is authoritative for, which the
    # OA's curation pass can promote to net-new in-scope hosts when
    # the SAN matches the programme's apex.
    tls_sans: list[FQDN] = Field(default_factory=list)
    # The leaf cert observed on this endpoint, as the OAM ``TLSCertificate``
    # asset shape (issuer / validity / fingerprint / full SAN list). Where
    # ``tls_sans`` is the FQDN-typed discovery side-channel (wildcards
    # dropped), this carries the cert faithfully. ``None`` outside
    # ``WEB_INVENTORY`` / when no cert was grabbed. ``run_recon`` lifts
    # these off the endpoints into ``AttackGraph.tls_certificates``.
    tls_certificate: TLSCertificate | None = None


class EndpointPage(BaseModel):
    """Paginated slice of Endpoint results from a recon query."""

    total: int
    offset: int
    returned: int
    endpoints: list[Endpoint]


class IpAsset(BaseModel):
    """The cybersquad shape that maps to amass's IPAddress asset.

    Composes the lookups we run for one IP into a single typed record:
    ASN data via Cymru (``asn``), registrant data via RDAP (``rdap``),
    reverse-DNS hostnames via dnsx PTR (``ptr``). One IpAsset = one
    amass IPAddress asset with its hanging Property values.

    When amass lands (#45), each nested record becomes one or more
    ``SimpleProperty`` / ``DNSRecordProperty`` entries on the
    IPAddress asset node:

    * ``asn`` -> ``SimpleProperty{name:"asn", value:<n>}`` +
      ``SimpleProperty{name:"asn_org", value:<name>}`` etc.; the
      ``prefix`` field separately surfaces the parent Netblock asset.
    * ``rdap`` -> ``SimpleProperty`` per registrant field +
      a join into the ``RIROrganization`` asset.
    * ``ptr`` -> one ``DNSRecordProperty`` per reverse-DNS hostname.

    All three fields default to None / empty - an IP is useful with
    whatever subset of enrichment landed. The OA's enrichment pass
    composes one IpAsset per unique IP observed in the sweep,
    populating whichever sources succeeded.
    """

    ip: IPAddress
    asn: AsnRecord | None = None
    rdap: RdapRecord | None = None
    ptr: list[FQDN] = Field(default_factory=list)


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


class TLSCertificate(BaseModel):
    """The cybersquad shape that maps to amass's ``TLSCertificate`` asset.

    One X.509 leaf certificate as observed on a host's HTTPS service -
    what httpx's ``-tls-grab`` and testssl.sh surface during the OSINT
    Analyst's sweep. Today only the SAN list is harvested (into
    ``Endpoint.tls_sans``, for in-scope-FQDN discovery) and posture
    problems become ``RawFinding`` rows; the cert itself is never
    persisted as an asset. This model is that asset node.

    Carries the cert's *identity and properties*, not its posture:
    subject / issuer / serial / fingerprint / validity window / SANs.
    Posture judgements (self-signed, expired, weak cipher) stay in the
    testssl ``RawFinding`` path - this shape answers "what cert is
    this", the findings answer "what is wrong with it".

    When amass lands (#45), each ``TLSCertificate`` becomes one amass
    ``TLSCertificate`` asset node:

    * ``fingerprint_sha256`` / ``serial`` -> the node's stable identity
      and the natural join key for a Censys / Shodan ``cert hash`` pivot.
    * ``subject_common_name`` / ``issuer`` / ``not_before`` /
      ``not_after`` -> ``SimpleProperty`` values on the node.
    * ``subject_alt_names`` -> ``SAN_FOR`` edges to the ``FQDN`` assets
      the cert vouches for; a multi-SAN cert is the densest single-asset
      FQDN-discovery surface recon produces.
    * ``host`` -> the edge back to the ``FQDN`` / ``IPAddress`` the cert
      was observed on (provenance), mirroring ``Service.host``.

    All fields beyond ``host`` default to None / empty - a cert is
    useful with whatever subset the grab recovered.
    """

    host: FQDN | IPAddress

    # Tool-captured from the leaf cert the *target* presents - i.e.
    # attacker-controlled text. Defence on every field below: a boundary
    # length cap (the cert owner picks these strings, so they are not
    # trustworthy); none are re-issued to an LLM as instruction context,
    # they flow to the asset graph and the human-facing report only.
    subject_common_name: str | None = Field(default=None, max_length=255)
    issuer: str | None = Field(default=None, max_length=255)  # issuing CA CN / org
    serial: str | None = Field(default=None, max_length=128)  # hex serial number
    fingerprint_sha256: str | None = Field(default=None, max_length=128)

    not_before: datetime | None = None  # validity window start
    not_after: datetime | None = None  # validity window end (expiry signal)

    # Subject Alternative Names exactly as the cert lists them. Bare
    # ``list[str]`` (not ``list[FQDN]`` like ``Endpoint.tls_sans``) on
    # purpose: a cert's SANs routinely include wildcards (``*.example.com``)
    # and occasionally ``iPAddress`` entries, which the FQDN validator
    # rejects - and the cert asset must represent the SANs faithfully
    # rather than drop the non-RFC-1123 ones the way the discovery-side
    # ``Endpoint.tls_sans`` does. Same defence posture as
    # ``Endpoint.technologies``: raw external strings, filtered through
    # ``filter_in_scope`` before any are promoted to in-scope hosts, and
    # never fed back to an LLM as instructions.
    subject_alt_names: list[str] = Field(default_factory=list)


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
