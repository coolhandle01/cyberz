"""
models/network.py - typed shapes for the asset-layer network properties
of an attack surface.

Sits between ``models.primitives.IPAddress`` (the typed address) and
``models.asset`` (the FQDN / Endpoint layer agents reason about). The
data here is what Team Cymru bulk-whois, RDAP lookups, and (eventually)
amass's graph emit about the IP-layer ownership of an asset.

When amass lands (#45), the ASN / netblock / RIR-Org data persists
there as ``SimpleProperty`` / ``SourceProperty`` values on amass's
``IPAddress`` and ``ASN`` asset nodes. This module is the runtime
in-memory shape; the amass-side property is the persisted shape. Two
layers, one model.

Reference: the Open Asset Model's IPAddress / AutonomousSystem /
Netblock / RIROrganization asset types
(https://github.com/owasp-amass/open-asset-model).

``RdapRecord`` is the structured-registrant sibling of ``AsnRecord``.
RFC 7483 / RDAP gives us per-field registrant_organisation /
abuse_email / registered_at / last_changed_at rather than Cymru's
single stringly-typed organisation field. Each field becomes a separate
amass ``SimpleProperty`` on the ``RIROrganization`` asset; the agent
reads them individually rather than parsing a concatenation. The
``RdapRecord`` here is the runtime in-memory shape; the
``RIROrganization`` properties at amass-write time are the persisted
shape. Two layers, one record.

Distinct from ``models/scanner.py`` - that file carries the CLI
scanner config (NmapMode / HttpxMode / scan-result shapes). This file
describes the asset; ``scanner.py`` describes the scan.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from models.primitives import IPAddress


class AsnRecord(BaseModel):
    """One row of the Team Cymru / RDAP IP-to-ASN lookup result.

    Carries the four data points a Cymru bulk whois returns for a
    given IP: the AS number, the announcing BGP prefix (== netblock),
    the country code, and the registered AS organisation name. RDAP
    can fill the same fields when Cymru is unreachable.

    Maps cleanly to amass's Open Asset Model triple:
    ``IPAddress -> Netblock -> AutonomousSystem``. ``prefix`` is the
    netblock; ``asn`` + ``organisation`` are the AS. Stored together
    here because Cymru returns them as one row - splitting them
    pre-amass adds joins for no gain.
    """

    ip: IPAddress
    asn: int = Field(ge=0, le=4_294_967_295)  # 32-bit ASN range per RFC 6793
    prefix: str = Field(
        max_length=64,
        # CIDR notation, e.g. "1.2.3.0/24" or "2001:db8::/32". Validated
        # up-front by Cymru; we cap length as a boundary defence in case
        # an injection ever slips past Cymru's response shape.
    )
    country: str = Field(
        max_length=8,
        # Two-letter ISO 3166-1 alpha-2 (e.g. "GB", "US"). Capped loose
        # to allow for Cymru's occasional 4-char variants ("EU" / "AP")
        # without rejecting on real-world data.
    )
    organisation: str = Field(
        max_length=255,
        # Tool-captured from Cymru's response. Defence: Cymru emits
        # short trustworthy strings (typically "<AS_NAME>, <CC>"); the
        # length cap is the boundary guard, no further sanitisation
        # needed at this layer.
    )


class RdapRecord(BaseModel):
    """Structured-registrant record from an RDAP (RFC 7483) lookup.

    Maps to amass's ``RIROrganization`` asset - the entity an IP /
    netblock / ASN is registered to. Where ``AsnRecord`` carries the
    Cymru flat row (ASN + netblock + AS-name + country in one string),
    ``RdapRecord`` carries the RDAP-structured equivalent: each
    registrant property is a separate field, abuse contact is its own
    typed entry, registration / last-change events are typed datetimes
    rather than strings.

    Both lookups can run for the same IP - they answer different
    questions: ``AsnRecord`` asks "what ASN announces this IP" (BGP-
    routing layer), ``RdapRecord`` asks "what RIR entity owns this
    address space" (registration layer). The two together populate the
    full ``IPAddress -> Netblock -> AutonomousSystem -> RIROrganization``
    OAM chain.

    All optional fields default to None - RIRs vary in which entities
    they expose (some omit abuse contacts, some omit events), and the
    record is useful with whatever subset returns. ``source_url`` is
    the audit trail: the RDAP endpoint we actually queried, so a future
    re-lookup or a triage cross-check has a deterministic starting
    point.
    """

    query: str = Field(
        max_length=64,
        # The IP address (e.g. "8.8.8.8") or AS handle (e.g. "AS15169")
        # we sent to RDAP. Captured as-sent so the record carries its
        # own provenance; the validator on the typed lookup-fn entry
        # points already rejected mis-shaped values upstream.
    )
    handle: str | None = Field(
        default=None,
        max_length=128,
        # The RIR-assigned handle for this resource (e.g. "NET-8-8-8-0-1"
        # for an ARIN network, "AS15169" for an ARIN autnum). Stable
        # across re-lookups; the natural join key into the RIROrganization
        # asset once amass lands.
    )
    rir: str | None = Field(
        default=None,
        max_length=16,
        # Which Regional Internet Registry served this record:
        # ARIN / RIPE / APNIC / LACNIC / AFRINIC. Derived from the
        # bootstrap registry hop, not from the RDAP payload itself.
    )
    registrant_organisation: str | None = Field(
        default=None,
        max_length=255,
        # The registrant entity's display name from its vCard ``fn``
        # field. Tool-captured: RIRs validate this at registration time,
        # but length-cap as the boundary guard against an RDAP server
        # returning an outsize string.
    )
    abuse_email: str | None = Field(
        default=None,
        max_length=255,
        # Preferred contact email from the entity with role "abuse" in
        # the RDAP response. The natural target for a disclosure email
        # that needs to reach the asset owner directly rather than
        # through the bug bounty platform.
    )
    registered_at: datetime | None = Field(
        default=None,
        # Earliest "registration" event from the RDAP events array. When
        # the resource was first allocated by the RIR. None when the
        # RIR did not surface a registration event.
    )
    last_changed_at: datetime | None = Field(
        default=None,
        # Latest "last changed" event from the RDAP events array. Useful
        # signal for "registrant may have changed since the prior recon".
    )
    source_url: str | None = Field(
        default=None,
        max_length=512,
        # The RDAP endpoint URL we queried. Audit trail: a triage cross-
        # check or re-lookup hits the same authoritative endpoint
        # without re-running the bootstrap-registry hop.
    )


__all__ = ["AsnRecord", "RdapRecord"]
