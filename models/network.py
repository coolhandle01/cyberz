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

TODO(#180): ``RdapRecord`` lands here as the structured-registrant
sibling of ``AsnRecord``. RFC 7483 / RDAP gives us per-field
registrant_organisation / registrar / registered_at / abuse_email /
nameservers rather than Cymru's single stringly-typed organisation
field. Each field becomes a separate amass Property on the asset; the
agent reads them individually rather than parsing a concatenation.
That's the "structured registrant entry in amass" target shape -
this module gets it once #180 lands.

Distinct from ``models/scanner.py`` - that file carries the CLI
scanner config (NmapMode / HttpxMode / scan-result shapes). This file
describes the asset; ``scanner.py`` describes the scan.
"""

from __future__ import annotations

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


__all__ = ["AsnRecord"]
