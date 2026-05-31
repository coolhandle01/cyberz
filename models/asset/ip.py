"""
models.asset.ip - the cybersquad ``IpAsset`` (amass IPAddress asset).

Composes the per-IP enrichment lookups (Cymru ASN, RDAP registrant, dnsx
PTR) into one typed record. Depends on the ``models.asset.network``
registrant / ASN shapes.

OAM asset (``IPAddress``):
<https://owasp-amass.github.io/docs/open_asset_model/assets/ip_address/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.asset.network import AsnRecord, RdapRecord
from models.primitives import FQDN, IpAddr


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

    ip: IpAddr
    asn: AsnRecord | None = None
    rdap: RdapRecord | None = None
    ptr: list[FQDN] = Field(default_factory=list)
