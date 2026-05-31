"""Decompose RDAP registrant lookups into their OAM asset subgraph.

RDAP answers "who owns this resource". This decomposes the recon-internal
``RdapRecord`` parse shape into faithful OAM assets - the analogue of
``services_from_nmap`` for the registration layer.

This module covers the **autnum** (AS-registration) side: an RDAP-by-ASN lookup
yields the ``AutnumRecord`` registry record, the registrant ``Organization``,
and the contact emails as ``Identifier`` assets, joined by the spec relation
labels (``registrant_org`` / ``managed_by`` / ``<role>_email``). The IP-network
side (``IPNetRecord``, which needs the CIDR correlated from the Cymru netblock)
lands in its own slice.
"""

from __future__ import annotations

from typing import NamedTuple

from models import AutnumRecord, Identifier, Organization, Relation, RelationType
from models.asset.network import RdapRecord


class RegistrantGraph(NamedTuple):
    """The OAM registration subgraph a set of RDAP records decomposes into.

    ``organizations`` / ``autnum_records`` / ``identifiers`` are the asset nodes
    (de-duplicated by identity); ``relations`` are the ``registrant_org`` /
    ``managed_by`` / ``<role>_email`` edges that ``relations.json`` holds.
    """

    organizations: list[Organization]
    autnum_records: list[AutnumRecord]
    identifiers: list[Identifier]
    relations: list[Relation]


def _asn_from_query(query: str) -> int | None:
    """Parse the ASN out of an RDAP autnum query ("AS15169" -> 15169).

    Returns ``None`` for an IP-network query (handled by the IPNetRecord
    producer) or a mis-shaped value.
    """
    if query.startswith("AS") and query[2:].isdigit():
        return int(query[2:])
    return None


def autnum_assets_from_rdap(rdap_records: list[RdapRecord]) -> RegistrantGraph:
    """Decompose RDAP-by-ASN records into the OAM registration subgraph.

    One ``AutnumRecord`` per AS (de-duplicated by number), the registrant
    ``Organization`` (by name), and an ``Identifier`` per contact email - with
    a ``registrant_org`` edge (AutnumRecord -> Organization), a ``managed_by``
    edge (AutonomousSystem -> Organization), and a ``<role>_email`` edge from
    the registrant (or the AS record when no org) to each email. IP-network
    RDAP records are skipped here.
    """
    organizations: dict[str, Organization] = {}
    autnum_by_number: dict[int, AutnumRecord] = {}
    identifiers: dict[str, Identifier] = {}
    relations: list[Relation] = []

    for rec in rdap_records:
        asn = _asn_from_query(rec.query)
        if asn is None:
            continue
        autnum_by_number.setdefault(asn, AutnumRecord(number=asn, handle=rec.handle or ""))
        autnum_key = rec.handle or f"AS{asn}"

        org_key: str | None = None
        if rec.registrant_organisation:
            org = organizations.setdefault(
                rec.registrant_organisation,
                Organization(name=rec.registrant_organisation),
            )
            org_key = org.name
            relations.append(
                Relation(
                    relation_type=RelationType.SIMPLE,
                    label="registrant_org",
                    from_key=autnum_key,
                    to_key=org_key,
                )
            )
            relations.append(
                Relation(
                    relation_type=RelationType.SIMPLE,
                    label="managed_by",
                    from_key=f"AS{asn}",
                    to_key=org_key,
                )
            )

        anchor = org_key or autnum_key
        for contact in rec.contacts:
            if contact.email:
                ident = identifiers.setdefault(
                    contact.email, Identifier(id=contact.email, id_type="email")
                )
                relations.append(
                    Relation(
                        relation_type=RelationType.SIMPLE,
                        label=f"{contact.role.value}_email",
                        from_key=anchor,
                        to_key=ident.id,
                    )
                )

    return RegistrantGraph(
        list(organizations.values()),
        list(autnum_by_number.values()),
        list(identifiers.values()),
        relations,
    )


__all__ = ["RegistrantGraph", "autnum_assets_from_rdap"]
