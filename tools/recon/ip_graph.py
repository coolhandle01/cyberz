"""Decompose Team Cymru ASN lookups into their OAM IP-routing subgraph.

The faithful replacement for the legacy ``IpAsset`` composition: where
``compose_ip_assets`` bundled ASN / RDAP / PTR into one record per IP, this
decomposes Cymru's bulk-whois rows into the OAM routing spine - one
``IPAddress`` node per IP, the ``Netblock`` it sits in, the ``AutonomousSystem``
that announces that prefix, and the typed relations that join them
(``contains``: Netblock -> IPAddress; ``announces``: AutonomousSystem ->
Netblock). The analogue of ``services_from_nmap`` for the IP layer.

RDAP registrant assets (``AutnumRecord`` / ``IPNetRecord`` / ``Organization`` /
``ContactRecord``) and reverse-DNS (``ptr_record``) land in their own slices;
``AsnRecord`` is the recon-internal parse shape this reads, the way
``services_from_nmap`` reads ``NmapHostResult``.
"""

from __future__ import annotations

import ipaddress
from typing import NamedTuple

from models import (
    AutonomousSystem,
    IPAddress,
    Netblock,
    Relation,
    RelationType,
    SourceProperty,
)
from models.asset.network import AsnRecord
from models.primitives import IPType

# Cymru bulk-whois is the BGP routing table itself - authoritative for the
# ASN / prefix layer - so its assets carry a full-confidence provenance stamp.
_CYMRU_SOURCE = "team-cymru"
_CYMRU_CONFIDENCE = 100


class IpGraph(NamedTuple):
    """The OAM IP-routing subgraph a set of Cymru rows decomposes into.

    ``addresses`` / ``netblocks`` / ``autonomous_systems`` are the asset nodes
    (de-duplicated by their OAM identity); ``relations`` are the ``contains`` /
    ``announces`` edges that ``relations.json`` holds.
    """

    addresses: list[IPAddress]
    netblocks: list[Netblock]
    autonomous_systems: list[AutonomousSystem]
    relations: list[Relation]


def _ip_type(address: str) -> IPType:
    """IPv4 / IPv6 from the literal (already validated by the ``IpAddr`` field)."""
    return IPType.IPV6 if ipaddress.ip_address(address).version == 6 else IPType.IPV4


def _cidr_type(cidr: str) -> IPType:
    """IPv4 / IPv6 from a CIDR prefix (already validated by the ``Cidr`` field)."""
    return IPType.IPV6 if ipaddress.ip_network(cidr).version == 6 else IPType.IPV4


def ip_assets_from_asn(asn_records: list[AsnRecord]) -> IpGraph:
    """Decompose Cymru ASN rows into the OAM IP-routing subgraph.

    One ``IPAddress`` per IP, one ``Netblock`` per announced prefix, one
    ``AutonomousSystem`` per ASN - de-duplicated by identity (address / cidr /
    number) across the batch - plus a ``contains`` edge (Netblock -> IPAddress)
    and an ``announces`` edge (AutonomousSystem -> Netblock) per row. Rows whose
    prefix fails ``Cidr`` validation drop the netblock/AS edges but keep the
    IPAddress node.
    """
    addresses: dict[str, IPAddress] = {}
    netblocks: dict[str, Netblock] = {}
    autonomous_systems: dict[int, AutonomousSystem] = {}
    relations: list[Relation] = []

    def _source() -> SourceProperty:
        return SourceProperty(source=_CYMRU_SOURCE, confidence=_CYMRU_CONFIDENCE)

    for record in asn_records:
        addresses.setdefault(
            record.ip,
            IPAddress(address=record.ip, type=_ip_type(record.ip), sources=[_source()]),
        )
        try:
            netblock = Netblock(cidr=record.prefix, type=_cidr_type(record.prefix))
        except ValueError:
            # Cymru returned a prefix the Cidr primitive rejects; keep the
            # IPAddress node but skip the netblock / AS edges for this row.
            continue
        netblocks.setdefault(netblock.cidr, netblock)
        autonomous_systems.setdefault(record.asn, AutonomousSystem(number=record.asn))

        as_key = f"AS{record.asn}"
        relations.append(
            Relation(
                relation_type=RelationType.SIMPLE,
                label="contains",
                from_key=netblock.cidr,
                to_key=record.ip,
            )
        )
        relations.append(
            Relation(
                relation_type=RelationType.SIMPLE,
                label="announces",
                from_key=as_key,
                to_key=netblock.cidr,
            )
        )

    return IpGraph(
        list(addresses.values()),
        list(netblocks.values()),
        list(autonomous_systems.values()),
        relations,
    )


__all__ = ["IpGraph", "ip_assets_from_asn"]
