"""Decompose dnsx forward-resolution records into OAM ``DNSRecordProperty``.

Each A / CNAME answer dnsx returns for a host becomes a ``DNSRecordProperty``
hung off that host's ``FQDN`` node - the record's *content* - faithful to OAM
modelling a DNS record as a property on the FQDN (as well as a relation edge to
the answer asset). The relation edges (``BasicDNSRelation``: FQDN -> IPAddress /
FQDN) persist separately through the relations facet; this producer is the
property side, the analogue of ``services_from_nmap`` for the DNS layer.
"""

from __future__ import annotations

from models import DNSRecordProperty, RRHeader
from tools.recon.dnsx import DNSRecord

# DNS numeric resource-record type codes (IANA / RFC 1035) and the IN class.
_RR_TYPE_A = 1
_RR_TYPE_CNAME = 5
_RR_CLASS_IN = 1


def dns_records_from_dnsx(records: list[DNSRecord]) -> list[DNSRecordProperty]:
    """Turn dnsx forward records into OAM ``DNSRecordProperty`` entries.

    One property per A answer (rr_type 1) and per CNAME answer (rr_type 5):
    ``property_name`` is the resolved host, ``data`` the answer (IP / CNAME
    target). ``ttl`` is 0 - dnsx's forward output as parsed into ``DNSRecord``
    does not carry a per-record TTL; the field is modelled faithfully and
    populates if TTL capture is wired into ``resolve_records`` later.
    """
    properties: list[DNSRecordProperty] = []
    for record in records:
        for ip in record.a_records:
            properties.append(
                DNSRecordProperty(
                    property_name=record.hostname,
                    header=RRHeader(rr_type=_RR_TYPE_A, rr_class=_RR_CLASS_IN),
                    data=ip,
                )
            )
        for cname in record.cname:
            properties.append(
                DNSRecordProperty(
                    property_name=record.hostname,
                    header=RRHeader(rr_type=_RR_TYPE_CNAME, rr_class=_RR_CLASS_IN),
                    data=cname,
                )
            )
    return properties


__all__ = ["dns_records_from_dnsx"]
