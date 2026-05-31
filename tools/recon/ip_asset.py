"""
tools/recon/ip_asset.py - IP-rooted enrichment, composes ``IpAsset`` records.

For each unique IP, runs the three IP-rooted lookups we already have:

* ``lookup_asn`` (Team Cymru) - ASN + netblock + AS-name + country
* ``resolve_ptr`` (dnsx ``-ptr``) - reverse-DNS hostnames
* ``lookup_rdap_for_ip`` (RFC 7483) - registrant + abuse contact

Each lookup runs independently. None / empty results degrade the
corresponding field on the ``IpAsset`` rather than dropping the asset
itself - an IP with only ASN data is still useful. One IpAsset per
unique IP; duplicates dedupe on input.

This is the "amass IPAddress asset + hanging SimpleProperty values"
shape the OA's enrichment pass produces. Per-IP file evidence (PTR
zone snapshots, RDAP raw payloads) is out of scope here - the typed
record is what downstream agents consume; raw evidence can land in
the per-host ``hosts/<fqdn>/`` directory when the host-resolution
join is made.
"""

from __future__ import annotations

import logging

from models.asset import IpAsset
from models.primitives import IPAddress
from tools.recon.asn import lookup_asn
from tools.recon.dnsx import resolve_ptr
from tools.recon.rdap import lookup_rdap_for_ip

logger = logging.getLogger(__name__)


def compose_ip_assets(
    ips: list[IPAddress],
    *,
    with_rdap: bool = True,
) -> list[IpAsset]:
    """Build one ``IpAsset`` per unique IP, populating all three lookups.

    ``with_rdap=False`` skips the per-IP RDAP HTTP fetches when the OA
    wants the cheap ASN+PTR enrichment without paying for the
    registrant detail (RDAP is per-IP HTTP; the others batch). Defaults
    True so the full enrichment is the cheap-default opt-out.

    Returns ``list[IpAsset]`` ordered by the de-duplicated input. Empty
    list on empty input. Per-IP failures (validator rejection) drop the
    affected record only; the rest of the batch lands.
    """
    if not ips:
        return []

    unique = list(dict.fromkeys(ips))

    asn_by_ip = {record.ip: record for record in lookup_asn(unique)}
    ptr_by_ip = {record.ip: record for record in resolve_ptr(unique)}

    assets: list[IpAsset] = []
    for ip in unique:
        rdap = lookup_rdap_for_ip(ip) if with_rdap else None
        ptr_record = ptr_by_ip.get(ip)
        ptr_hostnames = list(ptr_record.hostnames) if ptr_record else []
        try:
            assets.append(
                IpAsset(
                    ip=ip,
                    asn=asn_by_ip.get(ip),
                    rdap=rdap,
                    ptr=ptr_hostnames,
                )
            )
        except ValueError as exc:
            # IPAddress validator rejected an unexpected shape upstream.
            # Drop this asset rather than failing the whole batch.
            logger.debug("ip_asset rejected for %s: %s", ip, exc)
            continue
    logger.info("composed %d IpAsset records from %d unique IPs", len(assets), len(unique))
    return assets


__all__ = ["compose_ip_assets"]
