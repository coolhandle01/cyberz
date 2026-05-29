"""
squad/osint_analyst/enrichment.py - the OSINT post-sweep pivot surface.

Where ``discovery.py`` answers "what is the attack surface" (the sweep
and the slicers over it), this module carries the tools the OA reaches
for *after* the sweep to enrich and pivot on what it surfaced:

- ``Lookup IP Assets`` - ASN + RDAP + PTR for IPs the sweep surfaced,
  composed into one ``IpAsset`` per IP (the amass IPAddress-asset shape).

These are the "explore, don't just record" half: the sweep records the
surface; these tools let the agent follow a thread off it with
judgement. The ``recon-flow`` skill steers when to reach for each.

No scope filter on the IP-rooted lookups: the programme scope model is
FQDN-shaped, and the IPs the agent passes were surfaced (and
scope-filtered) by the sweep upstream. The filtering lives at the FQDN
boundary, not the IP one - see the per-tool notes below.
"""

from pydantic import BaseModel, Field

from models import IPAddress, IpAsset
from squad import cyber_tool
from tools.recon.ip_asset import compose_ip_assets


class _LookupIpAssetsArgs(BaseModel):
    """Explicit args_schema for the Lookup IP Assets tool."""

    ips: list[IPAddress] = Field(
        description=(
            "IPv4 / IPv6 addresses surfaced by the sweep (e.g. the"
            " resolved IPs behind in-scope hostnames, or traceroute"
            " hops worth enriching). Each is validated as an IP address;"
            " a hostname where an IP was expected rejects upstream"
            " (resolve it first via the sweep). Pass the IPs the sweep"
            " already surfaced - this tool does not discover new IPs, it"
            " enriches known ones. Duplicates dedupe."
        ),
    )


@cyber_tool("Lookup IP Assets", args_schema=_LookupIpAssetsArgs)
def lookup_ip_assets_tool(ips: list[IPAddress]) -> list[IpAsset]:
    """
    Enrich a set of IPs with ASN, RDAP, and reverse-DNS (PTR) data,
    returning one ``IpAsset`` per unique IP. This is the IP-rooted pivot:
    given IPs the sweep surfaced, find the netblock / AS-owner (Team
    Cymru), the registrant + abuse contact (RDAP), and any cohabiting
    hostnames that PTR back to the same IP.

    Fires outbound lookups per IP: Team Cymru bulk-whois (ASN), an RDAP
    HTTP fetch (registrant), and a dnsx ``-ptr`` reverse query. Each
    source degrades independently - an IP with only ASN data still
    returns a useful ``IpAsset`` rather than being dropped.

    Returns ``list[IpAsset]`` ({ip, asn, rdap, ptr}), ordered by the
    de-duplicated input; empty list on empty input. PTR-discovered
    hostnames ride in on ``IpAsset.ptr`` and are out-of-scope by
    default - they are pivot evidence, not in-scope assets, until the
    annotation pass promotes any that share the programme's apex.
    """
    return compose_ip_assets(ips)


__all__ = [
    "_LookupIpAssetsArgs",
    "lookup_ip_assets_tool",
]
