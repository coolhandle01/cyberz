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

from models import IPAddress, IpAsset, RdapRecord
from squad import cyber_tool
from tools.recon.ip_asset import compose_ip_assets
from tools.recon.rdap import lookup_rdap_for_asn


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


class _LookupRdapAsnArgs(BaseModel):
    """Explicit args_schema for the Lookup RDAP for ASN tool."""

    asn: int = Field(
        ge=0,
        le=4_294_967_295,  # 32-bit ASN range per RFC 6793
        description=(
            "Autonomous System Number to look up, as a bare integer (e.g."
            " 13335 for Cloudflare) - no ``AS`` prefix; a non-numeric"
            " string rejects upstream. Read it off an ``IpAsset.asn``"
            " record surfaced by Lookup IP Assets. Out-of-range values"
            " (negative, or above the 32-bit ceiling) reject at the"
            " boundary."
        ),
    )


@cyber_tool("Lookup RDAP for ASN", args_schema=_LookupRdapAsnArgs)
def lookup_rdap_asn_tool(asn: int) -> RdapRecord | None:
    """
    Look up the RDAP (RFC 7483) registration record for one ASN: the
    AS-owner organisation, abuse / registrant contacts, and registration
    events. This is the ASN-side pivot - IP-side RDAP already rides in on
    ``Lookup IP Assets`` (``IpAsset.rdap``), so reach for this when the
    question is about the AS itself: who to disclose to, or building a
    pattern-of-life view of an org's address space.

    Fires one RDAP HTTP fetch against the authoritative RIR (resolved via
    the IANA bootstrap registry). Returns an ``RdapRecord`` ({query,
    handle, rir, registrant_organisation, abuse_email, registered_at,
    last_changed_at, source_url, contacts}), or ``None`` when the
    bootstrap has no entry for the ASN or the RIR lookup fails - the OA
    keeps moving rather than blocking on a miss.
    """
    return lookup_rdap_for_asn(asn)


__all__ = [
    "_LookupIpAssetsArgs",
    "_LookupRdapAsnArgs",
    "lookup_ip_assets_tool",
    "lookup_rdap_asn_tool",
]
