"""tests/tools/recon/test_ip_graph.py - unit tests for the Cymru ASN -> OAM
IP-routing subgraph decomposition (tools/recon/ip_graph.py).
"""

from __future__ import annotations

import pytest

from models import RelationType
from models.asset.network import AsnRecord
from tools.recon.ip_graph import ip_assets_from_asn

pytestmark = pytest.mark.unit


def _row(ip="8.8.8.8", asn=15169, prefix="8.8.8.0/24", country="US", org="GOOGLE, US"):
    return AsnRecord(ip=ip, asn=asn, prefix=prefix, country=country, organisation=org)


class TestIpAssetsFromAsn:
    def test_single_row_builds_routing_spine(self):
        g = ip_assets_from_asn([_row()])
        assert [a.address for a in g.addresses] == ["8.8.8.8"]
        assert g.addresses[0].type == "IPv4"
        assert g.addresses[0].sources[0].source == "team-cymru"
        assert [n.cidr for n in g.netblocks] == ["8.8.8.0/24"]
        assert [s.number for s in g.autonomous_systems] == [15169]
        # contains: Netblock -> IPAddress ; announces: AutonomousSystem -> Netblock
        contains = next(r for r in g.relations if r.label == "contains")
        assert contains.relation_type == RelationType.SIMPLE
        assert contains.from_key == "8.8.8.0/24"
        assert contains.to_key == "8.8.8.8"
        announces = next(r for r in g.relations if r.label == "announces")
        assert announces.from_key == "AS15169"
        assert announces.to_key == "8.8.8.0/24"

    def test_dedupes_netblock_and_as_across_ips(self):
        g = ip_assets_from_asn([_row(ip="8.8.8.8"), _row(ip="8.8.8.9")])
        assert len(g.addresses) == 2
        assert len(g.netblocks) == 1  # same prefix
        assert len(g.autonomous_systems) == 1  # same ASN
        assert sum(1 for r in g.relations if r.label == "contains") == 2

    def test_ipv6_row(self):
        g = ip_assets_from_asn([_row(ip="2001:db8::1", asn=64500, prefix="2001:db8::/32")])
        assert g.addresses[0].type == "IPv6"
        assert g.netblocks[0].type == "IPv6"

    def test_bad_prefix_keeps_address_drops_edges(self):
        # A prefix the Cidr primitive rejects: keep the IPAddress node, skip the
        # netblock / AS edges for that row.
        g = ip_assets_from_asn([_row(prefix="not-a-cidr")])
        assert [a.address for a in g.addresses] == ["8.8.8.8"]
        assert g.netblocks == []
        assert g.autonomous_systems == []
        assert g.relations == []

    def test_empty(self):
        assert ip_assets_from_asn([]) == ([], [], [], [])
