"""tests/tools/recon/test_rdap_assets.py - unit tests for the RDAP -> OAM
registration subgraph decomposition (tools/recon/rdap_assets.py).
"""

from __future__ import annotations

import pytest

from models import RelationType
from models.asset.network import Contact, ContactRole, RdapRecord
from tools.recon.rdap_assets import autnum_assets_from_rdap

pytestmark = pytest.mark.unit


class TestAutnumAssetsFromRdap:
    def test_full_asn_record(self):
        g = autnum_assets_from_rdap(
            [
                RdapRecord(
                    query="AS15169",
                    handle="AS15169",
                    registrant_organisation="Google LLC",
                    contacts=[Contact(role=ContactRole.ABUSE, email="abuse@google.com")],
                )
            ]
        )
        assert [a.number for a in g.autnum_records] == [15169]
        assert [o.name for o in g.organizations] == ["Google LLC"]
        assert [i.id for i in g.identifiers] == ["abuse@google.com"]
        assert g.identifiers[0].id_type == "email"

        labels = {r.label for r in g.relations}
        assert labels == {"registrant_org", "managed_by", "abuse_email"}
        managed_by = next(r for r in g.relations if r.label == "managed_by")
        assert managed_by.relation_type == RelationType.SIMPLE
        assert managed_by.from_key == "AS15169"
        assert managed_by.to_key == "Google LLC"
        registrant = next(r for r in g.relations if r.label == "registrant_org")
        assert registrant.from_key == "AS15169"  # the handle
        assert registrant.to_key == "Google LLC"
        abuse = next(r for r in g.relations if r.label == "abuse_email")
        assert abuse.from_key == "Google LLC"  # anchored on the org
        assert abuse.to_key == "abuse@google.com"

    def test_no_org_anchors_email_on_autnum(self):
        g = autnum_assets_from_rdap(
            [
                RdapRecord(
                    query="AS64500",
                    handle="",
                    contacts=[Contact(role=ContactRole.ABUSE, email="noc@example.net")],
                )
            ]
        )
        assert g.organizations == []
        abuse = next(r for r in g.relations if r.label == "abuse_email")
        assert abuse.from_key == "AS64500"  # no org, no handle -> the AS key

    def test_ip_query_is_skipped(self):
        # An IP-network RDAP record is handled by the IPNetRecord producer.
        g = autnum_assets_from_rdap([RdapRecord(query="8.8.8.8", handle="NET-8-8-8-0-1")])
        assert g == ([], [], [], [])

    def test_dedupes_org_and_autnum(self):
        rec = RdapRecord(query="AS15169", handle="AS15169", registrant_organisation="Google LLC")
        g = autnum_assets_from_rdap([rec, rec])
        assert len(g.autnum_records) == 1
        assert len(g.organizations) == 1

    def test_empty(self):
        assert autnum_assets_from_rdap([]) == ([], [], [], [])
