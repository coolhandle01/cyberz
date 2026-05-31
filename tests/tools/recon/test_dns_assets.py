"""tests/tools/recon/test_dns_assets.py - unit tests for the dnsx -> OAM
DNSRecordProperty decomposition (tools/recon/dns_assets.py).
"""

from __future__ import annotations

import pytest

from tools.recon.dns_assets import dns_records_from_dnsx
from tools.recon.dnsx import DNSRecord

pytestmark = pytest.mark.unit


class TestDnsRecordsFromDnsx:
    def test_a_record_becomes_property(self, target_apex):
        props = dns_records_from_dnsx(
            [DNSRecord(hostname=f"api.{target_apex}", a_records=["8.8.8.8"], cname=[])]
        )
        assert len(props) == 1
        assert props[0].property_name == f"api.{target_apex}"
        assert props[0].header.rr_type == 1  # A
        assert props[0].header.rr_class == 1  # IN
        assert props[0].data == "8.8.8.8"

    def test_cname_becomes_property(self, target_apex):
        props = dns_records_from_dnsx(
            [DNSRecord(hostname=f"www.{target_apex}", a_records=[], cname=[f"api.{target_apex}"])]
        )
        assert len(props) == 1
        assert props[0].header.rr_type == 5  # CNAME
        assert props[0].data == f"api.{target_apex}"

    def test_multiple_answers_each_get_a_property(self, target_apex):
        props = dns_records_from_dnsx(
            [
                DNSRecord(
                    hostname=f"api.{target_apex}",
                    a_records=["8.8.8.8", "8.8.4.4"],
                    cname=[f"lb.{target_apex}"],
                )
            ]
        )
        # two A answers + one CNAME = three properties, in answer order.
        assert len(props) == 3
        assert [p.data for p in props] == ["8.8.8.8", "8.8.4.4", f"lb.{target_apex}"]

    def test_empty_input(self):
        assert dns_records_from_dnsx([]) == []
