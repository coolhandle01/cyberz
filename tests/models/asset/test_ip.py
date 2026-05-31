"""tests/models/asset/test_ip.py - unit tests for models/asset/ip.py."""

from __future__ import annotations

import pytest

from models import IpAsset

pytestmark = pytest.mark.unit


class TestIpAsset:
    def test_ip_only_minimum(self):
        # An IpAsset with only an IP is a useful starting record - the
        # asn / rdap / ptr fields populate as enrichment completes.

        asset = IpAsset(ip="8.8.8.8")
        assert asset.ip == "8.8.8.8"
        assert asset.asn is None
        assert asset.rdap is None
        assert asset.ptr == []

    def test_composes_typed_records(self, target_apex):
        # The nested ``AsnRecord`` / ``RdapRecord`` / PTR hostnames
        # arrive as separate lookups; IpAsset is the join point.
        from models.network import AsnRecord

        asset = IpAsset(
            ip="8.8.8.8",
            asn=AsnRecord(
                ip="8.8.8.8",
                asn=15169,
                prefix="8.8.8.0/24",
                country="US",
                organisation="GOOGLE, US",
            ),
            ptr=[f"api.{target_apex}"],
        )
        assert asset.asn is not None
        assert asset.asn.asn == 15169
        assert asset.ptr == [f"api.{target_apex}"]

    def test_serialise_roundtrip(self):

        original = IpAsset(ip="1.1.1.1", ptr=["one.one.one.one"])
        restored = IpAsset.model_validate_json(original.model_dump_json())
        assert restored.ip == "1.1.1.1"
        assert restored.ptr == ["one.one.one.one"]

    def test_invalid_ip_rejects(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            IpAsset(ip="not an ip")
