"""tests/tools/recon/test_ip_asset.py - unit tests for the IP enrichment composer."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models import IpAsset
from models.asset.network import AsnRecord, RdapRecord
from models.dns import PtrRecord
from tools.recon.ip_asset import compose_ip_assets

pytestmark = pytest.mark.unit


def _asn(ip: str, asn: int = 15169, org: str = "GOOGLE, US") -> AsnRecord:
    return AsnRecord(ip=ip, asn=asn, prefix=f"{ip}/24", country="US", organisation=org)


def _ptr(ip: str, hostnames: list[str]) -> PtrRecord:
    return PtrRecord(ip=ip, hostnames=hostnames)


def _rdap(ip: str) -> RdapRecord:
    return RdapRecord(
        query=ip,
        handle="NET-X",
        rir="ARIN",
        registrant_organisation="Google LLC",
        source_url=f"https://rdap.arin.net/registry/ip/{ip}",
    )


class TestComposeIpAssets:
    def test_empty_input_returns_empty(self):
        assert compose_ip_assets([]) == []

    def test_joins_three_lookups_per_ip(self):
        with (
            patch("tools.recon.ip_asset.lookup_asn", return_value=[_asn("8.8.8.8")]) as mock_asn,
            patch(
                "tools.recon.ip_asset.resolve_ptr",
                return_value=[_ptr("8.8.8.8", ["dns.google"])],
            ) as mock_ptr,
            patch(
                "tools.recon.ip_asset.lookup_rdap_for_ip", return_value=_rdap("8.8.8.8")
            ) as mock_rdap,
        ):
            assets = compose_ip_assets(["8.8.8.8"])

        # The batch lookups are called once with the de-duplicated list;
        # RDAP is per-IP.
        mock_asn.assert_called_once_with(["8.8.8.8"])
        mock_ptr.assert_called_once_with(["8.8.8.8"])
        mock_rdap.assert_called_once_with("8.8.8.8")

        assert len(assets) == 1
        asset = assets[0]
        assert isinstance(asset, IpAsset)
        assert asset.ip == "8.8.8.8"
        assert asset.asn is not None and asset.asn.asn == 15169
        assert asset.rdap is not None and asset.rdap.handle == "NET-X"
        assert asset.ptr == ["dns.google"]

    def test_with_rdap_false_skips_per_ip_http(self):
        with (
            patch("tools.recon.ip_asset.lookup_asn", return_value=[]),
            patch("tools.recon.ip_asset.resolve_ptr", return_value=[]),
            patch("tools.recon.ip_asset.lookup_rdap_for_ip") as mock_rdap,
        ):
            assets = compose_ip_assets(["8.8.8.8"], with_rdap=False)

        mock_rdap.assert_not_called()
        assert assets[0].rdap is None

    def test_deduplicates_input(self):
        with (
            patch("tools.recon.ip_asset.lookup_asn", return_value=[]) as mock_asn,
            patch("tools.recon.ip_asset.resolve_ptr", return_value=[]),
            patch("tools.recon.ip_asset.lookup_rdap_for_ip", return_value=None) as mock_rdap,
        ):
            assets = compose_ip_assets(["8.8.8.8", "8.8.8.8", "1.1.1.1"])

        # De-dupes: one asset per unique IP, batch tools see the unique list,
        # RDAP fires once per unique IP.
        mock_asn.assert_called_once_with(["8.8.8.8", "1.1.1.1"])
        assert mock_rdap.call_count == 2
        assert [a.ip for a in assets] == ["8.8.8.8", "1.1.1.1"]

    def test_missing_lookups_degrade_to_none_per_field(self):
        # Cymru returns nothing for this IP; PTR finds nothing; RDAP returns
        # None. The IpAsset still lands with all fields empty.
        with (
            patch("tools.recon.ip_asset.lookup_asn", return_value=[]),
            patch("tools.recon.ip_asset.resolve_ptr", return_value=[]),
            patch("tools.recon.ip_asset.lookup_rdap_for_ip", return_value=None),
        ):
            assets = compose_ip_assets(["8.8.8.8"])

        assert len(assets) == 1
        assert assets[0].asn is None
        assert assets[0].rdap is None
        assert assets[0].ptr == []

    def test_partial_enrichment_lands_per_ip(self):
        # Two IPs: one has ASN+PTR, the other has only RDAP. Both land
        # with whichever fields populated.
        with (
            patch("tools.recon.ip_asset.lookup_asn", return_value=[_asn("8.8.8.8")]),
            patch(
                "tools.recon.ip_asset.resolve_ptr",
                return_value=[_ptr("8.8.8.8", ["dns.google"])],
            ),
            patch(
                "tools.recon.ip_asset.lookup_rdap_for_ip",
                side_effect=[None, _rdap("1.1.1.1")],
            ),
        ):
            assets = compose_ip_assets(["8.8.8.8", "1.1.1.1"])

        by_ip = {a.ip: a for a in assets}
        assert by_ip["8.8.8.8"].asn is not None
        assert by_ip["8.8.8.8"].rdap is None
        assert by_ip["8.8.8.8"].ptr == ["dns.google"]
        assert by_ip["1.1.1.1"].asn is None
        assert by_ip["1.1.1.1"].rdap is not None
        assert by_ip["1.1.1.1"].ptr == []

    def test_invalid_ip_drops_that_asset_only(self):
        # An IP that fails the IPAddress validator skips its IpAsset
        # construction; the rest of the batch lands intact.
        with (
            patch("tools.recon.ip_asset.lookup_asn", return_value=[]),
            patch("tools.recon.ip_asset.resolve_ptr", return_value=[]),
            patch("tools.recon.ip_asset.lookup_rdap_for_ip", return_value=None),
        ):
            assets = compose_ip_assets(["not an ip", "8.8.8.8"])

        assert [a.ip for a in assets] == ["8.8.8.8"]
