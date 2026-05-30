"""
tests/squad/osint_analyst/test_enrichment.py - contract + invocation tests
for the OSINT Analyst's post-sweep pivot tools in
``squad/osint_analyst/enrichment.py``.

The pivot tools (``Lookup IP Assets``, ``Lookup RDAP for ASN``, ``Deep
Scan Host``) are the "explore, don't just record" surface from #181:
the agent reaches for them *after* the initial sweep to enrich IPs it
surfaced, pivot on an ASN, or deep-scan a single host's open ports.

This file carries the wrapper-invocation + scope-decision cases; the
generic args_schema contract sweep (explicit schema wired, every field
described, closed-world mapping) is parametrised over ``MEMBER.schemas``
in ``test_args_schemas.py`` and picks these tools up automatically once
they are registered.
"""

from __future__ import annotations

import pytest

from models.asset import IpAsset, Service
from models.network import RdapRecord
from models.scanner import NmapHostResult, NmapMode, NmapScanResult, NmapScripts, NmapService
from squad.osint_analyst import (
    _DeepScanHostArgs,
    _LookupIpAssetsArgs,
    _LookupRdapAsnArgs,
    deep_scan_host_tool,
    lookup_ip_assets_tool,
    lookup_rdap_asn_tool,
)

pytestmark = pytest.mark.unit


class TestLookupIpAssets:
    """``Lookup IP Assets`` wraps ``compose_ip_assets`` - no scope filter.

    The IPs come from the sweep, which was already scope-filtered upstream
    (the programme scope model is FQDN-shaped, so there is no IP-level
    scope alias to apply). The wrapper is a thin typed pass-through.
    """

    def test_schema_accepts_ip_list(self) -> None:
        """A list of dotted-quad IPs validates without raising."""
        instance = _LookupIpAssetsArgs.model_validate({"ips": ["1.2.3.4", "8.8.8.8"]})
        assert instance.ips == ["1.2.3.4", "8.8.8.8"]

    def test_schema_rejects_non_ip(self) -> None:
        """A hostname where an IP was asked for rejects at the boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupIpAssetsArgs.model_validate({"ips": ["not-an-ip"]})

    def test_returns_composed_assets(self, invoke_tool, monkeypatch) -> None:
        """The wrapper returns ``compose_ip_assets``' typed result verbatim."""
        composed = [IpAsset(ip="1.2.3.4"), IpAsset(ip="8.8.8.8")]
        captured: dict[str, object] = {}

        def _fake_compose(ips):
            captured["ips"] = ips
            return composed

        monkeypatch.setattr("squad.osint_analyst.enrichment.compose_ip_assets", _fake_compose)

        result = invoke_tool(lookup_ip_assets_tool, ips=["1.2.3.4", "8.8.8.8"])

        assert result == composed
        assert captured["ips"] == ["1.2.3.4", "8.8.8.8"]


class TestLookupRdapAsn:
    """``Lookup RDAP for ASN`` wraps ``lookup_rdap_for_asn`` - no scope filter.

    The ASN-side pivot: IP-side RDAP is already embedded in ``IpAsset``,
    so this is the genuinely new lookup (who owns the AS, what's its
    registrant / abuse contact). The ASN is a number the agent read off
    an ``IpAsset.asn`` record, not a scope-bearing target.
    """

    def test_schema_accepts_asn(self) -> None:
        """A 32-bit ASN validates without raising."""
        instance = _LookupRdapAsnArgs.model_validate({"asn": 13335})
        assert instance.asn == 13335

    def test_schema_rejects_negative_asn(self) -> None:
        """ASN below the 0..2^32-1 range rejects at the boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupRdapAsnArgs.model_validate({"asn": -1})

    def test_schema_rejects_out_of_range_asn(self) -> None:
        """ASN above the 32-bit range rejects at the boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupRdapAsnArgs.model_validate({"asn": 4_294_967_296})

    def test_schema_rejects_non_numeric_asn(self) -> None:
        """An ``AS``-prefixed string is not coercible to int and rejects."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupRdapAsnArgs.model_validate({"asn": "AS13335"})

    def test_returns_rdap_record(self, invoke_tool, monkeypatch) -> None:
        """The wrapper returns ``lookup_rdap_for_asn``' result verbatim."""
        record = RdapRecord(query="AS13335", registrant_organisation="Cloudflare, Inc.")
        captured: dict[str, object] = {}

        def _fake_lookup(asn):
            captured["asn"] = asn
            return record

        monkeypatch.setattr("squad.osint_analyst.enrichment.lookup_rdap_for_asn", _fake_lookup)

        result = invoke_tool(lookup_rdap_asn_tool, asn=13335)

        assert result is record
        assert captured["asn"] == 13335

    def test_returns_none_on_miss(self, invoke_tool, monkeypatch) -> None:
        """A bootstrap / lookup miss returns ``None`` straight through."""
        monkeypatch.setattr("squad.osint_analyst.enrichment.lookup_rdap_for_asn", lambda asn: None)

        result = invoke_tool(lookup_rdap_asn_tool, asn=64512)

        assert result is None


class TestDeepScanHost:
    """``Deep Scan Host`` wraps ``nmap_scan`` in SERVICE_VERSION mode - this
    one DOES scope-filter.

    Unlike the IP / ASN lookups, the target is an FQDN, and the programme
    scope model is FQDN-shaped, so ``host`` is a ``TargetFQDN`` (single,
    loud-reject). An out-of-scope host raises at validation before any
    nmap subprocess fires. The wrapper deep-scans one host's known-open
    ports, returning the host's open ``Service`` assets (with CPE +
    provenance) and writing them to the host's ``services.json``.
    """

    def test_schema_accepts_in_scope_host(self, programme_in_workspace, target_apex) -> None:
        """An in-scope hostname + port list validates without raising."""
        instance = _DeepScanHostArgs.model_validate(
            {"host": f"api.{target_apex}", "ports": [22, 443]}
        )
        assert instance.host == f"api.{target_apex}"
        assert instance.ports == [22, 443]

    def test_schema_rejects_out_of_scope_host(self, programme_in_workspace, bystander_url) -> None:
        """A ``TargetFQDN`` host outside the programme scope rejects loudly."""
        from urllib.parse import urlparse

        from pydantic import ValidationError

        oos_host = urlparse(bystander_url).hostname
        with pytest.raises(ValidationError, match="not in the selected programme's scope"):
            _DeepScanHostArgs.model_validate({"host": oos_host, "ports": [443]})

    def test_schema_rejects_url_in_host(self, programme_in_workspace, target_url) -> None:
        """A URL where a bare hostname is expected trips the FQDN primitive."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _DeepScanHostArgs.model_validate({"host": target_url, "ports": [443]})

    def test_runs_service_version_scan_and_persists_services(
        self, invoke_tool, programme_in_workspace, target_apex, monkeypatch
    ) -> None:
        """The wrapper runs nmap in SERVICE_VERSION mode, translates the
        open services into OAM ``Service`` assets (with CPE + provenance),
        and writes them to the host's ``services.json``."""
        from tools.recon_host_store import load_host_services

        host = f"api.{target_apex}"
        host_result = NmapHostResult(
            host=host,
            services=[
                NmapService(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="OpenSSH",
                    version="7.4",
                    cpe="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                ),
                # A filtered port is not a present service - it must NOT
                # become a Service node (OAM is a presence graph).
                NmapService(port=443, protocol="tcp", state="filtered", service="https"),
            ],
        )
        captured_hosts: list[str] = []
        captured_kwargs: dict[str, object] = {}

        def _fake_nmap_scan(hosts, **kwargs):
            captured_hosts.extend(hosts)
            captured_kwargs.update(kwargs)
            return NmapScanResult(mode=NmapMode.SERVICE_VERSION, hosts=[host_result])

        monkeypatch.setattr("squad.osint_analyst.enrichment.nmap_scan", _fake_nmap_scan)

        result = invoke_tool(deep_scan_host_tool, host=host, ports=[22, 443])

        # nmap invoked correctly
        assert captured_hosts == [host]
        assert captured_kwargs["mode"] == NmapMode.SERVICE_VERSION
        assert captured_kwargs["scripts"] == NmapScripts.DEFAULT
        assert captured_kwargs["ports"] == [22, 443]

        # Returns OAM Service assets - only the OPEN service, with CPE +
        # provenance; the filtered port is dropped.
        assert [s.port for s in result] == [22]
        svc = result[0]
        assert isinstance(svc, Service)
        assert svc.host == host
        assert svc.product == "OpenSSH"
        assert svc.cpe == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        assert svc.detected_by == "nmap"

        # ... and persisted to the host's services.json
        persisted = load_host_services(host)
        assert [s.port for s in persisted] == [22]
        assert persisted[0].cpe == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"

    def test_returns_empty_when_nmap_finds_nothing(
        self, invoke_tool, programme_in_workspace, target_apex, monkeypatch
    ) -> None:
        """When nmap returns no host rows (host down / scan failed), the
        wrapper returns an empty list - the OA always gets a typed result
        back - and writes no services.json."""
        from tools.recon_host_store import load_host_services

        host = f"api.{target_apex}"

        monkeypatch.setattr(
            "squad.osint_analyst.enrichment.nmap_scan",
            lambda hosts, **kwargs: NmapScanResult(mode=NmapMode.SERVICE_VERSION, hosts=[]),
        )

        result = invoke_tool(deep_scan_host_tool, host=host, ports=[443])

        assert result == []
        assert load_host_services(host) == []
