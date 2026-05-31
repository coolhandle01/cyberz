"""tests/models/test_asset.py - unit tests for models/asset.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    AttackGraph,
    Endpoint,
    HostInsight,
    HostPriority,
    HostRole,
    HostScore,
    IpAsset,
    Product,
    ProductRelease,
    Service,
    TLSCertificate,
    VulnProperty,
)

pytestmark = pytest.mark.unit


class TestEndpoint:
    def test_valid_endpoint(self, endpoint):
        assert endpoint.status_code == 200
        assert "nginx" in endpoint.technologies

    def test_optional_fields_default(self, target_apex):
        ep = Endpoint(url=f"https://{target_apex}")
        assert ep.status_code is None
        assert ep.technologies == []
        assert ep.parameters == []


# FQDN is exercised through a throwaway pydantic model so the validator
# fires the same way it does when carried on a real schema field. Stick to
# pytest.raises(ValidationError) rather than the lower-level ValueError so
# the test mirrors what schema callers will see.


class TestAttackGraph:
    def test_valid_recon_result(self, recon_result):
        assert len(recon_result.subdomains) == 2
        assert len(recon_result.endpoints) == 1

    def test_completed_at_is_set(self, recon_result):
        assert recon_result.completed_at is not None

    def test_serialise_roundtrip(self, recon_result):
        json_str = recon_result.model_dump_json()
        restored = AttackGraph.model_validate_json(json_str)
        assert restored.programme.handle == recon_result.programme.handle
        assert len(restored.endpoints) == len(recon_result.endpoints)


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


class TestService:
    def test_minimal_record(self):
        # host + port + protocol is the floor; the -sV banner fields, the
        # CPE and the detection-tool provenance populate only when the scan
        # recovered them.

        svc = Service(host="8.8.8.8", port=443, protocol="tcp")
        assert svc.host == "8.8.8.8"
        assert svc.port == 443
        assert svc.name is None
        assert svc.product is None
        assert svc.cpe is None
        assert svc.detected_by is None

    def test_carries_cpe_and_provenance(self, target_apex):
        # The OA-boundary translation stamps the NIST CPE nmap matched and
        # the detecting tool onto the Service - no separate Technology rows;
        # the service's own product / version / cpe IS the technology.
        svc = Service(
            host=f"api.{target_apex}",
            port=443,
            protocol="tcp",
            name="http",
            product="nginx",
            version="1.25.3",
            cpe="cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*",
            detected_by="nmap",
        )
        assert svc.product == "nginx"
        assert svc.cpe == "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"
        assert svc.detected_by == "nmap"

    def test_serialise_roundtrip(self):

        original = Service(host="1.1.1.1", port=53, protocol="udp", name="domain")
        restored = Service.model_validate_json(original.model_dump_json())
        assert restored.host == "1.1.1.1"
        assert restored.port == 53
        assert restored.name == "domain"

    def test_rejects_out_of_range_port(self):

        with pytest.raises(ValidationError):
            Service(host="8.8.8.8", port=70000, protocol="tcp")

    def test_rejects_malformed_host(self):
        # The FQDN | IPAddress union rejects a URL-shaped host upstream of
        # any graph emission, the same boundary FQDN enforces elsewhere.

        with pytest.raises(ValidationError):
            Service(host="https://evil.test/x", port=443, protocol="tcp")

    def test_rejects_oversize_banner(self):
        # The max_length cap on the tool-captured banner fields is the
        # boundary defence against an outsize injection riding a malformed
        # service banner across the OA -> PT handoff.

        with pytest.raises(ValidationError):
            Service(host="8.8.8.8", port=443, protocol="tcp", product="x" * 129)


class TestTLSCertificate:
    def test_minimal_record(self, target_apex):
        # host is the only floor; the grabbed cert detail populates as
        # the tls-grab / testssl pass recovers it.

        cert = TLSCertificate(host=f"www.{target_apex}")
        assert cert.host == f"www.{target_apex}"
        assert cert.subject_common_name is None
        assert cert.fingerprint_sha256 is None
        assert cert.subject_alt_names == []

    def test_captures_wildcard_san(self, target_apex):
        # The whole reason SANs are list[str] not list[FQDN]: a wildcard
        # SAN must survive into the cert asset, where list[FQDN] would
        # reject it. iPAddress SANs land the same way.

        cert = TLSCertificate(
            host=f"www.{target_apex}",
            subject_common_name=f"www.{target_apex}",
            issuer="Let's Encrypt",
            subject_alt_names=[f"*.{target_apex}", target_apex, "203.0.113.7"],
        )
        assert f"*.{target_apex}" in cert.subject_alt_names
        assert "203.0.113.7" in cert.subject_alt_names

    def test_serialise_roundtrip(self, target_apex):

        original = TLSCertificate(
            host=f"www.{target_apex}",
            fingerprint_sha256="ab" * 32,
            subject_alt_names=[f"*.{target_apex}"],
        )
        restored = TLSCertificate.model_validate_json(original.model_dump_json())
        assert restored.fingerprint_sha256 == "ab" * 32
        assert restored.subject_alt_names == [f"*.{target_apex}"]

    def test_rejects_malformed_host(self):

        with pytest.raises(ValidationError):
            TLSCertificate(host="https://evil.test/x")

    def test_rejects_oversize_issuer(self, target_apex):
        # The attacker-controlled cert string fields carry boundary caps.

        with pytest.raises(ValidationError):
            TLSCertificate(host=f"www.{target_apex}", issuer="x" * 256)


class TestVulnProperty:
    def test_minimal_record(self):
        # id is the only floor: the OA / VR can hang a bare CVE annotation off
        # an asset and let description / source / category populate from the
        # NVD lookup that produced it.
        vuln = VulnProperty(id="CVE-2022-22965")
        assert vuln.id == "CVE-2022-22965"
        assert vuln.description == ""
        assert vuln.source == ""
        assert vuln.enumeration == ""

    def test_carries_full_nvd_annotation(self):
        vuln = VulnProperty(
            id="CVE-2022-22965",
            description="Spring Framework RCE via data binding (Spring4Shell).",
            source="nvd",
            category="CWE-94",
            enumeration="CVE",
            reference="https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
        )
        assert vuln.source == "nvd"
        assert vuln.category == "CWE-94"
        assert vuln.enumeration == "CVE"

    def test_serialise_roundtrip(self):

        original = VulnProperty(id="CVE-2021-44228", source="nvd", enumeration="CVE")
        restored = VulnProperty.model_validate_json(original.model_dump_json())
        assert restored.id == "CVE-2021-44228"
        assert restored.source == "nvd"

    def test_rejects_empty_id(self):

        with pytest.raises(ValidationError):
            VulnProperty(id="")

    def test_rejects_oversize_description(self):

        with pytest.raises(ValidationError):
            VulnProperty(id="CVE-2022-22965", description="x" * 2001)


class TestOamAssetsTakeVulns:
    """The OAM asset shapes the OA / VR deal in carry hanging VulnProperty."""

    def test_endpoint_vulns_default_empty(self, target_apex):
        ep = Endpoint(url=f"https://{target_apex}")
        assert ep.vulns == []

    def test_service_carries_vulns(self, target_apex):
        svc = Service(
            host=f"api.{target_apex}",
            port=443,
            protocol="tcp",
            cpe="cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*",
            vulns=[VulnProperty(id="CVE-2021-23017", source="nvd", enumeration="CVE")],
        )
        assert svc.vulns[0].id == "CVE-2021-23017"

    def test_host_insight_carries_vulns(self, target_apex):
        insight = HostInsight(
            hostname=f"blog.{target_apex}",
            role=HostRole.APP,
            priority=HostPriority.HIGH,
            notes="WordPress 5.8.1 blog host - dated core, worth a CVE pass here.",
            detected_tech=["WordPress 5.8.1"],
            vulns=[VulnProperty(id="CVE-2021-44223", source="nvd", enumeration="CVE")],
        )
        assert insight.vulns[0].id == "CVE-2021-44223"

    def test_roundtrip_preserves_vulns(self, target_apex):
        svc = Service(
            host=f"api.{target_apex}",
            port=8080,
            protocol="tcp",
            vulns=[VulnProperty(id="CVE-2022-22965", enumeration="CVE")],
        )
        restored = Service.model_validate_json(svc.model_dump_json())
        assert restored.vulns[0].id == "CVE-2022-22965"


class TestProduct:
    def test_minimal_record(self):
        # product_name is the only floor; the rest of the OAM Product facets
        # populate as the agent / feed enriches them.
        p = Product(name="WordPress")
        assert p.name == "WordPress"
        assert p.product_id == ""
        assert p.category == ""

    def test_full_record(self):
        p = Product(
            name="Spring Framework",
            product_id="pkg:maven/org.springframework",
            type="web-framework",
            category="application framework",
            country_of_origin="US",
        )
        assert p.type == "web-framework"
        assert p.country_of_origin == "US"

    def test_rejects_empty_name(self):

        with pytest.raises(ValidationError):
            Product(name="")


class TestProductRelease:
    def test_minimal_record(self):
        rel = ProductRelease(name="WordPress 5.8.1")
        assert rel.name == "WordPress 5.8.1"
        assert rel.release_date == ""
        assert rel.vulns == []

    def test_carries_vulns_the_spec_proper_anchor(self):
        # ProductRelease is where a VulnProperty hangs in OAM - the CVE is
        # carried by the exact released version.
        rel = ProductRelease(
            name="WordPress 5.8.1",
            release_date="2021-09-09",
            vulns=[VulnProperty(id="CVE-2021-44223", source="nvd", enumeration="CVE")],
        )
        assert rel.vulns[0].id == "CVE-2021-44223"

    def test_serialise_roundtrip(self):

        original = ProductRelease(
            name="nginx 1.25.3",
            vulns=[VulnProperty(id="CVE-2021-23017", enumeration="CVE")],
        )
        restored = ProductRelease.model_validate_json(original.model_dump_json())
        assert restored.name == "nginx 1.25.3"
        assert restored.vulns[0].id == "CVE-2021-23017"

    def test_rejects_empty_name(self):

        with pytest.raises(ValidationError):
            ProductRelease(name="")


class TestHostScore:
    def test_minimal(self, target_apex):

        s = HostScore(hostname=f"api.{target_apex}", role=HostRole.API, priority=HostPriority.HIGH)
        assert s.role == HostRole.API
        assert s.priority == HostPriority.HIGH
        assert s.annotated_at is not None

    def test_serialise_roundtrip(self, target_apex):

        original = HostScore(
            hostname=f"auth.{target_apex}", role=HostRole.AUTH, priority=HostPriority.MEDIUM
        )
        restored = HostScore.model_validate_json(original.model_dump_json())
        assert restored.hostname == f"auth.{target_apex}"
        assert restored.role == HostRole.AUTH

    def test_rejects_malformed_host(self):

        with pytest.raises(ValidationError):
            HostScore(hostname="https://x/y", role=HostRole.API, priority=HostPriority.LOW)
