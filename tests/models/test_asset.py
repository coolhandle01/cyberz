"""tests/models/test_asset.py - unit tests for models/asset.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    AttackGraph,
    Endpoint,
    HostPriority,
    HostRole,
    HostScore,
    IpAsset,
    Service,
    TLSCertificate,
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
        # host + port + protocol is the floor; the -sV banner fields and
        # the technology rows populate only when the scan recovered them.

        svc = Service(host="8.8.8.8", port=443, protocol="tcp")
        assert svc.host == "8.8.8.8"
        assert svc.port == 443
        assert svc.name is None
        assert svc.product is None
        assert svc.technologies == []

    def test_composes_typed_technologies(self, target_apex):
        # The OA-boundary translation coerces banner detail into typed
        # ``Technology`` rows hanging off the Service node.
        from models.technology import Technology

        svc = Service(
            host=f"api.{target_apex}",
            port=443,
            protocol="tcp",
            name="http",
            product="nginx",
            version="1.25.3",
            technologies=[Technology(name="nginx", version="1.25.3")],
        )
        assert svc.product == "nginx"
        assert svc.technologies[0].name == "nginx"

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
