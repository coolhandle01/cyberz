"""tests/models/asset/test_service.py - unit tests for models/asset/service.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import Product, ProductRelease, Service, VulnProperty

pytestmark = pytest.mark.unit


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

    def test_carries_vulns(self, target_apex):
        svc = Service(
            host=f"api.{target_apex}",
            port=443,
            protocol="tcp",
            cpe="cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*",
            vulns=[VulnProperty(id="CVE-2021-23017", source="nvd", enumeration="CVE")],
        )
        assert svc.vulns[0].id == "CVE-2021-23017"

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
