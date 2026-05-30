"""tests/tools/recon/nmap/test_service.py - unit tests for the
NmapHostResult -> OAM Service translation (tools/recon/nmap/service.py).
"""

from __future__ import annotations

import pytest

from models.scanner import NmapHostResult, NmapService
from tools.recon.nmap.service import services_from_nmap

pytestmark = pytest.mark.unit


class TestServicesFromNmap:
    def test_translates_open_service_with_cpe_and_provenance(self):
        result = NmapHostResult(
            host="example.com",
            services=[
                NmapService(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="OpenSSH",
                    version="7.4",
                    extra_info="Ubuntu",
                    cpe="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                )
            ],
        )
        services = services_from_nmap(result)
        assert len(services) == 1
        svc = services[0]
        assert svc.host == "example.com"
        assert svc.port == 22
        assert svc.protocol == "tcp"
        assert svc.name == "ssh"  # nmap "service" field -> Service.name
        assert svc.product == "OpenSSH"
        assert svc.version == "7.4"
        assert svc.extra_info == "Ubuntu"
        assert svc.cpe == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        assert svc.detected_by == "nmap"

    def test_drops_non_open_services(self):
        # OAM is a presence graph: only an *open* service is a node.
        result = NmapHostResult(
            host="example.com",
            services=[
                NmapService(port=80, protocol="tcp", state="open", service="http"),
                NmapService(port=443, protocol="tcp", state="filtered", service="https"),
                NmapService(port=25, protocol="tcp", state="closed", service="smtp"),
            ],
        )
        services = services_from_nmap(result)
        assert [s.port for s in services] == [80]

    def test_empty_host_result_yields_no_services(self):
        assert services_from_nmap(NmapHostResult(host="example.com")) == []

    def test_cpe_none_passes_through(self):
        # A service-name-only row (no -sV CPE match) still becomes a
        # Service - just without a CPE.
        result = NmapHostResult(
            host="example.com",
            services=[NmapService(port=6379, protocol="tcp", state="open", service="redis")],
        )
        services = services_from_nmap(result)
        assert len(services) == 1
        assert services[0].cpe is None
        assert services[0].detected_by == "nmap"
