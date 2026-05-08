"""
tests/test_cloud.py - unit tests for tools/cloud/

Covers S3 bucket checks, Azure Blob Storage checks, and exposed services.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Programme, ReconResult, Severity
from tools.cloud.aws import check_s3_buckets
from tools.cloud.azure import check_azure_storage
from tools.cloud.services import (
    check_admin_panels,
    check_consul_vault,
    check_cpanel,
    check_directadmin,
    check_exposed_services,
    check_grafana,
    check_kibana,
    check_plesk,
    check_portainer,
    check_sensitive_files,
    check_unauthenticated_databases,
    check_webmin,
)

pytestmark = pytest.mark.unit


# Fixtures


@pytest.fixture()
def minimal_recon(programme) -> ReconResult:
    return ReconResult(
        programme=programme,
        subdomains=["app.example.com"],
        endpoints=[Endpoint(url="https://app.example.com/", status_code=200)],
        open_ports={},
        technologies=[],
    )


# check_s3_buckets


class TestCheckS3Buckets:
    def test_detects_publicly_listable_bucket(self, minimal_recon):
        listing_xml = (
            '<?xml version="1.0"?><ListBucketResult><Name>example</Name></ListBucketResult>'
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = listing_xml

        with patch("requests.get", return_value=mock_resp):
            results = check_s3_buckets(minimal_recon)

        listable = [r for r in results if "Publicly Listable" in r.title]
        assert len(listable) >= 1
        assert listable[0].severity_hint == Severity.HIGH
        assert listable[0].vuln_class == "CloudMisconfiguration"

    def test_detects_publicly_accessible_bucket(self, minimal_recon):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "some non-listing content"

        with patch("requests.get", return_value=mock_resp):
            results = check_s3_buckets(minimal_recon)

        accessible = [r for r in results if "Publicly Accessible" in r.title]
        assert len(accessible) >= 1
        assert accessible[0].severity_hint == Severity.MEDIUM

    def test_non_200_produces_no_finding(self, minimal_recon):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Access Denied"

        with patch("requests.get", return_value=mock_resp):
            results = check_s3_buckets(minimal_recon)

        assert results == []

    def test_includes_candidates_from_programme_handle(self, minimal_recon):
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Denied"
            return resp

        with patch("requests.get", side_effect=recording_get):
            check_s3_buckets(minimal_recon)

        assert any("test-programme" in u for u in seen_urls)

    def test_picks_up_s3_subdomain(self):
        prog = Programme(
            handle="myapp",
            name="MyApp",
            url="https://hackerone.com/myapp",
            bounty_table={},
            in_scope=[],
            out_of_scope=[],
            allows_automated_scanning=True,
        )
        recon = ReconResult(
            programme=prog,
            subdomains=["myapp-assets.s3.us-east-1.amazonaws.com"],
            endpoints=[],
            open_ports={},
            technologies=[],
        )
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Denied"
            return resp

        with patch("requests.get", side_effect=recording_get):
            check_s3_buckets(recon)

        assert any("myapp-assets" in u for u in seen_urls)

    def test_network_exception_is_swallowed(self, minimal_recon):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_s3_buckets(minimal_recon)
        assert results == []


# check_azure_storage


class TestCheckAzureStorage:
    def test_detects_publicly_listed_container(self, minimal_recon):
        listing_xml = '<?xml version="1.0"?><EnumerationResults><Blobs/></EnumerationResults>'
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = listing_xml

        with patch("requests.get", return_value=mock_resp):
            results = check_azure_storage(minimal_recon)

        listed = [r for r in results if "Publicly Listed" in r.title]
        assert len(listed) >= 1
        assert listed[0].severity_hint == Severity.HIGH

    def test_detects_sas_token_in_endpoint_url(self):
        prog = Programme(
            handle="corp",
            name="Corp",
            url="https://hackerone.com/corp",
            bounty_table={},
            in_scope=[],
            out_of_scope=[],
            allows_automated_scanning=True,
        )
        sas_url = (
            "https://corpassets.blob.core.windows.net/files/doc.pdf"
            "?sv=2021-01-01&se=2025-12-31&sr=b&sp=r&sig=abc123"
        )
        recon = ReconResult(
            programme=prog,
            subdomains=[],
            endpoints=[Endpoint(url=sas_url, status_code=200)],
            open_ports={},
            technologies=[],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Denied"

        with patch("requests.get", return_value=mock_resp):
            results = check_azure_storage(recon)

        sas_findings = [r for r in results if "SAS Token" in r.title]
        assert len(sas_findings) == 1
        assert sas_findings[0].severity_hint == Severity.HIGH

    def test_picks_up_blob_subdomain(self):
        prog = Programme(
            handle="myapp",
            name="MyApp",
            url="https://hackerone.com/myapp",
            bounty_table={},
            in_scope=[],
            out_of_scope=[],
            allows_automated_scanning=True,
        )
        recon = ReconResult(
            programme=prog,
            subdomains=["myappstorage.blob.core.windows.net"],
            endpoints=[],
            open_ports={},
            technologies=[],
        )
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Denied"
            return resp

        with patch("requests.get", side_effect=recording_get):
            check_azure_storage(recon)

        assert any("myappstorage" in u for u in seen_urls)

    def test_network_exception_is_swallowed(self, minimal_recon):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_azure_storage(minimal_recon)
        assert results == []


# check_exposed_services


class TestCheckExposedServicesElasticsearch:
    def test_detects_unauthenticated_elasticsearch(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=["elastic.example.com"],
            endpoints=[],
            open_ports={"elastic.example.com": [9200]},
            technologies=[],
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"cluster_name":"mycluster","status":"green"}'

        with patch("requests.get", return_value=mock_resp):
            results = check_exposed_services(recon)

        es_findings = [r for r in results if "Elasticsearch" in r.title]
        assert len(es_findings) == 1
        assert es_findings[0].severity_hint == Severity.CRITICAL

    def test_no_finding_when_port_not_open(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"host.example.com": [80, 443]},
            technologies=[],
        )
        with patch("requests.get"):
            results = check_exposed_services(recon)
        assert not any("Elasticsearch" in r.title for r in results)


class TestCheckExposedServicesCouchDb:
    def test_detects_unauthenticated_couchdb(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"db.example.com": [5984]},
            technologies=[],
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '["_users","_replicator","mydb"]'

        with patch("requests.get", return_value=mock_resp):
            results = check_exposed_services(recon)

        couch = [r for r in results if "CouchDB" in r.title]
        assert len(couch) == 1
        assert couch[0].severity_hint == Severity.CRITICAL


class TestCheckExposedServicesAdminPanels:
    def test_detects_exposed_admin_panel(self, minimal_recon):
        admin_content = "<html><title>Admin Dashboard</title></html>"

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/admin" in url and "admin" in url:
                resp.status_code = 200
                resp.text = admin_content
            else:
                resp.status_code = 404
                resp.text = "Not Found"
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_exposed_services(minimal_recon)

        admin_findings = [r for r in results if "Admin Panel" in r.title]
        assert len(admin_findings) >= 1
        assert admin_findings[0].severity_hint == Severity.HIGH

    def test_detects_exposed_git_head(self, minimal_recon):
        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/.git/HEAD" in url:
                resp.status_code = 200
                resp.text = "ref: refs/heads/main\n"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_exposed_services(minimal_recon)

        git_findings = [r for r in results if "Git Repository" in r.title]
        assert len(git_findings) == 1

    def test_network_exception_swallowed(self, minimal_recon):
        with patch("requests.get", side_effect=Exception("conn refused")):
            results = check_exposed_services(minimal_recon)
        assert results == []


class TestCheckExposedServicesPanels:
    """Brand-specific control panel detection on non-standard ports."""

    def _make_recon(self, programme, host="app.example.com"):
        return ReconResult(
            programme=programme,
            subdomains=[host],
            endpoints=[Endpoint(url=f"https://{host}/", status_code=200)],
            open_ports={},
            technologies=[],
        )

    def _panel_mock(self, port: int, marker: str):
        """Return a requests.get side_effect that 200s only on the target port."""
        from urllib.parse import urlparse as _up

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if _up(url).port == port:
                resp.status_code = 200
                resp.text = f"<html><title>{marker}</title></html>"
            else:
                resp.status_code = 404
                resp.text = "Not Found"
            return resp

        return fake_get

    def test_detects_cpanel_on_port_2083(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(2083, "cPanel")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "cPanel" in r.title]
        assert len(panel) >= 1
        assert panel[0].severity_hint == Severity.HIGH
        assert panel[0].vuln_class == "ExposedAdminPanel"

    def test_detects_cpanel_on_port_2082(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(2082, "cPanel")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "cPanel" in r.title]
        assert len(panel) >= 1

    def test_detects_whm_on_port_2087(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(2087, "WebHost Manager")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "WHM" in r.title]
        assert len(panel) >= 1
        assert panel[0].severity_hint == Severity.HIGH

    def test_detects_whm_on_port_2086(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(2086, "WebHost Manager")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "WHM" in r.title]
        assert len(panel) >= 1

    def test_detects_plesk_on_port_8443(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(8443, "Plesk")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "Plesk" in r.title]
        assert len(panel) >= 1
        assert panel[0].severity_hint == Severity.HIGH

    def test_detects_plesk_on_port_8880(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(8880, "Plesk")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "Plesk" in r.title]
        assert len(panel) >= 1

    def test_detects_directadmin_on_port_2222(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(2222, "DirectAdmin")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "DirectAdmin" in r.title]
        assert len(panel) >= 1
        assert panel[0].severity_hint == Severity.HIGH

    def test_detects_webmin_on_port_10000(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=self._panel_mock(10000, "Webmin")):
            results = check_exposed_services(recon)
        panel = [r for r in results if "Webmin" in r.title]
        assert len(panel) >= 1
        assert panel[0].severity_hint == Severity.HIGH

    def test_no_finding_when_port_returns_404(self, programme):
        recon = self._make_recon(programme)

        def always_404(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = "Not Found"
            return resp

        with patch("requests.get", side_effect=always_404):
            results = check_exposed_services(recon)
        panel = [r for r in results if r.vuln_class == "ExposedAdminPanel"]
        assert panel == []

    def test_panel_exception_is_swallowed(self, programme):
        recon = self._make_recon(programme)
        with patch("requests.get", side_effect=Exception("connection refused")):
            results = check_exposed_services(recon)
        assert results == []

    def test_deduplicates_by_hostname(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=["app.example.com"],
            endpoints=[
                Endpoint(url="https://app.example.com/page1", status_code=200),
                Endpoint(url="https://app.example.com/page2", status_code=200),
            ],
            open_ports={},
            technologies=[],
        )
        seen_ports: list[int] = []

        def recording_get(url, **kwargs):
            from urllib.parse import urlparse as _up

            p = _up(url).port
            if p:
                seen_ports.append(p)
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=recording_get):
            check_exposed_services(recon)

        # Each panel port should appear exactly once despite two endpoints sharing
        # the same hostname
        from collections import Counter

        counts = Counter(seen_ports)
        for count in counts.values():
            assert count == 1


# ---------------------------------------------------------------------------
# Granular service check functions
# ---------------------------------------------------------------------------


@pytest.fixture()
def _recon_with_ports(programme):
    return ReconResult(
        programme=programme,
        subdomains=["app.example.com"],
        endpoints=[Endpoint(url="https://app.example.com/", status_code=200)],
        open_ports={"app.example.com": [9200, 5984, 6379, 27017]},
        technologies=[],
    )


class TestCheckUnauthenticatedDatabases:
    def test_detects_elasticsearch(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"es.example.com": [9200]},
            technologies=[],
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"cluster_name":"prod","status":"green"}'
        with patch("requests.get", return_value=mock_resp):
            results = check_unauthenticated_databases(recon)
        es = [r for r in results if "Elasticsearch" in r.title]
        assert len(es) == 1
        assert es[0].severity_hint == Severity.CRITICAL
        assert es[0].vuln_class == "ExposedService"

    def test_detects_couchdb(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"db.example.com": [5984]},
            technologies=[],
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '["_users","mydb"]'
        with patch("requests.get", return_value=mock_resp):
            results = check_unauthenticated_databases(recon)
        couch = [r for r in results if "CouchDB" in r.title]
        assert len(couch) == 1
        assert couch[0].severity_hint == Severity.CRITICAL

    def test_detects_redis_via_ping(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"cache.example.com": [6379]},
            technologies=[],
        )
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"+PONG\r\n"
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("tools.cloud.databases.redis.socket.create_connection", return_value=mock_sock):
            results = check_unauthenticated_databases(recon)
        redis = [r for r in results if "Redis" in r.title]
        assert len(redis) == 1
        assert redis[0].severity_hint == Severity.CRITICAL

    def test_detects_mongodb_via_ismaster(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"mongo.example.com": [27017]},
            technologies=[],
        )
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00" * 20 + b"ismaster" + b"\x00" * 10
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch(
            "tools.cloud.databases.mongodb.socket.create_connection", return_value=mock_sock
        ):
            results = check_unauthenticated_databases(recon)
        mongo = [r for r in results if "MongoDB" in r.title]
        assert len(mongo) == 1
        assert mongo[0].severity_hint == Severity.CRITICAL

    def test_skips_host_without_matching_ports(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"host.example.com": [80, 443]},
            technologies=[],
        )
        with patch("requests.get") as mock_get:
            results = check_unauthenticated_databases(recon)
        mock_get.assert_not_called()
        assert results == []

    def test_exception_is_swallowed(self, programme):
        recon = ReconResult(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"host.example.com": [9200]},
            technologies=[],
        )
        with patch("requests.get", side_effect=Exception("refused")):
            results = check_unauthenticated_databases(recon)
        assert results == []


class TestCheckSensitiveFiles:
    def _make_eps(self):
        return [Endpoint(url="https://app.example.com/", status_code=200)]

    def test_detects_git_head(self):
        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/.git/HEAD" in url:
                resp.status_code = 200
                resp.text = "ref: refs/heads/main\n"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_sensitive_files(self._make_eps())
        git = [r for r in results if "Git Repository" in r.title]
        assert len(git) == 1
        assert git[0].severity_hint == Severity.HIGH
        assert git[0].vuln_class == "SensitiveFileExposed"

    def test_detects_env_file(self):
        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/.env" in url and "git" not in url:
                resp.status_code = 200
                resp.text = "APP_KEY=abc\nDB_PASSWORD=secret\n"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_sensitive_files(self._make_eps())
        env = [r for r in results if ".env File" in r.title]
        assert len(env) == 1

    def test_deduplicates_by_origin(self):
        endpoints = [
            Endpoint(url="https://app.example.com/page1", status_code=200),
            Endpoint(url="https://app.example.com/page2", status_code=200),
        ]
        call_count = 0

        def counting_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=counting_get):
            check_sensitive_files(endpoints)

        # Only one origin, so paths are probed once each
        assert call_count == len(
            ["/.git/HEAD", "/.env", "/phpinfo.php", "/server-status", "/.DS_Store"]
        )

    def test_exception_is_swallowed(self):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_sensitive_files(self._make_eps())
        assert results == []


class TestCheckAdminPanels:
    def _make_eps(self):
        return [Endpoint(url="https://app.example.com/", status_code=200)]

    def test_detects_admin_panel(self):
        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/admin" in url:
                resp.status_code = 200
                resp.text = "<html><h1>Admin Dashboard</h1></html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_admin_panels(self._make_eps())
        panels = [r for r in results if "Admin Panel" in r.title]
        assert len(panels) >= 1
        assert panels[0].severity_hint == Severity.HIGH
        assert panels[0].vuln_class == "ExposedAdminPanel"

    def test_no_finding_for_404(self):
        def always_404(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=always_404):
            results = check_admin_panels(self._make_eps())
        assert results == []

    def test_exception_is_swallowed(self):
        with patch("requests.get", side_effect=Exception("refused")):
            results = check_admin_panels(self._make_eps())
        assert results == []


class TestGranularPanels:
    """Spot-check each branded panel tool hits the right port."""

    def _recon(self, programme):
        return ReconResult(
            programme=programme,
            subdomains=["app.example.com"],
            endpoints=[Endpoint(url="https://app.example.com/", status_code=200)],
            open_ports={},
            technologies=[],
        )

    def _port_mock(self, port: int, marker: str):
        from urllib.parse import urlparse as _up

        def fake_get(url, **kwargs):
            resp = MagicMock()
            parsed = _up(url)
            if parsed.port == port:
                resp.status_code = 200
                resp.text = f"<html>{marker}</html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        return fake_get

    def test_cpanel_port_2083(self, programme):
        with patch("requests.get", side_effect=self._port_mock(2083, "cPanel")):
            results = check_cpanel(self._recon(programme))
        assert any("cPanel" in r.title for r in results)

    def test_whm_port_2087(self, programme):
        with patch("requests.get", side_effect=self._port_mock(2087, "WebHost Manager")):
            results = check_cpanel(self._recon(programme))
        assert any("WHM" in r.title for r in results)

    def test_plesk_port_8443(self, programme):
        with patch("requests.get", side_effect=self._port_mock(8443, "Plesk")):
            results = check_plesk(self._recon(programme))
        assert any("Plesk" in r.title for r in results)

    def test_directadmin_port_2222(self, programme):
        with patch("requests.get", side_effect=self._port_mock(2222, "DirectAdmin")):
            results = check_directadmin(self._recon(programme))
        assert any("DirectAdmin" in r.title for r in results)

    def test_webmin_port_10000(self, programme):
        with patch("requests.get", side_effect=self._port_mock(10000, "Webmin")):
            results = check_webmin(self._recon(programme))
        assert any("Webmin" in r.title for r in results)

    def test_grafana_port_3000(self, programme):
        with patch("requests.get", side_effect=self._port_mock(3000, "Grafana")):
            results = check_grafana(self._recon(programme))
        assert any("Grafana" in r.title for r in results)

    def test_kibana_port_5601(self, programme):
        with patch("requests.get", side_effect=self._port_mock(5601, "Kibana")):
            results = check_kibana(self._recon(programme))
        assert any("Kibana" in r.title for r in results)

    def test_portainer_port_9000(self, programme):
        with patch("requests.get", side_effect=self._port_mock(9000, "Portainer")):
            results = check_portainer(self._recon(programme))
        assert any("Portainer" in r.title for r in results)

    def test_consul_port_8500(self, programme):
        with patch("requests.get", side_effect=self._port_mock(8500, "Consul")):
            results = check_consul_vault(self._recon(programme))
        assert any("Consul" in r.title for r in results)

    def test_vault_port_8200(self, programme):
        with patch("requests.get", side_effect=self._port_mock(8200, "Vault")):
            results = check_consul_vault(self._recon(programme))
        assert any("Vault" in r.title for r in results)

    def test_grafana_path_probe(self, programme):
        """Grafana also probes /grafana on existing origins."""

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url.endswith("/grafana"):
                resp.status_code = 200
                resp.text = "<html>Grafana dashboard</html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_grafana(self._recon(programme))
        assert any("Grafana" in r.title for r in results)

    def test_no_finding_when_all_404(self, programme):
        def always_404(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=always_404):
            for fn in (
                check_cpanel,
                check_plesk,
                check_directadmin,
                check_webmin,
                check_grafana,
                check_kibana,
                check_portainer,
                check_consul_vault,
            ):
                assert fn(self._recon(programme)) == []

    def test_exception_is_swallowed(self, programme):
        with patch("requests.get", side_effect=Exception("refused")):
            for fn in (
                check_cpanel,
                check_plesk,
                check_directadmin,
                check_webmin,
                check_grafana,
                check_kibana,
                check_portainer,
                check_consul_vault,
            ):
                assert fn(self._recon(programme)) == []
