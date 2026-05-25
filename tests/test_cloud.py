"""
tests/test_cloud.py - unit tests for tools/cloud/

Covers S3 bucket checks, Azure Blob Storage checks, and exposed services.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, ReconResult, Severity
from tools.cloud.aws import check_s3_buckets
from tools.cloud.azure import check_azure_blob_containers, check_azure_sas_tokens
from tools.cloud.services import (
    check_admin_panels,
    check_consul_vault_paths,
    check_consul_vault_ports,
    check_cpanel,
    check_directadmin,
    check_grafana_paths,
    check_grafana_ports,
    check_kibana_paths,
    check_kibana_ports,
    check_plesk,
    check_portainer_paths,
    check_portainer_ports,
    check_sensitive_files,
    check_unauthenticated_databases,
    check_webmin,
)

pytestmark = pytest.mark.unit


# check_s3_buckets


class TestCheckS3Buckets:
    """The agent picks S3 hostnames OSINT actually surfaced in recon;
    no bucket-name guessing - we only probe assets the programme has
    exposed."""

    def test_detects_publicly_listable_bucket(self, s3_hostname):
        listing_xml = (
            '<?xml version="1.0"?><ListBucketResult><Name>example</Name></ListBucketResult>'
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = listing_xml

        with patch("requests.get", return_value=mock_resp):
            results = check_s3_buckets([s3_hostname])

        listable = [r for r in results if "Publicly Listable" in r.title]
        assert len(listable) == 1
        assert listable[0].severity_hint == Severity.HIGH
        assert listable[0].vuln_class == "CloudMisconfiguration"
        assert listable[0].target == f"https://{s3_hostname}/"

    def test_detects_publicly_accessible_bucket(self, make_s3_hostname):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "some non-listing content"

        with patch("requests.get", return_value=mock_resp):
            results = check_s3_buckets([make_s3_hostname()])

        accessible = [r for r in results if "Publicly Accessible" in r.title]
        assert len(accessible) == 1
        assert accessible[0].severity_hint == Severity.MEDIUM

    def test_non_200_produces_no_finding(self, s3_hostname):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Access Denied"

        with patch("requests.get", return_value=mock_resp):
            results = check_s3_buckets([s3_hostname])

        assert results == []

    def test_empty_input_makes_no_requests(self):
        with patch("requests.get") as mget:
            results = check_s3_buckets([])

        assert results == []
        mget.assert_not_called()

    def test_iterates_every_supplied_hostname(self, make_s3_hostname):
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Denied"
            return resp

        hostnames = [make_s3_hostname("assets"), make_s3_hostname("backup")]
        with patch("requests.get", side_effect=recording_get):
            check_s3_buckets(hostnames)

        for hostname in hostnames:
            assert any(hostname in u for u in seen_urls)

    def test_network_exception_is_swallowed(self, s3_hostname):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_s3_buckets([s3_hostname])
        assert results == []


# check_azure_blob_containers


class TestCheckAzureBlobContainers:
    """The agent picks Azure Blob hostnames OSINT actually surfaced in
    recon; the canonical container-name list (``public``, ``assets``,
    ``static``, ...) is probed against each."""

    def test_detects_publicly_listed_container(self, azure_blob_hostname):
        listing_xml = '<?xml version="1.0"?><EnumerationResults><Blobs/></EnumerationResults>'
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = listing_xml

        with patch("requests.get", return_value=mock_resp):
            results = check_azure_blob_containers([azure_blob_hostname])

        listed = [r for r in results if "Publicly Listed" in r.title]
        assert len(listed) >= 1
        assert listed[0].severity_hint == Severity.HIGH

    def test_empty_input_makes_no_requests(self):
        with patch("requests.get") as mget:
            results = check_azure_blob_containers([])

        assert results == []
        mget.assert_not_called()

    def test_probes_every_supplied_hostname(self, make_azure_blob_hostname):
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Denied"
            return resp

        hostnames = [make_azure_blob_hostname("storage"), make_azure_blob_hostname("assets")]
        with patch("requests.get", side_effect=recording_get):
            check_azure_blob_containers(hostnames)

        for hostname in hostnames:
            assert any(hostname in u for u in seen_urls)

    def test_network_exception_is_swallowed(self, azure_blob_hostname):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_azure_blob_containers([azure_blob_hostname])
        assert results == []


# check_azure_sas_tokens


class TestCheckAzureSasTokens:
    """Static URL inspection - no HTTP requests fire."""

    def test_detects_sas_token_in_endpoint_url(self, azure_sas_endpoint):
        with patch("requests.get") as mget:
            results = check_azure_sas_tokens([azure_sas_endpoint])

        sas_findings = [r for r in results if "SAS Token" in r.title]
        assert len(sas_findings) == 1
        assert sas_findings[0].severity_hint == Severity.HIGH
        # Static URL inspection: never fires HTTP.
        mget.assert_not_called()

    def test_clean_urls_produce_no_findings(self, target_url):
        endpoint = Endpoint(url=f"{target_url}/files/doc.pdf?download=1", status_code=200)

        with patch("requests.get") as mget:
            results = check_azure_sas_tokens([endpoint])

        assert results == []
        mget.assert_not_called()

    def test_empty_input_makes_no_requests(self):
        with patch("requests.get") as mget:
            results = check_azure_sas_tokens([])

        assert results == []
        mget.assert_not_called()


# ---------------------------------------------------------------------------
# Granular service check functions
# ---------------------------------------------------------------------------


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
    def _make_eps(self, target_apex):
        return [Endpoint(url=f"https://app.{target_apex}/", status_code=200)]

    def test_detects_git_head(self, target_apex):
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
            results = check_sensitive_files(self._make_eps(target_apex))
        git = [r for r in results if "Git Repository" in r.title]
        assert len(git) == 1
        assert git[0].severity_hint == Severity.HIGH
        assert git[0].vuln_class == "SensitiveFileExposed"

    def test_detects_env_file(self, target_apex):
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
            results = check_sensitive_files(self._make_eps(target_apex))
        env = [r for r in results if ".env File" in r.title]
        assert len(env) == 1

    def test_deduplicates_by_origin(self, target_url: str):
        endpoints = [
            Endpoint(url=f"{target_url}/page1", status_code=200),
            Endpoint(url=f"{target_url}/page2", status_code=200),
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

    def test_exception_is_swallowed(self, target_apex):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_sensitive_files(self._make_eps(target_apex))
        assert results == []


class TestCheckAdminPanels:
    def _make_eps(self, target_apex):
        return [Endpoint(url=f"https://app.{target_apex}/", status_code=200)]

    def test_detects_admin_panel(self, target_apex):
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
            results = check_admin_panels(self._make_eps(target_apex))
        panels = [r for r in results if "Admin Panel" in r.title]
        assert len(panels) >= 1
        assert panels[0].severity_hint == Severity.HIGH
        assert panels[0].vuln_class == "ExposedAdminPanel"

    def test_no_finding_for_404(self, target_apex):
        def always_404(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=always_404):
            results = check_admin_panels(self._make_eps(target_apex))
        assert results == []

    def test_exception_is_swallowed(self, target_apex):
        with patch("requests.get", side_effect=Exception("refused")):
            results = check_admin_panels(self._make_eps(target_apex))
        assert results == []


class TestGranularPanels:
    """Spot-check each branded panel / dashboard tool hits the right
    port (or reverse-proxy path) on the right host. Helpers now take
    typed inputs (``list[str]`` for hostnames, ``list[Endpoint]`` for
    path probes) rather than ``ReconResult``; the conversion lives at
    the wrapper layer."""

    def _hostnames(self, target_apex: str) -> list[str]:
        return [f"app.{target_apex}"]

    def _endpoints(self, target_apex: str) -> list[Endpoint]:
        return [Endpoint(url=f"https://app.{target_apex}/", status_code=200)]

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

    def test_cpanel_port_2083(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(2083, "cPanel")):
            results = check_cpanel(self._hostnames(target_apex))
        assert any("cPanel" in r.title for r in results)

    def test_whm_port_2087(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(2087, "WebHost Manager")):
            results = check_cpanel(self._hostnames(target_apex))
        assert any("WHM" in r.title for r in results)

    def test_plesk_port_8443(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(8443, "Plesk")):
            results = check_plesk(self._hostnames(target_apex))
        assert any("Plesk" in r.title for r in results)

    def test_directadmin_port_2222(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(2222, "DirectAdmin")):
            results = check_directadmin(self._hostnames(target_apex))
        assert any("DirectAdmin" in r.title for r in results)

    def test_webmin_port_10000(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(10000, "Webmin")):
            results = check_webmin(self._hostnames(target_apex))
        assert any("Webmin" in r.title for r in results)

    def test_grafana_port_3000(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(3000, "Grafana")):
            results = check_grafana_ports(self._hostnames(target_apex))
        assert any("Grafana" in r.title for r in results)

    def test_kibana_port_5601(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(5601, "Kibana")):
            results = check_kibana_ports(self._hostnames(target_apex))
        assert any("Kibana" in r.title for r in results)

    def test_portainer_port_9000(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(9000, "Portainer")):
            results = check_portainer_ports(self._hostnames(target_apex))
        assert any("Portainer" in r.title for r in results)

    def test_consul_port_8500(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(8500, "Consul")):
            results = check_consul_vault_ports(self._hostnames(target_apex))
        assert any("Consul" in r.title for r in results)

    def test_vault_port_8200(self, target_apex):
        with patch("requests.get", side_effect=self._port_mock(8200, "Vault")):
            results = check_consul_vault_ports(self._hostnames(target_apex))
        assert any("Vault" in r.title for r in results)

    def test_grafana_path_probe(self, target_apex):
        """Grafana path check probes /grafana on supplied origins."""

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
            results = check_grafana_paths(self._endpoints(target_apex))
        assert any("Grafana" in r.title for r in results)

    def test_no_finding_when_all_404(self, target_apex):
        def always_404(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        hostnames = self._hostnames(target_apex)
        endpoints = self._endpoints(target_apex)
        with patch("requests.get", side_effect=always_404):
            for fn in (
                check_cpanel,
                check_plesk,
                check_directadmin,
                check_webmin,
                check_grafana_ports,
                check_kibana_ports,
                check_portainer_ports,
                check_consul_vault_ports,
            ):
                assert fn(hostnames) == []
            for fn in (
                check_grafana_paths,
                check_kibana_paths,
                check_portainer_paths,
                check_consul_vault_paths,
            ):
                assert fn(endpoints) == []

    def test_exception_is_swallowed(self, target_apex):
        hostnames = self._hostnames(target_apex)
        endpoints = self._endpoints(target_apex)
        with patch("requests.get", side_effect=Exception("refused")):
            for fn in (
                check_cpanel,
                check_plesk,
                check_directadmin,
                check_webmin,
                check_grafana_ports,
                check_kibana_ports,
                check_portainer_ports,
                check_consul_vault_ports,
            ):
                assert fn(hostnames) == []
            for fn in (
                check_grafana_paths,
                check_kibana_paths,
                check_portainer_paths,
                check_consul_vault_paths,
            ):
                assert fn(endpoints) == []
