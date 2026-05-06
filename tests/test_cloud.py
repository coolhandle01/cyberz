"""
tests/test_cloud.py - unit tests for tools/cloud/

Covers S3 bucket checks, Azure Blob Storage checks, and exposed services.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Programme, ReconResult, Severity
from tools.cloud.aws import check_s3_buckets
from tools.cloud.services import check_exposed_services
from tools.cloud.storage import check_azure_storage

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
