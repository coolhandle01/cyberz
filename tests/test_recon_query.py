"""
tests/test_recon_query.py - tools/recon/query.py slicers.

These let an agent ask "which endpoints serve WordPress and returned 200?"
without loading the full ReconResult into context.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

import pytest

from models import Endpoint
from tools.recon import query

pytestmark = pytest.mark.unit


@pytest.fixture()
def recon_file(tmp_path: Path, recon_result, victim_url: str) -> Iterator[str]:
    """Write a populated recon.json into tmp_path and patch runtime.run_dir
    so query._load resolves "recon.json" under tmp_path.

    Returns the relative filename - tests pass this through, matching the
    inter-agent contract (relative paths only)."""
    domain = urlparse(victim_url).hostname  # "victim.example.com"
    endpoints = [
        Endpoint(url=f"https://api.{domain}/v1", status_code=200, technologies=["nginx"]),
        Endpoint(url=f"https://blog.{domain}/", status_code=200, technologies=["WordPress"]),
        Endpoint(
            url=f"https://admin.{domain}/login",
            status_code=401,
            technologies=["WordPress"],
        ),
        Endpoint(url=f"https://old.{domain}/", status_code=404, technologies=[]),
    ]
    recon = recon_result.model_copy(
        update={
            "subdomains": [f"api.{domain}", f"blog.{domain}", f"admin.{domain}"],
            "endpoints": endpoints,
            "open_ports": {
                f"api.{domain}": [80, 443],
                f"redis.{domain}": [6379],
            },
        }
    )
    recon_path = tmp_path / "recon.json"
    recon_path.write_text(recon.model_dump_json(), encoding="utf-8")
    with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
        yield "recon.json"


class TestReconSubdomains:
    def test_returns_all_subdomains(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        result = query.recon_subdomains(recon_file)
        assert result == [f"api.{domain}", f"blog.{domain}", f"admin.{domain}"]

    def test_filters_case_insensitively(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        assert query.recon_subdomains(recon_file, host_filter="API") == [f"api.{domain}"]

    def test_filter_no_match_returns_empty(self, recon_file: str) -> None:
        assert query.recon_subdomains(recon_file, host_filter="nope") == []


class TestReconEndpoints:
    def test_no_filters_returns_all(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        result = query.recon_endpoints(recon_file)
        assert result.total == 4
        assert result.returned == 4
        assert {e.url for e in result.endpoints} == {
            f"https://api.{domain}/v1",
            f"https://blog.{domain}/",
            f"https://admin.{domain}/login",
            f"https://old.{domain}/",
        }

    def test_filter_by_status(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        result = query.recon_endpoints(recon_file, status=200)
        assert result.total == 2
        assert {e.url for e in result.endpoints} == {
            f"https://api.{domain}/v1",
            f"https://blog.{domain}/",
        }

    def test_filter_by_tech_case_insensitive(self, recon_file: str) -> None:
        result = query.recon_endpoints(recon_file, tech="wordpress")
        assert result.total == 2

    def test_conjunctive_filters(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        result = query.recon_endpoints(recon_file, status=200, tech="wordpress")
        assert result.total == 1
        assert result.endpoints[0].url == f"https://blog.{domain}/"

    def test_filter_by_host_contains(self, recon_file: str) -> None:
        result = query.recon_endpoints(recon_file, host_contains="admin")
        assert result.total == 1

    def test_pagination(self, recon_file: str) -> None:
        first = query.recon_endpoints(recon_file, limit=2)
        assert first.total == 4
        assert first.returned == 2
        assert first.offset == 0
        second = query.recon_endpoints(recon_file, offset=2, limit=2)
        assert second.returned == 2
        assert second.offset == 2
        first_urls = {e.url for e in first.endpoints}
        second_urls = {e.url for e in second.endpoints}
        assert first_urls.isdisjoint(second_urls)

    def test_rejects_bad_offset(self, recon_file: str) -> None:
        with pytest.raises(ValueError, match="offset must be non-negative"):
            query.recon_endpoints(recon_file, offset=-1)

    def test_rejects_bad_limit(self, recon_file: str) -> None:
        with pytest.raises(ValueError, match="limit must be at least 1"):
            query.recon_endpoints(recon_file, limit=0)


class TestReconOpenPorts:
    def test_returns_all_hosts(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        result = query.recon_open_ports(recon_file)
        assert result == {
            f"api.{domain}": [80, 443],
            f"redis.{domain}": [6379],
        }

    def test_returns_single_host(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        assert query.recon_open_ports(recon_file, host=f"redis.{domain}") == {
            f"redis.{domain}": [6379]
        }

    def test_unknown_host_returns_empty(self, recon_file: str, victim_url: str) -> None:
        domain = urlparse(victim_url).hostname
        assert query.recon_open_ports(recon_file, host=f"ghost.{domain}") == {}
