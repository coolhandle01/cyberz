"""Recon-shaped fixtures: ``Endpoint`` / ``AttackGraph`` plus the
cloud-storage hostname factories.

Bucket / container names are built from ``target_sld`` (the
second-level domain of ``target_apex``) so flipping ``target_url``
propagates through every cloud-storage test the same way it does for
every other in-scope-target literal. Factories rather than single
values where tests need variants (the "iterate every supplied
hostname" tests pass two distinct ones); single-value fixtures wrap
the factory at its canonical suffix for the common case. Mirrors the
``make_html_page`` pattern in ``domains.py``.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from models import AttackGraph, Endpoint


@pytest.fixture()
def endpoint(target_apex: str) -> Endpoint:
    return Endpoint(
        url=f"https://api.{target_apex}",
        status_code=200,
        technologies=["nginx", "React"],
        parameters=["q", "page"],
    )


@pytest.fixture()
def recon_result(programme, endpoint, target_apex: str) -> AttackGraph:
    return AttackGraph(
        programme=programme,
        subdomains=[f"api.{target_apex}", f"admin.{target_apex}"],
        endpoints=[endpoint],
        open_ports={f"api.{target_apex}": [80, 443]},
        technologies=["nginx", "React"],
        notes="Test recon result.",
    )


@pytest.fixture()
def make_s3_hostname(target_sld: str) -> Callable[..., str]:
    """Factory for in-scope-themed S3 hostnames.

    ``make_s3_hostname("assets")`` -> ``"example-assets.s3.us-east-1.amazonaws.com"``;
    ``make_s3_hostname()`` -> ``"example.s3.us-east-1.amazonaws.com"``.
    Override ``region`` for variants.
    """

    def _make(suffix: str = "", *, region: str = "us-east-1") -> str:
        bucket = f"{target_sld}-{suffix}" if suffix else target_sld
        return f"{bucket}.s3.{region}.amazonaws.com"

    return _make


@pytest.fixture()
def s3_hostname(make_s3_hostname: Callable[..., str]) -> str:
    """Single canonical S3 hostname for the simple cases - the suite's
    equivalent of ``target_url`` for AWS S3. Use ``make_s3_hostname``
    when a test needs more than one or a non-default region."""
    return make_s3_hostname("assets")


@pytest.fixture()
def make_azure_blob_hostname(target_sld: str) -> Callable[..., str]:
    """Factory for in-scope-themed Azure Blob hostnames.

    ``make_azure_blob_hostname("storage")`` ->
    ``"examplestorage.blob.core.windows.net"``. Azure storage account
    names are 3-24 lowercase alphanumeric (no hyphens), so the suffix
    concatenates without a separator.
    """

    def _make(suffix: str = "") -> str:
        account = f"{target_sld}{suffix}"
        return f"{account}.blob.core.windows.net"

    return _make


@pytest.fixture()
def azure_blob_hostname(make_azure_blob_hostname: Callable[..., str]) -> str:
    """Single canonical Azure Blob hostname for the simple cases."""
    return make_azure_blob_hostname("storage")


@pytest.fixture()
def azure_sas_endpoint(target_url: str) -> Endpoint:
    """``Endpoint`` whose URL carries embedded Azure SAS-token query
    parameters - the canonical positive case for
    ``check_azure_sas_tokens``. Built on ``target_url`` so the host
    is in-scope; the test exercises the query-string detection."""
    return Endpoint(
        url=(f"{target_url}/files/doc.pdf?sv=2021-01-01&se=2025-12-31&sr=b&sp=r&sig=abc123"),
        status_code=200,
    )
