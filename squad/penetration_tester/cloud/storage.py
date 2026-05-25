"""
Cloud-storage exposure probes - S3 buckets and Azure Blob storage.

Each wrapper takes a typed target the agent picks from recon (the
``*.s3.*.amazonaws.com`` / ``*.blob.core.windows.net`` hostnames the
OSINT Analyst discovered, or the endpoints whose URLs contain SAS
tokens) and a wrapper-level ``scope_filter`` drops anything outside
the selected programme's structured scope before the probe fires.

No bucket-name or account-name guessing: every probed asset is one
the programme has actually exposed and OSINT has actually inventoried
in ``recon.subdomains`` / ``recon.endpoints``. Aligns with the
pipeline split (PM transcribes scope; OSINT inventories the surface;
PT attacks the inventoried surface) - storage is structurally the
same shape as every other cloud wrapper.
"""

from pydantic import BaseModel, Field

from models import Endpoint, Hostname, RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _parse_endpoints
from tools.cloud import check_azure_blob_containers, check_azure_sas_tokens, check_s3_buckets
from tools.recon.scope import filter_endpoints_in_scope, filter_in_scope


class _S3CheckArgs(BaseModel):
    """Explicit args_schema for the S3 Bucket Check tool."""

    hostnames: list[Hostname] = Field(
        description=(
            "S3 hostnames the OSINT Analyst surfaced in recon.subdomains"
            " (matching ``*.s3.*.amazonaws.com``) or via cert"
            " transparency / historical URLs. Probes each for public"
            " listing (``<ListBucketResult``) or bare 200. The wrapper's"
            " scope filter drops out-of-scope hostnames before any HTTP"
            " request."
        ),
    )


@cyber_tool(
    "S3 Bucket Check",
    args_schema=_S3CheckArgs,
    scope_filter=("hostnames", filter_in_scope),
)
def s3_check_tool(hostnames: list[Hostname]) -> list[RawFinding]:
    """
    Check each supplied S3 hostname for public listing or accessibility.

    Pick hostnames from Recon Subdomains where the entry matches
    ``*.s3.*.amazonaws.com``, or from Recon Endpoints whose host fits
    that pattern. The wrapper scope-filters the list against the
    selected programme; the body probes whatever survives.
    """
    return list(check_s3_buckets(hostnames))


class _AzureBlobContainerArgs(BaseModel):
    """Explicit args_schema for the Azure Blob Container Check tool."""

    hostnames: list[Hostname] = Field(
        description=(
            "Azure Blob hostnames the OSINT Analyst surfaced in"
            " recon.subdomains (matching ``*.blob.core.windows.net``)."
            " Probes each for publicly listable containers under the"
            " canonical Azure-pattern names (``public``, ``assets``,"
            " ``static``, ``uploads``, ...). The wrapper's scope filter"
            " drops out-of-scope hostnames before any HTTP request."
        ),
    )


@cyber_tool(
    "Azure Blob Container Check",
    args_schema=_AzureBlobContainerArgs,
    scope_filter=("hostnames", filter_in_scope),
)
def azure_blob_container_check_tool(hostnames: list[Hostname]) -> list[RawFinding]:
    """
    Check each supplied Azure Blob hostname for publicly listable
    containers under the canonical Azure-pattern names.

    Pick hostnames from Recon Subdomains where the entry matches
    ``*.blob.core.windows.net``. The wrapper scope-filters the list
    against the selected programme; the body probes whatever survives.
    """
    return list(check_azure_blob_containers(hostnames))


class _AzureSasTokenArgs(BaseModel):
    """Explicit args_schema for the Azure SAS Token Check tool."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects. Scans each URL for embedded Azure SAS"
            " token query parameters (sv / se / sig / sr / sp). Static"
            " URL inspection - no HTTP requests fire. Run broadly on"
            " all live endpoints; SAS tokens in URLs leak via proxy"
            " logs and browser history. The wrapper's scope filter"
            " drops endpoints whose host is outside the selected"
            " programme's structured scope."
        ),
    )


@cyber_tool(
    "Azure SAS Token Check",
    args_schema=_AzureSasTokenArgs,
    scope_filter=("endpoints", filter_endpoints_in_scope),
)
def azure_sas_token_check_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Scan each supplied endpoint URL for embedded Azure SAS-token query
    parameters (``sv`` / ``se`` / ``sig`` / ``sr`` / ``sp``). No HTTP
    requests fire - this is static URL inspection.

    Pick a representative set of live endpoints from Recon Endpoints.
    The wrapper scope-filters the list against the selected programme.
    """
    return list(check_azure_sas_tokens(_parse_endpoints(endpoints)))
