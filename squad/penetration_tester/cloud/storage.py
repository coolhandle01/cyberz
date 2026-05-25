"""
Cloud-storage exposure probes - S3 and Azure Blob buckets the
programme uses (or once used) that should not be world-readable.

These two wrappers still take ``recon_path: str`` rather than the
typed ``list[Hostname]`` / ``list[Endpoint]`` shape every other
``cloud/`` wrapper moved to: third-party storage tenants
(``*.s3.amazonaws.com``, ``*.blob.core.windows.net``) are not in the
programme's structured scope, so ``filter_in_scope`` against
``programme.in_scope`` would reject every candidate. The
scope-of-discovery boundary here is workspace state
(``recon.programme.handle`` + the S3 / Azure subdomains
``finalise_recon`` already scope-filtered into ``recon.subdomains``),
which the ``_bucket_candidates`` / ``_account_candidates`` helpers
read directly.

See the package-level FIXME in ``cloud/__init__.py`` for the broader
third-party-infrastructure scope-semantics work (#83 follow-on).
"""

from pydantic import BaseModel, Field

from models import RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _recon_from_path
from tools.cloud import check_azure_storage, check_s3_buckets


class _S3CheckArgs(BaseModel):
    """Explicit args_schema for the S3 Bucket Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Buckets are"
            " derived from the programme handle and any S3 subdomains the"
            " OSINT Analyst surfaced. Worth firing when the target is known"
            " to use AWS or when *.s3 / *.s3.amazonaws.com subdomains appear"
            " in recon."
        ),
    )


@cyber_tool("S3 Bucket Check", args_schema=_S3CheckArgs)
def s3_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for publicly accessible or listable AWS S3 buckets derived from the
    programme handle and any S3 subdomains in the recon surface.
    Use when the target is known to use AWS, or when S3 subdomains appear in recon.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_s3_buckets(recon))


class _AzureStorageCheckArgs(BaseModel):
    """Explicit args_schema for the Azure Blob Storage Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when the"
            " target is known to use Azure, or when"
            " *.blob.core.windows.net subdomains appear in recon. Probes for"
            " public containers and SAS-token leakage in endpoint URLs."
        ),
    )


@cyber_tool("Azure Blob Storage Check", args_schema=_AzureStorageCheckArgs)
def azure_storage_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for publicly accessible Azure Blob Storage containers and exposed SAS
    tokens in endpoint URLs. Use when the target is known to use Azure, or when
    *.blob.core.windows.net subdomains appear in recon.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_azure_storage(recon))
