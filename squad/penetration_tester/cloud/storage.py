"""
Cloud-storage exposure probes - S3 and Azure Blob buckets the
programme uses (or once used) that should not be world-readable.

FIXME: these checks derive bucket / container names from the
programme handle and any storage-shaped subdomains the OSINT Analyst
surfaced. They should only fire when a cloud resource URL is
definitely explicitly in scope (the programme's structured scope
names a bucket / container), or when the squad is working on a
programme run by that cloud provider itself - guessing storage URLs
from the programme handle risks probing third-party tenants that
happen to share a name. Track in a follow-up; for #150 the wrappers
keep the recon-derived shape they had pre-split.
"""

from pydantic import BaseModel, Field

from models import RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _recon_from_path
from tools.cloud import check_azure_storage, check_s3_buckets


class _S3CheckArgs(BaseModel):
    """Explicit args_schema for the S3 Bucket Check tool (#147)."""

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
    """Explicit args_schema for the Azure Blob Storage Check tool (#147)."""

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
