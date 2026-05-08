"""AWS S3 bucket misconfiguration checks."""

from __future__ import annotations

import logging

import requests

from models import RawFinding, ReconResult, Severity

logger = logging.getLogger(__name__)

_BUCKET_SUFFIXES = [
    "",
    "-assets",
    "-backup",
    "-dev",
    "-staging",
    "-prod",
    "-static",
    "-uploads",
    "-media",
    "-data",
    "-files",
]


def _bucket_candidates(recon: ReconResult) -> list[str]:
    handle = recon.programme.handle
    candidates = [handle + s for s in _BUCKET_SUFFIXES]
    for sub in recon.subdomains:
        if ".s3." in sub and ".amazonaws.com" in sub:
            bucket = sub.split(".s3.")[0]
            candidates.append(bucket)
    return list(dict.fromkeys(candidates))


def check_s3_buckets(recon: ReconResult) -> list[RawFinding]:
    """
    Check for publicly accessible S3 buckets derived from the programme handle
    and any S3-pattern subdomains in the recon surface.

    Checks bucket listing only - does not attempt writes.
    """
    findings: list[RawFinding] = []

    for bucket in _bucket_candidates(recon):
        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False)  # nosemgrep
        except Exception as exc:
            logger.debug("S3 check failed for %s: %s", bucket, exc)
            continue

        if resp.status_code == 200 and "<ListBucketResult" in resp.text:
            findings.append(
                RawFinding(
                    title=f"S3 Bucket Publicly Listable - {bucket}",
                    vuln_class="CloudMisconfiguration",
                    target=url,
                    evidence=(
                        f"Bucket listing returned HTTP 200.\nResponse excerpt:\n{resp.text[:500]}"
                    ),
                    tool="s3_bucket_check",
                    severity_hint=Severity.HIGH,
                )
            )
        elif resp.status_code == 200:
            findings.append(
                RawFinding(
                    title=f"S3 Bucket Publicly Accessible - {bucket}",
                    vuln_class="CloudMisconfiguration",
                    target=url,
                    evidence="Bucket URL returned HTTP 200 without listing - verify manually.",
                    tool="s3_bucket_check",
                    severity_hint=Severity.MEDIUM,
                )
            )

    logger.info("S3 check found %d findings", len(findings))
    return findings
