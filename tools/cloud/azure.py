"""Azure Blob Storage misconfiguration checks."""

from __future__ import annotations

import logging
import re

import requests

from models import RawFinding, ReconResult, Severity

logger = logging.getLogger(__name__)

_CONTAINER_NAMES = [
    "public",
    "assets",
    "static",
    "uploads",
    "media",
    "files",
    "images",
    "data",
    "$root",
]
_ACCOUNT_SUFFIXES = ["", "assets", "storage", "static", "media"]

# Azure SAS token query parameters
_SAS_RE = re.compile(r"[?&](sv|se|sig|sr|sp)=", re.I)


def _account_candidates(recon: ReconResult) -> list[str]:
    handle = recon.programme.handle
    candidates = [handle + s for s in _ACCOUNT_SUFFIXES]
    for sub in recon.subdomains:
        if ".blob.core.windows.net" in sub:
            account = sub.split(".blob.core.windows.net")[0]
            candidates.append(account)
    return list(dict.fromkeys(candidates))


def check_azure_storage(recon: ReconResult) -> list[RawFinding]:
    """
    Check for publicly listable Azure Blob Storage containers and SAS tokens
    embedded in discovered endpoint URLs.
    """
    findings: list[RawFinding] = []

    # Check for SAS tokens in discovered URLs
    for ep in recon.endpoints:
        if _SAS_RE.search(ep.url):
            findings.append(
                RawFinding(
                    title=f"Azure SAS Token in URL - {ep.url}",
                    vuln_class="CloudMisconfiguration",
                    target=ep.url,
                    evidence=(
                        "SAS token query parameters (sv/se/sig/sr/sp) detected in URL. "
                        "Tokens embedded in URLs are logged by proxies and browsers."
                    ),
                    tool="azure_storage_check",
                    severity_hint=Severity.HIGH,
                )
            )

    # Check for publicly listable containers
    for account in _account_candidates(recon):
        for container in _CONTAINER_NAMES:
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                resp = requests.get(url, timeout=10, allow_redirects=False)  # nosemgrep
            except Exception as exc:
                logger.debug("Azure check failed for %s/%s: %s", account, container, exc)
                continue

            if resp.status_code == 200 and "<EnumerationResults" in resp.text:
                findings.append(
                    RawFinding(
                        title=f"Azure Blob Container Publicly Listed - {account}/{container}",
                        vuln_class="CloudMisconfiguration",
                        target=url,
                        evidence=(
                            f"Container listing returned HTTP 200.\n"
                            f"Response excerpt:\n{resp.text[:500]}"
                        ),
                        tool="azure_storage_check",
                        severity_hint=Severity.HIGH,
                    )
                )

    logger.info("Azure storage check found %d findings", len(findings))
    return findings
