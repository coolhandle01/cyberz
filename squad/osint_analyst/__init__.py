"""OSINT Analyst - maps the in-scope attack surface."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from squad import SquadMember
from tools.h1_api import h1
from tools.recon import cert_transparency, historical_urls, run_recon


@tool("Run Recon")
def recon_tool(programme_handle: str) -> dict:
    """
    Run full OSINT recon (subdomain enumeration, HTTP probing, port scanning)
    against the in-scope assets of the given programme handle.
    Returns a serialised ReconResult.
    """
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    programme = h1.parse_programme(policy["data"], scope)
    result = run_recon(programme)
    return result.model_dump()


@tool("Certificate Transparency Lookup")
def cert_transparency_tool(domain: str) -> list[str]:
    """
    Query crt.sh certificate transparency logs to discover subdomains not found
    by active enumeration. Returns deduplicated hostnames.
    """
    return cert_transparency(domain)


@tool("Historical URL Discovery")
def historical_urls_tool(domain: str) -> list[str]:
    """
    Use waybackurls to find historical endpoints for a domain from the Wayback
    Machine. Surfaces paths that may no longer be linked but still exist.
    """
    return historical_urls(domain)


MEMBER = SquadMember(
    slug="osint_analyst",
    dir=Path(__file__).parent,
    tools=[recon_tool, cert_transparency_tool, historical_urls_tool],
)
