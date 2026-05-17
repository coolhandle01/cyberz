"""OSINT Analyst - maps the in-scope attack surface."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from models import Endpoint
from squad import SquadMember
from tools import http
from tools.h1_api import h1
from tools.recon import cert_transparency, detect_llm_endpoints, historical_urls, run_recon


@tool("Run Recon")
def recon_tool(programme_handle: str) -> str:
    """
    Run full OSINT recon (subdomain enumeration, HTTP probing, port scanning)
    against the in-scope assets of the given programme handle. Writes the
    serialised ReconResult to recon.json in the run directory and returns
    the absolute path.
    """
    import runtime

    http.set_programme(programme_handle)
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    programme = h1.parse_programme(policy["data"], scope)
    result = run_recon(programme)
    out_path = runtime.run_dir() / "recon.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.model_dump_json(), encoding="utf-8")
    return str(out_path)


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


@tool("LLM Endpoint Detection")
def llm_detection_tool(endpoints_json: str) -> list[dict]:
    """
    Scan a set of live endpoints for signals that they are backed by an LLM or
    AI assistant. Uses two methods:

    1. URL path inspection - checks path segments against known LLM tokens
       (chat, ask, ai, assistant, completions, generate, copilot, etc.)
    2. Response probing - checks HTTP headers (OpenAI gateway headers), content
       type (text/event-stream for streaming responses), JSON structure
       (OpenAI-format choices/tokens keys), and body text (AI self-identification
       phrases).

    endpoints_json: JSON array of endpoint objects from ReconResult. Pass the
      full endpoint list after run_recon completes - the tool filters internally.
      Example: '[{"url": "https://example.com/chat", "status_code": 200}]'

    Returns endpoint dicts tagged with 'LLM' in their technologies list. Pass
    these to the Penetration Tester for prompt injection testing.
    """
    import json

    endpoints = [Endpoint.model_validate(e) for e in json.loads(endpoints_json)]
    return [ep.model_dump() for ep in detect_llm_endpoints(endpoints)]


MEMBER = SquadMember(
    slug="osint_analyst",
    dir=Path(__file__).parent,
    tools=[recon_tool, cert_transparency_tool, historical_urls_tool, llm_detection_tool],
)
