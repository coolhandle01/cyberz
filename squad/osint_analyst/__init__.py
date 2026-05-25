"""OSINT Analyst - maps the in-scope attack surface.

The agent's tools split across sibling modules so each file owns one
cohesive responsibility:

- ``discovery`` - sweep + slicers + passive expansion (cert
  transparency, historical URLs, LLM endpoint detection) + active
  hostname probes + takeover detection. The "what is the surface"
  half. Imports the shared ``load_programme`` from
  ``squad.workspace_tools`` (was a per-agent ``_helpers.py`` before
  the dedupe).
- ``curation`` - lookup (CWE / OWASP) + ``Annotate Host`` +
  ``Uncovered Hosts`` + ``Finalise Recon``. The "what do we record
  about the surface" half.

This module imports each wrapper, assembles ``MEMBER.tools``, and re-
exports both the wrappers and their args_schema classes so existing
consumers (tests, ``crew.py``, the contract tests in
``tests/test_osint_args_schemas.py``) keep importing from
``squad.osint_analyst`` directly.
"""

from pathlib import Path

from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from squad.osint_analyst.curation import (
    _AnnotateHostArgs,
    _FinaliseReconArgs,
    _OsintLookupCweArgs,
    _OsintLookupOwaspArgs,
    _UncoveredHostsArgs,
    annotate_host_tool,
    finalise_recon_tool,
    lookup_cwe_tool,
    lookup_owasp_tool,
    uncovered_hosts_tool,
)
from squad.osint_analyst.discovery import (
    _CertTransparencyArgs,
    _DetectTakeoverCandidatesArgs,
    _HistoricalUrlsArgs,
    _LlmDetectionArgs,
    _ProbeHostnamesArgs,
    _ReconEndpointsArgs,
    _ReconOpenPortsArgs,
    _ReconSubdomainsArgs,
    _RunInitialSweepArgs,
    cert_transparency_tool,
    detect_takeover_candidates_tool,
    historical_urls_tool,
    llm_detection_tool,
    probe_hostnames_tool,
    recon_endpoints_tool,
    recon_open_ports_tool,
    recon_subdomains_tool,
    run_initial_sweep_tool,
)

MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[
        run_initial_sweep_tool,
        recon_subdomains_tool,
        recon_endpoints_tool,
        recon_open_ports_tool,
        cert_transparency_tool,
        historical_urls_tool,
        llm_detection_tool,
        probe_hostnames_tool,
        detect_takeover_candidates_tool,
        lookup_cwe_tool,
        lookup_owasp_tool,
        annotate_host_tool,
        uncovered_hosts_tool,
        finalise_recon_tool,
        # Shared workspace wrappers
        read_run_filelist_tool,
        read_run_file_tool,
    ],
)

__all__ = [
    # Public API
    "MEMBER",
    # Wrappers - discovery
    "cert_transparency_tool",
    "detect_takeover_candidates_tool",
    "historical_urls_tool",
    "llm_detection_tool",
    "probe_hostnames_tool",
    "recon_endpoints_tool",
    "recon_open_ports_tool",
    "recon_subdomains_tool",
    "run_initial_sweep_tool",
    # Wrappers - curation
    "annotate_host_tool",
    "finalise_recon_tool",
    "lookup_cwe_tool",
    "lookup_owasp_tool",
    "uncovered_hosts_tool",
    # args_schema classes (re-exported so test imports stay stable)
    "_AnnotateHostArgs",
    "_CertTransparencyArgs",
    "_DetectTakeoverCandidatesArgs",
    "_FinaliseReconArgs",
    "_HistoricalUrlsArgs",
    "_LlmDetectionArgs",
    "_OsintLookupCweArgs",
    "_OsintLookupOwaspArgs",
    "_ProbeHostnamesArgs",
    "_ReconEndpointsArgs",
    "_ReconOpenPortsArgs",
    "_ReconSubdomainsArgs",
    "_RunInitialSweepArgs",
    "_UncoveredHostsArgs",
]
