"""
squad/osint_analyst/curation.py - the OSINT curation surface.

Tools the OA uses to turn the in-progress sweep into the canonical
``recon.json`` artefact: cite remediation guidance (CWE / OWASP), label
discovered hosts (role / priority / notes / detected tech), surface
hosts that have not yet been annotated, and consolidate everything into
the typed artefact downstream agents (VR research, PT probes) consume.
"""

from pydantic import BaseModel, Field

from models import (
    CWEEntry,
    HostAnnotation,
    HostInsight,
    Hostname,
    HostPriority,
    HostRole,
    OWASPEntry,
    ReconFinalisationError,
)
from squad import cyber_tool
from squad.workspace_tools import current_programme
from tools.cwe_data import lookup as cwe_lookup
from tools.owasp_data import lookup as owasp_lookup
from tools.recon_insights import (
    finalise_recon,
    save_insight,
    uncovered_interesting_hosts,
    validate_insight,
)
from tools.recon_insights import (
    load_insights as load_insights_impl,
)
from tools.recon_insights import (
    load_sweep as load_sweep_impl,
)


class _OsintLookupCweArgs(BaseModel):
    """Explicit args_schema for the OSINT Lookup CWE tool."""

    query: str = Field(
        description=(
            "Free-text query against the Common Weakness Enumeration index."
            " Matches CWE id, name, or description (case-insensitive"
            " substring). Useful when annotating a host whose detected tech"
            " has a well-known weakness class (e.g. 'WordPress' -> XSS /"
            " SQLi; 'Spring Boot' -> SSTI / RCE)."
        ),
    )


@cyber_tool("Lookup CWE", args_schema=_OsintLookupCweArgs)
def lookup_cwe_tool(query: str) -> list[CWEEntry]:
    """
    Find Common Weakness Enumeration entries that match a query - useful
    when annotating a host whose detected tech has a well-known weakness
    class (e.g. "WordPress" -> XSS / SQLi; "Spring Boot" -> SSTI / RCE).
    Returns each match's cwe_id, name, short description, and the matching
    OWASP cheat-sheet topic.
    """
    return list(cwe_lookup(query))


class _OsintLookupOwaspArgs(BaseModel):
    """Explicit args_schema for the OSINT Lookup OWASP Guidance tool."""

    query: str = Field(
        description=(
            "Free-text query against the OWASP Cheat Sheet index. Matches"
            " on cheatsheet title and topic (case-insensitive substring)."
            " Use to surface guidance the downstream VR can reason against"
            " when building the attack plan."
        ),
    )


@cyber_tool("Lookup OWASP Guidance", args_schema=_OsintLookupOwaspArgs)
def lookup_owasp_tool(query: str) -> list[OWASPEntry]:
    """
    Find OWASP Cheat Sheet entries for a vuln class or topic - hint for
    the downstream VR's attack-plan reasoning. Returns each match's title,
    key_principles, and the canonical cheatsheetseries.owasp.org URL.
    """
    return list(owasp_lookup(query))


class _AnnotateHostArgs(BaseModel):
    """Explicit args_schema for the Annotate Host tool."""

    hostname: Hostname = Field(
        description=(
            "Hostname to annotate. Must already be in the sweep, or have"
            " been surfaced by Certificate Transparency / Historical URL"
            " Discovery / Probe Hostnames. Validated as an RFC 1123"
            " hostname (URLs / ports / paths reject upstream)."
        ),
    )
    role: HostRole = Field(
        description=(
            "Functional role this host plays. Drives downstream"
            " prioritisation - admin / auth hosts attract more probe"
            " budget than static / cdn ones. The schema enforces the"
            " enum upstream so an unknown role rejects before the"
            " wrapper body runs."
        ),
    )
    priority: HostPriority = Field(
        description=(
            "Curation signal the PT uses to allocate probe budget."
            " ``high`` means 'spend probes here'; ``skip`` means 'do not"
            " probe this even if reachable'. Must match the threat model"
            " in the notes; the quality gate checks both."
        ),
    )
    notes: str = Field(
        description=(
            ">= 30 characters (>= 60 for high-priority). Explain what the"
            " host is, what tech runs on it, and why it matters (or why"
            " not). Quality gate fires below the length threshold and"
            " when the priority does not match the prose."
        ),
    )
    detected_tech: list[str] | None = Field(
        default=None,
        description=(
            "Ideally with versions ('Spring Boot 2.6.3' beats 'Spring"
            " Boot'). The quality gate warns when the sweep saw tech the"
            " annotation drops - the annotation is meant to be a curation"
            " of what was seen, not an alternate inventory."
        ),
    )
    sweep_path: str = Field(
        default="sweep.json",
        description="Relative path to the OA's sweep file. Defaults to ``sweep.json``.",
    )


@cyber_tool("Annotate Host", args_schema=_AnnotateHostArgs)
def annotate_host_tool(
    hostname: Hostname,
    role: HostRole,
    priority: HostPriority,
    notes: str,
    detected_tech: list[str] | None = None,
    sweep_path: str = "sweep.json",
) -> HostAnnotation:
    """
    Author one HostInsight for a single hostname and run the quality gate.

    Inputs:
      - hostname: a hostname from the sweep, or one newly discovered via
        Certificate Transparency / Historical URL Discovery / Probe Hostnames
      - role: one of admin, api, auth, app, cdn, static, mail, infra, dev,
        unknown
      - priority: one of high, medium, low, skip - the curation signal the
        Penetration Tester uses to allocate probe budget
      - notes: >= 30 chars (>= 60 for high-priority), explaining what the
        host is, what tech runs on it, and why it matters (or does not)
      - detected_tech: ideally with versions ("Spring Boot 2.6.3" beats
        "Spring Boot"); the warning fires when the sweep saw tech that the
        annotation drops

    Returns a HostAnnotation with the relative insight path and an
    InsightValidationReport. Re-run with the issues addressed when
    validation.ok is false.
    """
    sweep = load_sweep_impl(sweep_path)
    programme = current_programme()

    insight = HostInsight(
        hostname=hostname.strip().lower(),
        role=HostRole(role),
        priority=HostPriority(priority),
        notes=notes.strip(),
        detected_tech=[t.strip() for t in (detected_tech or []) if t.strip()],
    )
    path = save_insight(insight)
    return HostAnnotation(
        path=str(path.relative_to(path.parents[1])),
        validation=validate_insight(insight, sweep, programme),
    )


class _UncoveredHostsArgs(BaseModel):
    """Explicit args_schema for the Uncovered Hosts tool."""

    sweep_path: str = Field(
        default="sweep.json",
        description=(
            "Relative path to the OA's sweep file. Defaults to"
            " ``sweep.json``. Returns interesting-status hostnames (200,"
            " 301, 302, 401, 403, ...) in the sweep that have no insight"
            " yet - use as a checklist before Finalise Recon."
        ),
    )


@cyber_tool("Uncovered Hosts", args_schema=_UncoveredHostsArgs)
def uncovered_hosts_tool(sweep_path: str = "sweep.json") -> list[str]:
    """
    Return interesting-status hostnames in the sweep (200, 301, 302, 401,
    403, ...) that have no insight yet. Use as a checklist before calling
    Finalise Recon - hosts you choose to leave uncovered should at least be
    a deliberate decision.
    """
    sweep = load_sweep_impl(sweep_path)
    insights = load_insights_impl()
    return uncovered_interesting_hosts(sweep, insights)


class _FinaliseReconArgs(BaseModel):
    """Explicit args_schema for the Finalise Recon tool."""

    sweep_path: str = Field(
        default="sweep.json",
        description="Relative path to the OA's sweep file. Defaults to ``sweep.json``.",
    )


@cyber_tool("Finalise Recon", args_schema=_FinaliseReconArgs)
def finalise_recon_tool(
    sweep_path: str = "sweep.json",
) -> str:
    """
    Consolidate the sweep + every authored HostInsight into recon.json for
    the Vulnerability Researcher and Penetration Tester. Refuses if no
    insights have been authored, if any insight has unresolved validation
    errors, or if the surface is non-empty but no host has been marked
    HIGH priority. Returns the bare filename ``recon.json`` on success.
    """
    programme = current_programme()
    try:
        path = finalise_recon(programme, sweep_filename=sweep_path)
    except ReconFinalisationError as exc:
        raise ValueError(str(exc)) from exc
    return path.name


# Helpers
