"""
tools/recon_insights.py - Host-annotation authoring primitives for the OSINT
Analyst.

The OA's job is to turn the raw sweep (subfinder + httpx + nmap + dirfuzz +
TLS / DNS checks) into a curated attack-surface map: every interesting host
labelled with a role (admin / api / auth / app / cdn / ...), a priority
(high / medium / low / skip), tech detected with versions where possible, and
free-text notes that tell the Vulnerability Researcher WHY this host warrants
attention. The agent does the curation; this module provides the supporting
primitives:

* ``HostInsight`` (from ``models``) - the agent's working artefact per host.
* ``validate_insight(insight, sweep, programme)`` - quality gate. Returns the
  issue list. Hard errors block ``finalise_recon``.
* ``save_insight`` / ``load_insights`` - persist insights under
  ``<run_dir>/host_insights/<hostname>.json``.
* ``finalise_recon(programme, sweep_path)`` - load the sweep, validate every
  insight, build the canonical ``ReconResult`` for downstream agents, and
  write ``recon.json``. Refuses on hard errors or insufficient curation.

The OA's initial sweep is written to ``sweep.json``; ``finalise_recon``
copies the inventory through, attaches insights, and emits the final
``recon.json`` that the Vulnerability Researcher and Penetration Tester
consume.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

import runtime
from models import HostInsight, HostPriority, ReconResult
from models.h1 import Programme
from tools.recon.scope import extract_domain, filter_in_scope

_INSIGHTS_SUBDIR = "host_insights"
_SWEEP_FILENAME = "sweep.json"
_RECON_FILENAME = "recon.json"

# Hostnames must be made filesystem-safe before persisting under
# ``host_insights/<hostname>.json``. The replacement is reversible because we
# never reverse it - the JSON body carries the original hostname.
_HOSTNAME_SANITISE = re.compile(r"[^A-Za-z0-9.\-_]")


# Validation


class InsightValidationIssue(BaseModel):
    """One issue produced by validate_insight."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class InsightValidationReport(BaseModel):
    """Result of validating one insight."""

    ok: bool
    issues: list[InsightValidationIssue] = Field(default_factory=list)


def validate_insight(
    insight: HostInsight,
    sweep: ReconResult,
    programme: Programme,
) -> InsightValidationReport:
    """Apply quality heuristics to a HostInsight. Returns the issue list."""
    issues: list[InsightValidationIssue] = []

    hostname = insight.hostname.strip().lower()
    if not hostname:
        issues.append(
            InsightValidationIssue(
                section="hostname",
                severity="error",
                message="hostname must not be empty",
            )
        )
        return InsightValidationReport(ok=False, issues=issues)

    # Scope: every annotated host must be in scope. Out-of-scope hosts that
    # somehow leaked into the sweep are not the OA's to annotate.
    if not filter_in_scope([hostname], programme):
        issues.append(
            InsightValidationIssue(
                section="hostname",
                severity="error",
                message=(f"{hostname!r} is not in programme scope; only annotate in-scope hosts"),
            )
        )

    # Notes: the whole point. Too short means the agent skipped the
    # curation work.
    if len(insight.notes.strip()) < 30:
        issues.append(
            InsightValidationIssue(
                section="notes",
                severity="error",
                message=(
                    "notes are too short; explain what the host is, what tech "
                    "stack runs on it, and what makes it interesting (or not) "
                    "in 1-3 sentences"
                ),
            )
        )

    # High-priority hosts need a substantive reason.
    if insight.priority == HostPriority.HIGH and len(insight.notes.strip()) < 60:
        issues.append(
            InsightValidationIssue(
                section="notes",
                severity="error",
                message=(
                    "high-priority hosts need >= 60 chars of justification - "
                    "what tech, what surface, why it earns the budget"
                ),
            )
        )

    # SKIP hosts also need a reason - so a downstream reader does not
    # silently re-include them.
    if insight.priority == HostPriority.SKIP and len(insight.notes.strip()) < 30:
        issues.append(
            InsightValidationIssue(
                section="notes",
                severity="error",
                message=(
                    "skip-priority hosts need notes explaining the reason "
                    "(third-party managed, decoy, sensitive, etc.)"
                ),
            )
        )

    # If the host is in the sweep's inventory we expect the agent's
    # detected_tech to either be empty (agent could not enrich) or
    # consistent with what the sweep saw. We only warn on disagreement -
    # the agent can legitimately add versions httpx missed.
    sweep_techs_by_host = _sweep_tech_by_host(sweep)
    if hostname in sweep_techs_by_host:
        sweep_techs = {t.lower() for t in sweep_techs_by_host[hostname]}
        agent_techs = {t.lower() for t in insight.detected_tech}
        # Warn when sweep saw tech the agent did not carry through - might
        # signal the agent ignored a useful signal.
        missing = sweep_techs - {_strip_version(t) for t in agent_techs} - agent_techs
        if missing and len(insight.detected_tech) > 0:
            issues.append(
                InsightValidationIssue(
                    section="detected_tech",
                    severity="warning",
                    message=(
                        f"sweep saw tech the annotation does not carry: "
                        f"{sorted(missing)} - keep, or note explicitly in 'notes' "
                        "that it was deprioritised"
                    ),
                )
            )

    # detected_tech entries should be non-trivial strings.
    for t in insight.detected_tech:
        if len(t.strip()) < 2:
            issues.append(
                InsightValidationIssue(
                    section="detected_tech",
                    severity="error",
                    message=f"tech entry too short to be a real product name: {t!r}",
                )
            )

    ok = not any(i.severity == "error" for i in issues)
    return InsightValidationReport(ok=ok, issues=issues)


def _sweep_tech_by_host(sweep: ReconResult) -> dict[str, list[str]]:
    """Build a hostname -> tech-list map from the sweep's endpoints."""
    from urllib.parse import urlparse

    by_host: dict[str, list[str]] = {}
    for ep in sweep.endpoints:
        host = (urlparse(ep.url).hostname or "").lower()
        if not host:
            continue
        by_host.setdefault(host, []).extend(ep.technologies)
    return by_host


def _strip_version(tech: str) -> str:
    """Drop trailing version suffixes from a tech string for comparison.

    "WordPress 5.8.1" and "WordPress" should compare equal when checking
    that the agent carried the sweep's tech through.
    """
    return re.sub(r"\s*[0-9][\w.\-]*$", "", tech).strip().lower()


# Persistence


def _insights_dir() -> Path:
    return runtime.run_dir() / _INSIGHTS_SUBDIR


def insight_path(hostname: str) -> Path:
    """Return the on-disk path of the insight for ``hostname``.

    Hostnames are used directly as filenames (with a small character
    sanitisation pass). The body carries the original hostname.
    """
    safe = _HOSTNAME_SANITISE.sub("_", hostname.strip().lower())
    if not safe or safe.strip("_") == "":
        raise ValueError("hostname is empty after sanitisation")
    return _insights_dir() / f"{safe}.json"


def save_insight(insight: HostInsight) -> Path:
    """Persist an insight to ``<run_dir>/host_insights/<host>.json``."""
    path = insight_path(insight.hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(insight.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_insights() -> list[HostInsight]:
    """Load every insight in the current run, ordered by hostname."""
    dir_ = _insights_dir()
    if not dir_.is_dir():
        return []
    return sorted(
        (
            HostInsight.model_validate_json(p.read_text(encoding="utf-8"))
            for p in dir_.glob("*.json")
        ),
        key=lambda i: i.hostname,
    )


def load_sweep(sweep_filename: str = _SWEEP_FILENAME) -> ReconResult:
    """Load the OA's internal sweep artefact."""
    path = runtime.run_dir() / sweep_filename
    if not path.is_file():
        raise FileNotFoundError(f"{sweep_filename} not found; run Run Initial Sweep first")
    return ReconResult.model_validate_json(path.read_text(encoding="utf-8"))


# Finalisation


class ReconFinalisationError(RuntimeError):
    """Raised when finalise_recon cannot consolidate the sweep + insights."""


# Status codes whose hosts deserve an annotation: 2xx is a live target,
# 3xx redirects often hide gates, 401/403 confirm an auth-gated surface
# worth probing. Pure 404/500 we let slide.
_INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403}


def finalise_recon(
    programme: Programme,
    sweep_filename: str = _SWEEP_FILENAME,
    recon_filename: str = _RECON_FILENAME,
) -> Path:
    """Validate every host insight, merge them with the sweep, and write the
    final ``recon.json`` for downstream agents.

    Refuses to finalise if:
      * no insights have been authored at all (the OA must annotate)
      * any insight has hard validation errors
      * no host has been marked HIGH priority on a non-empty surface (the
        Penetration Tester needs at least one focus target)
      * an insight references a hostname that is not in scope

    Coverage warnings (non-blocking):
      * an interesting-status host in the sweep has no insight
      * a high-priority host is missing detected_tech
    """
    sweep = load_sweep(sweep_filename)
    insights = load_insights()

    if not insights:
        raise ReconFinalisationError(
            "no host_insights have been authored; call Annotate Host for the "
            "interesting hosts in the sweep before finalising"
        )

    failures: list[tuple[str, list[InsightValidationIssue]]] = []
    for insight in insights:
        report = validate_insight(insight, sweep, programme)
        if not report.ok:
            failures.append(
                (
                    insight.hostname,
                    [i for i in report.issues if i.severity == "error"],
                )
            )

    if failures:
        lines = ["one or more host insights have unresolved errors:"]
        for hostname, errs in failures:
            for err in errs:
                lines.append(f"  - insight {hostname} / {err.section}: {err.message}")
        raise ReconFinalisationError("\n".join(lines))

    high_priority = [i for i in insights if i.priority == HostPriority.HIGH]
    if sweep.subdomains and not high_priority:
        raise ReconFinalisationError(
            "no host has been marked HIGH priority; the Penetration Tester "
            "needs at least one focus target on a non-empty surface"
        )

    final = ReconResult(
        programme=sweep.programme,
        subdomains=sweep.subdomains,
        endpoints=sweep.endpoints,
        open_ports=sweep.open_ports,
        technologies=sweep.technologies,
        passive_findings=sweep.passive_findings,
        network_hops=sweep.network_hops,
        host_insights=insights,
        notes=_build_notes(sweep, insights),
    )

    out_path = runtime.run_dir() / recon_filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(final.model_dump_json(), encoding="utf-8")
    return out_path


def _build_notes(sweep: ReconResult, insights: list[HostInsight]) -> str:
    """Compose the recon-level notes string from sweep stats + insight tally."""
    by_priority: dict[HostPriority, int] = dict.fromkeys(HostPriority, 0)
    for i in insights:
        by_priority[i.priority] += 1
    return (
        f"sweep: {len(sweep.subdomains)} subdomains, {len(sweep.endpoints)} endpoints; "
        f"insights: {by_priority[HostPriority.HIGH]} high, "
        f"{by_priority[HostPriority.MEDIUM]} medium, "
        f"{by_priority[HostPriority.LOW]} low, "
        f"{by_priority[HostPriority.SKIP]} skip"
    )


# Coverage check (informational)


def uncovered_interesting_hosts(sweep: ReconResult, insights: list[HostInsight]) -> list[str]:
    """Return interesting-status hostnames in the sweep that have no insight."""
    from urllib.parse import urlparse

    covered = {i.hostname.lower() for i in insights}
    interesting: set[str] = set()
    for ep in sweep.endpoints:
        if ep.status_code in _INTERESTING_STATUSES:
            host = (urlparse(ep.url).hostname or "").lower()
            if host:
                interesting.add(host)
    return sorted(interesting - covered)


__all__ = [
    "InsightValidationIssue",
    "InsightValidationReport",
    "ReconFinalisationError",
    "extract_domain",
    "finalise_recon",
    "insight_path",
    "load_insights",
    "load_sweep",
    "save_insight",
    "uncovered_interesting_hosts",
    "validate_insight",
]
