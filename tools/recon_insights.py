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
* ``host_dir(fqdn)`` - the per-host evidence directory under
  ``<run_dir>/hosts/<fqdn>/``. Future recon tools (screenshots, scan
  output, response bodies) write per-host artefacts here so each
  directory carries one FQDN asset's worth of evidence end-to-end.
* ``save_insight`` / ``load_insights`` - persist insights under
  ``<run_dir>/hosts/<fqdn>/insight.json``.
* ``finalise_recon(programme, attack_graph_path)`` - load the sweep, validate every
  insight, build the canonical ``AttackGraph`` for downstream agents, and
  write ``recon.json``. Refuses on hard errors or insufficient curation.

The OA's initial sweep is written to ``attack_graph.json``; ``finalise_recon``
copies the inventory through, attaches insights, and emits the final
``recon.json`` that the Vulnerability Researcher and Penetration Tester
consume.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import TypeAdapter

import runtime
from models import AttackGraph, HostInsight, HostPriority, HostScore, RawFinding, TLSCertificate
from models.h1 import Programme

# The insight shapes (HostAnnotation, InsightValidationIssue,
# InsightValidationReport, ReconFinalisationError) live in
# models/insight.py per the typed-shapes-live-in-models rule. Re-
# exported here so existing ``from tools.recon_insights import X``
# consumers keep working; the canonical import path is ``from models
# import X``.
from models.insight import (
    InsightValidationIssue,
    InsightValidationReport,
    ReconFinalisationError,
)
from models.primitives import FQDN
from tools.recon.scope import filter_in_scope

_HOSTS_SUBDIR = "hosts"
_ATTACK_GRAPH_FILENAME = "attack_graph.json"
_RECON_FILENAME = "recon.json"

# FQDNs must be made filesystem-safe before persisting under
# ``hosts/<fqdn>/``. The replacement is reversible because we never
# reverse it - the persisted artefacts carry the original hostname in
# their body.
_HOSTNAME_SANITISE = re.compile(r"[^A-Za-z0-9.\-_]")


# Validation


def validate_insight(
    insight: HostInsight,
    sweep: AttackGraph,
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


def _sweep_tech_by_host(sweep: AttackGraph) -> dict[str, list[str]]:
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


def _hosts_dir() -> Path:
    return runtime.run_dir() / _HOSTS_SUBDIR


def host_dir(hostname: FQDN) -> Path:
    """Return the per-host evidence directory under ``<run_dir>/hosts/``.

    Each in-scope FQDN gets its own directory; ``insight_path`` writes
    ``insight.json`` here, and future evidence-writing tools (httpx
    screenshots, nmap output, response bodies) hang their per-host
    artefacts off the same dir. The layout maps cleanly onto an amass
    FQDN asset's worth of input: one directory = one node's evidence
    trail.

    Sanitises the hostname for filesystem use. The replacement is
    reversible because we never reverse it - the persisted artefacts
    inside carry the original hostname in their body.
    """
    safe = _HOSTNAME_SANITISE.sub("_", hostname.strip().lower())
    if not safe or safe.strip("_") == "":
        raise ValueError("hostname is empty after sanitisation")
    return _hosts_dir() / safe


def insight_path(hostname: FQDN) -> Path:
    """Return the on-disk path of the insight for ``hostname``.

    The insight lives at ``<host_dir>/insight.json`` - one file inside
    the host's per-FQDN directory. Sibling files (screenshots, scan
    output, response bodies) land alongside as recon tools write them.
    """
    return host_dir(hostname) / "insight.json"


def save_insight(insight: HostInsight) -> Path:
    """Persist an insight to ``<run_dir>/hosts/<host>/insight.json``."""
    path = insight_path(insight.hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(insight.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_insights() -> list[HostInsight]:
    """Load every insight in the current run, ordered by hostname."""
    dir_ = _hosts_dir()
    if not dir_.is_dir():
        return []
    return sorted(
        (
            HostInsight.model_validate_json(p.read_text(encoding="utf-8"))
            for p in dir_.glob("*/insight.json")
        ),
        key=lambda i: i.hostname,
    )


def tls_path(hostname: FQDN) -> Path:
    """Return the on-disk path of the TLS cert for ``hostname``.

    The cert lives at ``<host_dir>/tls.json`` - the per-host sibling of
    ``insight.json``, the leaf certificate hanging off the host's
    per-FQDN directory the way ``host_dir`` reserves room for.
    """
    return host_dir(hostname) / "tls.json"


def save_tls_certificate(certificate: TLSCertificate) -> Path:
    """Persist a cert to ``<run_dir>/hosts/<host>/tls.json``."""
    path = tls_path(certificate.host)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(certificate.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_tls_certificates() -> list[TLSCertificate]:
    """Load every per-host TLS cert in the current run, ordered by host."""
    dir_ = _hosts_dir()
    if not dir_.is_dir():
        return []
    return sorted(
        (
            TLSCertificate.model_validate_json(p.read_text(encoding="utf-8"))
            for p in dir_.glob("*/tls.json")
        ),
        key=lambda c: c.host,
    )


# Typed adapters for the per-host facet files that hold bare collections
# rather than a single model - so the JSON still round-trips through a
# typed boundary (the #45 amass-read side validates the same way).
_HOST_FINDINGS = TypeAdapter(list[RawFinding])
_HOST_PORTS = TypeAdapter(list[int])


def host_score_path(hostname: FQDN) -> Path:
    """Per-host score file: ``<host_dir>/host.json``."""
    return host_dir(hostname) / "host.json"


def save_host_score(score: HostScore) -> Path:
    """Persist a ``HostScore`` to ``<run_dir>/hosts/<host>/host.json``."""
    path = host_score_path(score.hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(score.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_host_scores() -> list[HostScore]:
    """Load every per-host score in the current run, ordered by hostname."""
    dir_ = _hosts_dir()
    if not dir_.is_dir():
        return []
    return sorted(
        (
            HostScore.model_validate_json(p.read_text(encoding="utf-8"))
            for p in dir_.glob("*/host.json")
        ),
        key=lambda s: s.hostname,
    )


def notes_path(hostname: FQDN) -> Path:
    """Per-host prose file: ``<host_dir>/notes.md``."""
    return host_dir(hostname) / "notes.md"


def save_host_notes(hostname: FQDN, notes: str) -> Path:
    """Persist the OA's prose guidance to ``<run_dir>/hosts/<host>/notes.md``.

    The "look here, because ..." half of the curation, kept as markdown
    outside the typed data shape. Agent-authored prose: it is read back by
    downstream agents as workspace context (that is the point of the
    handoff), so no injection guard - the risk surface is *verbatim
    tool-captured* strings, which live in the typed evidence facets
    (findings / tls), not here.
    """
    path = notes_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(notes, encoding="utf-8")
    return path


def findings_path(hostname: FQDN) -> Path:
    """Per-host findings file: ``<host_dir>/findings.json``."""
    return host_dir(hostname) / "findings.json"


def save_host_findings(hostname: FQDN, findings: list[RawFinding]) -> Path:
    """Persist a host's node-local findings to ``hosts/<host>/findings.json``."""
    path = findings_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_FINDINGS.dump_json(findings, indent=2))
    return path


def load_host_findings(hostname: FQDN) -> list[RawFinding]:
    """Load a host's node-local findings; empty when none were written."""
    path = findings_path(hostname)
    if not path.is_file():
        return []
    return _HOST_FINDINGS.validate_json(path.read_text(encoding="utf-8"))


def ports_path(hostname: FQDN) -> Path:
    """Per-host open-ports file: ``<host_dir>/ports.json``."""
    return host_dir(hostname) / "ports.json"


def save_host_ports(hostname: FQDN, ports: list[int]) -> Path:
    """Persist a host's open ports to ``hosts/<host>/ports.json``."""
    path = ports_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_PORTS.dump_json(ports, indent=2))
    return path


def load_host_ports(hostname: FQDN) -> list[int]:
    """Load a host's open ports; empty when none were written."""
    path = ports_path(hostname)
    if not path.is_file():
        return []
    return _HOST_PORTS.validate_json(path.read_text(encoding="utf-8"))


def load_attack_graph(attack_graph_filename: str = _ATTACK_GRAPH_FILENAME) -> AttackGraph:
    """Load the OA's internal sweep artefact."""
    path = runtime.run_dir() / attack_graph_filename
    if not path.is_file():
        raise FileNotFoundError(f"{attack_graph_filename} not found; run Run Initial Sweep first")
    return AttackGraph.model_validate_json(path.read_text(encoding="utf-8"))


# Finalisation

# Status codes whose hosts deserve an annotation: 2xx is a live target,
# 3xx redirects often hide gates, 401/403 confirm an auth-gated surface
# worth probing. Pure 404/500 we let slide.
_INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403}


def _finding_host(target: str) -> str:
    """Best-effort hostname from a ``RawFinding`` target (URL or bare host)."""
    from urllib.parse import urlparse

    candidate = target if "://" in target else f"//{target}"
    return (urlparse(candidate).hostname or target).strip().lower()


def _materialise_host_dirs(sweep: AttackGraph, insights: list[HostInsight]) -> None:
    """Write each host's OAM-node directory under ``hosts/<fqdn>/``.

    The OA's per-node handoff, split into typed facets so #45 can swap each
    JSON write for an amass insert one day:

    * ``host.json`` / ``notes.md`` - the curation: the typed score+priority,
      and the prose "look here, because ..." lifted out of the data shape.
    * ``ports.json`` / ``findings.json`` / ``tls.json`` - the recon facts,
      read back off the sweep.

    Dormant facets stay unwritten (empty ports, no certs) rather than
    littering empty files.
    """
    for insight in insights:
        save_host_score(
            HostScore(
                hostname=insight.hostname,
                role=insight.role,
                priority=insight.priority,
                annotated_at=insight.annotated_at,
            )
        )
        save_host_notes(insight.hostname, insight.notes)

    for hostname, ports in sweep.open_ports.items():
        if ports:
            save_host_ports(hostname, ports)

    findings_by_host: dict[str, list[RawFinding]] = {}
    for finding in sweep.passive_findings:
        host = _finding_host(finding.target)
        if host:
            findings_by_host.setdefault(host, []).append(finding)
    for hostname, host_findings in findings_by_host.items():
        save_host_findings(hostname, host_findings)

    for certificate in sweep.tls_certificates:
        save_tls_certificate(certificate)


def finalise_recon(
    programme: Programme,
    attack_graph_filename: str = _ATTACK_GRAPH_FILENAME,
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
    sweep = load_attack_graph(attack_graph_filename)
    insights = load_insights()

    if not insights:
        raise ReconFinalisationError(
            "no host insights have been authored; call Annotate Host for the "
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

    _materialise_host_dirs(sweep, insights)

    final = AttackGraph(
        programme=sweep.programme,
        subdomains=sweep.subdomains,
        endpoints=sweep.endpoints,
        open_ports=sweep.open_ports,
        technologies=sweep.technologies,
        passive_findings=sweep.passive_findings,
        network_hops=sweep.network_hops,
        # Carry the sweep's enrichment forward - finalise previously dropped
        # ip_assets (and would drop tls_certificates), losing it from the
        # PT-facing recon.json even though the sweep gathered it.
        ip_assets=sweep.ip_assets,
        tls_certificates=sweep.tls_certificates,
        host_insights=insights,
        notes=_build_notes(sweep, insights),
    )

    out_path = runtime.run_dir() / recon_filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(final.model_dump_json(), encoding="utf-8")
    return out_path


def _build_notes(sweep: AttackGraph, insights: list[HostInsight]) -> str:
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


def uncovered_interesting_hosts(sweep: AttackGraph, insights: list[HostInsight]) -> list[str]:
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
    "finalise_recon",
    "findings_path",
    "host_dir",
    "host_score_path",
    "insight_path",
    "load_attack_graph",
    "load_host_findings",
    "load_host_ports",
    "load_host_scores",
    "load_insights",
    "load_tls_certificates",
    "notes_path",
    "ports_path",
    "save_host_findings",
    "save_host_notes",
    "save_host_ports",
    "save_host_score",
    "save_insight",
    "save_tls_certificate",
    "tls_path",
    "uncovered_interesting_hosts",
    "validate_insight",
]
