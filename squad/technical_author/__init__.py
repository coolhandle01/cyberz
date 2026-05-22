"""Technical Author - writes professional H1-format disclosure reports."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from models import ProgrammeReportSummary
from squad import SquadMember, cached_tool, read_run_file_tool, read_run_filelist_tool
from tools import http
from tools.cwe_data import CWEEntry
from tools.cwe_data import lookup as cwe_lookup
from tools.h1_api import h1
from tools.owasp_data import OWASPEntry
from tools.owasp_data import lookup as owasp_lookup
from tools.report_tools import (
    FinalisationError,
    ReportDraft,
    ReportDraftResult,
    SanitisationReport,
    calculate_cvss_score,
    finalise_drafts,
    load_verified,
    sanitise_evidence,
    save_draft,
    validate_draft,
)
from tools.workspace import resolve_run_path


@tool("Sanitise Evidence")
def sanitise_evidence_tool(text: str) -> SanitisationReport:
    """
    Redact credentials, cookies, bearer tokens, JWTs, AWS keys and secret-shaped
    key=value pairs from a chunk of evidence so it is safe to inline in a
    public-by-default report. Returns {sanitised, redactions, warnings}.
    Payloads (XSS strings, SQL injection vectors, SSRF URLs) are deliberately
    NOT redacted - the disclosure is private and the triager needs the literal
    request that proves the issue. Run this on the Penetration Tester's raw
    evidence before pasting it into Draft Vulnerability Report.
    """
    return sanitise_evidence(text)


@cached_tool("Lookup CWE")
def lookup_cwe_tool(query: str) -> list[CWEEntry]:
    """
    Find Common Weakness Enumeration entries that match a query. Pass a
    vuln_class string ("SQLi", "ReflectedXSS"), a CWE name ("Cross-Site
    Scripting"), or a free-text keyword. Returns each match's cwe_id, name,
    short description, MITRE URL, and the matching OWASP cheat-sheet topic so
    you can chain to Lookup OWASP Guidance.
    """
    return list(cwe_lookup(query))


@cached_tool("Lookup OWASP Guidance")
def lookup_owasp_tool(query: str) -> list[OWASPEntry]:
    """
    Find OWASP Cheat Sheet entries that match a query (topic slug or title
    keyword such as "sql injection", "ssrf", "authorization"). Returns each
    match's title, key_principles (short, paste-friendly statements), and the
    canonical cheatsheetseries.owasp.org URL to cite in the Remediation
    section.
    """
    return list(owasp_lookup(query))


@tool("Calculate CVSS Score")
def calculate_cvss_tool(vector: str) -> float:
    """
    Compute the CVSS 3.1 base score from a vector string such as
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Returns a value in 0.0-10.0.
    Use this instead of guessing the score; Draft Vulnerability Report verifies
    that cvss_score matches the computed value before accepting the draft.
    """
    return calculate_cvss_score(vector)


@tool("List Programme Reports")
def list_programme_reports_tool(
    programme_handle: str, page_size: int = 25
) -> list[ProgrammeReportSummary]:
    """
    List recent public reports on this programme so you can write a title that
    is distinct from existing submissions. Returns each report's id, title,
    severity, and state. Use this BEFORE drafting if you suspect collision -
    the Disclosure Coordinator will reject duplicates at submission time and a
    well-differentiated title speeds up triage.
    """
    http.set_programme(programme_handle)
    reports = h1.list_reports(programme_handle, page_size=page_size)
    return [
        ProgrammeReportSummary(
            report_id=r.get("id"),
            title=r.get("attributes", {}).get("title"),
            severity=r.get("attributes", {}).get("severity_rating"),
            state=r.get("attributes", {}).get("state"),
        )
        for r in reports
    ]


@tool("Draft Vulnerability Report")
def draft_report_tool(
    finding_index: int,
    title: str,
    summary: str,
    description: str,
    steps_to_reproduce: list[str],
    evidence: str,
    impact: str,
    remediation: str,
    cvss_vector: str,
    cwe_id: int,
    verified_path: str = "verified.json",
) -> ReportDraftResult:
    """
    Draft a single H1-format report for one verified finding and run quality
    validation against it. The carried fields (target, vuln_class, severity)
    are pulled from verified.json at ``finding_index`` so you cannot
    accidentally contradict the Vulnerability Researcher.

    Inputs are the prose the triager will read:
      - title: `[Type] in [Component/Endpoint] allows [Outcome]`
      - summary: 2-3 sentences (root cause + location + concrete impact)
      - description: developer-focused explanation of WHY the code is vulnerable
      - steps_to_reproduce: numbered list, each step at least 10 chars
      - evidence: PRE-SANITISED tool output / HTTP excerpt; run Sanitise
        Evidence first to strip credentials and cookies
      - impact: specific, named data/system and worst realistic outcome
      - remediation: actionable fix with an OWASP or CWE URL citation
      - cvss_vector + cwe_id: must match the computed CVSS score and an entry
        in the CWE catalogue

    Returns a ReportDraftResult with the relative draft path and a
    ValidationReport. When validation.ok is false, re-run with the issues
    addressed - Finalise Reports refuses to consolidate drafts with
    unresolved errors.
    """
    verified = load_verified(resolve_run_path(verified_path))
    if finding_index < 0 or finding_index >= len(verified):
        raise ValueError(
            f"finding_index {finding_index} out of range "
            f"(verified.json has {len(verified)} findings)"
        )
    finding = verified[finding_index]

    draft = ReportDraft(
        finding_index=finding_index,
        target=finding.target,
        vuln_class=finding.vuln_class,
        severity=finding.severity,
        cvss_vector=cvss_vector,
        cvss_score=calculate_cvss_score(cvss_vector),
        cwe_id=cwe_id,
        title=title.strip(),
        summary=summary.strip(),
        description=description.strip(),
        steps_to_reproduce=[s.strip() for s in steps_to_reproduce],
        evidence=evidence,
        impact=impact.strip(),
        remediation=remediation.strip(),
    )
    path = save_draft(draft)
    return ReportDraftResult(
        path=str(path.relative_to(path.parents[1])),
        validation=validate_draft(draft),
    )


@tool("Finalise Reports")
def finalise_reports_tool(
    programme_handle: str,
    summary: str,
    verified_path: str = "verified.json",
) -> str:
    """
    Roll up every draft in the current run into reports.json for the Disclosure
    Coordinator. Refuses if any draft is missing or has unresolved validation
    errors; the error message lists exactly which draft / section needs work.

    ``summary`` is a 2-3 sentence executive summary covering the overall
    session; it is attached to every report.

    Returns the bare filename "reports.json" on success.
    """
    verified = load_verified(resolve_run_path(verified_path))
    try:
        path = finalise_drafts(programme_handle, summary, expected_count=len(verified))
    except FinalisationError as exc:
        raise ValueError(str(exc)) from exc
    return path.name


MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[
        draft_report_tool,
        finalise_reports_tool,
        sanitise_evidence_tool,
        lookup_cwe_tool,
        lookup_owasp_tool,
        calculate_cvss_tool,
        list_programme_reports_tool,
        read_run_filelist_tool,
        read_run_file_tool,
    ],
)
