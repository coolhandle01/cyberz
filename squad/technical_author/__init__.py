"""Technical Author - writes professional H1-format disclosure reports."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from models import ProgrammeReportSummary
from squad import SquadMember, cyber_tool, read_run_file_tool, read_run_filelist_tool
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


class _SanitiseEvidenceArgs(BaseModel):
    """Explicit args_schema for the Sanitise Evidence tool (#150)."""

    text: str = Field(
        description=(
            "Raw evidence text - HTTP request/response excerpts, tool"
            " output, captured headers - that may carry credentials,"
            " cookies, bearer tokens, JWTs, AWS keys, or other secret-"
            "shaped key=value pairs. Pass the unredacted text as it"
            " appears in the PT's raw finding; the wrapper returns a"
            " ``SanitisationReport`` carrying the redacted body, a list"
            " of redactions made, and any warnings. Payloads (XSS"
            " strings, SQL injection vectors, SSRF URLs) are"
            " deliberately NOT redacted - the triager needs the literal"
            " request that proves the issue. Run this before pasting"
            " evidence into ``Draft Vulnerability Report``."
        ),
    )


@cyber_tool("Sanitise Evidence", args_schema=_SanitiseEvidenceArgs)
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


class _TaLookupCweArgs(BaseModel):
    """Explicit args_schema for the TA's Lookup CWE tool (#150)."""

    query: str = Field(
        description=(
            "Free-text query against the Common Weakness Enumeration"
            " index. Accepts a ``vuln_class`` string (``SQLi``,"
            " ``ReflectedXSS``), a CWE name (``Cross-Site Scripting``),"
            " or a free-text keyword. Use to cite the canonical MITRE"
            " definition in the remediation section - the returned"
            " entry surfaces the matching OWASP cheat-sheet topic so"
            " you can chain to ``Lookup OWASP Guidance``."
        ),
    )


@cyber_tool("Lookup CWE", args_schema=_TaLookupCweArgs)
def lookup_cwe_tool(query: str) -> list[CWEEntry]:
    """
    Find Common Weakness Enumeration entries that match a query. Pass a
    vuln_class string ("SQLi", "ReflectedXSS"), a CWE name ("Cross-Site
    Scripting"), or a free-text keyword. Returns each match's cwe_id, name,
    short description, MITRE URL, and the matching OWASP cheat-sheet topic so
    you can chain to Lookup OWASP Guidance.
    """
    return list(cwe_lookup(query))


class _TaLookupOwaspArgs(BaseModel):
    """Explicit args_schema for the TA's Lookup OWASP Guidance tool (#150)."""

    query: str = Field(
        description=(
            "Free-text query against the OWASP Cheat Sheet index. Matches"
            " topic slug or title keyword (e.g. ``sql injection``,"
            " ``ssrf``, ``authorization``). Use to source the canonical"
            " ``cheatsheetseries.owasp.org`` URL cited in the"
            " Remediation section of the H1 report - the returned"
            " entry's ``key_principles`` are short, paste-friendly"
            " statements suitable for the report body."
        ),
    )


@cyber_tool("Lookup OWASP Guidance", args_schema=_TaLookupOwaspArgs)
def lookup_owasp_tool(query: str) -> list[OWASPEntry]:
    """
    Find OWASP Cheat Sheet entries that match a query (topic slug or title
    keyword such as "sql injection", "ssrf", "authorization"). Returns each
    match's title, key_principles (short, paste-friendly statements), and the
    canonical cheatsheetseries.owasp.org URL to cite in the Remediation
    section.
    """
    return list(owasp_lookup(query))


class _TaCalculateCvssArgs(BaseModel):
    """Explicit args_schema for the TA's Calculate CVSS Score tool (#150).

    Same vector format as on the VR's copy. ``Draft Vulnerability
    Report`` re-runs the compute and refuses if the declared score
    does not match the recomputed value - a mis-formed vector here
    flips the verdict before the draft is even validated.
    """

    vector: str = Field(
        description=(
            "Full CVSS 3.1 vector string"
            " (``CVSS:3.1/AV:<n>/AC:<n>/PR:<n>/UI:<n>/S:<n>/C:<n>/I:<n>"
            "/A:<n>``, e.g."
            " ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``). Each"
            " metric must use the documented short codes; malformed"
            " vectors raise rather than silently scoring 0. Use this"
            " before drafting so the report's declared score matches"
            " what the validator recomputes."
        ),
    )


@cyber_tool("Calculate CVSS Score", args_schema=_TaCalculateCvssArgs)
def calculate_cvss_tool(vector: str) -> float:
    """
    Compute the CVSS 3.1 base score from a vector string such as
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Returns a value in 0.0-10.0.
    Use this instead of guessing the score; Draft Vulnerability Report verifies
    that cvss_score matches the computed value before accepting the draft.
    """
    return calculate_cvss_score(vector)


class _TaListProgrammeReportsArgs(BaseModel):
    """Explicit args_schema for the TA's List Programme Reports tool (#150)."""

    programme_handle: str = Field(
        description=(
            "Exact HackerOne programme handle (lowercase, no slashes, no"
            " spaces) the report list is filtered by - the H1 API uses"
            " the handle as the authoritative key. A mis-cased or wrong"
            " handle returns 404 / an empty list and the TA drafts a"
            " title against an empty prior-art surface rather than the"
            " real one."
        ),
    )
    page_size: int = Field(
        default=25,
        description=(
            "Number of reports to pull per H1 API page (default 25)."
            " Used to right-size the prior-art sample before drafting a"
            " distinct title - 25 is enough to spot collisions without"
            " a full sweep."
        ),
    )


@cyber_tool("List Programme Reports", args_schema=_TaListProgrammeReportsArgs)
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


class _DraftReportArgs(BaseModel):
    """Explicit args_schema for the Draft Vulnerability Report tool (#150).

    The longest authored contract on the TA: every field below feeds
    the report quality gate that runs before any draft can roll up
    into reports.json. The per-field descriptions are how the LLM
    learns the gate's grammar - a wrong-shape draft refuses upstream
    rather than after the body has written a half-validated artefact
    the Disclosure Coordinator then has to clean up.
    """

    finding_index: int = Field(
        description=(
            "Zero-based index into ``verified.json``. Carries target /"
            " vuln_class / severity forward from the VR's verified"
            " entry so the draft cannot accidentally contradict the"
            " Vulnerability Researcher. Out-of-range refuses explicitly."
        ),
    )
    title: str = Field(
        description=(
            "H1-format title following ``[Type] in [Component/Endpoint]"
            " allows [Outcome]``. The validator refuses generic titles -"
            " be specific about the component AND the outcome. Pair"
            " with ``List Programme Reports`` to check for collisions"
            " against existing submissions before drafting."
        ),
    )
    summary: str = Field(
        description=(
            "2-3 sentences naming root cause + location + concrete"
            " impact. This is the first thing a triager reads; if it"
            " does not name a concrete impact, the report ranks lower."
        ),
    )
    description: str = Field(
        description=(
            "Developer-focused explanation of WHY the code is"
            " vulnerable - the underlying class of flaw, not the"
            " reproduction steps (those go in ``steps_to_reproduce``)."
        ),
    )
    steps_to_reproduce: list[str] = Field(
        description=(
            "Numbered list a triager can follow verbatim. The validator"
            " refuses steps under 10 characters - each step must be"
            " concrete enough to act on without guessing."
        ),
    )
    evidence: str = Field(
        description=(
            "PRE-SANITISED tool output / HTTP excerpt. Run ``Sanitise"
            " Evidence`` first to strip credentials, cookies, and"
            " secret-shaped key=value pairs - the disclosure is"
            " private, but the report is permanent and a leaked"
            " credential cannot be quietly removed once filed."
        ),
    )
    impact: str = Field(
        description=(
            "Specific named data / system and the worst realistic"
            " outcome. The validator refuses hand-wavy language"
            " (``could compromise``, ``potential``) - this section is"
            " what the programme uses to band severity."
        ),
    )
    remediation: str = Field(
        description=(
            "Actionable fix paired with an OWASP or CWE URL citation."
            " The validator refuses remediations that name no fix or"
            " carry no citation - use ``Lookup CWE`` / ``Lookup OWASP"
            " Guidance`` to find the matching URL."
        ),
    )
    cvss_vector: str = Field(
        description=(
            "Full CVSS 3.1 vector. The wrapper recomputes ``cvss_score``"
            " and the validator refuses drafts where the score does not"
            " match the declared severity. Use ``Calculate CVSS Score``"
            " upstream to double-check."
        ),
    )
    cwe_id: int = Field(
        description=(
            "Numeric CWE identifier matching the entry from ``Lookup"
            " CWE``. The validator verifies the id resolves to a real"
            " CWE entry; an unknown id refuses upstream of the H1"
            " submission."
        ),
    )
    verified_path: str = Field(
        default="verified.json",
        description=(
            "Relative path to the VR's verified findings artefact"
            " (defaults to ``verified.json``). Override only when"
            " drafting against a non-default writer; the typical TA"
            " call accepts the default."
        ),
    )


@cyber_tool("Draft Vulnerability Report", args_schema=_DraftReportArgs)
# Every authored field is exposed as a top-level parameter so the LLM can
# fill them by name; collapsing into a single payload dict would force the
# agent to guess valid keys.
# pylint: disable=R0913,R0917
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


class _FinaliseReportsArgs(BaseModel):
    """Explicit args_schema for the TA's Finalise Reports tool (#150)."""

    programme_handle: str = Field(
        description=(
            "Exact HackerOne programme handle stamped onto every"
            " consolidated report. Must match the handle the VR's"
            " ``verified.json`` was produced under; a mismatch would"
            " ship reports labelled against the wrong programme and"
            " the DC would file them against whichever handle the body"
            " carries."
        ),
    )
    summary: str = Field(
        description=(
            "2-3 sentence executive summary covering the overall"
            " session - attached to every report in the consolidated"
            " manifest. Describe the surface tested and the breadth of"
            " what was found at a glance; the triager reads this"
            " before the per-finding body."
        ),
    )
    verified_path: str = Field(
        default="verified.json",
        description=(
            "Relative path to the VR's verified findings artefact"
            " (defaults to ``verified.json``). Override only when"
            " finalising against a non-default writer."
        ),
    )


@cyber_tool("Finalise Reports", args_schema=_FinaliseReportsArgs)
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
