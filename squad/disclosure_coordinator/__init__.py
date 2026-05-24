"""Disclosure Coordinator - submits finalised reports to HackerOne."""

from pathlib import Path

from pydantic import BaseModel, Field

from models import ProgrammeReportSummary
from models.h1 import DisclosureReport, SubmissionResult
from squad import SquadMember, cyber_tool, read_run_file_tool, read_run_filelist_tool
from tools import http
from tools.h1_api import h1
from tools.report_tools import save_report


class _SubmitReportArgs(BaseModel):
    """Explicit args_schema for the Submit Report tool (#149).

    IRREVERSIBLE: a successful call publishes a report to hackerone.com.
    Once filed the report is visible to the programme's triage team and
    cannot be silently retried - the field descriptions below name the
    consequences the agent must reason about before calling.
    """

    report_json: str = Field(
        description=(
            "Serialised ``DisclosureReport`` JSON. Built by the Technical"
            " Author and parsed via ``DisclosureReport.model_validate_json``"
            " before submission. IRREVERSIBLE: a successful call publishes"
            " the report to hackerone.com and cannot be silently retried."
            " Mis-shaped JSON rejects upstream of the HTTP POST, but a"
            " well-shaped report with the wrong ``programme_handle`` inside"
            " it does NOT: it files a report against the wrong target,"
            " which is a public scope violation the operator has to"
            " apologise for. Double-check the ``programme_handle`` field"
            " inside the payload against the selected programme before"
            " calling. Also verify ``title``, ``vulnerability.severity``,"
            " ``weakness_id``, and ``structured_scope_id`` - all four are"
            " submission-time authoritative; H1 records them verbatim and"
            " there is no quiet edit path."
        ),
    )


@cyber_tool("Submit Report", args_schema=_SubmitReportArgs)
def submit_report_tool(report_json: str) -> SubmissionResult:
    """Submit a serialised DisclosureReport to HackerOne."""
    report = DisclosureReport.model_validate_json(report_json)
    http.set_programme(report.programme_handle)
    save_report(report)
    return h1.submit_report(report)


class _CheckDuplicateArgs(BaseModel):
    """Explicit args_schema for the Check H1 Duplicate tool (#149)."""

    programme_handle: str = Field(
        description=(
            "Exact HackerOne programme handle as it appears in the URL"
            " (lowercase, no slashes, no spaces). Must match the programme"
            " the report is about to be submitted against - querying the"
            " wrong programme's reports list returns a false-negative"
            " duplicate check and an actual duplicate slips through."
        ),
    )
    title: str = Field(
        description=(
            "Draft report title to fuzzy-match against existing reports on"
            " this programme. The first 30 characters (case-insensitive)"
            " are used as the substring needle, so phrase the title so its"
            " leading 30 characters are distinctive (target host or"
            " vulnerability class up front)."
        ),
    )


@cyber_tool("Check H1 Duplicate", args_schema=_CheckDuplicateArgs)
def check_duplicate_tool(programme_handle: str, title: str) -> list[ProgrammeReportSummary]:
    """
    Last-chance duplicate check before submission. Lists recent reports on this
    programme whose titles resemble the given title. A match means another
    researcher may have already submitted this finding.
    """
    http.set_programme(programme_handle)
    reports = h1.list_reports(programme_handle, page_size=25)
    title_lower = title.lower()
    return [
        ProgrammeReportSummary(
            report_id=r.get("id"),
            title=r.get("attributes", {}).get("title"),
            state=r.get("attributes", {}).get("state"),
        )
        for r in reports
        if title_lower[:30] in (r.get("attributes", {}).get("title") or "").lower()
    ]


MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[
        submit_report_tool,
        check_duplicate_tool,
        read_run_filelist_tool,
        read_run_file_tool,
    ],
)
