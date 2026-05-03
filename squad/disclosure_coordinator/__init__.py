"""Disclosure Coordinator - submits finalised reports to HackerOne."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from squad import SquadMember
from tools.h1_api import h1
from tools.report_tools import save_report


@tool("Submit Report")
def submit_report_tool(report_json: str) -> dict:
    """Submit a serialised DisclosureReport to HackerOne."""
    from models import DisclosureReport

    report = DisclosureReport.model_validate_json(report_json)
    save_report(report)
    result = h1.submit_report(report)
    return result.model_dump()


@tool("Check H1 Duplicate")
def check_duplicate_tool(programme_handle: str, title: str) -> list[dict]:
    """
    Last-chance duplicate check before submission. Lists recent reports on this
    programme whose titles resemble the given title. A match means another
    researcher may have already submitted this finding.
    """
    reports = h1.list_reports(programme_handle, page_size=25)
    title_lower = title.lower()
    return [
        {
            "report_id": r.get("id"),
            "title": r.get("attributes", {}).get("title"),
            "state": r.get("attributes", {}).get("state"),
        }
        for r in reports
        if title_lower[:30] in (r.get("attributes", {}).get("title") or "").lower()
    ]


MEMBER = SquadMember(
    slug="disclosure_coordinator",
    dir=Path(__file__).parent,
    tools=[submit_report_tool, check_duplicate_tool],
)
