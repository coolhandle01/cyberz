"""Technical Author - writes professional H1-format disclosure reports."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from models import VerifiedVulnerability
from squad import SquadMember
from tools.report_tools import (
    calculate_cvss_score,
    create_disclosure_report,
    save_report,
)


@tool("Create Disclosure Report")
def create_report_tool(programme_handle: str, vulnerability_json: str, summary: str) -> dict:
    """
    Create and save a structured DisclosureReport from a verified vulnerability.
    Returns the serialised report ready for submission.
    """
    vuln = VerifiedVulnerability.model_validate_json(vulnerability_json)
    report = create_disclosure_report(programme_handle, vuln, summary)
    save_report(report)
    return report.model_dump()


@tool("Calculate CVSS Score")
def calculate_cvss_tool(vector: str) -> float:
    """
    Compute the CVSS 3.1 base score from a vector string such as
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Returns a value in 0.0-10.0.
    Use this instead of guessing the score.
    """
    return calculate_cvss_score(vector)


MEMBER = SquadMember(
    slug="technical_author",
    dir=Path(__file__).parent,
    tools=[create_report_tool, calculate_cvss_tool],
)
