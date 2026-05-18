"""Technical Author - writes professional H1-format disclosure reports."""

from __future__ import annotations

import json
from pathlib import Path

from crewai.tools import tool

import runtime
from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from tools.report_tools import (
    calculate_cvss_score,
    create_disclosure_report,
    save_report,
)
from tools.workspace import resolve_run_path


@tool("Create Disclosure Reports")
def create_reports_tool(verified_path: str, programme_handle: str, summary: str) -> str:
    """
    Create a DisclosureReport for every VerifiedVulnerability in verified.json
    and write them all to reports.json in the run directory. Returns the bare
    filename "reports.json". The Disclosure Coordinator reads this file to
    submit each finding independently.

    ``summary`` is a 2-3 sentence executive summary covering the overall
    session; it is included in each report alongside the finding detail.
    """
    from models import VerifiedVulnerability

    raw = json.loads(resolve_run_path(verified_path).read_text(encoding="utf-8"))
    if not raw:
        raise ValueError(f"No verified findings in {verified_path}")
    verified = [VerifiedVulnerability.model_validate(v) for v in raw]
    reports = []
    for vuln in verified:
        report = create_disclosure_report(programme_handle, vuln, summary)
        save_report(report)
        reports.append(report.model_dump(mode="json"))
    out_path = runtime.run_dir() / "reports.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(reports), encoding="utf-8")
    return "reports.json"


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
    tools=[
        create_reports_tool,
        calculate_cvss_tool,
        read_run_filelist_tool,
        read_run_file_tool,
    ],
)
