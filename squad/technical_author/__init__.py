"""Technical Author - writes professional H1-format disclosure reports."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from tools import http
from tools.h1_api import h1
from tools.pentest import triage_findings
from tools.report_tools import (
    calculate_cvss_score,
    create_disclosure_report,
    save_report,
)


@tool("Create Disclosure Report")
def create_report_tool(findings_path: str, programme_handle: str, summary: str) -> dict:
    """
    Create and save a structured DisclosureReport from the highest-severity
    finding in findings.json. Internally upgrades RawFindings to a verified,
    scored VerifiedVulnerability (scope check + severity floor + CVSS assignment),
    selects the top-severity one, and writes report.json into the run directory.
    Returns the serialised report ready for submission.
    """
    import json

    import runtime
    from models import RawFinding
    from tools.workspace import resolve_run_path

    http.set_programme(programme_handle)
    raw_data = json.loads(resolve_run_path(findings_path).read_text(encoding="utf-8"))
    if not raw_data:
        raise ValueError(f"No findings found in {findings_path}")
    raw = [RawFinding.model_validate(f) for f in raw_data]
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    programme = h1.parse_programme(policy["data"], scope)
    verified = triage_findings(raw, programme)
    if not verified:
        raise ValueError(f"No findings in {findings_path} passed scope + severity-floor triage")
    report = create_disclosure_report(programme_handle, verified[0], summary)
    save_report(report)
    out_path = runtime.run_dir() / "report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.model_dump_json(), encoding="utf-8")
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
    tools=[
        create_report_tool,
        calculate_cvss_tool,
        read_run_filelist_tool,
        read_run_file_tool,
    ],
)
