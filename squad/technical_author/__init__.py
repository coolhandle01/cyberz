"""Technical Author - writes professional H1-format disclosure reports."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from models import VerifiedVulnerability
from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from tools import http
from tools.report_tools import (
    calculate_cvss_score,
    create_disclosure_report,
    save_report,
)


@tool("Create Disclosure Report")
def create_report_tool(verified_path: str, programme_handle: str, summary: str) -> dict:
    """
    Create and save a structured DisclosureReport from the highest-severity
    verified vulnerability. Reads the verified vulnerabilities list from
    verified_path. Writes report.json into the run directory and returns the
    serialised report ready for submission.
    """
    import json
    from pathlib import Path

    import runtime

    http.set_programme(programme_handle)
    verified_data = json.loads(Path(verified_path).read_text(encoding="utf-8"))
    if not verified_data:
        raise ValueError(f"No verified vulnerabilities found in {verified_path}")
    vuln = VerifiedVulnerability.model_validate(verified_data[0])
    report = create_disclosure_report(programme_handle, vuln, summary)
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
