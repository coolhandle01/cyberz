"""
tests/test_squad_disclosure_coordinator.py - exercise the @tool wrappers on
the Disclosure Coordinator.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestDisclosureCoordinatorTools:
    def test_submit_report_tool(self, disclosure_report) -> None:
        from models.h1 import SubmissionResult, SubmissionStatus
        from squad.disclosure_coordinator import submit_report_tool

        report_json = disclosure_report.model_dump_json()
        submission = SubmissionResult(report_id="h1-42", status=SubmissionStatus.SUBMITTED)

        with (
            patch("squad.disclosure_coordinator.http.set_programme") as mhttp,
            patch("squad.disclosure_coordinator.save_report") as msave,
            patch(
                "squad.disclosure_coordinator.h1.submit_report",
                return_value=submission,
            ) as msub,
        ):
            result = submit_report_tool.func(report_json)

        assert result == submission
        mhttp.assert_called_once_with(disclosure_report.programme_handle)
        msave.assert_called_once()
        msub.assert_called_once()

    def test_check_duplicate_tool(self) -> None:
        from squad.disclosure_coordinator import check_duplicate_tool

        reports = [
            {
                "id": "1",
                "attributes": {"title": "SQL Injection in search", "state": "open"},
            },
        ]
        with (
            patch("squad.disclosure_coordinator.http.set_programme"),
            patch(
                "squad.disclosure_coordinator.h1.list_reports",
                return_value=reports,
            ),
        ):
            result = check_duplicate_tool.func("acme", "SQL Injection in search")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].title == "SQL Injection in search"
        assert result[0].report_id == "1"
