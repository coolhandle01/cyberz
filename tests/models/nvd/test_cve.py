"""tests/models/nvd/test_cve.py - unit tests for the CveEntry shape."""

from __future__ import annotations

import pytest

from models import CveEntry

pytestmark = pytest.mark.unit


class TestCveEntry:
    def test_minimal(self):
        entry = CveEntry(id="CVE-2021-44228")
        assert entry.id == "CVE-2021-44228"
        assert entry.cvss_score is None
        assert entry.cvss_vector is None
        assert entry.description == ""

    def test_full(self):
        entry = CveEntry(
            id="CVE-2021-44228",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            description="Log4Shell.",
        )
        assert entry.cvss_score == 10.0
        # CveEntry.cvss_vector stays a bare str: it carries NVD's external
        # vectorString verbatim (which may be CVSS 2.0/3.x/4.0), so it is not
        # constrained by the CvssVector primitive.
        assert entry.cvss_vector.startswith("CVSS:3.1")

    def test_serialise_roundtrip(self):
        original = CveEntry(id="CVE-2022-22965", cvss_score=9.8)
        restored = CveEntry.model_validate_json(original.model_dump_json())
        assert restored.id == "CVE-2022-22965"
        assert restored.cvss_score == 9.8
