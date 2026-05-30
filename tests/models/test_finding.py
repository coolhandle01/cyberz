"""tests/models/test_finding.py - unit tests for models/finding.py."""

from __future__ import annotations

import pytest

from models import (
    RawFinding,
    Severity,
    VerifiedVulnerability,
)

pytestmark = pytest.mark.unit


class TestRawFinding:
    def test_valid_finding(self, raw_finding_high):
        assert raw_finding_high.vuln_class == "SQLi"
        assert raw_finding_high.severity_hint == Severity.HIGH

    def test_severity_defaults_to_medium(self, target_apex):
        finding = RawFinding(
            title="Test",
            vuln_class="XSS",
            target=f"https://{target_apex}",
            evidence="payload reflected",
            tool="nuclei",
        )
        assert finding.severity_hint == Severity.MEDIUM


class TestVerifiedVulnerability:
    def test_valid_verified_vuln(self, verified_vuln):
        assert verified_vuln.in_scope is True
        assert verified_vuln.cvss_score == 8.8
        assert len(verified_vuln.steps_to_reproduce) == 3

    def test_confirmed_at_is_set(self, verified_vuln):
        assert verified_vuln.confirmed_at is not None

    def test_serialise_roundtrip(self, verified_vuln):
        json_str = verified_vuln.model_dump_json()
        restored = VerifiedVulnerability.model_validate_json(json_str)
        assert restored.cvss_vector == verified_vuln.cvss_vector
