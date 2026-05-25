"""
tests/test_models.py - unit tests for models.py
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from models import (
    Endpoint,
    Hostname,
    HttpUrl,
    RawFinding,
    ReconResult,
    Severity,
    VerifiedVulnerability,
)
from models.attack import AttackPlan, AttackPlanItem
from models.h1 import (
    DisclosureReport,
    Programme,
    ScopeItem,
    ScopeType,
    SubmissionResult,
    SubmissionStatus,
)

pytestmark = pytest.mark.unit


class TestSeverityEnum:
    def test_all_values_present(self):
        levels = {s.value for s in Severity}
        assert levels == {"informational", "low", "medium", "high", "critical"}

    def test_severity_is_string_enum(self):
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "high"


class TestScopeItem:
    def test_valid_url_scope_item(self, scope_item_url):
        assert scope_item_url.asset_type == ScopeType.URL
        assert scope_item_url.eligible_for_bounty is True

    def test_valid_wildcard_scope_item(self, scope_item_wildcard):
        assert scope_item_wildcard.asset_type == ScopeType.WILDCARD

    def test_instruction_defaults_to_none(self):
        item = ScopeItem(
            asset_identifier="https://example.com",
            asset_type=ScopeType.URL,
        )
        assert item.instruction is None

    def test_invalid_asset_type_raises(self):
        with pytest.raises(ValidationError):
            ScopeItem(
                asset_identifier="https://example.com",
                asset_type="not_a_real_type",
            )


class TestProgramme:
    def test_valid_programme(self, programme):
        assert programme.handle == "test-programme"
        assert Severity.HIGH in programme.bounty_table

    def test_priority_score_defaults_to_zero(self, programme):
        assert programme.priority_score == 0.0

    def test_selected_at_is_set(self, programme):
        assert programme.selected_at is not None

    def test_serialise_roundtrip(self, programme):
        data = programme.model_dump()
        restored = Programme.model_validate(data)
        assert restored.handle == programme.handle
        assert restored.bounty_table == programme.bounty_table


class TestEndpoint:
    def test_valid_endpoint(self, endpoint):
        assert endpoint.status_code == 200
        assert "nginx" in endpoint.technologies

    def test_optional_fields_default(self):
        ep = Endpoint(url="https://example.com")
        assert ep.status_code is None
        assert ep.technologies == []
        assert ep.parameters == []


# Hostname is exercised through a throwaway pydantic model so the validator
# fires the same way it does when carried on a real schema field. Stick to
# pytest.raises(ValidationError) rather than the lower-level ValueError so
# the test mirrors what schema callers will see.
class _HostnameProbe(BaseModel):
    """Thin probe model used to drive the Hostname validator in isolation."""

    value: Hostname


class TestHostname:
    def test_accepts_target_apex(self, target_url):
        # urlparse hostname is the canonical way to derive a Hostname-shaped
        # string from a URL fixture; using the fixture keeps test intent
        # ("the in-scope target") readable at the call site.
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        apex = host.split(".", 1)[-1]  # "example.com" from "victim.example.com"
        assert _HostnameProbe(value=apex).value == apex

    def test_accepts_victim_subdomain(self, target_url):
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        assert _HostnameProbe(value=host).value == host

    def test_accepts_single_label(self):
        # ``localhost`` is the canonical single-label hostname; no URL fixture
        # exposes one because the rest of the codebase doesn't reach for it.
        assert _HostnameProbe(value="localhost").value == "localhost"

    def test_accepts_numeric_labels(self):
        # 10.0.0.1 looks IP-shaped but parses as a valid hostname per RFC 1123
        # label rules (digits are allowed). The scope filter is the next layer
        # that decides whether to accept it as an in-scope target.
        assert _HostnameProbe(value="10.0.0.1").value == "10.0.0.1"

    def test_lowercases_victim_host(self, target_url):
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        assert _HostnameProbe(value=host.upper()).value == host

    def test_strips_whitespace_around_victim_host(self, target_url):
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        assert _HostnameProbe(value=f"  {host}  ").value == host

    def test_rejects_malformed(self, target_url):
        """Walks the malformed corpus, deriving each case from target_url
        so test intent ("a deliberately broken version of the in-scope
        target") is readable. Pytest parametrize literals cannot consume
        fixtures, so a single dedicated method loops the corpus instead.
        """
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        cases: list[tuple[str, str]] = [
            ("", "empty"),
            ("   ", "whitespace only"),
            (f"https://{host}", "scheme present"),
            (f"ftp://{host}", "non-http scheme"),
            (f"{host}:8080", "port present"),
            (f"{host}/path", "path present"),
            (f"{host}/", "trailing slash"),
            (f"-{host}", "leading hyphen"),
            (f"{host}-", "trailing hyphen on label"),
            (host.replace(".", "..", 1), "empty label"),
            ("a" * 64 + f".{host}", "label > 63 chars"),
            (".".join(["a"] * 200), "total > 253 chars"),
            (host.replace(".", " .", 1), "space in label"),
            (f"{host}\nextra", "newline injection"),
        ]
        for value, label in cases:
            with pytest.raises(ValidationError, match=r".*"):
                _HostnameProbe.model_validate({"value": value})
            # ``label`` is unused at the assertion level but appears in the
            # case tuple so a future debugger can identify which case failed.
            del label

    def test_rejects_non_string(self):
        with pytest.raises(ValidationError):
            _HostnameProbe.model_validate({"value": 42})


class _HttpUrlProbe(BaseModel):
    """Thin probe model used to drive the HttpUrl validator in isolation."""

    value: HttpUrl


class TestHttpUrl:
    def test_accepts_target_url(self, target_url):
        assert _HttpUrlProbe(value=target_url).value == target_url

    def test_accepts_target_url_with_path(self, target_url):
        url = f"{target_url}/api/users?id=1"
        assert _HttpUrlProbe(value=url).value == url

    def test_accepts_http_scheme(self, target_url):
        url = target_url.replace("https://", "http://")
        assert _HttpUrlProbe(value=url).value == url

    def test_rejects_malformed(self, target_url):
        """Walks the malformed corpus, deriving each case from target_url so
        intent ("a deliberately broken URL based on the in-scope target") is
        readable at the call site. The Hostname-component check inside
        HttpUrl is exercised by the leading-hyphen case - a URL whose host
        fails Hostname validation rejects too.
        """
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        cases: list[tuple[str, str]] = [
            ("", "empty"),
            ("   ", "whitespace only"),
            (host, "no scheme - bare hostname"),
            (f"ftp://{host}", "non-http scheme"),
            ("javascript:alert(1)", "javascript scheme"),
            ("file:///etc/passwd", "file scheme"),
            ("https://", "scheme with no host"),
            ("https:///path", "scheme + path with no host"),
            (f"https://-{host}", "hostname inside URL fails RFC 1123"),
        ]
        for value, label in cases:
            with pytest.raises(ValidationError):
                _HttpUrlProbe.model_validate({"value": value})
            del label

    def test_preserves_path_and_query(self, target_url):
        url = f"{target_url}/search?q=hello&page=2#top"
        assert _HttpUrlProbe(value=url).value == url


class TestReconResult:
    def test_valid_recon_result(self, recon_result):
        assert len(recon_result.subdomains) == 2
        assert len(recon_result.endpoints) == 1

    def test_completed_at_is_set(self, recon_result):
        assert recon_result.completed_at is not None

    def test_serialise_roundtrip(self, recon_result):
        json_str = recon_result.model_dump_json()
        restored = ReconResult.model_validate_json(json_str)
        assert restored.programme.handle == recon_result.programme.handle
        assert len(restored.endpoints) == len(recon_result.endpoints)


class TestAttackPlan:
    def test_serialise_roundtrip(self, attack_plan):
        restored = AttackPlan.model_validate_json(attack_plan.model_dump_json())
        assert restored.programme_handle == attack_plan.programme_handle
        assert restored.items[0].expected_ceiling == Severity.CRITICAL


class TestAttackPlanItem:
    def test_accepts_vulnerability_class_probe(self, target_url):
        # The fixture covers CVE-id probes; this variant exercises the
        # vulnerability-class name shape (the second canonical probe form)
        # with a recon-evidence list to confirm the model accepts it end to end.
        item = AttackPlanItem(
            probe="reflected XSS",
            target=f"{target_url}/?q=test",
            expected_ceiling=Severity.MEDIUM,
            rationale="parameterised endpoint reflects q into response without escaping",
            recon_evidence=[f"{target_url} hosts a Vue 2 SPA"],
        )
        assert item.probe == "reflected XSS"
        assert item.expected_ceiling == Severity.MEDIUM

    def test_recon_evidence_strips_and_filters_empties(self, target_url):
        # The recon_evidence field carries a Pydantic field_validator:
        # whitespace is trimmed off every entry, and empties are
        # dropped. Every constructor (direct call, model_validate,
        # model_validate_json on a re-loaded plan) sees the same
        # cleaned list, so the wrapper does not need its
        # own defensive shaping and the persisted artefact never carries
        # whitespace-only entries.
        item = AttackPlanItem(
            probe="reflected XSS",
            target=f"{target_url}/?q=test",
            expected_ceiling=Severity.MEDIUM,
            rationale="parameterised endpoint reflects q into response without escaping",
            recon_evidence=["  signal one  ", "", "   ", "signal two"],
        )
        assert item.recon_evidence == ["signal one", "signal two"]


class TestRawFinding:
    def test_valid_finding(self, raw_finding_high):
        assert raw_finding_high.vuln_class == "SQLi"
        assert raw_finding_high.severity_hint == Severity.HIGH

    def test_severity_defaults_to_medium(self):
        finding = RawFinding(
            title="Test",
            vuln_class="XSS",
            target="https://example.com",
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


class TestDisclosureReport:
    def test_valid_report(self, disclosure_report):
        assert disclosure_report.programme_handle == "test-programme"
        assert disclosure_report.weakness_id == 89

    def test_attachments_default_empty(self, disclosure_report):
        assert disclosure_report.attachments == []

    def test_serialise_roundtrip(self, disclosure_report):
        json_str = disclosure_report.model_dump_json()
        restored = DisclosureReport.model_validate_json(json_str)
        assert restored.title == disclosure_report.title


class TestSubmissionResult:
    def test_default_status_is_pending(self):
        result = SubmissionResult()
        assert result.status == SubmissionStatus.PENDING
        assert result.report_id is None

    def test_successful_submission(self):
        from datetime import UTC, datetime

        result = SubmissionResult(
            report_id="12345",
            status=SubmissionStatus.SUBMITTED,
            h1_url="https://hackerone.com/reports/12345",
            submitted_at=datetime.now(UTC),
        )
        assert result.report_id == "12345"
        assert result.submitted_at is not None
