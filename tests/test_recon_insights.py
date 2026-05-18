"""tests/test_recon_insights.py - unit tests for tools/recon_insights.py."""

from __future__ import annotations

import json

import pytest

from models import (
    Endpoint,
    HostInsight,
    HostPriority,
    HostRole,
    ReconResult,
)
from tools.recon_insights import (
    ReconFinalisationError,
    finalise_recon,
    insight_path,
    load_insights,
    save_insight,
    uncovered_interesting_hosts,
    validate_insight,
)

pytestmark = pytest.mark.unit


# Fixtures
#
# The `programme` (with its `*.example.com` wildcard) and the `bystander_url`
# fixture (out-of-scope by construction) come from tests/conftest.py.


@pytest.fixture
def sweep(programme) -> ReconResult:
    return ReconResult(
        programme=programme,
        subdomains=["api.example.com", "admin.example.com", "cdn.example.com"],
        endpoints=[
            Endpoint(
                url="https://api.example.com",
                status_code=200,
                technologies=["Nginx", "Spring Boot 2.6"],
            ),
            Endpoint(
                url="https://admin.example.com",
                status_code=401,
                technologies=["WordPress 5.8"],
            ),
            Endpoint(
                url="https://cdn.example.com",
                status_code=200,
                technologies=["CloudFront"],
            ),
            Endpoint(
                url="https://dead.example.com",
                status_code=500,
                technologies=[],
            ),
        ],
    )


def _good_insight(**overrides) -> HostInsight:
    base: dict = {
        "hostname": "api.example.com",
        "role": HostRole.API,
        "priority": HostPriority.HIGH,
        "notes": (
            "Public REST API gateway running Spring Boot 2.6 behind Nginx; "
            "primary target for the programme."
        ),
        "detected_tech": ["Nginx", "Spring Boot 2.6"],
    }
    base.update(overrides)
    return HostInsight(**base)


# Validation


class TestValidateInsight:
    def test_clean_insight_passes(self, sweep, programme):
        report = validate_insight(_good_insight(), sweep, programme)
        assert report.ok is True
        assert all(i.severity != "error" for i in report.issues)

    def test_rejects_empty_hostname(self, sweep, programme):
        report = validate_insight(_good_insight(hostname=""), sweep, programme)
        assert report.ok is False
        assert any(i.section == "hostname" for i in report.issues)

    def test_rejects_out_of_scope_hostname(self, sweep, programme, bystander_url):
        from urllib.parse import urlparse

        oos_host = urlparse(bystander_url).hostname
        report = validate_insight(_good_insight(hostname=oos_host), sweep, programme)
        assert report.ok is False
        assert any(
            i.section == "hostname" and "not in programme scope" in i.message for i in report.issues
        )

    def test_rejects_thin_notes(self, sweep, programme):
        report = validate_insight(_good_insight(notes="too short"), sweep, programme)
        assert report.ok is False
        assert any(i.section == "notes" for i in report.issues)

    def test_rejects_thin_notes_on_high_priority(self, sweep, programme):
        # 35 chars is >= 30 (so not the basic floor) but < 60 (the high-priority floor)
        thirty_five = "Public API gateway hosting v2 routes."
        report = validate_insight(_good_insight(notes=thirty_five), sweep, programme)
        assert report.ok is False
        assert any(
            i.section == "notes" and "high-priority hosts" in i.message for i in report.issues
        )

    def test_rejects_thin_notes_on_skip(self, sweep, programme):
        report = validate_insight(
            _good_insight(priority=HostPriority.SKIP, notes="skip"),
            sweep,
            programme,
        )
        assert report.ok is False
        assert any(i.section == "notes" for i in report.issues)

    def test_warns_when_agent_drops_sweep_tech(self, sweep, programme):
        # sweep saw ['Nginx', 'Spring Boot 2.6']; agent only carries 'Nginx'
        report = validate_insight(
            _good_insight(detected_tech=["Nginx"]),
            sweep,
            programme,
        )
        assert report.ok is True
        assert any(i.section == "detected_tech" and i.severity == "warning" for i in report.issues)

    def test_accepts_when_agent_adds_version_to_sweep_tech(self, sweep, programme):
        # sweep saw 'Spring Boot 2.6'; agent carries 'Spring Boot 2.6.3' (more specific)
        report = validate_insight(
            _good_insight(detected_tech=["Nginx", "Spring Boot 2.6.3"]),
            sweep,
            programme,
        )
        # The version-stripping check accepts more-specific versions, but the
        # exact comparison may still warn. Either way, no errors.
        assert report.ok is True

    def test_rejects_trivial_tech_entry(self, sweep, programme):
        report = validate_insight(
            _good_insight(detected_tech=["X"]),
            sweep,
            programme,
        )
        assert report.ok is False
        assert any(i.section == "detected_tech" for i in report.issues)


# Persistence


class TestPersistence:
    def test_save_insight_writes_per_host_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        path = save_insight(_good_insight())
        assert path == tmp_path / "host_insights" / "api.example.com.json"
        assert path.exists()
        loaded = HostInsight.model_validate_json(path.read_text())
        assert loaded.hostname == "api.example.com"

    def test_save_insight_handles_special_chars_in_hostname(self, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        # Hostnames in practice are RFC 1123, but defensively sanitise unusual chars.
        ins = _good_insight(hostname="weird host/name.example.com")
        path = save_insight(ins)
        assert path.exists()

    def test_load_insights_orders_by_hostname(self, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        save_insight(_good_insight(hostname="zebra.example.com"))
        save_insight(_good_insight(hostname="aardvark.example.com"))
        loaded = load_insights()
        assert [i.hostname for i in loaded] == [
            "aardvark.example.com",
            "zebra.example.com",
        ]

    def test_load_insights_empty_when_no_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        assert load_insights() == []

    def test_insight_path_rejects_empty_hostname(self, tmp_path, monkeypatch):
        # ``insight_path`` builds <run_dir>/host_insights/<sanitised>.json, so
        # the sanitisation check has to run against a stub run_dir or
        # runtime.run_dir() raises first.
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        with pytest.raises(ValueError, match="empty after sanitisation"):
            insight_path("///")


# Coverage helper


class TestUncoveredInterestingHosts:
    def test_returns_hosts_without_insights(self, sweep):
        # No insights yet, all interesting hosts uncovered
        uncovered = uncovered_interesting_hosts(sweep, [])
        # api / admin / cdn are 200/401/200 (interesting); dead is 500 (skip)
        assert set(uncovered) == {
            "api.example.com",
            "admin.example.com",
            "cdn.example.com",
        }

    def test_drops_hosts_with_insights(self, sweep):
        uncovered = uncovered_interesting_hosts(
            sweep,
            [_good_insight(hostname="api.example.com")],
        )
        assert "api.example.com" not in uncovered
        assert "admin.example.com" in uncovered

    def test_excludes_uninteresting_status(self, sweep):
        uncovered = uncovered_interesting_hosts(sweep, [])
        assert "dead.example.com" not in uncovered


# Finalisation


def _write_sweep(tmp_path, sweep: ReconResult) -> None:
    (tmp_path / "sweep.json").write_text(sweep.model_dump_json(), encoding="utf-8")


class TestFinaliseRecon:
    def test_writes_recon_json_for_clean_insights(self, sweep, programme, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        _write_sweep(tmp_path, sweep)
        save_insight(_good_insight())
        path = finalise_recon(programme)
        assert path == tmp_path / "recon.json"
        data = json.loads(path.read_text())
        assert len(data["host_insights"]) == 1
        assert data["host_insights"][0]["hostname"] == "api.example.com"

    def test_refuses_without_insights(self, sweep, programme, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        _write_sweep(tmp_path, sweep)
        with pytest.raises(ReconFinalisationError, match="no host_insights"):
            finalise_recon(programme)

    def test_refuses_when_no_high_priority(self, sweep, programme, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        _write_sweep(tmp_path, sweep)
        save_insight(
            _good_insight(
                priority=HostPriority.MEDIUM,
                notes="Standard public API with no version disclosed yet.",
            )
        )
        with pytest.raises(ReconFinalisationError, match="HIGH priority"):
            finalise_recon(programme)

    def test_refuses_on_validation_errors(self, sweep, programme, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        _write_sweep(tmp_path, sweep)
        save_insight(_good_insight(notes="too short"))
        with pytest.raises(ReconFinalisationError, match="unresolved errors"):
            finalise_recon(programme)

    def test_refuses_without_sweep(self, programme, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        save_insight(_good_insight())
        with pytest.raises(FileNotFoundError, match="sweep.json"):
            finalise_recon(programme)

    def test_carries_sweep_fields_through(self, sweep, programme, tmp_path, monkeypatch):
        monkeypatch.setattr("tools.recon_insights.runtime.run_dir", lambda: tmp_path)
        _write_sweep(tmp_path, sweep)
        save_insight(_good_insight())
        path = finalise_recon(programme)
        data = json.loads(path.read_text())
        assert data["subdomains"] == sweep.subdomains
        assert len(data["endpoints"]) == len(sweep.endpoints)
