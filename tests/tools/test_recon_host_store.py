"""tests/tools/test_recon_host_store.py - unit tests for the per-host
workspace artefact store (tools/recon_host_store.py)."""

from __future__ import annotations

import pytest

from models import (
    HostInsight,
    HostPriority,
    HostRole,
    HostScore,
    RawFinding,
    TLSCertificate,
    Url,
)
from tools.recon_host_store import (
    findings_path,
    host_dir,
    host_score_path,
    insight_path,
    load_host_findings,
    load_host_ports,
    load_host_scores,
    load_host_urls,
    load_insights,
    load_tls_certificates,
    ports_path,
    save_host_findings,
    save_host_notes,
    save_host_ports,
    save_host_score,
    save_host_urls,
    save_insight,
    save_tls_certificate,
    tls_path,
    urls_path,
)

pytestmark = pytest.mark.unit


class TestUrlPersistence:
    def test_save_and_load_round_trip(self, run_dir, target_apex):
        host = f"api.{target_apex}"
        url = Url(raw=f"https://{host}:8443/v1?q=1#f", scheme="https", host=host, port=8443)
        path = save_host_urls(host, [url])
        assert path == urls_path(host)
        assert path.exists()
        loaded = load_host_urls(host)
        assert [u.raw for u in loaded] == [f"https://{host}:8443/v1?q=1#f"]
        assert loaded[0].port == 8443

    def test_load_missing_returns_empty(self, run_dir, target_apex):
        assert load_host_urls(f"ghost.{target_apex}") == []


class TestInsightPersistence:
    def test_save_insight_writes_per_host_file(self, make_host_insight, run_dir):
        path = save_insight(make_host_insight())
        assert path == run_dir / "hosts" / "api.example.com" / "insight.json"
        assert path.exists()
        loaded = HostInsight.model_validate_json(path.read_text())
        assert loaded.hostname == "api.example.com"

    def test_host_dir_is_per_fqdn_directory_under_hosts(self, run_dir):
        # host_dir is the public hook future evidence-writing tools
        # (screenshots, scan output, response bodies) call to find the
        # per-FQDN slot.
        d = host_dir("api.example.com")
        assert d == run_dir / "hosts" / "api.example.com"

    def test_insight_path_sanitises_special_chars(self, run_dir):
        # / in the FQDN is sanitised to _ so the host's directory stays
        # inside hosts/ rather than escaping via path traversal.
        path = insight_path("weird host/name.example.com")
        assert "/" not in path.parent.name
        assert path.parent.parent.name == "hosts"
        assert path.name == "insight.json"

    def test_load_insights_orders_by_hostname(self, make_host_insight, run_dir):
        save_insight(make_host_insight(hostname="zebra.example.com"))
        save_insight(make_host_insight(hostname="aardvark.example.com"))
        loaded = load_insights()
        assert [i.hostname for i in loaded] == ["aardvark.example.com", "zebra.example.com"]

    def test_load_insights_empty_when_no_dir(self, run_dir):
        assert load_insights() == []

    def test_insight_path_rejects_empty_hostname(self, run_dir):
        # insight_path builds <run_dir>/hosts/<sanitised>/insight.json, so the
        # sanitisation check runs before runtime.run_dir() is needed.
        with pytest.raises(ValueError, match="empty after sanitisation"):
            insight_path("///")


class TestTlsCertificatePersistence:
    def test_save_writes_per_host_file(self, run_dir, target_apex):
        cert = TLSCertificate(host=f"api.{target_apex}", issuer="Let's Encrypt")
        path = save_tls_certificate(cert)
        assert path == run_dir / "hosts" / f"api.{target_apex}" / "tls.json"
        restored = TLSCertificate.model_validate_json(path.read_text(encoding="utf-8"))
        assert restored.issuer == "Let's Encrypt"

    def test_tls_json_is_sibling_of_insight(self, run_dir, target_apex):
        # The cert hangs off the same per-FQDN directory as insight.json.
        assert tls_path(f"api.{target_apex}").parent == insight_path(f"api.{target_apex}").parent

    def test_load_orders_by_host(self, run_dir, target_apex):
        save_tls_certificate(TLSCertificate(host=f"zebra.{target_apex}"))
        save_tls_certificate(TLSCertificate(host=f"aardvark.{target_apex}"))
        loaded = load_tls_certificates()
        assert [c.host for c in loaded] == [f"aardvark.{target_apex}", f"zebra.{target_apex}"]

    def test_load_empty_when_no_dir(self, run_dir):
        assert load_tls_certificates() == []


class TestHostFacetPersistence:
    """The per-host OAM-node facets: host.json (score), notes.md, findings.json,
    ports.json - writer/reader pairs under hosts/<fqdn>/."""

    def test_host_score_writes_and_loads(self, run_dir, target_apex):
        save_host_score(
            HostScore(hostname=f"api.{target_apex}", role=HostRole.API, priority=HostPriority.HIGH)
        )
        assert host_score_path(f"api.{target_apex}") == (
            run_dir / "hosts" / f"api.{target_apex}" / "host.json"
        )
        # sibling of insight.json in the same per-FQDN dir
        score_dir = host_score_path(f"api.{target_apex}").parent
        assert score_dir == insight_path(f"api.{target_apex}").parent
        loaded = load_host_scores()
        assert [s.hostname for s in loaded] == [f"api.{target_apex}"]

    def test_load_host_scores_empty_when_no_dir(self, run_dir):
        assert load_host_scores() == []

    def test_notes_writes_markdown(self, run_dir, target_apex):
        path = save_host_notes(f"api.{target_apex}", "look here, because it is the admin panel")
        assert path == run_dir / "hosts" / f"api.{target_apex}" / "notes.md"
        assert "admin panel" in path.read_text(encoding="utf-8")

    def test_findings_roundtrip_and_empty(self, run_dir, target_apex):
        finding = RawFinding(
            title="weak TLS",
            vuln_class="tls",
            target=f"https://api.{target_apex}",
            evidence="TLS 1.0 enabled",
            tool="testssl",
        )
        save_host_findings(f"api.{target_apex}", [finding])
        assert findings_path(f"api.{target_apex}").is_file()
        loaded = load_host_findings(f"api.{target_apex}")
        assert [f.title for f in loaded] == ["weak TLS"]
        # absent host -> empty, no raise
        assert load_host_findings(f"absent.{target_apex}") == []

    def test_ports_roundtrip_and_empty(self, run_dir, target_apex):
        save_host_ports(f"api.{target_apex}", [22, 443])
        assert ports_path(f"api.{target_apex}").is_file()
        assert load_host_ports(f"api.{target_apex}") == [22, 443]
        assert load_host_ports(f"absent.{target_apex}") == []
