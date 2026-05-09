"""
tests/test_ledger.py - unit tests for tools/ledger.py
"""

from __future__ import annotations

import importlib
from datetime import UTC

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture()
def tmp_reports(tmp_path, monkeypatch):
    """Point config.reports_dir at a temporary directory."""
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
    import config as cfg_module

    importlib.reload(cfg_module)
    import tools.ledger as ledger_module

    importlib.reload(ledger_module)
    return tmp_path


class TestWriteRetro:
    def test_creates_file_at_expected_path(self, tmp_reports):
        from tools.ledger import write_retro

        path = write_retro("acme", "# Retro\nAll good.", campaign_date="2026-01-15")
        assert path.exists()
        assert "acme" in str(path)
        assert "2026-01-15" in str(path)
        assert path.name == "retrospective.md"

    def test_content_is_written_correctly(self, tmp_reports):
        from tools.ledger import write_retro

        content = "## What Went Well\nFound an SSRF."
        path = write_retro("acme", content, campaign_date="2026-01-15")
        assert path.read_text(encoding="utf-8") == content

    def test_defaults_to_todays_date(self, tmp_reports):
        from datetime import datetime

        from tools.ledger import write_retro

        path = write_retro("acme", "content")
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        assert today in str(path)

    def test_overwrites_existing_retro(self, tmp_reports):
        from tools.ledger import write_retro

        write_retro("acme", "old content", campaign_date="2026-01-15")
        write_retro("acme", "new content", campaign_date="2026-01-15")
        from tools.ledger import read_retro

        assert read_retro("acme", "2026-01-15") == "new content"


class TestReadRetro:
    def test_returns_none_for_missing_campaign(self, tmp_reports):
        from tools.ledger import read_retro

        assert read_retro("acme", "2020-01-01") is None

    def test_returns_content_for_existing_campaign(self, tmp_reports):
        from tools.ledger import read_retro, write_retro

        write_retro("acme", "retro body", campaign_date="2026-02-20")
        assert read_retro("acme", "2026-02-20") == "retro body"


class TestReadRecentRetros:
    def test_returns_empty_for_unknown_programme(self, tmp_reports):
        from tools.ledger import read_recent_retros

        assert read_recent_retros("unknown") == []

    def test_returns_retros_newest_first(self, tmp_reports):
        from tools.ledger import read_recent_retros, write_retro

        write_retro("acme", "oldest", campaign_date="2026-01-01")
        write_retro("acme", "middle", campaign_date="2026-02-01")
        write_retro("acme", "newest", campaign_date="2026-03-01")

        retros = read_recent_retros("acme")
        assert retros[0] == ("2026-03-01", "newest")
        assert retros[1] == ("2026-02-01", "middle")
        assert retros[2] == ("2026-01-01", "oldest")

    def test_respects_n_limit(self, tmp_reports):
        from tools.ledger import read_recent_retros, write_retro

        for i in range(5):
            write_retro("acme", f"retro {i}", campaign_date=f"2026-0{i + 1}-01")

        assert len(read_recent_retros("acme", n=2)) == 2

    def test_ignores_campaigns_without_retrospective(self, tmp_reports):
        from pathlib import Path

        from tools.ledger import read_recent_retros, write_retro

        write_retro("acme", "has retro", campaign_date="2026-03-01")
        # Create a campaign dir without a retro file
        empty = Path(str(tmp_reports)) / "programs" / "acme" / "campaigns" / "2026-04-01"
        empty.mkdir(parents=True)

        retros = read_recent_retros("acme")
        assert len(retros) == 1
        assert retros[0][0] == "2026-03-01"
