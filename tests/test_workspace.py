"""
tests/test_workspace.py - tools/workspace.py helpers.

Covers the two safety invariants: path containment (no escape from
runtime.run_dir()) and size cap (no slurping past MAX_READ_BYTES).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tools import workspace

pytestmark = pytest.mark.unit


class TestListRunFiles:
    def test_empty_dir(self, tmp_path: Path) -> None:
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            assert workspace.list_run_files() == []

    def test_missing_dir_returns_empty(self, tmp_path: Path) -> None:
        absent = tmp_path / "not-yet-created"
        with patch("tools.workspace.runtime.run_dir", return_value=absent):
            assert workspace.list_run_files() == []

    def test_lists_files_with_sizes(self, tmp_path: Path) -> None:
        (tmp_path / "recon.json").write_text("a" * 12, encoding="utf-8")
        (tmp_path / "findings.json").write_text("b" * 5, encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = workspace.list_run_files()
        assert result == [
            {"name": "findings.json", "size_bytes": 5},
            {"name": "recon.json", "size_bytes": 12},
        ]

    def test_recurses_subdirs(self, tmp_path: Path) -> None:
        sub = tmp_path / "evidence"
        sub.mkdir()
        (sub / "screenshot.txt").write_text("x", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = workspace.list_run_files()
        assert result == [{"name": "evidence/screenshot.txt", "size_bytes": 1}]


class TestReadRunFile:
    def test_reads_full_small_file(self, tmp_path: Path) -> None:
        (tmp_path / "recon.json").write_text("hello world", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = workspace.read_run_file("recon.json")
        assert result["content"] == "hello world"
        assert result["size_bytes"] == 11
        assert result["offset"] == 0
        assert result["end"] == 11
        assert result["truncated"] is False

    def test_respects_limit_and_signals_truncation(self, tmp_path: Path) -> None:
        (tmp_path / "big.json").write_text("x" * 100, encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = workspace.read_run_file("big.json", limit_bytes=10)
        assert len(result["content"]) == 10
        assert result["end"] == 10
        assert result["size_bytes"] == 100
        assert result["truncated"] is True

    def test_offset_paginates(self, tmp_path: Path) -> None:
        (tmp_path / "data").write_text("abcdefghij", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = workspace.read_run_file("data", offset=4, limit_bytes=3)
        assert result["content"] == "efg"
        assert result["offset"] == 4
        assert result["end"] == 7
        assert result["truncated"] is True

    def test_rejects_path_escape_via_dotdot(self, tmp_path: Path) -> None:
        secret = tmp_path.parent / "secret.txt"
        secret.write_text("not for the agent", encoding="utf-8")
        try:
            with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
                with pytest.raises(ValueError, match="escapes the run directory"):
                    workspace.read_run_file("../secret.txt")
        finally:
            secret.unlink()

    def test_rejects_absolute_path_escape(self, tmp_path: Path) -> None:
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="escapes the run directory"):
                workspace.read_run_file("/etc/passwd")

    def test_rejects_symlink_escape(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            (tmp_path / "link").symlink_to(outside)
            with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
                with pytest.raises(ValueError, match="escapes the run directory"):
                    workspace.read_run_file("link")
        finally:
            outside.unlink()

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(FileNotFoundError):
                workspace.read_run_file("nope.json")

    def test_rejects_limit_above_ceiling(self, tmp_path: Path) -> None:
        (tmp_path / "f").write_text("x", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="limit_bytes must be between"):
                workspace.read_run_file("f", limit_bytes=workspace.MAX_READ_BYTES + 1)

    def test_rejects_zero_limit(self, tmp_path: Path) -> None:
        (tmp_path / "f").write_text("x", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="limit_bytes must be between"):
                workspace.read_run_file("f", limit_bytes=0)

    def test_rejects_negative_offset(self, tmp_path: Path) -> None:
        (tmp_path / "f").write_text("x", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="offset must be non-negative"):
                workspace.read_run_file("f", offset=-1)
