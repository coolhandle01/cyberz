"""
tests/test_workspace.py - tools/workspace/ helpers.

Covers the two safety invariants: path containment (no escape from
runtime.run_dir()) and correct file reads.
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
    def test_reads_full_file(self, tmp_path: Path) -> None:
        recon_path = tmp_path / "recon.json"
        recon_path.write_text("hello world", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = workspace.read_run_file("recon.json")
        assert result["content"] == "hello world"
        assert result["size_bytes"] == 11
        assert result["name"] == "recon.json"

    def test_rejects_parent_traversal(self, tmp_path: Path) -> None:
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="must not contain '..'"):
                workspace.read_run_file("../secret.txt")

    def test_rejects_absolute_path(self, tmp_path: Path) -> None:
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="must be relative, not absolute"):
                workspace.read_run_file("/etc/passwd")

    def test_rejects_empty_path(self, tmp_path: Path) -> None:
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="must not be empty"):
                workspace.read_run_file("")

    def test_rejects_symlink_escape(self, tmp_path: Path) -> None:
        # Belt-and-braces: the shape check above only inspects the input.
        # A symlink inside run_dir pointing outside passes the shape check,
        # so the resolve-and-verify step has to catch it.
        outside = tmp_path.parent / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            (tmp_path / "link").symlink_to(outside)
            with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
                with pytest.raises(ValueError, match="resolves outside the run directory"):
                    workspace.read_run_file("link")
        finally:
            outside.unlink()

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(FileNotFoundError):
                workspace.read_run_file("nope.json")
