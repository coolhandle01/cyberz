"""
tests/test_squad_workspace_tools.py - exercise the shared workspace @tool
wrappers (``read_run_filelist_tool`` / ``read_run_file_tool``).

The wrappers are thin: unmarshal JSON, call into tools/workspace helpers,
serialise the result. Coverage here is regression coverage of the wrapping
itself; the underlying helpers are exercised in ``tests/test_workspace.py``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestSharedWorkspaceTools:
    def test_read_run_filelist_tool(self, tmp_path) -> None:
        from squad import read_run_filelist_tool

        (tmp_path / "recon.json").write_text("{}", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = read_run_filelist_tool.func()
        assert result == [{"name": "recon.json", "size_bytes": 2}]

    def test_read_run_file_tool(self, tmp_path) -> None:
        from squad import read_run_file_tool

        (tmp_path / "recon.json").write_text("hello", encoding="utf-8")
        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            result = read_run_file_tool.func("recon.json")
        assert isinstance(result, dict)
        assert result["content"] == "hello"
        assert result["size_bytes"] == 5

    def test_read_run_file_tool_refuses_escape(self, tmp_path) -> None:
        from squad import read_run_file_tool

        with patch("tools.workspace.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(ValueError, match="must not contain '..'"):
                read_run_file_tool.func("../etc/passwd")

    def test_read_attack_plan_tool_returns_typed_plan(self, attack_plan, tmp_path) -> None:
        from squad import read_attack_plan_tool

        (tmp_path / "attack_plan.json").write_text(attack_plan.model_dump_json(), encoding="utf-8")
        with patch("tools.research_tools.runtime.run_dir", return_value=tmp_path):
            result = read_attack_plan_tool.func()
        assert isinstance(result, dict)
        assert result["programme_handle"] == attack_plan.programme_handle
        assert len(result["items"]) == len(attack_plan.items)
        assert result["items"][0]["probe"] == attack_plan.items[0].probe
        assert result["items"][0]["expected_ceiling"] == attack_plan.items[0].expected_ceiling.value

    def test_read_attack_plan_tool_raises_when_missing(self, tmp_path) -> None:
        from squad import read_attack_plan_tool

        with patch("tools.research_tools.runtime.run_dir", return_value=tmp_path):
            with pytest.raises(FileNotFoundError, match="attack plan not found"):
                read_attack_plan_tool.func()
