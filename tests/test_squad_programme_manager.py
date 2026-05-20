"""
tests/test_squad_programme_manager.py - exercise the @tool wrappers on the
Programme Manager.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import runtime

pytestmark = pytest.mark.unit


class TestProgrammeManagerTools:
    def test_find_programmes_tool_caches_each(self, programme, tmp_path) -> None:
        from squad.programme_manager import find_programmes_tool

        cache_paths: dict[str, Path] = {}

        def cache_path_for(handle):
            p = tmp_path / handle / "programme.json"
            cache_paths[handle] = p
            return p

        with (
            patch(
                "squad.programme_manager.h1.find_programmes",
                return_value=[programme],
            ) as mfind,
            patch(
                "runtime.programme_cache_path",
                side_effect=cache_path_for,
            ),
        ):
            result = find_programmes_tool.func()

        assert result == [programme.model_dump()]
        mfind.assert_called_once_with(open_only=True, bounty_only=True)
        assert cache_paths[programme.handle].exists()

    def test_find_programmes_tool_passes_explicit_flags(self, programme, tmp_path) -> None:
        from squad.programme_manager import find_programmes_tool

        with (
            patch(
                "squad.programme_manager.h1.find_programmes",
                return_value=[],
            ) as mfind,
            patch(
                "runtime.programme_cache_path",
                return_value=tmp_path / "unused" / "programme.json",
            ),
        ):
            find_programmes_tool.func(open_only=False, bounty_only=False)

        mfind.assert_called_once_with(open_only=False, bounty_only=False)

    def test_save_programme_tool_sets_handle_and_copies(self, programme, tmp_path) -> None:
        from squad.programme_manager import save_programme_tool

        cache = tmp_path / "cache" / "programme.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(programme.model_dump_json(), encoding="utf-8")
        run_dir = tmp_path / "run"

        with (
            patch("runtime.run_dir", return_value=run_dir),
            patch("runtime.programme_cache_path", return_value=cache),
        ):
            result = save_programme_tool.func(programme.handle)

        assert runtime.programme_handle == programme.handle
        assert result == str(run_dir)
        assert (run_dir / "programme.json").exists()

    def test_save_programme_tool_skips_copy_when_cache_missing(self, programme, tmp_path) -> None:
        from squad.programme_manager import save_programme_tool

        run_dir = tmp_path / "run"
        absent_cache = tmp_path / "cache" / "programme.json"

        with (
            patch("runtime.run_dir", return_value=run_dir),
            patch("runtime.programme_cache_path", return_value=absent_cache),
        ):
            result = save_programme_tool.func(programme.handle)

        assert runtime.programme_handle == programme.handle
        assert result == str(run_dir)
        assert run_dir.exists()
        assert not (run_dir / "programme.json").exists()
