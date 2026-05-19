"""
tests/test_squad_programme_manager.py - exercise the @tool wrappers on the
Programme Manager.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestProgrammeManagerTools:
    def test_list_programmes_tool(self) -> None:
        from squad.programme_manager import list_programmes_tool

        sentinel = [{"handle": "acme"}]
        with patch("squad.programme_manager.h1.list_programmes", return_value=sentinel) as m:
            result = list_programmes_tool.func(page_size=5)

        assert result == sentinel
        m.assert_called_once_with(page_size=5)

    def test_get_scope_tool(self) -> None:
        from squad.programme_manager import get_scope_tool

        with (
            patch(
                "squad.programme_manager.h1.get_programme_policy",
                return_value={"data": {"x": 1}},
            ) as mp,
            patch(
                "squad.programme_manager.h1.get_structured_scope",
                return_value={"items": []},
            ) as ms,
        ):
            result = get_scope_tool.func("acme")

        assert result == {"policy": {"data": {"x": 1}}, "scope": {"items": []}}
        mp.assert_called_once_with("acme")
        ms.assert_called_once_with("acme")

    def test_get_programme_stats_tool(self) -> None:
        from squad.programme_manager import get_programme_stats_tool

        sentinel = {"reports_received": 100}
        with patch(
            "squad.programme_manager.h1.get_programme_stats",
            return_value=sentinel,
        ) as m:
            result = get_programme_stats_tool.func("acme")

        assert result == sentinel
        m.assert_called_once_with("acme")
