"""
tests/test_crew.py - covers the MCP-tool distribution path added by #144.

The rest of ``build_crew()`` (LLM construction, memory wiring, task
context chaining) is exercised end-to-end by the BDD tests and the
``--dry-run`` smoke path in CI; this file pins the small invariant the
``cybersquad-mcp`` skill cares about: provisioned-MCP tools are passed
to every member's ``build_agent`` via the ``crew_wide_mcp_tools`` kwarg,
or an empty tuple when no ``ProvisionedMCPTools`` registry is supplied.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _wire_build_crew_mocks(monkeypatch, captured: dict[str, dict[str, tuple]]) -> None:
    """Stub the heavy dependencies of ``crew.build_crew`` so the only thing
    actually exercised is the MCP-tool distribution branch.

    ``build_agent`` records the ``crew_wide_mcp_tools`` and
    ``member_specific_mcp_tools`` it received per member, keyed under
    ``crew_wide`` / ``member_specific``; ``_build_llm`` /
    ``_build_long_term_memory`` / ``build_tasks`` / ``Crew`` are stubbed
    away so the test does not touch CrewAI's real constructors.
    """
    import crew

    def fake_build_agent(
        member, llm, verbose, crew_wide_mcp_tools=(), member_specific_mcp_tools=()
    ):
        captured[member.slug] = {
            "crew_wide": tuple(crew_wide_mcp_tools),
            "member_specific": tuple(member_specific_mcp_tools),
        }
        return MagicMock()

    monkeypatch.setattr(crew, "build_agent", fake_build_agent)
    monkeypatch.setattr(crew, "_build_llm", lambda: MagicMock())
    monkeypatch.setattr(crew, "_build_long_term_memory", lambda: None)
    monkeypatch.setattr(crew, "build_tasks", lambda _agents_by_slug: [])
    monkeypatch.setattr(crew, "Crew", MagicMock())


class TestBuildCrewMCPDistribution:
    def test_no_mcp_tools_means_empty_crew_wide_for_every_member(self, monkeypatch):
        """Default ``mcp_tools=None`` resolves to an empty tuple at the splat,
        and every member's ``build_agent`` sees ``crew_wide_mcp_tools=()``."""
        import crew

        captured: dict[str, dict[str, tuple]] = {}
        _wire_build_crew_mocks(monkeypatch, captured)

        crew.build_crew()

        # All six members got empty buckets on both sides.
        assert captured, "expected build_agent to be called for at least one member"
        assert all(call["crew_wide"] == () for call in captured.values())
        assert all(call["member_specific"] == () for call in captured.values())

    def test_provisioned_mcp_tools_distribute_crew_wide_to_every_member(self, monkeypatch):
        """``ProvisionedMCPTools.crew_wide`` is the only injection point for
        cross-cutting MCP-sourced tools (Rule 2 of cybersquad-mcp). Every
        member's ``build_agent`` gets the same tuple - confirmed by
        sampling all captured calls."""
        import crew
        from mcp_servers import ProvisionedMCPTools

        captured: dict[str, dict[str, tuple]] = {}
        _wire_build_crew_mocks(monkeypatch, captured)

        fake_tool = MagicMock()
        fake_tool.name = "get_current_time"
        registry = ProvisionedMCPTools(crew_wide=(fake_tool,))

        crew.build_crew(mcp_tools=registry)

        assert captured, "expected build_agent to be called for at least one member"
        for slug, call in captured.items():
            assert call["crew_wide"] == (fake_tool,), (
                f"member {slug!r} did not receive the crew-wide MCP tool"
            )

    def test_penetration_tester_mcp_tools_route_only_to_pt(self, monkeypatch):
        """``ProvisionedMCPTools.penetration_tester`` reaches the PT and
        nobody else - the Playwright MCP (#23) is too expensive (200MB
        Chromium) to broadcast to agents that have no use for browser
        automation."""
        import crew
        from mcp_servers import ProvisionedMCPTools
        from squad.penetration_tester import MEMBER as PENETRATION_TESTER

        captured: dict[str, dict[str, tuple]] = {}
        _wire_build_crew_mocks(monkeypatch, captured)

        pw_tool = MagicMock()
        pw_tool.name = "browser_navigate"
        registry = ProvisionedMCPTools(penetration_tester=(pw_tool,))

        crew.build_crew(mcp_tools=registry)

        assert captured[PENETRATION_TESTER.slug]["member_specific"] == (pw_tool,), (
            "PT did not receive the penetration-tester-scoped MCP tool"
        )
        for slug, call in captured.items():
            if slug == PENETRATION_TESTER.slug:
                continue
            assert call["member_specific"] == (), (
                f"member {slug!r} should not see PT-scoped MCP tools"
            )
