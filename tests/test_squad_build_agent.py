"""
tests/test_squad_build_agent.py - covers the MCP-tool splice in ``build_agent``.

The agent factory is otherwise exercised end-to-end by the BDD tests and
by every per-agent contract test that instantiates a CrewAI ``Agent`` to
walk its ``tools`` registry. This file pins the smaller invariant the
``cybersquad-mcp`` skill cares about: the per-member static tools come
first, the crew-wide MCP tools are spliced on the end.
"""

from __future__ import annotations

import pytest
from crewai import LLM
from crewai.tools import tool

from squad import build_agent
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER

pytestmark = pytest.mark.unit


# A real LLM instance (no network calls at construction time - the
# cybersquad-agent-llm skill's "use crewai.LLM directly" rule pre-validates
# the wiring). Pydantic rejects a plain MagicMock for `Agent(llm=...)`
# because the field is typed `str | BaseLLM`.
_TEST_LLM = LLM(model="anthropic/claude-sonnet-4-20250514", temperature=0.0, max_tokens=1)


def _make_fake_mcp_tool(name: str):
    """Build a stand-in for a MCP-provisioned BaseTool.

    A MagicMock is rejected by Agent(tools=...) because Pydantic validates
    each tool against the BaseTool model. ``@crewai.tools.tool`` returns a
    concrete BaseTool subclass, so a no-op wrapped function suffices.
    """

    @tool(name)
    def _stub() -> str:
        """Stand-in MCP tool for build_agent splice tests."""
        return ""

    return _stub


class TestBuildAgentMCPSplice:
    def test_static_tools_first_then_crew_wide_mcp_tools(self):
        """The agent's tool list is the splice ``[*member.tools, *crew_wide_mcp_tools]``.

        Order matters - the LLM-visible tool menu opens with the
        canonical typed surface, MCP-sourced tools sit on the end.
        """
        mcp_tool_a = _make_fake_mcp_tool("get_current_time")
        mcp_tool_b = _make_fake_mcp_tool("convert_time")

        agent = build_agent(
            PROGRAMME_MANAGER,
            _TEST_LLM,
            crew_wide_mcp_tools=[mcp_tool_a, mcp_tool_b],
        )

        # Static tools occupy the front of the list; MCP tools are on the end.
        assert len(agent.tools) == len(PROGRAMME_MANAGER.tools) + 2
        assert agent.tools[-2].name == "get_current_time"
        assert agent.tools[-1].name == "convert_time"

    def test_default_crew_wide_mcp_tools_is_empty(self):
        """Omitting ``crew_wide_mcp_tools`` means the agent gets only the
        member's static tool registry - the no-MCP path used in the
        dry-run and in every existing pre-PR test that builds an Agent."""
        agent = build_agent(PROGRAMME_MANAGER, _TEST_LLM)

        assert len(agent.tools) == len(PROGRAMME_MANAGER.tools)

    def test_member_specific_mcp_tools_splice_after_crew_wide(self):
        """The full splice is ``[*member.tools, *crew_wide_mcp_tools,
        *member_specific_mcp_tools]``. Order: static tools, then crew-wide
        MCPs, then role-specific MCPs at the end."""
        crew_wide = _make_fake_mcp_tool("get_current_time")
        member_specific_a = _make_fake_mcp_tool("browser_navigate")
        member_specific_b = _make_fake_mcp_tool("browser_snapshot")

        agent = build_agent(
            PROGRAMME_MANAGER,
            _TEST_LLM,
            crew_wide_mcp_tools=[crew_wide],
            member_specific_mcp_tools=[member_specific_a, member_specific_b],
        )

        assert len(agent.tools) == len(PROGRAMME_MANAGER.tools) + 3
        assert agent.tools[-3].name == "get_current_time"
        assert agent.tools[-2].name == "browser_navigate"
        assert agent.tools[-1].name == "browser_snapshot"

    def test_default_member_specific_mcp_tools_is_empty(self):
        """Omitting ``member_specific_mcp_tools`` keeps the tool list at
        member.tools + crew_wide only - every non-PT member's regular path."""
        crew_wide = _make_fake_mcp_tool("get_current_time")

        agent = build_agent(
            PROGRAMME_MANAGER,
            _TEST_LLM,
            crew_wide_mcp_tools=[crew_wide],
        )

        assert len(agent.tools) == len(PROGRAMME_MANAGER.tools) + 1
        assert agent.tools[-1].name == "get_current_time"
