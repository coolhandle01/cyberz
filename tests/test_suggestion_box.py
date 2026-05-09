"""
tests/test_suggestion_box.py - unit tests for tools/suggestion_box.py
"""

from __future__ import annotations

import pytest

from tools.suggestion_box import (
    VALID_CATEGORIES,
    Suggestion,
    clear,
    get_suggestions,
    log_suggestion,
    make_suggestion_tool,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def reset_suggestion_box():
    """Ensure the global suggestion list is empty before and after each test."""
    clear()
    yield
    clear()


class TestLogAndGet:
    def test_log_appends_suggestion(self):
        log_suggestion("osint_analyst", "missing_tool", "subfinder not in PATH")
        suggestions = get_suggestions()
        assert len(suggestions) == 1
        assert suggestions[0].agent == "osint_analyst"
        assert suggestions[0].category == "missing_tool"
        assert suggestions[0].message == "subfinder not in PATH"

    def test_multiple_agents_accumulate(self):
        log_suggestion("osint_analyst", "missing_tool", "nmap missing")
        log_suggestion("penetration_tester", "hallucination_urge", "no parameters found")
        suggestions = get_suggestions()
        assert len(suggestions) == 2
        assert suggestions[0].agent == "osint_analyst"
        assert suggestions[1].agent == "penetration_tester"

    def test_get_returns_copy(self):
        log_suggestion("osint_analyst", "tooling_feedback", "add retries")
        first = get_suggestions()
        log_suggestion("penetration_tester", "missing_tool", "nuclei missing")
        second = get_suggestions()
        assert len(first) == 1
        assert len(second) == 2

    def test_clear_empties_list(self):
        log_suggestion("osint_analyst", "missing_tool", "x")
        clear()
        assert get_suggestions() == []


class TestSuggestionDataclass:
    def test_suggestion_fields(self):
        s = Suggestion(agent="foo", category="missing_tool", message="bar")
        assert s.agent == "foo"
        assert s.category == "missing_tool"
        assert s.message == "bar"


class TestValidCategories:
    def test_expected_categories_present(self):
        assert "missing_tool" in VALID_CATEGORIES
        assert "hallucination_urge" in VALID_CATEGORIES
        assert "false_positive_risk" in VALID_CATEGORIES
        assert "scope_limitation" in VALID_CATEGORIES
        assert "tooling_feedback" in VALID_CATEGORIES


class TestMakeSuggestionBoxTool:
    def test_tool_logs_with_correct_agent(self):
        sb = make_suggestion_tool("penetration_tester")
        sb.func(category="missing_tool", message="ffuf not found")
        suggestions = get_suggestions()
        assert len(suggestions) == 1
        assert suggestions[0].agent == "penetration_tester"
        assert suggestions[0].category == "missing_tool"

    def test_tool_returns_confirmation_string(self):
        sb = make_suggestion_tool("osint_analyst")
        result = sb.func(category="hallucination_urge", message="insufficient data")
        assert "hallucination_urge" in result
        assert "insufficient data" in result

    def test_separate_agents_get_independent_tools(self):
        sb_osint = make_suggestion_tool("osint_analyst")
        sb_pt = make_suggestion_tool("penetration_tester")
        sb_osint.func(category="tooling_feedback", message="a")
        sb_pt.func(category="missing_tool", message="b")
        suggestions = get_suggestions()
        agents = [s.agent for s in suggestions]
        assert "osint_analyst" in agents
        assert "penetration_tester" in agents
