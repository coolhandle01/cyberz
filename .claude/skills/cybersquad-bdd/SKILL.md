---
name: cybersquad-bdd
description: Gherkin conventions, step definition patterns, fixture injection, running BDD tests in isolation. Trigger: creating or editing files under tests/features/ or tests/bdd/.
---

# cybersquad BDD tests

BDD tests exercise agent *reasoning* — prompts, skills, and how an agent uses its tools given a context. They are not for testing tool logic (that is unit tests). They call a real LLM, are slow, and cost tokens.

**BDD tests require a real `ANTHROPIC_API_KEY` in your local environment.** They cannot be run by Claude in a remote execution environment (no access to your key), and they are not run in CI until an API key is wired up via Secrets. Run them locally when working on prompts or skills.

## When to write a BDD test

- You changed a prompt or skill file and want a regression signal.
- You are driving a fix by writing the expected behaviour first, then tweaking the prompt until the scenario passes.
- You want living documentation of what an agent is supposed to do.

## File layout

```
tests/
  features/
    programme_manager.feature   # Gherkin scenarios - one file per agent
    osint_analyst.feature
  bdd/
    test_programme_manager.py   # step definitions for programme_manager.feature
    test_osint_analyst.py
```

## Running

```bash
# BDD tests only (requires ANTHROPIC_API_KEY)
pytest -m bdd

# Unit tests only (default CI run - no LLM key needed)
pytest -m unit

# Everything
pytest
```

## Token cost tracking

CrewAI returns token usage on `CrewOutput.token_usage`. Use `estimate_cost()` from `tools/metrics.py` to convert counts to USD and log the cost at the end of each BDD scenario. This gives a running record of what each agent costs per test run and lets you spot prompt regressions that cause runaway token usage.

Add this to `tests/bdd/conftest.py` when writing the first BDD test:

```python
import pytest
from tools.metrics import estimate_cost

@pytest.fixture()
def log_token_cost(request):
    """Fixture that logs LLM token cost after a BDD scenario completes."""
    costs: list[float] = []

    def _record(crew_output, model: str) -> float:
        usage = crew_output.token_usage
        cost = estimate_cost(model, usage.prompt_tokens, usage.completion_tokens)
        costs.append(cost)
        return cost

    yield _record

    total = sum(costs)
    print(f"\n[token cost] {request.node.name}: ${total:.4f}")
```

Call `log_token_cost(crew_output, model)` inside your `@when` step after the crew runs. A significant cost increase between runs is a prompt regression signal — if a change makes an agent 3x more expensive, something went wrong in the reasoning.

Token cost assertions are optional but useful for spike detection:

```python
@then("the agent completes within a reasonable token budget")
def check_token_budget(pm_output, log_token_cost):
    cost = log_token_cost(pm_output, "anthropic/claude-sonnet-4")
    assert cost < 0.10, f"Agent cost ${cost:.4f} — possible prompt regression"
```

## Writing a .feature file

One feature file per agent. Scenarios describe observable behaviour, not implementation.

```gherkin
Feature: Programme Manager agent

  Scenario: Agent selects a programme that allows automated scanning
    Given the H1 API returns two programmes, one allowing and one prohibiting automated scanning
    When the Programme Manager agent runs
    Then the selected programme allows automated scanning
    And the selected programme accepts new reports
```

Keep scenarios short. One observable outcome per scenario. Do not describe internal agent steps ("and the agent calls list_programmes") — describe what comes out, not what happens inside.

## Writing step definitions

Step definitions live in `tests/bdd/test_<agent>.py`. Use `scenarios()` to link to the feature file. Steps receive pytest fixtures via normal dependency injection — all fixtures from `tests/conftest.py` are available.

```python
from pytest_bdd import scenarios, given, when, then
import pytest
from unittest.mock import patch

pytestmark = pytest.mark.bdd

scenarios("programme_manager.feature")


@given(
    "the H1 API returns two programmes, one allowing and one prohibiting automated scanning",
    target_fixture="h1_programmes",
)
def h1_programmes(programme):
    # programme is from conftest.py - derive variants with model_copy
    allowed = programme.model_copy(update={"allows_automated_scanning": True})
    blocked = programme.model_copy(update={"allows_automated_scanning": False, "handle": "blocked"})
    return [allowed, blocked]


@when("the Programme Manager agent runs", target_fixture="pm_output")
def pm_output(h1_programmes):
    with patch("squad.programme_manager.h1.list_programmes", return_value=h1_programmes):
        from squad.programme_manager import build_agent
        # call the agent or crew here - real LLM, mocked H1 API
        ...
    return result


@then("the selected programme allows automated scanning")
def check_allows_scanning(pm_output):
    assert pm_output.allows_automated_scanning is True
```

## Fixture injection rules

- Use `target_fixture` on `@given` and `@when` steps to name the fixture the step produces.
- Downstream steps receive those fixtures by parameter name automatically.
- Reuse `conftest.py` fixtures (`programme`, `endpoint`, `recon_result`, etc.) as starting points. Derive variants with `model_copy(update={...})`.
- Do not define local model constructors in step definition files.

## What to mock

Mock the H1 API and any external HTTP calls. Do **not** mock the LLM — the point of a BDD test is to exercise the real reasoning. Do not mock CrewAI agent internals.

```python
# correct - mock the boundary, let the LLM run
with patch("squad.programme_manager.h1.list_programmes", return_value=programmes):
    result = run_agent(...)

# wrong - mocking the LLM defeats the purpose
with patch("crewai.Agent.execute_task", return_value="fake output"):
    ...
```

## Marker

All BDD test files must carry `pytestmark = pytest.mark.bdd` at module level. This keeps them out of `pytest -m unit` runs and out of CI until the LLM key is available.
