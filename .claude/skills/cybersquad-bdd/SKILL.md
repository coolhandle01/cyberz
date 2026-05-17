---
name: cybersquad-bdd
description: Gherkin conventions, step definition patterns, fixture injection, and running BDD tests in isolation. Use when creating or editing files under tests/features/ or tests/bdd/.
---

# cybersquad BDD tests

BDD tests exercise agent *reasoning* — prompts, skills, and how an agent uses its tools given a context. They are not for testing tool logic (that is unit tests). They hit a real LLM, are slow, and cost tokens. Run them intentionally, not as part of every commit.

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
# BDD tests only
pytest -m bdd

# Unit tests only (default CI run - does not include BDD)
pytest -m unit

# Both
pytest -m "unit or bdd"
```

BDD tests are excluded from CI by default. They are run locally when working on prompts or skills.

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

All BDD test files must carry `pytestmark = pytest.mark.bdd` at module level. This keeps them out of `pytest -m unit` runs.
