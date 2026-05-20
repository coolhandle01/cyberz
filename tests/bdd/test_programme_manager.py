"""BDD scenarios for the Programme Manager agent.

These exercise the prompt-driven access gate that lives in
``squad/programme_manager/select/description.md`` Step 0 and the matching
prose in ``backstory.md``. They call a real LLM and need
``ANTHROPIC_API_KEY`` in the developer's environment; they are excluded
from ``pytest -m unit`` and from CI by the ``bdd`` marker.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pytest_bdd import given, scenarios, then, when

import runtime

pytestmark = pytest.mark.bdd

scenarios("programme_manager.feature")


@given(
    "the H1 API returns a single non-public programme with no admission evidence",
    target_fixture="non_public_programme",
)
def non_public_programme(programme):
    # Generous bounty + permissive policy on purpose: every non-access
    # filter passes, so the only thing that can stop the agent from
    # selecting this programme is the prompt-driven access gate.
    return programme.model_copy(
        update={
            "state": "private_mode",
            "policy_text": (
                "Automated scanning is permitted. Standard rules apply. "
                "No invitation, admission, or participation language."
            ),
        }
    )


@when("the Programme Manager agent runs", target_fixture="pm_run")
def pm_runs(non_public_programme, tmp_path):
    from crewai import LLM, Crew, Process

    from config import config
    from models import ProgrammePreview
    from squad import build_agent, build_task
    from squad.programme_manager import MEMBER as PROGRAMME_MANAGER

    llm = LLM(
        model=config.llm.model,
        temperature=config.llm.temperature,
        max_tokens=config.llm.max_tokens,
    )
    agent = build_agent(PROGRAMME_MANAGER, llm)
    task = build_task("select", PROGRAMME_MANAGER, agent)
    crew = Crew(
        agents=[agent],
        tasks=[task],
        process=Process.sequential,
        memory=False,
        embedder=None,
    )

    # Reset the runtime singleton so we can detect a save by checking
    # programme_handle after kickoff (save_programme_tool sets it).
    runtime.programme_handle = ""

    # The agent now drives a two-step workflow: browse for previews, then
    # hydrate the shortlisted handles. Mock both boundaries so the LLM
    # sees a coherent non-public programme regardless of which tool path
    # it takes.
    preview = ProgrammePreview(
        handle=non_public_programme.handle,
        name=non_public_programme.name,
        offers_bounties=non_public_programme.offers_bounties,
        submission_state="open",
        state=non_public_programme.state,
    )
    with (
        patch(
            "squad.programme_manager.h1.browse_programmes",
            return_value=[preview],
        ),
        patch(
            "squad.programme_manager.h1.hydrate_programme",
            return_value=non_public_programme,
        ),
        patch("runtime.programme_cache_path", return_value=tmp_path / "programme.json"),
        patch("runtime.run_dir", return_value=tmp_path / "run"),
    ):
        crew_output = crew.kickoff()

    return {
        "crew_output": crew_output,
        "saved_handle": runtime.programme_handle,
    }


@then("the Programme Manager does not save the non-public programme")
def did_not_save(pm_run, non_public_programme):
    assert pm_run["saved_handle"] != non_public_programme.handle, (
        "Programme Manager called save_programme_tool with the non-public "
        f"handle {non_public_programme.handle!r}; the prose-driven access "
        "gate in select/description.md Step 0 has regressed."
    )
