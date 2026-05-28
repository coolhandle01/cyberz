---
name: cybersquad-task
description: Construct CrewAI tasks via build_task(). Prose lives in description.md / expected_output.md. Inter-agent structured handoff uses workspace files, not output_pydantic. Load before editing tasks.py.
---

# cybersquad task conventions

## Construction: build_task() - never bare `Task(...)`

`squad/__init__.py` defines `build_task(task_name, member, agent, context=[...], human_input=hi)`. It reads the per-task `description.md` and `expected_output.md` from the agent's directory, wires the agent, and centralises `human_input` gating via `config.human_input`.

Writing `Task(...)` directly puts prose in Python strings and bypasses the toggle. Use the helper.

## Prose lives in markdown, not Python strings

```
squad/<member>/
    role.md
    goal.md
    backstory.md
    <task_name>/description.md
    <task_name>/expected_output.md
```

Multi-task agents (Vulnerability Researcher has `research/` and `triage/`) get one subdirectory per task. `SquadMember.read()` is the only loader; missing files raise at build time.

This separation is deliberate: prompt iteration is a markdown edit, wiring is a Python edit, and neither blocks the other.

## Inter-agent structured handoff: workspace files, not `output_pydantic`

When data flows between agents (recon -> attack plan -> findings -> verified -> reports), use the workspace-file pair pattern:

- Producer agent calls a typed `@tool` like `Finalise Research(plan: AttackGraph)` that validates and writes `attack_graph.json` to the run directory; returns the bare filename.
- The *task's* textual output is freeform briefing prose plus that filename.
- Consumer agent calls a typed `@tool` like `Read Attack Plan -> AttackGraph` to deserialise the artefact.

DO NOT use `output_pydantic=SomeModel` on tasks for inter-agent flow. Three reasons:

1. **Size.** AttackSurface is ~115KB / ~30K tokens on real targets. `output_pydantic` puts the full JSON in every downstream `context=`, which torches the LLM window.
2. **Prose-coercion cost.** `output_pydantic` constrains the agent to JSON-only output. Agents naturally want to produce "Here is my reasoning, then the JSON" and JSON parsing breaks on the prose. Suppressing the prose reliably takes non-trivial prompt engineering.
3. **Both-and.** Workspace files let the task's textual output be reasoning-narrative (which the next agent uses to orient) AND the typed artefact be the structured contract (which downstream code consumes). `output_pydantic` collapses these into one.

For the tool-side conventions (writer/reader pair, return types, where shared tools live), load `cybersquad-tool`.

## When `output_pydantic` is acceptable

`output_pydantic` earns its keep when:

- The output is consumed by *orchestration code*, not by another agent in the chain (rare in cybersquad).
- The structure is small enough that the size argument does not apply AND you have a reason to want JSON over prose in the next agent's context.

If unsure, default to workspace files. The pair pattern earns its keep.

## `context=` chain

`context=[prior_task, ...]` lists upstream tasks whose outputs become this task's context. CrewAI's `aggregate_raw_outputs_from_tasks` joins each prior task's `output.raw` with dividers - there is no automatic structured passing.

Use `context=` explicitly even in sequential pipelines. It makes the data-flow graph readable and enables non-linear deps. Example - the Vulnerability Researcher's triage task reads from BOTH `pentest` AND its own earlier `research` task:

```python
triage = build_task(
    "triage", VULNERABILITY_RESEARCHER, agents["vulnerability_researcher"],
    context=[pentest, research, select],
    human_input=hi,
)
```

## `human_input` toggle

Always pass `human_input=hi` where `hi = config.human_input` (set via the `CYBERSQUAD_HUMAN_INPUT` env var). Never hardcode `True` or `False` - the toggle exists so production runs can be unattended while interactive runs gate at each step.

## Upstream alignment

CrewAI's [crewAIInc/skills `design-task`](https://github.com/crewAIInc/skills/blob/main/skills/design-task/SKILL.md) is the canonical upstream best-practice for task design. Its strong recommendation is `output_pydantic` for structured handoff between tasks. Cybersquad deliberately diverges on that one point - see the "workspace files" section above. The rest of upstream `design-task` (single-purpose tasks, specific `expected_output`, function/LLM guardrails, conditional tasks, async, callbacks) we follow without exception.
