---
name: cybersquad-tool
description: Universal rules for every CrewAI `@tool`-wrapped function in cybersquad. Pydantic return shape, typed parameters, writer/reader workspace pair. Load before editing any `@tool` wrapper.
---

# cybersquad @tool conventions

Every CrewAI `@tool`-wrapped function the agents see follows these rules. They are universal; `cybersquad-pentest-tool` is a specialisation that adds OWASP + StrEnum + `@pentest_tool` on top of this baseline. If you are touching a pentest probe wrapper, load both.

## Return a pydantic model, or `list[<Model>]`

```python
# correct - the agent sees a schema
@tool("Read Attack Plan")
def read_attack_plan_tool() -> AttackPlan:
    return load_attack_plan(attack_plan_path())

@tool("Reflected XSS Probe")
def xss_probe_tool(endpoints_json: str) -> list[RawFinding]:
    return list(check_reflected_xss(_parse_endpoints(endpoints_json)))
```

```python
# wrong - the agent sees a JSON-shaped dict and has to reconstitute the schema
# from the docstring
@tool("Reflected XSS Probe")
def xss_probe_tool(endpoints_json: str) -> list[dict]:
    return [f.model_dump() for f in check_reflected_xss(...)]
```

Never `dict`, `list[dict]`, or bare `list` (no inner type). CrewAI serialises pydantic models to JSON on its own; calling `.model_dump()` in the wrapper just strips the schema. If the underlying helper does not have a typed return yet, add the model before wiring the `@tool` - the model is the contract.

### The one exception: workspace-handle strings

`finalise_X` / `save_X` tools return the bare filename of the artifact they wrote (`"findings.json"`, `"attack_plan.json"`, `"verified.json"`). That `str` return is intentional - the filename is a handle the next agent passes to a typed reader. Document it in the docstring; do not invent a `WorkspaceHandle` wrapper model.

## Type the parameters too

```python
# correct
@pentest_tool("SSRF Probe", check_fn=check_ssrf)
def ssrf_probe_tool(
    endpoints_json: str,
    payloads: list[SsrfPayload] | None = None,
) -> list[RawFinding]:
    ...
```

```python
# wrong - the agent has no idea what strings are valid
def ssrf_probe_tool(endpoints_json: str, payloads: list[str] | None = None) -> ...:
```

The `endpoints_json: str` pattern exists because CrewAI's tool-call protocol cannot pass arbitrary pydantic objects in - the wrapper takes the JSON-encoded form and unmarshals via `_parse_endpoints`. That is the only acceptable use of a bare `str` parameter for structured data; everywhere else, use the typed shape.

## Workspace artifacts: writer and reader ship together

Any file an agent writes for the next agent to read needs both halves of the contract in the same PR:

| Writer | Reader |
|---|---|
| `finalise_recon(recon)` -> `recon.json` | `Recon Endpoints` / `Recon Open Ports` / `Recon Subdomains` slicers |
| `finalise_research(plan)` -> `attack_plan.json` | `read_attack_plan_tool` -> `AttackPlan` |
| `finalise_triage(...)` -> `verified.json` | (Technical Author's typed reader) |

The reader returns the typed model; downstream agents work against the schema, not raw bytes. A writer landing without a typed reader is the bug PR #138 fixed - do not repeat it.

## Where tools live

- **Per-agent**: `squad/<agent>/__init__.py`. Each `@tool` is added to that agent's `MEMBER.tools` list.
- **Shared between agents**: `squad/workspace_tools.py`. Re-export through `squad/__init__.py` (`__all__` and the explicit re-export) so consumers `from squad import read_attack_plan_tool`, not from the deeper path.

## The `SquadMember.tools` registry

Today `SquadMember.tools` is typed `list[Any]` because the local `_PentestTool` / `_ResearchBriefTool` Protocols do not share a base. That is being tightened in a follow-up (define a `CrewAITool` Protocol once, retype the registry). When that lands, the contract test that walks `MEMBER.tools` and asserts return-type annotations will be the mechanical enforcement of this skill - skill stays in AI context, test stays in CI.

## Anti-patterns to catch

- `[f.model_dump() for f in check_X(...)]` in any wrapper body - drop the comprehension, just `return list(check_X(...))`.
- Return annotation of `dict` for a structured payload that has a pydantic shape already.
- Bare `list` (no inner type) as a return annotation - either it is `list[str]` for a flat handle list, or it is `list[<Model>]` for structured rows.
- New workspace writer with no typed reader.
- `from squad.workspace_tools import ...` in a consumer instead of `from squad import ...` - the re-export exists so the import path stays stable when shared tools move.

## Canonical examples

Cross-agent intent matters: this skill applies to every agent's `@tool` wrappers, not just the pentester's. The codebase is mid-migration (#139) so exemplary typed returns are still sparse - one canonical pydantic-return example today, plus the workspace-handle string family.

- `squad/penetration_tester/__init__.py` `recon_endpoints_tool` returns `EndpointPage` - the only `@tool` in the codebase today that follows the pydantic-return rule end-to-end. The wrapper lives on PT but it reads OSINT's recon output, so the pattern is cross-agent.
- The workspace-handle string family demonstrates the `str` exception (writer returns the filename, next agent passes it to a typed reader):
  - `Finalise Recon` (`squad/osint_analyst/__init__.py`) -> `"recon.json"`
  - `Finalise Research` (`squad/vulnerability_researcher/__init__.py`) -> `"attack_plan.json"`
  - `Finalise Triage` (`squad/vulnerability_researcher/__init__.py`) -> `"verified.json"`
  - `Finalise Reports` (`squad/technical_author/__init__.py`) -> the reports manifest filename
- `squad/workspace_tools.py` `read_attack_plan_tool` is on the #139 backlog - it should return `AttackPlan` but currently returns a `dict` shape. Cite it as the *target* of the typed-reader pattern, not the example to mirror today.

## Upstream alignment

CrewAI's [crewAIInc/skills](https://github.com/crewAIInc/skills) repository publishes three skills today: `getting-started`, `design-agent`, `design-task`. None of them cover `@tool` conventions at the project level; the closest upstream document is [`design-agent/references/custom-tools.md`](https://github.com/crewAIInc/skills/blob/main/skills/design-agent/references/custom-tools.md), which covers `@tool` vs `BaseTool` decoration mechanics. This skill is a project layer on top of those mechanics, not a replacement.

Two relationship points to know:

- **"Return pydantic" vs upstream "return strings".** Upstream advises tool functions return strings because the LLM sees text. CrewAI serialises any return value to JSON for the LLM, so a pydantic-model return delivers the same text to the LLM *and* preserves the schema at the Python level (downstream code calling `tool.func(...)` directly gets a typed model; `mypy` can verify wiring; the contract test in #139 has something to introspect). Returning `dict` keeps the LLM side and strips the Python side.
- **`@tool` vs `BaseTool`.** This skill assumes `@tool` because that is what cybersquad uses today. If you reach for `BaseTool` (when you need `args_schema`, async via `_arun`, or per-tool state), defer to the upstream reference for mechanics - the pydantic-return rule still applies.
