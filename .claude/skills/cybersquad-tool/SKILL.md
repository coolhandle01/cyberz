---
name: cybersquad-tool
description: Universal rules for every CrewAI `@tool`-wrapped function in cybersquad. Covers the pydantic return-shape rule, typed parameters, the workspace writer/reader pair, and where shared tools live. Load before editing any `@tool` wrapper - `squad/*/__init__.py`, `squad/workspace_tools.py`, or `squad/__init__.py`. Pentest probes layer the `cybersquad-pentest-tool` skill on top of this one.
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

- `squad/workspace_tools.py` `read_attack_plan_tool` - the typed-reader pattern (returns `AttackPlan`).
- `squad/penetration_tester/__init__.py` `recon_endpoints_tool` - returns `EndpointPage`, the existing typed wrapper to mirror when retyping a `list[dict]` probe.
- `tools/research_tools.py` `finalise_research` + `load_attack_plan` - the writer / reader pair as a unit.
