---
name: cybersquad-mcp
description: Provision MCPs at `build_crew()` time, never at runtime. Three rules - install the vendor package locally and consume through its typed models; only `build_crew()` materialises an `MCPServerAdapter`; provisioned and discovered MCP sets stay disjoint. Load before editing `mcp_servers.py` or the MCP wiring in `crew.py`.
---

# MCP provisioning discipline

A poisoned MCP does not need to be exotic. It needs three things, all left to the server by the spec:

1. **A name and description that target the picker.** The consuming LLM reads tool prose when choosing - direct prose-to-prompt with no mediation.
2. **A loose return type.** `-> object`, `-> Any`, a Pydantic model with `extra = "allow"`, or a freeform `dict[str, Any]` field all leave latitude for arbitrary text to land in the consumer's context.
3. **A consumer that dereferences what was returned.** Recon and triage pipelines mostly do.

The slow-boil variant is the one to design against: a MCP that returns clean data for six months, then drops a payload only when the caller's context shows the specific programme handle that matters. Static review never catches it. Three rules keep us out of that hole.

## Rule 1 - Install the vendor package locally; consume through its models

For every provisioned MCP, install the vendor's Python package locally (pin it in `pyproject.toml`, not just the binary). Where the vendor publishes Pydantic models for tool returns, consume through those models so `mypy` enforces the boundary.

A return type of `Any` or `object` on a consumed MCP tool is a contributor signal. Treat it the same as any other linter finding (read it, understand it, fix or document why suppression is safe).

Schemas catch *shape*. They do not catch *intent* - an exfil URL is a valid `str`, and `model_validate` passes it cleanly. The shape contract is the first wall, not the only one. See #141 for return-side sanitisation of attacker-influenceable text crossing into agent context; the two walls compose.

## Rule 2 - No runtime MCP attach

The crew is provisioned with its MCP set at `build_crew()` time. Agents that discover an MCP URL during a run must be unable to attach or call it. The URL is data, not capability.

Construction-time wiring only:

- `mcp_servers.provisioned_mcp_tools()` is the only place an `MCPServerAdapter` is materialised.
- `crew.py` consumes its output; nothing else does.
- No `@cyber_tool` / `@pentest_tool` wrapper, no skill, no agent path can reach `MCPServerAdapter` (or `StdioServerParameters`).

```python
# wrong - runtime attach from inside a tool wrapper
@cyber_tool("attach_discovered_mcp", args_schema=AttachArgs)
def attach_discovered_mcp(url: str) -> ...:
    from crewai_tools import MCPServerAdapter  # NEVER
    adapter = MCPServerAdapter(...)
    ...

# correct - the URL is recorded as evidence; no adapter is constructed
@cyber_tool("record_discovered_mcp", args_schema=RecordArgs)
def record_discovered_mcp(url: str) -> DiscoveredMCP:
    return DiscoveredMCP(url=url, advertised_tools=..., evidence=...)
```

If a future test or contributor finds a path to materialise `MCPServerAdapter` outside `mcp_servers.py`, that is a design bug. Fix the path; do not narrow the rule.

## Rule 3 - Provisioned and discovered MCPs stay disjoint

A MCP we *provisioned* for capability is never one we *probe*. A MCP we *discovered* in recon is never one we *attach* to. Two non-overlapping sets, enforced at `build_crew()`.

The good case: OSINT labels a discovered MCP server, VR has visibility on it via the workspace handoff, PT receives it as recon evidence and probes it through a dedicated MCP-attack tool (a sibling of `prompt_injection_tool`; future work behind #141 plus a `DiscoveredMCP` model). The MCP server's claimed tool inventory becomes the attack surface.

The bad case: any agent treating an in-the-wild MCP URL as something it can install on the fly. The build-time provisioning rule plus the workspace handoff for discovered MCPs keep the sets disjoint.

## Wiring layout

- `mcp_servers.py` - declares each provisioned MCP. `provisioned_mcp_tools()` is the context manager owning adapter lifecycles via `ExitStack`. Adapters start on `__enter__`, stop in reverse on `__exit__`.
- `crew.py` - receives the tool list from `provisioned_mcp_tools()` and distributes it to agents via `build_agent(extra_tools=...)`.
- `main.py` - wraps `crew.kickoff()` in `with provisioned_mcp_tools() as mcp_tools:`. Dry-run skips MCP startup (the agent menu is shown from a no-MCP build).
- `config.py` - one boolean per provisioned MCP in `MCPConfig`, defaulting `false` so a fresh checkout starts without subprocess dependencies. Operator opts in per MCP, once they have the vendor package installed.

## Adding a new provisioned MCP

1. Pin the vendor package in `pyproject.toml` under `[project.optional-dependencies] mcp`. Confirm the package publishes Pydantic models for tool returns; if not, file the schema-gap as a follow-up before consuming.
2. Add `<name>_enabled` (and any timezone / endpoint / credential fields) to `MCPConfig` in `config.py`. Default `false`.
3. In `mcp_servers.py`, build the `StdioServerParameters` and add an `enter_context(MCPServerAdapter(...))` branch inside `provisioned_mcp_tools()`. The `ExitStack` handles teardown.
4. Decide distribution in `crew.py`: crew-wide via `build_agent(extra_tools=...)`, or member-specific if the MCP serves one role. The default is member-specific; crew-wide is for genuinely cross-cutting capabilities (time, basic web search).
5. Add a config test covering enabled/disabled (`tests/test_config.py::TestMCPConfig`) and a structural test asserting the adapter is constructed when enabled (`tests/test_mcp_servers.py`, mocking `MCPServerAdapter`).

## What this skill does not cover

- **Discovered-MCP probing.** The recon-side reasoning about advertised tool inventories, schema mismatches, and `object` returns lives in the future MCP-attack probe behind #141, not here. This skill is only the provisioned side.
- **The runtime skill story.** Whether the consuming agent needs a member-specialist skill telling it about a newly-available tool is a separate decision (see `cybersquad-skill`). Small MCPs (time, misp) usually do not; large ones (playwright) usually do.

## Common leaks

- Bad: a `@cyber_tool` wrapper that calls `MCPServerAdapter(...)` mid-function to attach a URL it received as input. Good: the URL is recorded as `DiscoveredMCP` evidence; no adapter is constructed.
- Bad: a return type of `dict[str, Any]` on a consumed MCP tool because "the vendor does not expose models". Good: file a follow-up, write a narrow Pydantic model locally that matches the vendor's documented schema, consume through it.
- Bad: defaulting a new MCP to `enabled=true` in `MCPConfig`. Good: `false` by default; operator opts in once the vendor package is installed.
- Bad: catching the adapter-start exception and silently falling through with an empty tool list. Good: log a warning (the existing missing-binary pattern - see `gitleaks` / `testssl` wrappers) and let `provisioned_mcp_tools()` yield without that adapter's tools. The operator sees the warning and either installs the dep or sets the env var to `false`.

## Upstream alignment

- CrewAI MCP docs (`crewai_tools.MCPServerAdapter`, `StdioServerParameters` from `mcp`) - the framework primitives we provision through.
- #144 - the MCP wishlist and threat-model comment this skill codifies.
- #146 - the input-edge symmetry. `args_schema` on every wrapper prevents the LLM from mis-calling our tools. This skill is the symmetric *return* edge for tools we consume.
- #141 - sanitisation of attacker-influenceable text crossing into agent context. Schemas catch shape; #141 catches intent.

## When this skill fires

Auto-loads on edits to:

- `mcp_servers.py` - the provisioning module
- `crew.py` - where MCP tools are distributed to agents (stacks on `cybersquad-agent-llm`)
