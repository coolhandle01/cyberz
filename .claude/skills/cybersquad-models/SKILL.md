---
name: cybersquad-models
description: Pydantic models in cybersquad carry the LLM-facing contract - typed primitives constrain what the LLM can say, typed JSON artefacts constrain what the LLM can read, and prompt-injection-prone free-text fields are explicitly flagged. Load before editing any file under models/.
---

# cybersquad models

`models/` carries the schema the LLM sees on both sides of every tool boundary - what it is *allowed to write* (args_schemas, return shapes) and what it is *allowed to read* (workspace JSON artefacts). Every field choice is a context-safety choice. The bar is "could a hostile string in this field shift the agent's reasoning, escape scope, or land an attack on a third party?"

## The contract you are maintaining

1. **Typed primitives reject mis-shaped values at the boundary** rather than letting them flow into a real DNS / HTTP / subprocess call. `Hostname` rejects `"https://x"` / `"x/../.."` / `"x:8080"` upstream of any tool body. `HttpUrl` rejects non-HTTP schemes and mis-shaped hosts.

2. **Workspace JSON artefacts are typed contracts** between agents. The OSINT Analyst writes `recon.json`, the PT reads it through `ReconResult.model_validate_json(...)` - a mis-shaped recon rejects on the *reader* side, not silently corrupts the next stage.

3. **Args_schemas constrain what the LLM can pass** - a tool's parameter list is the LLM's API surface. Typed fields with `Field(description=...)` give the LLM both shape and intent.

The cybersquad-tool skill covers the *consumer* side (how a wrapper author uses these models). This skill covers the *producer* side: how to shape a model so the consumer side stays safe.

## When to add a new typed primitive

A new constrained string deserves a typed primitive in `models/primitives.py` whenever:

- It will appear on **more than one** args_schema or model field, AND
- The valid shape is checkable up-front (regex, parse, catalogue lookup), AND
- A wrong-shape value reaching the tool body would do something silently bad (wrong target probed, wrong CWE attributed, wrong score computed).

The pattern is `Annotated[str, AfterValidator(_validate_...)]` (or `Annotated[int, ...]` for integer primitives). Runtime type stays `str` / `int` so consumers do not have to migrate in lockstep - the validator fires at `model_validate` time. The existing `Hostname` and `HttpUrl` are the reference shape; `CvssVector` and `CweId` are pending in `models/report.py` FIXMEs against `#156`.

Counter-example: a one-off internal field used only inside one model does not need a primitive - inline the validator on the field, or use a `Literal[...]` / `StrEnum` for a closed set.

## Prompt-injection awareness

Free-text fields fed back into the LLM's context are the highest-risk surface in the codebase. The threat model: an external source (HTTP response, recon command output, H1 ticket comment) carries an embedded instruction that biases a downstream agent's reasoning.

Fields that carry **agent-produced** text (`description`, `summary`, `rationale`, `notes`, `severity_rationale`) are lower risk - the agent authored them. Validate length, validate non-empty if required, but no injection guard needed.

Fields that carry **tool-captured** text from external sources (`evidence`, raw HTTP bodies, command outputs, OSINT-captured snippets) carry the risk. Three defences, ordered by preference:

1. **Strip at capture time** - the `Sanitise Evidence` tool exists for this; agents are instructed to run it before drafting reports.
2. **Constrain shape at the model boundary** - max length, max line count, no control characters. Reduces the room an injection has to manoeuvre.
3. **Keep the field out of the LLM's downstream context** - if a field is for human review only (the disclosure report's raw HTTP transcript), make sure no agent's task reads it back into context.

When you add a field that will carry tool-captured text, leave a one-line comment naming which defence applies. The next contributor reading the model should not have to guess whether the field is safe to feed back into context.

## Cross-model coupling

A field added to `RawFinding` ripples through `TriageAssessment` -> `VerifiedVulnerability` -> `AuthoredDraft` -> `DisclosureReport`. The reader/writer pair pattern (workspace tools write the typed artefact, the next agent reads it back through the same model) is what keeps the chain honest - break the model shape on one side and the reader's `model_validate_json` raises on the other.

If you are adding a field that crosses agent boundaries:

- Decide which agent populates it and which reads it.
- Update both sides in the same PR (the writer's args_schema, the reader's task description).
- The reader/writer pair test in `tests/test_workspace.py` and per-agent integration tests will catch a half-migrated change.

## Anti-patterns

- A bare `str` field for a value that has a constrained shape (hostname, URL, CVSS vector, CWE id, OWASP category). Use the matching primitive in `models/primitives.py`; if it does not exist, see "When to add a new typed primitive" above.
- A `dict[str, Any]` field where the LLM both reads and writes. The LLM can stuff arbitrary content into `Any` and the next reader gets whatever the previous one decided to put there. Define a typed inner model instead.
- A `Field()` with no `description=...` on an args_schema. The description is the LLM's per-parameter documentation; an empty one is the same gap the inferred-args path had.
- A new top-level model added to `models/__init__.py` directly. The package is split per domain (`finding.py`, `h1.py`, `report.py`, `attack.py`, etc); put it in the matching module and let the re-export carry it.
- A `Literal["a", "b", "c"]` for a closed set that will be reused across multiple models. Prefer `StrEnum` - it produces both a real Python type and a clean args_schema with named variants.
- Removing a field that an upstream agent populates without checking what the downstream reader does. The chain breaks at the reader's `model_validate_json`, often in a test that does not surface the agent that actually needed the field.
