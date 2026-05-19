---
name: cybersquad-agent-llm
description: Construct CrewAI Agents in cybersquad with an explicit `crewai.LLM(...)` carrying model, temperature, and max_tokens. A bare model string passed to `Agent(llm=...)` silently ignores temperature and max_tokens. Load before editing crew.py or any code constructing a CrewAI `Agent` or `LLM`.
---

# Agent LLM construction

## Construct the LLM explicitly

```python
from crewai import LLM

llm = LLM(
    model=config.llm.model,
    temperature=config.llm.temperature,
    max_tokens=config.llm.max_tokens,
)
```

Then pass `llm` into `Agent(llm=...)`. Never pass a bare model string to `Agent(llm=...)` directly - CrewAI silently ignores `temperature` and `max_tokens` in that path and the agent runs with defaults that do not match `config.llm`.

## The model prefix

The model name must carry its litellm provider prefix:

```python
# correct
config.llm.model == "anthropic/claude-sonnet-4-20250514"

# wrong - litellm cannot route this
config.llm.model == "claude-sonnet-4-20250514"
```

If you change the default model in `config.py`, keep the `anthropic/` (or other provider) prefix. `tools/metrics.py` strips everything up to and including the first `/` before its pricing-table lookup - do not regress that code path.

## When this applies

- Editing `crew.py`
- Editing anything that imports `crewai.Agent`
- Changing `config.llm.model`, `config.llm.temperature`, or `config.llm.max_tokens`
- Writing a test that instantiates an `LLM` or `Agent`
