---
name: cybersquad-agent-llm
description: Construct CrewAI Agents in cybersquad with the correct LLM. Always use crewai.LLM(model=..., temperature=..., max_tokens=...) with a litellm provider prefix on the model name. Passing a bare model string to Agent(llm=...) silently ignores temperature and max_tokens. Use when editing crew.py or any code that constructs a CrewAI Agent or LLM.
---

# Agent LLM construction

## The rule

Always construct the LLM explicitly using `crewai.LLM`:

```python
from crewai import LLM

llm = LLM(
    model=config.llm.model,
    temperature=config.llm.temperature,
    max_tokens=config.llm.max_tokens,
)
```

Then pass that `llm` into the `Agent(llm=...)` keyword. Never pass a bare model string to `Agent(llm=...)` directly - CrewAI silently ignores `temperature` and `max_tokens` in that path, and the agent runs with defaults that do not match `config.llm`.

## The model prefix

The model name must include the litellm provider prefix:

```python
# correct
config.llm.model == "anthropic/claude-sonnet-4-20250514"

# wrong - litellm cannot route this
config.llm.model == "claude-sonnet-4-20250514"
```

If you change the default model in `config.py`, keep the `anthropic/` (or other provider) prefix on it. If a test asserts on cost estimation or token counting, the prefix-aware code path in `tools/metrics.py` strips everything up to and including the first `/` before the pricing-table lookup - do not regress that.

## Trigger checklist

Apply this skill whenever you are:

- editing `crew.py`
- editing anything that imports `crewai.Agent`
- changing `config.llm.model`, `config.llm.temperature`, or `config.llm.max_tokens`
- writing a test that instantiates an `LLM` or an `Agent`
