---
name: cybersquad-conventions
description: Enforce cybersquad code conventions when editing Python or Markdown files in this repo. Covers ASCII-only source, StrEnum over (str, Enum), X | None over Optional[X], model_copy(update=...) over Pydantic constructor kwargs in tests, and the five-file prompt layout under squad/<member>/. Use when editing any .py or .md file in the cybersquad codebase.
---

# cybersquad conventions

Apply these rules to every edit. They are catch-at-review rules; the goal is to never make a reviewer ask for them.

## ASCII only

All source files, comments, docstrings, and prose (`.md`) files must use plain ASCII. No Unicode decorative characters: no em dashes, en dashes, curly quotes, box-drawing characters, arrows, bullets, or emoji. Use `-` not em-dash or en-dash, `->` not the Unicode arrow, `|` not the Unicode pipe. This is not a style preference - Unicode in source files inflates token counts for every AI tool that reads this codebase, wasting money and energy.

When writing a new file or editing an existing one: if your text contains anything outside the printable ASCII range, replace it before saving.

## StrEnum over (str, Enum)

Ruff rule UP042 enforces `StrEnum`. Use it for any string enumeration:

```python
# correct
from enum import StrEnum

class Severity(StrEnum):
    LOW = "low"
    HIGH = "high"

# wrong
class Severity(str, Enum):
    LOW = "low"
    HIGH = "high"
```

## X | None over Optional[X]

Use PEP 604 union syntax for optional types:

```python
# correct
def fetch(token: str | None = None) -> Programme | None: ...

# wrong
from typing import Optional
def fetch(token: Optional[str] = None) -> Optional[Programme]: ...
```

## model_copy(update=...) in tests

When deriving a test variant from a canonical fixture model, use `model_copy(update={...})` rather than reconstructing via the constructor:

```python
# correct
out_of_scope = programme.model_copy(update={"in_scope_assets": []})

# wrong - duplicates every other field
out_of_scope = Programme(handle=programme.handle, name=programme.name, ...)
```

## Five-file prompt layout

Each agent's prose lives in exactly five single-purpose markdown files inside its package:

```
squad/<member>/
    role.md
    goal.md
    backstory.md
    description.md
    expected_output.md
```

`SquadMember.read("<name>")` loads `<name>.md` and strips whitespace. Missing files raise `FileNotFoundError` at agent/task build time. No separators, no parsing, no other prompt files. If you need to add expertise to an agent, do it inside one of these five files, not by introducing a sixth.
