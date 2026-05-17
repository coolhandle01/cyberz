# cybersquad - AI Contributor Guide

This file carries only the rules that must hold on every turn. Anything situational lives under `docs/` or in a `.claude/skills/` skill that loads on demand.

**Read `README.md` first.** Setup, install, env vars, and how to run the pipeline live there.

## Before you commit - non-negotiable

1. **Work inside a virtualenv with full dev deps.** Without `python -m venv .venv && .venv/bin/pip install -e ".[dev]"`, `mypy` silently passes locally because it cannot resolve `crewai`, `crewai.tools`, or `langchain_anthropic`. No venv, no valid local signal.

2. **Run the full CI stack locally, in order, before every push.** Ruff alone is not enough:

   ```bash
   .venv/bin/ruff check .
   .venv/bin/ruff format --check .
   .venv/bin/mypy . --ignore-missing-imports
   H1_API_USERNAME=ci-user H1_API_TOKEN=ci-token CYBERSQUAD_CONTACT_EMAIL=ci@example.invalid .venv/bin/pytest -m unit --cov --cov-report=term-missing
   .venv/bin/bandit -c pyproject.toml -r . -q
   ```

   All five must pass. Fix locally - never "push and let CI tell me".

3. **Never push a change you haven't actually executed.** A passing mypy run after a `type: ignore` removal means nothing if the file wasn't reachable.

4. **Read the actual file before planning any change.** Check `proposals/` for in-flight design work.

5. **Never include session URLs (`https://claude.ai/code/session_...`) in commit messages.** They reference private conversations.

## Safety invariants - do not weaken

- **Scope enforcement** in `tools/recon/scope.py`: `if host == pattern or host.endswith("." + pattern)`. A bare `host.endswith(pattern)` would let `evil.notexample.com` match `example.com`.
- **Automated-scanning gate**: the Programme Manager reads `policy_text` in full and discards any programme whose policy forbids automated tools, scanners, fuzzing, brute force, or rate testing. The discard rule lives in `squad/programme_manager/description.md`; `policy_text` is the source of truth and there is intentionally no boolean shortcut on the `Programme` model.
- **Import order in `main.py`**: `check_env()` must run before `build_crew()` is imported. The crew import chain reads env vars; `check_env()` must exit cleanly first.
- **No module-level side effects in `crew.py`**. The old `crew = build_crew()` at module level was deliberately removed.

## Required skills and MCP

- **CrewAI skill** ([docs](https://docs.crewai.com/en/skills)) - understand/write valid CrewAI agents, tasks, tools.
- **skill-creator** ([SKILL.md](https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md)) - author skills under `.claude/skills/`.
- **Filesystem MCP** - configure `@modelcontextprotocol/server-filesystem` with this repo's absolute path in `claude_desktop_config.json`.

## Index

Reference docs (read on demand):

- `docs/architecture.md` - what the project does, key files
- `docs/git-workflow.md` - branch naming, fresh-from-main flow, commit-message rules
- `docs/testing.md` - pytest invocation, coverage floor, shared fixtures
- `docs/ci.md` - ruff/mypy/bandit guidance, SHA pinning, `upload-artifact` gotcha
- `docs/contributing/{adding-an-agent,adding-a-tool,adding-config}.md` - includes probe-`StrEnum` and `default_factory=lambda` rules

Skills under `.claude/skills/` fire automatically when relevant files are edited:

- `cybersquad-conventions` - ASCII-only, `StrEnum`, `X | None`, `model_copy`, five-file prompt layout. Trigger: `.py` / `.md` edits.
- `cybersquad-agent-llm` - `crewai.LLM(...)` construction + `anthropic/` model prefix. Trigger: `crew.py` / `Agent` construction.
- `cybersquad-test-fixtures` - the `conftest.py` fixture catalogue. Trigger: edits under `tests/`.
- `cybersquad-change-discipline` - minimal-diff philosophy, intentional renames, linter-as-signal, FIXME/TODO grammar, Chesterton's Fence. Trigger: editing existing code, suppressing a linter finding, or considering an out-of-scope rename/refactor.
- `cybersquad-pentest-tool` - attack-classification StrEnum, check function filter parameter, squad @tool wiring. Trigger: creating or editing files under `tools/pentest/` or `squad/penetration_tester/__init__.py`.
