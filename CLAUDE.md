# cybersquad - AI Contributor Guide

**Read `CONTRIBUTING.md` first.** It carries the universal rules (ASCII only, minimal diff, preserve names and comments, linter findings as signal, FIXME/TODO grammar, surface concerns), the `Before you commit` CI parity stack, and the safety invariants. Everything below is AI-contributor-specific layered on top.

## Commit messages

Never include session URLs (`https://claude.ai/code/session_...`) in commit messages or PR bodies. They reference private conversations.

## Skills

Skills under `.claude/skills/` are loaded explicitly via the `Skill` tool when their description matches your task - they do not auto-fire on file edits. **Before editing a file in scope of a skill, invoke that skill via the `Skill` tool first.** The descriptions in the session-start system reminder are summaries; the file contents carry the real guidance.

| Skill | When to load |
|---|---|
| `cybersquad-test-fixtures` | Editing any file under `tests/` |
| `cybersquad-pentest-tool` | Creating or editing files under `tools/pentest/` or `squad/penetration_tester/__init__.py` |
| `cybersquad-bdd` | Creating or editing files under `tests/features/` or `tests/bdd/` |
| `cybersquad-agent-llm` | Editing `crew.py` or any code constructing a CrewAI `Agent` or `LLM` |

## Required MCP

- **Filesystem MCP** - configure `@modelcontextprotocol/server-filesystem` with this repo's absolute path in `claude_desktop_config.json`.
