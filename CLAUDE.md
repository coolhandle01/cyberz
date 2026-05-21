# cybersquad - AI Contributor Guide

**Read `CONTRIBUTING.md` first.** It carries the universal rules (ASCII only, minimal diff, preserve names and comments, linter findings as signal, FIXME/TODO grammar, surface concerns), the `Before you commit` CI parity stack, and the safety invariants. Everything below is AI-contributor-specific layered on top.

## Commit messages

Never include session URLs (`https://claude.ai/code/session_...`) in commit messages or PR bodies. They reference private conversations.

## Skills

Two skill systems run in this repo. They do not interact - one targets the
contributor (you, editing code), the other targets the runtime crew (agents
executing the pipeline).

### Contributor skills (Claude Code)

Skills under `.claude/skills/` auto-load via a `PreToolUse` hook on `Write`/`Edit` configured in `.claude/settings.json`. The relevant skill's full `SKILL.md` is injected into context on the first matching edit per session, deduplicated so repeated edits to the same scope are silent.

| Skill | Triggers on |
|---|---|
| `cybersquad-test-fixtures` | Any file under `tests/` (except the two below) |
| `cybersquad-pentest-tool` | `tools/pentest/**` or `squad/penetration_tester/__init__.py` |
| `cybersquad-bdd` | `tests/features/**` or `tests/bdd/**` |
| `cybersquad-agent-llm` | `crew.py` |

The hook is wired in `.claude/settings.json`; the matching logic lives in `.claude/hooks/load-skill.sh`. If a hook fails to fire in your session, run `/hooks` once (or restart) - the watcher only sees `.claude/settings.json` if it existed at session start. You can always also load a skill manually via the `Skill` tool.

### Runtime crew skills (CrewAI)

Skills the CrewAI agents see at execution time live next to the squad packages and are loaded via `crewai.skills` (METADATA disclosure by default; the agent activates a skill to promote its body into the next system prompt).

| Layout | Loaded by | Visible to |
|---|---|---|
| `squad/skills/<name>/SKILL.md` | `Crew(skills=[SQUAD_SKILLS_DIR])` in `crew.py` | every agent |
| `squad/<member>/skills/<name>/SKILL.md` | `Agent(skills=[member.skills_dir])` in `squad/__init__.py:build_agent` | that member only |

Each skill is a directory containing a `SKILL.md` with frontmatter (`name`, `description`); the loader contract is the same one used by `skill-creator` upstream. Skills restate safety invariants enforced in code - they never relax them.

## Required MCP

- **Filesystem MCP** - configure `@modelcontextprotocol/server-filesystem` with this repo's absolute path in `claude_desktop_config.json`.
