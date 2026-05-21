---
name: cybersquad-skill
description: SKILL.md under squad/ is for the runtime CrewAI agent, not you. No codebase paths, no Python vocabulary, no framework meta. Load before editing.
---

# Runtime crew skills

SKILL.md files under `squad/skills/<name>/` and
`squad/<member>/skills/<name>/` are loaded into a CrewAI agent's
context at execution time via `crewai.skills`. The audience is the
agent, not you. The agent's perspective is narrower than yours, and
prose that drifts into your perspective wastes its context or
misleads it.

## METADATA vs INSTRUCTIONS

Each SKILL.md has two layers the agent sees differently:

- **METADATA** (the frontmatter `name` and `description`) is loaded
  into a menu of available skills the agent sees every turn. Cheap,
  always visible.
- **INSTRUCTIONS** (the body) is promoted into the agent's system
  prompt only when the agent activates the skill. Per-turn cost
  once activated.

The `description` is the menu entry the agent picks from. Phrase it
as the operational context where the skill applies, not as repo-meta:

- Good: "How the Programme Manager reads a HackerOne programme's
  policy_text - the conservative posture and how to handle silence."
- Bad: "Restates the cybersquad's hard scope rules in language every
  agent must operate under."

## What the agent knows

- HackerOne API concepts: programmes, scope items, `policy_text`,
  `bounty_table`, `asset_type`, `in_scope`, `eligible_for_bounty`,
  `state`, `accepts_new_reports`, `triage_active`, `max_severity`,
  `authorisation_basis`, `selection_rationale`.
- The other squad members by role (Programme Manager, OSINT Analyst,
  Penetration Tester, Vulnerability Researcher, Technical Author,
  Disclosure Coordinator) and their handoff artefacts.
- Its own `@tool` functions by name and docstring.
- The operator - a real person who receives surfaced concerns.

## What the agent does not know

- This repository's name, layout, or any file path within it.
  References like `tools/recon/scope.py` mean nothing to the agent -
  it does not navigate the source tree.
- That it is implemented in Python. Avoid "predicate", "function",
  "method", "class", "module", "callable", "dict", "JSON", "hook",
  "callback", "downstream code".
- The contributor-side skill loader, `.claude/`, or any Claude Code
  concept. The skills the agent sees are the ones we provision via
  `Crew(skills=...)` and `Agent(skills=...)`. They need no qualifier
  like "the CrewAI skills" or "the runtime skills" - to the agent
  they are just skills.
- That there is enforcement code beneath it. Telling the agent
  "this is enforced in code, you cannot relax it" implies the agent
  could try - it cannot, and saying so wastes context.

## Voice

- Address the agent as "you". The body is instruction, not
  description.
- Operational vocabulary only. If a sentence only makes sense to
  someone who has read your code, rewrite it.
- Other squad members can be named by role ("the Programme Manager
  records `authorisation_basis`") - the agent knows the pipeline.

## Common leaks (war stories from PR #142)

- Bad: "This skill is a restatement of the safety invariants
  enforced in code (`tools/recon/scope.py` and the H1 programme-
  detail loader)." Filesystem reference plus meta-framing about what
  skills do.
- Bad: "You are the gate, not a Python predicate downstream of you."
  Programming concept leak. Good: "You are the gate. If you do not
  stop here, nothing further down the pipeline will."
- Bad: "Restates the cybersquad's hard scope and authorisation rules
  in language every agent must operate under." Repo name plus
  meta-framing.

The pattern in all three: contributor-perspective phrasing where
operational phrasing was needed.

## Scope of this skill

Auto-loads on edits to:
- `squad/skills/<name>/SKILL.md` (squad-wide)
- `squad/<member>/skills/<name>/SKILL.md` (member specialist)

Edits to `squad/<member>/role.md`, `goal.md`, `backstory.md`, and the
per-task `description.md` / `expected_output.md` files share the
same audience (the agent at execution time) and the same voice rules
apply, even though this skill does not auto-load on those today.

## Upstream alignment

Frontmatter mechanics (`name`, `description`, lowercase alphanumeric
+ hyphens, description-as-trigger) follow Anthropic's `skill-creator`
contract. See [anthropics/skills `skill-creator`](https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md).

For CrewAI's own framework on the prose layer the runtime SKILL.md
complements - role-goal-backstory construction, task descriptions
and expected outputs, agent capability tuning - see
[crewAIInc/skills `design-agent`](https://github.com/crewAIInc/skills/blob/main/skills/design-agent/SKILL.md)
and [`design-task`](https://github.com/crewAIInc/skills/blob/main/skills/design-task/SKILL.md).
Those are the upstream canonicals. This skill is the cybersquad-
specific overlay - the leaks named above are the ones we have
actually shipped, not theoretical risks.

cybersquad runtime skills are progressive-disclosure markdown only;
the `scripts/` layer is out of scope per #62.
