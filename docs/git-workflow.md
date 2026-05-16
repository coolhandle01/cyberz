# Git workflow

Always cut branches fresh from a current main. Do not reuse or rebase a branch that was used for a previous PR - once a PR merges, its commits are in main and rebasing on top of them causes conflicts that require skipping commits. Place the branch in a folder depending on the semantics of the change. The correct flow every time for a feature:

```bash
git fetch origin
git checkout main
git pull origin main
git checkout -b feat/your-branch-name
```

Substitute `feat/` for the appropriate prefix from the type table below.

A `git diff origin/main --stat` before any push is a fast sanity check that only your intended changes are included.

## Commit and branch type prefixes

This repo follows [Conventional Commits](https://www.conventionalcommits.org/). Branch prefixes match commit types so the two stay in lockstep and `commitizen` lands cleanly when it's wired up.

Format: `<type>(<scope>)?: <subject>` for commit messages, `<type>/<short-description>` for branch names. Scope is optional but encouraged when it sharpens the subject - e.g. `chore(coverage):`, `fix(recon):`, `docs(git-workflow):`.

| Type | When to use |
|---|---|
| `feat` | A new feature visible to a user or another agent |
| `fix` | A bug fix |
| `docs` | Documentation only - no code or test change |
| `style` | Formatting, whitespace, missing semicolons - no logic change |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | A change that improves performance |
| `test` | Adding or correcting tests - no production code change |
| `build` | Build system or dependency changes (`pyproject.toml` deps, packaging) |
| `ci` | CI configuration only (`.github/workflows/`, pre-commit hooks) |
| `chore` | Maintenance that doesn't fit the above - bumping a gate value, tidying a config |
| `revert` | Reverts a previous commit; subject is the reverted commit's subject |

Examples:

- `feat(squad/triage): add CVSS sanity-check pass after vulnerability researcher`
- `fix(recon/scope): treat sub.example.com as in-scope when pattern is example.com`
- `chore(coverage): raise fail_under from 70 to 88`
- `docs(git-workflow): document --force-with-lease policy`

## One issue, one branch, one PR

For each GitHub issue worked on, present a single branch with a single PR for review. Do not bundle multiple issues into one PR even if they touch adjacent files - reviewer attention is the bottleneck, not branch count. If mid-task you discover unrelated work that needs doing, capture it as a `# FIXME` or `# TODO` (see `.claude/skills/cybersquad-change-discipline/SKILL.md`) or as a new issue, and finish the original task first.

## Force-push policy

- **Never** force-push to `main` or any protected/shared branch.
- **Never** force-push to a PR branch while a review is in progress - it destroys review-comment anchors and reviewers lose context.
- **Allowed**: `git push --force-with-lease` on your own PR branch *before* requesting review, to clean up history (e.g. after `git rebase origin/main`). Use `--force-with-lease`, never bare `--force` - the lease check fails safe if upstream moved.

## Commit messages

Never include session URLs in commit messages. Links of the form `https://claude.ai/code/session_...` embed a reference to a private conversation and must not appear in commit history. Use a plain one- or two-sentence description instead.
