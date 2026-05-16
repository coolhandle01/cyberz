# Git workflow

Always cut branches fresh from a current main. Do not reuse or rebase a branch that was used for a previous PR - once a PR merges, its commits are in main and rebasing on top of them causes conflicts that require skipping commits. Place the branch in a folder depending on the semantics of the change. The correct flow every time for a feature:

```bash
git fetch origin
git checkout main
git pull origin main
git checkout -b feat/your-branch-name
```

For bugs use `bug/your-branch-name` for the branch name, for refactors and ci (non-breaking, non-bugfix) changes use `task/your-branch-name`.

A `git diff origin/main --stat` before any push is a fast sanity check that only your intended changes are included.

## One issue, one branch, one PR

For each GitHub issue worked on, present a single branch with a single PR for review. Do not bundle multiple issues into one PR even if they touch adjacent files - reviewer attention is the bottleneck, not branch count. If mid-task you discover unrelated work that needs doing, capture it as a `# FIXME` or `# TODO` (see `.claude/skills/cybersquad-change-discipline/SKILL.md`) or as a new issue, and finish the original task first.

## Force-push policy

- **Never** force-push to `main` or any protected/shared branch.
- **Never** force-push to a PR branch while a review is in progress - it destroys review-comment anchors and reviewers lose context.
- **Allowed**: `git push --force-with-lease` on your own PR branch *before* requesting review, to clean up history (e.g. after `git rebase origin/main`). Use `--force-with-lease`, never bare `--force` - the lease check fails safe if upstream moved.

## Commit messages

Never include session URLs in commit messages. Links of the form `https://claude.ai/code/session_...` embed a reference to a private conversation and must not appear in commit history. Use a plain one- or two-sentence description instead.
