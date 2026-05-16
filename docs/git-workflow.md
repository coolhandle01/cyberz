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

## Commit messages

Never include session URLs in commit messages. Links of the form `https://claude.ai/code/session_...` embed a reference to a private conversation and must not appear in commit history. Use a plain one- or two-sentence description instead.
