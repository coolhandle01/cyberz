---
name: cybersquad-change-discipline
description: Apply change-discipline when editing existing code in this repo. Keep diffs minimal and in-scope, preserve comments and symbol names unless the rename is intentional and in scope, treat linter and SAST findings as engineering signal rather than noise to suppress, and surface blockers via question or a well-formed FIXME/TODO rather than silently working around them. Use when editing existing files, about to add `# noqa` / `# type: ignore` / `# nosec`, considering a rename or refactor outside the stated task, or encountering a CI failure.
---

# Change discipline

The goal of any PR is to satisfy its acceptance criteria with the smallest, most inarguable diff possible. Reviewer attention is the bottleneck; every byte of unrelated change is friction.

## Minimal diff

Inspired by Google's "Small CLs" guidance: a PR should do one thing. Before any commit:

- Run `git diff origin/main --stat` and ask: does every changed file relate to the stated task? If not, revert the unrelated change or move it to its own branch.
- Leave whitespace, formatting, and import order alone unless the linter required the change.
- Do not rewrite working code to a "cleaner" form unless cleanliness was the task.

## Preserve names, comments, and structure unless the change is the task

Code carries intent. Symbol names, comment wording, and file layout all encode what the original author understood. A drive-by rename inside an unrelated PR:

- breaks `git blame` continuity
- loses the author's framing
- makes the diff argue about two things at once (the rename *and* the actual change)

Rules:

- **Comments**: leave them alone unless they are actively incorrect (lying about what the code does). Reword for "style" elsewhere.
- **Symbol names**: rename only when (a) the new name is materially clearer, *and* (b) renaming is in scope for this PR. A deliberate "rename `X` to `Y`" PR is fine. A bug-fix PR with a sneaky rename is not.
- **Structure**: moving code between files, splitting functions, extracting helpers - all valid, all out of scope unless that *is* the task.

Counterexample to internalise: the `parse_llm` method on PR #42, where churn during an unrelated change cost real progress.

## Linter and SAST signal is engineering signal

ruff / mypy / bandit / semgrep findings are not bureaucracy. Each one is the tool flagging an assumption it could not verify. Before suppressing:

1. **Read the finding.** What is the tool worried about?
2. **Identify the unstated assumption.** Why is the code actually safe / correct? Write that down.
3. **Choose the cheaper fix.** Often making the assumption explicit in code is cheaper and clearer than suppressing the warning.
4. **If you must suppress**: the suppression must carry a one-line comment explaining the why. No bare `# noqa`, `# type: ignore`, or `# nosec`.

```python
# acceptable - the why is in the comment
os.getenv("FOO", "/tmp/bar")  # nosec B108  # noqa: S108 - intentional dev default, prod requires FOO
```

```python
# not acceptable - what is being silenced and why?
result = something_dangerous()  # nosec
```

Even a bandit finding that is "not a real security issue" usually points at an unidentified assumption (e.g. "this string is always trusted because..."). Make the assumption explicit, then decide.

## Surface concerns, do not silently override

When you find yourself wanting to break a stated rule (rename for clarity in a non-rename PR, suppress a linter finding you do not understand, change a comment that might actually be correct), stop. The options are, in order of preference:

1. **Ask.** A one-line question to the human is cheap and prevents wrong work.
2. **Note it.** Add a `# FIXME` or `# TODO` (see grammar below) and proceed with the original task untouched.
3. **Defer it.** Open a follow-up issue and link it.

### FIXME / TODO grammar

Use a consistent shape so these are greppable and actionable:

```python
# FIXME: this swallows ConnectTimeout but should retry once - tracked in #NN
# TODO: extract the cookie-jar logic when test_csrf.py stabilises
```

- `FIXME` means the code is wrong or incomplete in a way that should be fixed.
- `TODO` means the code is fine but improvement is possible later.
- Include enough context that another contributor could act on it without scrolling git history. If you cannot phrase the FIXME/TODO clearly, the right answer is "ask" not "note it".

## Chesterton's Fence

Before deleting or simplifying anything that looks redundant, find out why it was put there. Examples that look removable but are not:

- The `host == pattern or host.endswith("." + pattern)` check in `tools/recon/scope.py` (would let `evil.notexample.com` match `example.com` if simplified).
- The `default_factory=lambda` pattern in `config.py` (preserves `monkeypatch.setenv` semantics in tests).
- The `check_env()` call before `build_crew()` import in `main.py` (env vars are read at import time).

These are documented in `CLAUDE.md` as safety invariants. They exist for reasons that are not obvious from the code alone. Same principle applies to undocumented oddities: read git history, ask the author, or leave it.
