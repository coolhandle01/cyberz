# Contributing to cybersquad

Thanks for working on this. This file is the contributor surface: setup pointers, the rules every change must follow, and the safety invariants that hold across the codebase. If you are working with Claude Code, also read `CLAUDE.md` for the AI-specific instructions and the skill catalogue.

For project setup (Python version, external binaries, API credentials, install commands), see `README.md`.

## Before you commit

Work inside a virtualenv with full dev dependencies installed. Without it, `mypy` cannot resolve `crewai`, `crewai.tools`, or `langchain_anthropic` and will silently pass.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Then run the full CI stack locally, in this order. All five must pass before pushing - never "push and let CI tell me":

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy . --ignore-missing-imports
H1_API_USERNAME=ci-user H1_API_TOKEN=ci-token CYBERSQUAD_CONTACT_EMAIL=ci@example.invalid .venv/bin/pytest -m unit --cov --cov-report=term-missing
.venv/bin/bandit -c pyproject.toml -r . -q
```

Never push a change you haven't actually executed. A passing `mypy` run after removing a `# type: ignore` means nothing if the file wasn't reachable.

Read the actual file before planning any change. Check `proposals/` for in-flight design work.

## Universal rules

These apply to every edit, no exceptions.

### ASCII only

All source files, comments, docstrings, and `.md` prose must be plain ASCII. No em dashes, en dashes, curly quotes, box-drawing characters, arrows, bullets, or emoji. Use `-` not em-dash, `->` not the Unicode arrow, `|` not the Unicode pipe. Unicode in source inflates token counts for every AI tool that reads this codebase.

### Minimal diff

One PR does one thing. Before any commit, run `git diff origin/main --stat` and ask: does every changed file relate to the stated task? If not, revert the unrelated change or move it to its own branch. Leave whitespace, formatting, and import order alone unless the linter required the change. Do not rewrite working code to a "cleaner" form unless cleanliness was the task.

### Preserve names, comments, and structure unless the change is the task

Code carries intent. Symbol names, comment wording, and file layout all encode what the original author understood. A drive-by rename inside an unrelated PR breaks `git blame` continuity, loses the author's framing, and makes the diff argue about two things at once.

- **Comments**: leave them alone unless they are actively incorrect (lying about what the code does). Do not reword for "style".
- **Symbol names**: rename only when (a) the new name is materially clearer, *and* (b) renaming is in scope for this PR.
- **Structure**: moving code between files, splitting functions, extracting helpers - all valid, all out of scope unless that *is* the task.

Before deleting or simplifying anything that looks redundant (Chesterton's Fence): find out why it was put there. See the safety invariants below for documented examples.

### Linter and SAST findings are engineering signal

ruff / mypy / bandit / semgrep findings are not bureaucracy. Each one is the tool flagging an assumption it could not verify. Before suppressing:

1. Read the finding. What is the tool worried about?
2. Identify the unstated assumption. Why is the code actually safe or correct?
3. Choose the cheaper fix. Often making the assumption explicit in code is cheaper than suppressing the warning.
4. If you must suppress, the suppression must carry a one-line comment explaining the why. No bare `# noqa`, `# type: ignore`, or `# nosec`.

```python
# acceptable - the why is in the comment
os.getenv("FOO", "/tmp/bar")  # nosec B108  # noqa: S108 - intentional dev default, prod requires FOO

# not acceptable
result = something_dangerous()  # nosec
```

### FIXME and TODO grammar

Use a consistent shape so these are greppable and actionable:

```python
# FIXME: this swallows ConnectTimeout but should retry once - tracked in #NN
# TODO: extract the cookie-jar logic when test_csrf.py stabilises
```

`FIXME` means the code is wrong or incomplete in a way that should be fixed. `TODO` means the code is fine but improvement is possible later. Include enough context that another contributor could act on it without scrolling git history. If you cannot phrase the FIXME or TODO clearly, the right answer is "ask", not "note it".

### Surface concerns, do not silently override

When you find yourself wanting to break a stated rule (rename for clarity in a non-rename PR, suppress a linter finding you do not understand, change a comment that might actually be correct), stop. The options in order of preference:

1. Ask. A one-line question is cheap and prevents wrong work.
2. Note it via FIXME or TODO using the grammar above, and proceed with the original task untouched.
3. Defer it by opening a follow-up issue and linking it.

### Tests: derive variants with `model_copy(update=...)`

When deriving a test variant from a canonical fixture model, do not reconstruct the model from scratch via the constructor. Use `model_copy`:

```python
# correct
out_of_scope = programme.model_copy(update={"in_scope": []})

# wrong - duplicates every other field
out_of_scope = Programme(handle=programme.handle, name=programme.name, ...)
```

### Five-file prompt layout

Each agent's prose lives in exactly five single-purpose markdown files inside its package:

```
squad/<member>/
    role.md
    goal.md
    backstory.md
    description.md
    expected_output.md
```

`SquadMember.read("<name>")` loads `<name>.md` and strips whitespace. Missing files raise `FileNotFoundError` at agent or task build time. If you need to add expertise to an agent, do it inside one of these five files, not by introducing a sixth.

## Safety invariants - do not weaken

These exist for reasons that are not obvious from the code alone. Touching any of them requires deliberate, explained intent.

- **Scope enforcement** in `tools/recon/scope.py`: `if host == pattern or host.endswith("." + pattern)`. A bare `host.endswith(pattern)` would let `evil.notexample.com` match `example.com`.
- **Automated-scanning gate** in `tools/h1_api.py:parse_programme()`: sets `allows_automated_scanning=False` on policy text like "no automated" or "automated scanning prohibited". The Programme Manager discards such programmes.
- **Import order in `main.py`**: `check_env()` must run before `build_crew()` is imported. The crew import chain reads env vars; `check_env()` must exit cleanly first.
- **No module-level side effects in `crew.py`**. The old `crew = build_crew()` at module level was deliberately removed.
- **`default_factory=lambda` in `config.py`** preserves `monkeypatch.setenv` semantics in tests. Do not "simplify" to direct env reads at class-definition time.

## Where to find more

- `docs/architecture.md` - what the project does, key files
- `docs/git-workflow.md` - branch naming, fresh-from-main flow, commit-message rules
- `docs/testing.md` - pytest invocation, coverage floor, shared fixtures
- `docs/ci.md` - ruff/mypy/bandit guidance, SHA pinning, `upload-artifact` gotcha
- `docs/contributing/adding-an-agent.md` - the agent recipe
- `docs/contributing/adding-a-tool.md` - the tool recipe, including probe-StrEnum and `default_factory=lambda` rules
- `docs/contributing/adding-config.md` - config knobs and their tests
