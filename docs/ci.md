# CI

Three jobs run on every push: `lint` (ruff + mypy), `test` (pytest, 70% coverage floor), and `sast` (bandit + semgrep). The local commands in the pre-commit checklist in `CLAUDE.md` mirror them exactly - use those.

## Notes on fixing findings

### ruff

`ruff check --fix` and `ruff format` resolve most issues automatically.

### mypy

Ensure all public functions have annotated parameters and return types. If a real dep (crewai, pydantic) has incomplete stubs and you need to suppress a false positive, use a targeted `# type: ignore[<code>]` rather than a blanket ignore.

### bandit

Suppress with `# nosec B<code>` (bandit's own directive, *not* `# noqa`). Keep the accompanying `# noqa: S<code>` for ruff - both are needed:

```python
os.getenv("FOO", "/tmp/bar")  # nosec B108  # noqa: S108
```

### GitHub Actions pins

Every action must be pinned to a full-length commit SHA, not a tag. Branch protection enforces this. Add the version as a trailing comment for readability:

```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4.3.1
```

### upload-artifact v4 and hidden files

`.coverage` and other dotfiles are skipped by default. Set `include-hidden-files: true` on the step.
