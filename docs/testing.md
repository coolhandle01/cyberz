# Testing

All tests are marked `@pytest.mark.unit` and must run without network access, real API credentials, or external binaries. Use `monkeypatch` and `unittest.mock` to isolate.

```bash
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit
```

Tests that reload modules for config isolation use `importlib.reload()` - this is the correct pattern for testing env-var-backed dataclasses.

Coverage floor is 85%. Every new public function in `tools/` needs a test. Every bug fix needs a regression test.

## Shared fixtures

`tests/conftest.py` provides fixtures for all tests. Use them instead of defining local equivalents.

The `cybersquad-test-fixtures` skill at `.claude/skills/cybersquad-test-fixtures/SKILL.md` covers the same material in a form Claude Code can load on demand when editing test files. The reference below is the same information in human-readable prose.

### `make_response`

Factory for `MagicMock` objects shaped like `requests.Response`. Accepts `status`, `body`, `headers`, `cookies`, and `json`. Use this for any generic HTTP response mock. Tool-specific response builders that carry extra logic (e.g. cookie-jar inspection, POST body reflection) can stay local to their test file.

```python
# correct - uses shared fixture
def test_no_finding(self, make_response: Callable[..., MagicMock]) -> None:
    with patch("requests.get", return_value=make_response(body="<html>ok</html>")):
        pass  # assertions go here

# wrong - duplicates the fixture locally
def _resp(body="", status=200):
    r = MagicMock()
    r.text = body
    r.status_code = status
    return r
```

### Model fixtures

`programme`, `endpoint`, `recon_result`, `raw_finding_high/low/oos`, `verified_vuln`, `disclosure_report` - canonical model instances. Use `model_copy(update={...})` to derive variants.

### `clean_response_body`

An HTML body verified at fixture-setup time to contain none of the strings any pentest probe treats as a positive match. Use it for "no finding" cases to avoid false negatives caused by accidental marker collisions.

## Mocking network and binaries

Tests must mock all network and binary calls. Patch `socket.create_connection` at the module path where it is imported (e.g. `tools.cloud.databases.redis.socket.create_connection`), not at the top-level `socket` module.
