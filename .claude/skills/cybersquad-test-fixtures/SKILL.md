---
name: cybersquad-test-fixtures
description: Use the shared pytest fixtures in tests/conftest.py instead of defining local equivalents when writing or editing cybersquad tests. Covers make_response (HTTP response factory), canonical model fixtures (programme, endpoint, recon_result, raw_finding_high/low/oos, verified_vuln, disclosure_report), and clean_response_body (false-positive-safe HTML). Use when editing any file under tests/.
---

# cybersquad test fixtures

`tests/conftest.py` provides fixtures for all tests. Use them. Do not redefine local equivalents - duplicates drift, hide accidental marker collisions, and make refactors of the canonical models painful.

## make_response

Factory for `MagicMock` objects shaped like `requests.Response`. Accepts `status`, `body`, `headers`, `cookies`, and `json`. Use this for any generic HTTP response mock.

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

Tool-specific response builders that carry extra logic (e.g. cookie-jar inspection, POST body reflection) can stay local to their test file. The rule is: if a local helper is just constructing a generic mock response, replace it with `make_response`.

## Canonical model fixtures

Use these as starting points and derive variants with `model_copy(update={...})`:

- `programme` - a `Programme` model instance
- `endpoint` - an `Endpoint` model instance
- `recon_result` - a `ReconResult` model instance
- `raw_finding_high`, `raw_finding_low`, `raw_finding_oos` - `RawFinding` instances at each severity / scope tier
- `verified_vuln` - a `VerifiedVuln` model instance
- `disclosure_report` - a `DisclosureReport` model instance

```python
# correct - derive a variant
def test_excludes_out_of_scope(programme):
    oos = programme.model_copy(update={"in_scope_assets": []})
    ...

# wrong - reconstruct from scratch
def test_excludes_out_of_scope():
    oos = Programme(handle="x", name="y", ...)
```

## clean_response_body

An HTML body verified at fixture-setup time to contain none of the strings any pentest probe treats as a positive match. Use it for "no finding" cases to avoid false negatives caused by accidental marker collisions in hand-rolled HTML.

```python
def test_no_finding(make_response, clean_response_body):
    with patch("requests.get", return_value=make_response(body=clean_response_body)):
        result = my_probe("https://target.invalid")
    assert result is None
```

## When in doubt

Read `tests/conftest.py` - it is the source of truth for what is available.
