---
name: cybersquad-test-fixtures
description: Use the shared pytest fixtures in tests/conftest.py instead of redefining local equivalents when writing or editing cybersquad tests. Covers make_response, the canonical model fixtures, clean_response_body, and the domain URL fixtures. Load before editing any file under tests/.
---

# cybersquad test fixtures

`tests/conftest.py` is the source of truth. Use these fixtures rather than redefining local equivalents - duplicates drift, hide accidental marker collisions, and make canonical-model refactors painful.

## Catalogue

| Fixture | What it provides |
|---|---|
| `make_response` | Factory for `MagicMock` shaped like `requests.Response`. Accepts `status`, `body`, `headers`, `cookies`, `json`. |
| `make_html_page` | Factory for minimal HTML pages with `<script>` tags. Default: one script at `{victim_url}/app.js`. |
| `programme` | A `Programme` model. In-scope: `https://example.com` and `*.example.com`. |
| `endpoint` | An `Endpoint` model at `https://api.example.com`. |
| `recon_result` | A `ReconResult` combining `programme` and `endpoint`. |
| `raw_finding_high` / `raw_finding_low` / `raw_finding_oos` | `RawFinding` instances at each severity / scope tier. |
| `verified_vuln` | A `VerifiedVulnerability` model. |
| `disclosure_report` | A `DisclosureReport` derived from `verified_vuln`. |
| `clean_response_body` | An HTML body verified at setup time to contain no pentest probe marker - use for "no finding" cases. |
| `victim_url` | `https://victim.example.com` - in-scope target. |
| `bystander_url` | `https://bystander.example.org` - out-of-scope; use whenever a test exercises the scope guard. |
| `callback_url` | `https://callback.cybersquad.com` - OOB receiver placeholder. |
| `reload_module` | Wraps `importlib.reload` so tests can pick up env-var changes on module-level singletons. |

## Derive variants with `model_copy`

Do not reconstruct a fixture model from scratch:

```python
# correct
out_of_scope = programme.model_copy(update={"in_scope": []})

# wrong - duplicates every other field
out_of_scope = Programme(handle=programme.handle, name=programme.name, ...)
```

## Use the domain fixtures

```python
# correct - intent is readable at the call site
def test_drops_out_of_scope(make_response, bystander_url):
    ...

# wrong - opaque hostname, no indication of role
def test_drops_out_of_scope(make_response):
    url = "https://malicious.invalid"
```

## Tool-specific response builders

A local response builder that carries extra logic (cookie-jar inspection, POST body reflection - see `_post_resp` in `test_csrf.py`, the cookie-aware `_resp` in `test_cookies.py`) can stay local. The rule is: if the local helper is just constructing a generic mock response, replace it with `make_response`.
