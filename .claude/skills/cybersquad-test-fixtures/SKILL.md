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
| `victim_url` | `https://victim.example.com` - in-scope target. **Single knob**: every in-scope fixture derives from this via `victim_apex`. Flip `victim_url` and `scope_item_url`, `scope_item_wildcard`, `programme`, `endpoint`, `recon_result`, `attack_plan_item` all follow. |
| `victim_apex` | Apex domain parsed out of `victim_url` (e.g. `example.com`). The derivation point every in-scope fixture builds against - use it when authoring a new in-scope fixture rather than embedding a literal. |
| `bystander_url` | `https://bystander.example.org` - out-of-scope; use whenever a test exercises the scope guard. |
| `callback_url` | `https://callback.cybersquad.com` - OOB receiver placeholder. |
| `programme` | A `Programme` model. In-scope: `https://<victim_apex>` and `*.<victim_apex>`. |
| `programme_in_workspace` | `programme` staged into the test's `tmp_path` as `<run_dir>/programme.json`, with `runtime.run_dir` + `runtime.programme_handle` monkeypatched. Tests that need `current_programme()` to work end-to-end take this fixture instead of patching the loader at every import site. |
| `dvwa_programme` | A `Programme` shaped like Damn Vulnerable Web Application on `http://localhost` / `http://127.0.0.1`. Use for BDD scenarios and integration work that point at a real runnable target (the usual deployment is a local Docker container). |
| `dvwa_in_workspace` | DVWA staged into the rundir - same shape as `programme_in_workspace` but the in-flight programme is DVWA. |
| `endpoint` | An `Endpoint` model at `https://api.<victim_apex>`. |
| `recon_result` | A `ReconResult` combining `programme` and `endpoint`. |
| `raw_finding_high` / `raw_finding_low` / `raw_finding_oos` | `RawFinding` instances at each severity / scope tier. |
| `verified_vuln` | A `VerifiedVulnerability` model. |
| `disclosure_report` | A `DisclosureReport` derived from `verified_vuln`. |
| `clean_response_body` | An HTML body verified at setup time to contain no pentest probe marker - use for "no finding" cases. |
| `reload_module` | Wraps `importlib.reload` so tests can pick up env-var changes on module-level singletons. |

## Authoring a new in-scope fixture

Derive from `victim_apex`, never embed the apex literal:

```python
# correct
@pytest.fixture()
def my_admin_endpoint(victim_apex: str) -> Endpoint:
    return Endpoint(url=f"https://admin.{victim_apex}", status_code=200, ...)

# wrong - hardcoded apex won't follow when victim_url changes
@pytest.fixture()
def my_admin_endpoint() -> Endpoint:
    return Endpoint(url="https://admin.example.com", status_code=200, ...)
```

The chain `victim_url -> victim_apex -> in-scope fixtures` is the single knob for retargeting the suite (e.g. flipping to DVWA on localhost would adjust `victim_url` and the dependent fixtures follow). A new fixture that hardcodes `example.com` breaks that property and gets caught at review.

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
