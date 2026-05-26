"""
tests/conftest.py - shared fixtures for the Bounty Squad test suite.
"""

from __future__ import annotations

# Seed the env vars that config.py reads at import time so test runs that
# do not export them on the command line still load the config singleton
# cleanly. These are placeholders only; production runs supply real values.
import os

os.environ.setdefault("H1_API_USERNAME", "ci-user")
os.environ.setdefault("H1_API_TOKEN", "ci-token")
os.environ.setdefault("CYBERSQUAD_CONTACT_EMAIL", "ci@example.invalid")

from collections.abc import Callable

import pytest

from models import (
    Endpoint,
    RawFinding,
    ReconResult,
    Severity,
    VerifiedVulnerability,
)
from models.attack import AttackPlan, AttackPlanItem
from models.h1 import (
    DisclosureReport,
    Programme,
    ScopeItem,
    ScopeType,
)


# Probe tools call tools._helpers.adaptive_sleep between requests for rate-limit
# politeness. Inside _helpers, adaptive_sleep calls time.sleep(delay) for real,
# which dominates unit-test wall-clock time (roughly 40% of the suite). Patch it
# once here for every test. Tests that need to observe sleep behaviour
# (TestAdaptiveSleep in test_scan_mode.py) re-patch time.sleep locally and the
# assertions still fire - the autouse lambda is below their inner patch.
@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args, **_kwargs: None)


# Domain fixtures
#
# Use these instead of ad-hoc hostnames so test intent is readable at a glance.
# target_url    - the scanning target (an app we are testing); in-scope per
#                 the ``programme`` fixture's ``*.example.com`` wildcard rule.
# bystander_url - an out-of-scope host on a different TLD. Use it whenever a
#                 test exercises the scope guard - the name makes the intent
#                 ("bystander, hands off") obvious at the call site.
# callback_url  - OOB receiver (a server we control, used for blind injection);
#                 placeholder until #77 lands real interactsh infrastructure.
@pytest.fixture()
def target_url() -> str:
    return "https://victim.example.com"


@pytest.fixture()
def bystander_url() -> str:
    return "https://bystander.example.org"


@pytest.fixture()
def callback_url() -> str:
    return "https://callback.cybersquad.com"


@pytest.fixture()
def make_html_page(target_url: str):
    """Factory for minimal HTML pages containing script tags.

    Returns a callable: make_html_page(scripts=[...]) -> str.
    Defaults to a single <script> pointing at {target_url}/app.js.
    """

    def _make(scripts: list[str] | None = None) -> str:
        _scripts = scripts if scripts is not None else [f"{target_url}/app.js"]
        tags = "".join(f'<script src="{s}"></script>' for s in _scripts)
        return f"<html><head>{tags}</head></html>"

    return _make


@pytest.fixture()
def run_dir(tmp_path, monkeypatch):
    """Point ``runtime.run_dir()`` at this test's ``tmp_path``.

    Every tool that reads / writes workspace artefacts resolves the
    rundir through ``runtime.run_dir()``. Tests that exercise those
    tools take this fixture to get a per-test rundir without patching
    the function at every consumer's import alias
    (``tools.workspace.runtime.run_dir`` / ``tools.triage_tools.runtime.run_dir``
    / etc) - every consumer ``import runtime`` so a single setattr on
    ``runtime.run_dir`` propagates to all of them.

    Returns the ``Path`` so tests can read / write fixture files
    against it directly.
    """
    monkeypatch.setattr("runtime.run_dir", lambda: tmp_path)
    return tmp_path


# Programme fixtures
@pytest.fixture()
def target_apex(target_url: str) -> str:
    """Apex domain derived from ``target_url``.

    Every fixture that builds an in-scope ScopeItem, hostname, or URL
    derives from this rather than embedding the apex literal. That way
    flipping ``target_url`` (e.g. to point the suite at DVWA on
    localhost) propagates through every dependent fixture - no
    per-fixture hardcoded ``example.com`` left to chase.
    """
    from urllib.parse import urlparse

    host = urlparse(target_url).hostname or ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@pytest.fixture()
def scope_item_url(target_apex: str) -> ScopeItem:
    return ScopeItem(
        asset_identifier=f"https://{target_apex}",
        asset_type=ScopeType.URL,
        eligible_for_bounty=True,
    )


@pytest.fixture()
def scope_item_wildcard(target_apex: str) -> ScopeItem:
    return ScopeItem(
        asset_identifier=f"*.{target_apex}",
        asset_type=ScopeType.WILDCARD,
        eligible_for_bounty=True,
    )


@pytest.fixture()
def programme(scope_item_url, scope_item_wildcard) -> Programme:
    return Programme(
        handle="test-programme",
        name="Test Programme",
        url="https://hackerone.com/test-programme",
        bounty_table={
            Severity.LOW: 100,
            Severity.MEDIUM: 500,
            Severity.HIGH: 2000,
            Severity.CRITICAL: 5000,
        },
        in_scope=[scope_item_url, scope_item_wildcard],
        out_of_scope=[],
    )


@pytest.fixture()
def programme_in_workspace(programme: Programme, run_dir, monkeypatch) -> Programme:
    """Stage ``programme.json`` into the run directory and point runtime at it.

    Reproduces what the PM's ``Save Selected Programme`` does at run
    start: writes ``<run_dir>/programme.json`` and sets ``runtime`` so
    every downstream consumer (``current_programme()``, the @cyber_tool
    ``scope_filter`` wrapper, every tool that reads
    ``runtime.programme_handle`` for HTTP attribution) sees the in-flight
    programme without any per-test stubbing of the loader itself.

    The artefact *is* the fixture: tests assert against the same shape
    the next agent would actually consume.
    """
    (run_dir / "programme.json").write_text(programme.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("runtime.programme_handle", programme.handle)
    return programme


@pytest.fixture()
def dvwa_programme() -> Programme:
    """A Programme shaped like Damn Vulnerable Web Application on localhost.

    DVWA (https://github.com/digininja/DVWA) is the canonical
    deliberately-vulnerable PHP/MySQL training target; the usual
    deployment is a local Docker container exposed on ``http://localhost``.
    A Programme-shaped fixture pointing at that lets BDD scenarios and
    DVWA-targeted integration work read 'the squad targets DVWA'
    against a fixture that maps to a real, runnable target rather than
    a synthetic ``example.com`` that does not exist.

    Bounty table mirrors the in-scope ``programme`` fixture's token
    values so downstream consumers do not need to special-case a
    zero-bounty programme; the comment is the documentation that DVWA
    is not actually a paying programme.

    FIXME(#121 Phase 3): piton for the DVWA sandboxed e2e work. Currently
    unused - landed alongside the ``programme_in_workspace`` fixture in
    #159 as scaffolding the BDD scenarios in Phase 3 will pick up. If
    #121 Phase 3 is descoped or solves the runnable-target need a
    different way, delete this fixture and ``dvwa_in_workspace`` below.
    """
    return Programme(
        handle="dvwa-localhost",
        name="Damn Vulnerable Web Application (localhost)",
        url="https://hackerone.com/dvwa-localhost",
        bounty_table={
            Severity.LOW: 100,
            Severity.MEDIUM: 500,
            Severity.HIGH: 2000,
            Severity.CRITICAL: 5000,
        },
        in_scope=[
            ScopeItem(
                asset_identifier="http://localhost",
                asset_type=ScopeType.URL,
                eligible_for_bounty=False,
            ),
            ScopeItem(
                asset_identifier="http://127.0.0.1",
                asset_type=ScopeType.URL,
                eligible_for_bounty=False,
            ),
        ],
        out_of_scope=[],
    )


@pytest.fixture()
def dvwa_in_workspace(dvwa_programme: Programme, run_dir, monkeypatch) -> Programme:
    """DVWA staged into the run dir - same shape as ``programme_in_workspace``
    but the in-flight programme is DVWA, so BDD scenarios that point the
    squad at DVWA exercise the artefact the runtime actually consumes.

    FIXME(#121 Phase 3): see ``dvwa_programme`` above - this is the
    workspace-staged counterpart waiting on the DVWA e2e scenarios."""
    (run_dir / "programme.json").write_text(dvwa_programme.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("runtime.programme_handle", dvwa_programme.handle)
    return dvwa_programme


# Recon fixtures
@pytest.fixture()
def endpoint(target_apex: str) -> Endpoint:
    return Endpoint(
        url=f"https://api.{target_apex}",
        status_code=200,
        technologies=["nginx", "React"],
        parameters=["q", "page"],
    )


@pytest.fixture()
def recon_result(programme, endpoint, target_apex: str) -> ReconResult:
    return ReconResult(
        programme=programme,
        subdomains=[f"api.{target_apex}", f"admin.{target_apex}"],
        endpoints=[endpoint],
        open_ports={f"api.{target_apex}": [80, 443]},
        technologies=["nginx", "React"],
        notes="Test recon result.",
    )


# Cloud-storage fixtures. Bucket / container names are built from the
# second-level domain of ``target_apex`` so flipping ``target_url``
# propagates through every cloud-storage test the same way it does for
# every other in-scope-target literal. Factories rather than single
# values where tests need variants (e.g. the "iterate every supplied
# hostname" tests pass two distinct ones); single-value fixtures wrap
# the factory at its canonical suffix for the common case. Mirrors the
# ``make_html_page`` pattern further up the file.
@pytest.fixture()
def target_sld(target_apex: str) -> str:
    """Second-level-domain prefix of ``target_apex`` (``example`` from
    ``example.com``). Cloud bucket / account names take this rather
    than the full apex - DNS labels in a bucket name cannot contain
    the apex's dot, so the bare SLD is what carries cleanly into
    ``<sld>-assets.s3...`` / ``<sld>storage.blob...``."""
    return target_apex.split(".")[0]


@pytest.fixture()
def make_s3_hostname(target_sld: str) -> Callable[..., str]:
    """Factory for in-scope-themed S3 hostnames.

    ``make_s3_hostname("assets")`` -> ``"example-assets.s3.us-east-1.amazonaws.com"``;
    ``make_s3_hostname()`` -> ``"example.s3.us-east-1.amazonaws.com"``.
    Override ``region`` for variants.
    """

    def _make(suffix: str = "", *, region: str = "us-east-1") -> str:
        bucket = f"{target_sld}-{suffix}" if suffix else target_sld
        return f"{bucket}.s3.{region}.amazonaws.com"

    return _make


@pytest.fixture()
def s3_hostname(make_s3_hostname: Callable[..., str]) -> str:
    """Single canonical S3 hostname for the simple cases - the suite's
    equivalent of ``target_url`` for AWS S3. Use ``make_s3_hostname``
    when a test needs more than one or a non-default region."""
    return make_s3_hostname("assets")


@pytest.fixture()
def make_azure_blob_hostname(target_sld: str) -> Callable[..., str]:
    """Factory for in-scope-themed Azure Blob hostnames.

    ``make_azure_blob_hostname("storage")`` ->
    ``"examplestorage.blob.core.windows.net"``. Azure storage account
    names are 3-24 lowercase alphanumeric (no hyphens), so the suffix
    concatenates without a separator.
    """

    def _make(suffix: str = "") -> str:
        account = f"{target_sld}{suffix}"
        return f"{account}.blob.core.windows.net"

    return _make


@pytest.fixture()
def azure_blob_hostname(make_azure_blob_hostname: Callable[..., str]) -> str:
    """Single canonical Azure Blob hostname for the simple cases."""
    return make_azure_blob_hostname("storage")


@pytest.fixture()
def azure_sas_endpoint(target_url: str) -> Endpoint:
    """``Endpoint`` whose URL carries embedded Azure SAS-token query
    parameters - the canonical positive case for
    ``check_azure_sas_tokens``. Built on ``target_url`` so the host
    is in-scope; the test exercises the query-string detection."""
    return Endpoint(
        url=(f"{target_url}/files/doc.pdf?sv=2021-01-01&se=2025-12-31&sr=b&sp=r&sig=abc123"),
        status_code=200,
    )


# Attack plan fixtures
@pytest.fixture()
def attack_plan_item(target_apex: str) -> AttackPlanItem:
    return AttackPlanItem(
        probe="CVE-2022-22965",
        target=f"https://api.{target_apex}",
        expected_ceiling=Severity.CRITICAL,
        rationale=(
            "Tomcat-served Spring Boot 2.3 detected in recon; test the standard "
            "POST payload and look for arbitrary file write in the webroot."
        ),
        recon_evidence=[
            f"api.{target_apex} runs Tomcat 9.0",
            "Spring Boot 2.3 banner observed on /actuator/info",
        ],
    )


@pytest.fixture()
def attack_plan(attack_plan_item) -> AttackPlan:
    from datetime import UTC, datetime

    return AttackPlan(
        programme_handle="test-programme",
        drafted_at=datetime(2026, 1, 1, tzinfo=UTC),
        items=[attack_plan_item],
    )


# Vulnerability fixtures
@pytest.fixture()
def raw_finding_high(target_apex: str) -> RawFinding:
    return RawFinding(
        title=f"SQL Injection - https://api.{target_apex}/search",
        vuln_class="SQLi",
        target=f"https://api.{target_apex}/search",
        evidence="sqlmap identified injection at parameter 'q'",
        tool="sqlmap",
        severity_hint=Severity.HIGH,
    )


@pytest.fixture()
def raw_finding_low(target_apex: str) -> RawFinding:
    return RawFinding(
        title="Missing X-Frame-Options",
        vuln_class="Headers",
        target=f"https://api.{target_apex}",
        evidence="X-Frame-Options header absent",
        tool="nuclei",
        severity_hint=Severity.LOW,
    )


@pytest.fixture()
def raw_finding_oos() -> RawFinding:
    """A finding whose target is outside programme scope."""
    return RawFinding(
        title="XSS - https://other.com/search",
        vuln_class="XSS",
        target="https://other.com/search",
        evidence="<script>alert(1)</script> reflected",
        tool="nuclei",
        severity_hint=Severity.HIGH,
    )


@pytest.fixture()
def verified_vuln(target_apex: str) -> VerifiedVulnerability:
    return VerifiedVulnerability(
        title=f"SQL Injection - https://api.{target_apex}/search",
        vuln_class="SQLi",
        target=f"https://api.{target_apex}/search",
        severity=Severity.HIGH,
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        description="A SQL injection vulnerability exists at the search endpoint.",
        steps_to_reproduce=[
            f"Navigate to https://api.{target_apex}/search?q=test",
            "Append a single quote to the q parameter",
            "Observe database error in the response",
        ],
        evidence="sqlmap identified injection at parameter 'q'",
        impact="An attacker can exfiltrate the entire database.",
        remediation="Use parameterised queries. See OWASP SQL Injection Prevention Cheat Sheet.",
    )


@pytest.fixture()
def disclosure_report(verified_vuln) -> DisclosureReport:
    return DisclosureReport(
        programme_handle="test-programme",
        title=verified_vuln.title,
        vulnerability=verified_vuln,
        summary="A SQL injection vulnerability at the search endpoint allows full DB exfiltration.",
        body_markdown="# SQL Injection\n\n## Summary\n\nTest report body.",
        weakness_id=89,
        impact_statement=verified_vuln.impact,
    )


# Response body fixtures
#
# These exist so tests for "no finding" cases don't accidentally include a
# string that one of the pentest probes uses as a positive detection marker.
# We caught one of those (an SSRF test where the body "not metadata" tripped
# the "metadata" marker) - the fixture catches the next one at setup time
# instead of at assertion time.
@pytest.fixture()
def clean_response_body() -> str:
    """An HTML response body verified to contain none of the strings any
    pentest probe uses as a positive detection marker. Use this for tests
    that need a generic 'nothing of interest in the response' body.
    """
    body = "<html><body><h1>Hello</h1><p>Welcome.</p></body></html>"

    from tools.pentest.cmd_injection import _CANARY as _CMD_CANARY
    from tools.pentest.ldap_injection import _LDAP_ERROR_MARKERS
    from tools.pentest.path_traversal import _PROBES as _PATH_PROBES
    from tools.pentest.prompt_injection import (
        _CANARY as _PROMPT_CANARY,
    )
    from tools.pentest.prompt_injection import (
        _SYSTEM_PROMPT_MARKERS,
    )
    from tools.pentest.prototype_pollution import _CANARY as _PP_CANARY
    from tools.pentest.ssrf import _SSRF_MARKERS
    from tools.pentest.ssti import _EXPECTED as _SSTI_EXPECTED
    from tools.pentest.xxe import _LINUX_MARKER, _WIN_MARKER, _XML_ERROR_MARKERS

    forbidden: list[str] = [
        _CMD_CANARY,
        _PROMPT_CANARY,
        _PP_CANARY,
        _LINUX_MARKER,
        _WIN_MARKER,
        _SSTI_EXPECTED,
        *_SSRF_MARKERS,
        *_LDAP_ERROR_MARKERS,
        *_XML_ERROR_MARKERS,
        *_SYSTEM_PROMPT_MARKERS,
        *(marker for _payload, marker in _PATH_PROBES.values()),
    ]

    for marker in forbidden:
        assert marker not in body, (
            f"clean_response_body fixture contains pentest marker {marker!r}; "
            "rewrite the body so no probe would treat it as a finding."
        )

    return body


@pytest.fixture()
def reload_module():
    """Reload a module so that monkeypatched env vars take effect on module-level singletons.

    Usage: reload_module(my_module)
    """
    import importlib

    return importlib.reload


@pytest.fixture()
def invoke_tool():
    """Invoke a ``@cyber_tool`` wrapper the way CrewAI does at runtime.

    CrewAI's tool-call path is ``args_schema.model_validate(payload).
    model_dump()`` -> ``func(**dumped)``. The ``TargetHostnames`` /
    ``TargetEndpoints`` / ``TargetHostname`` / ``TargetEndpoint``
    typed aliases run their ``AfterValidator`` during the
    ``model_validate`` step - that IS the scope guard. Tests that
    exercise scope-guard behaviour call wrappers through this fixture
    so the validator actually fires; ``.func(...)`` alone bypasses the
    args_schema and sees the raw input verbatim.
    """

    def _invoke(wrapper, **kwargs):
        validated = wrapper.args_schema.model_validate(kwargs).model_dump()
        return wrapper.func(**validated)

    return _invoke


@pytest.fixture
def make_response():
    """Factory for building MagicMock objects shaped like requests.Response.

    Use this instead of local _resp/_mock_resp helpers in individual test files.
    Tool-specific builders (e.g. _post_resp in test_csrf.py, the cookie-aware
    _resp in test_cookies.py) stay local - they are not generic response mocks.
    """
    from unittest.mock import MagicMock

    def _make(
        status: int = 200,
        body: str = "",
        headers: dict | None = None,
        cookies: dict | None = None,
        json: object = None,
    ) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        resp.headers = headers or {}
        resp.cookies = cookies or {}
        if json is not None:
            resp.json.return_value = json
        return resp

    return _make
