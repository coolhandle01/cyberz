"""Finding / vulnerability / disclosure / attack-plan fixtures.

The ``raw_finding_*`` set covers the three tiers the triage gate
discriminates against (high in-scope, low in-scope, out-of-scope);
``verified_vuln`` -> ``disclosure_report`` walks the post-triage
chain; ``attack_graph_node`` / ``attack_graph`` are the VR research
artefact the PT consumes.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

import pytest

from models import RawFinding, Severity, VerifiedVulnerability
from models.attack import AttackGraph, AttackGraphNode
from models.h1 import DisclosureReport


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


@pytest.fixture()
def attack_graph_node(target_apex: str) -> AttackGraphNode:
    return AttackGraphNode(
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
def attack_graph(attack_graph_node) -> AttackGraph:
    from datetime import UTC, datetime

    return AttackGraph(
        programme_handle="test-programme",
        drafted_at=datetime(2026, 1, 1, tzinfo=UTC),
        nodes=[attack_graph_node],
    )
