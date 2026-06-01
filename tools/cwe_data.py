"""
tools/cwe_data.py - CWE routing keyed to the vuln_class strings the pentest
tooling emits, enriched from the bundled MITRE corpus.

This module owns two things that no external API provides, and delegates the
rest to the ``cwe2`` library (the full MITRE CWE database, bundled offline):

* **Routing** (``_ROUTING``): the cybersquad-specific map from a vuln_class /
  alias the pentest stage emits ("xss", "SQLi", "IDOR") to a CWE id, plus the
  matching OWASP cheat-sheet slug from ``tools/owasp_data.py``. MITRE publishes
  no keyword-search API, and the vuln_class -> CWE choice is our editorial call
  anyway, so this stays local by design. It is a routing table, not a catalogue
  of CWE prose.
* **Enrichment**: the CWE *name* and *description* are no longer hand-copied
  here (they drift from MITRE the moment MITRE revises a weakness). They are
  pulled from ``cwe2`` at build time, so the agent always cites MITRE's current
  wording.

Entries are looked up by case-insensitive match against the CWE name, the
vuln_class, or any alias. A query like "xss", "reflected xss", "ReflectedXSS",
or "cross-site scripting" all resolve to CWE-79.

Adding a routing entry: append ``(cwe_id, aliases, owasp_topic)`` below and pick
the matching OWASP cheat-sheet slug from ``tools/owasp_data.py``. The name and
description come from the corpus automatically - do not hand-write them.
"""

from __future__ import annotations

from functools import cache

from cwe2.database import Database, InvalidCWEError

# CWEEntry lives in models/mitre/ per the typed-shapes-live-in-models
# rule. Re-exported here so existing ``from tools.cwe_data import
# CWEEntry`` consumers keep working; the canonical import path is
# ``from models import CWEEntry``.
from models.mitre import CWEEntry

# Routing table: ``(cwe_id, aliases, owasp_topic)``. One row per vuln_class the
# pentest stage can emit, plus a few extras for severity-adjusted
# re-classifications (e.g. AuthZ from IDOR). Name / description are NOT here -
# they come from the bundled MITRE corpus via ``_enrich``.
_ROUTING: list[tuple[int, list[str], str | None]] = [
    (22, ["PathTraversal", "path traversal", "directory traversal", "LFI", "lfi"], "File_Upload"),
    (
        77,
        ["CommandInjection", "command injection", "OS command injection", "RCE"],
        "OS_Command_Injection_Defense",
    ),
    (78, ["RCE", "remote code execution"], "OS_Command_Injection_Defense"),
    (
        79,
        ["XSS", "ReflectedXSS", "stored XSS", "HeaderXSS", "cross-site scripting"],
        "Cross_Site_Scripting_Prevention",
    ),
    (89, ["SQLi", "sql injection"], "SQL_Injection_Prevention"),
    (90, ["LDAPInjection", "ldap injection"], "LDAP_Injection_Prevention"),
    (
        94,
        ["SSTI", "server-side template injection", "code injection"],
        "Server_Side_Template_Injection_Prevention",
    ),
    (
        200,
        [
            "ErrorDisclosure",
            "error disclosure",
            "SourceMapLeak",
            "SensitiveFileExposed",
            "information disclosure",
        ],
        "Error_Handling",
    ),
    (201, ["EmailSpoofing", "spf misconfiguration"], "Transport_Layer_Security"),
    (235, ["HPP", "HTTP Parameter Pollution"], "Input_Validation"),
    (
        285,
        ["AuthZ", "authorization", "AccessControlBypass", "broken access control"],
        "Authorization",
    ),
    (287, ["AuthN", "authentication"], "Authentication"),
    (
        295,
        ["TLSMisconfiguration", "tls misconfiguration", "certificate validation"],
        "Transport_Layer_Security",
    ),
    (352, ["CSRF", "csrf"], "Cross-Site_Request_Forgery_Prevention"),
    (434, ["UnrestrictedFileUpload", "file upload"], "File_Upload"),
    (
        441,
        ["SSRF", "ssrf", "server-side request forgery"],
        "Server_Side_Request_Forgery_Prevention",
    ),
    (601, ["OpenRedirect", "open redirect"], "Unvalidated_Redirects_and_Forwards"),
    (611, ["XXE", "xxe"], "XML_External_Entity_Prevention"),
    (639, ["IDOR", "idor", "insecure direct object reference"], "Authorization"),
    (798, ["hardcoded credentials", "embedded secrets"], "Secrets_Management"),
    (
        829,
        ["MissingSRI", "missing sri", "subresource integrity"],
        "Third_Party_Javascript_Management",
    ),
    (918, [], "Server_Side_Request_Forgery_Prevention"),
    (942, ["CORS", "cors", "cors misconfiguration"], "HTML5_Security"),
    (1021, ["HeaderInjection", "clickjacking", "HostHeaderInjection"], "Clickjacking_Defense"),
    (1321, ["PrototypePollution", "prototype pollution"], "Input_Validation"),
    (1336, ["PromptInjection", "prompt injection"], "LLM_Top_10"),
    (345, ["JWT", "jwt", "JWT misconfiguration"], "JSON_Web_Token_for_Java"),
    (
        16,
        ["ExposedService", "ExposedAdminPanel", "CloudMisconfiguration", "cloud misconfiguration"],
        "Authorization",
    ),
    (943, ["NoSQLi", "nosqli", "nosql injection"], "Injection_Prevention_in_Java"),
]


@cache
def _db() -> Database:
    """The bundled MITRE CWE database, parsed once and reused."""
    return Database()


def _enrich(cwe_id: int, aliases: list[str], owasp_topic: str | None) -> CWEEntry:
    """Build a ``CWEEntry`` for ``cwe_id``, sourcing name + description from the
    bundled MITRE corpus. Raises ``InvalidCWEError`` if the id is not a real CWE.
    """
    weakness = _db().get(cwe_id)
    return CWEEntry(
        cwe_id=cwe_id,
        name=weakness.name,
        description=weakness.description,
        aliases=aliases,
        owasp_topic=owasp_topic,
    )


# Catalogue: the routing rows enriched with MITRE name / description.
CWE_CATALOGUE: list[CWEEntry] = [
    _enrich(cwe_id, aliases, owasp_topic) for cwe_id, aliases, owasp_topic in _ROUTING
]

_BY_ID: dict[int, CWEEntry] = {entry.cwe_id: entry for entry in CWE_CATALOGUE}


def get_by_id(cwe_id: int) -> CWEEntry | None:
    """Return the entry for ``cwe_id`` or None if it is not a real CWE.

    Routed ids carry their curated aliases + OWASP cheat-sheet pointer; any
    other *valid* CWE id resolves from the bundled corpus (name + description,
    no curated OWASP pointer) - the local routing table is a convenience, not
    the universe of citable CWEs. An id outside the corpus returns None.
    """
    if cwe_id in _BY_ID:
        return _BY_ID[cwe_id]
    try:
        return _enrich(cwe_id, [], None)
    except InvalidCWEError:
        return None


def lookup(query: str, limit: int = 5) -> list[CWEEntry]:
    """Return catalogue entries whose CWE name, vuln_class, or aliases match
    ``query`` case-insensitively. Most-specific matches first (exact alias,
    then prefix, then substring). Returns up to ``limit`` entries.

    Keyword search runs against the local routing table only - MITRE publishes
    no keyword-search API, so the full corpus is reachable by id (``get_by_id``)
    but not by keyword."""
    if not query:
        return []
    needle = query.strip().lower()

    exact: list[CWEEntry] = []
    prefix: list[CWEEntry] = []
    substring: list[CWEEntry] = []

    for entry in CWE_CATALOGUE:
        haystack = [entry.name.lower(), *(a.lower() for a in entry.aliases)]
        if any(h == needle for h in haystack):
            exact.append(entry)
        elif any(h.startswith(needle) for h in haystack):
            prefix.append(entry)
        elif any(needle in h for h in haystack):
            substring.append(entry)

    return (exact + prefix + substring)[:limit]
