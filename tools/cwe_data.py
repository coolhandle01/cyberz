"""
tools/cwe_data.py - local CWE catalogue keyed to the vuln_class strings the
pentest tooling emits.

The mapping that used to live as a 13-entry dict inside report_tools.py was
correct as far as it went but the Technical Author needs more: the CWE
*name*, a one-sentence summary suitable for inlining in a report, the canonical
MITRE URL, and a pointer into the OWASP cheat-sheet catalogue.

Entries are looked up by case-insensitive substring match against the
vuln_class string, the CWE name, or any of the aliases. A query like "xss",
"reflected xss", "ReflectedXSS", or "cross-site scripting" all resolve to
CWE-79.

Adding a new entry: copy the most relevant CWE from
https://cwe.mitre.org/data/definitions/ and pick the matching OWASP cheat-sheet
slug from `tools/owasp_data.py`.
"""

from __future__ import annotations

# CWEEntry lives in models/cwe.py per the typed-shapes-live-in-models
# rule. Re-exported here so existing ``from tools.cwe_data import
# CWEEntry`` consumers keep working; the canonical import path is
# ``from models import CWEEntry``.
from models.cwe import CWEEntry

# Catalogue. One entry per vuln_class the pentest stage can emit, plus a few
# extras for severity-adjusted re-classifications (e.g. AuthZ from IDOR).
CWE_CATALOGUE: list[CWEEntry] = [
    CWEEntry(
        cwe_id=22,
        name="Path Traversal",
        description=(
            "Improper limitation of a pathname to a restricted directory lets an "
            "attacker access files outside the intended location."
        ),
        aliases=["PathTraversal", "path traversal", "directory traversal", "LFI", "lfi"],
        owasp_topic="File_Upload",
    ),
    CWEEntry(
        cwe_id=77,
        name="Command Injection",
        description=(
            "Improper neutralization of special elements used in an OS command lets "
            "an attacker execute arbitrary commands on the host."
        ),
        aliases=["CommandInjection", "command injection", "OS command injection", "RCE"],
        owasp_topic="OS_Command_Injection_Defense",
    ),
    CWEEntry(
        cwe_id=78,
        name="OS Command Injection",
        description=(
            "Same root cause as CWE-77 but specific to operating-system shell "
            "commands assembled from untrusted input."
        ),
        aliases=["RCE", "remote code execution"],
        owasp_topic="OS_Command_Injection_Defense",
    ),
    CWEEntry(
        cwe_id=79,
        name="Cross-site Scripting",
        description=(
            "Improper neutralization of input during web-page generation lets an "
            "attacker execute script in another user's browser."
        ),
        aliases=["XSS", "ReflectedXSS", "stored XSS", "HeaderXSS", "cross-site scripting"],
        owasp_topic="Cross_Site_Scripting_Prevention",
    ),
    CWEEntry(
        cwe_id=89,
        name="SQL Injection",
        description=(
            "Improper neutralization of special elements used in an SQL command "
            "lets an attacker alter the meaning of a query or extract data."
        ),
        aliases=["SQLi", "sql injection"],
        owasp_topic="SQL_Injection_Prevention",
    ),
    CWEEntry(
        cwe_id=90,
        name="LDAP Injection",
        description=(
            "Improper neutralization of special elements used in an LDAP query "
            "lets an attacker alter directory queries."
        ),
        aliases=["LDAPInjection", "ldap injection"],
        owasp_topic="LDAP_Injection_Prevention",
    ),
    CWEEntry(
        cwe_id=94,
        name="Code Injection",
        description=(
            "Improper control of generation of code lets an attacker execute "
            "interpreter directives within the application context."
        ),
        aliases=["SSTI", "server-side template injection", "code injection"],
        owasp_topic="Server_Side_Template_Injection_Prevention",
    ),
    CWEEntry(
        cwe_id=200,
        name="Information Exposure",
        description=(
            "Exposure of sensitive information to an unauthorized actor through "
            "error messages, debug output, or backup files."
        ),
        aliases=[
            "ErrorDisclosure",
            "error disclosure",
            "SourceMapLeak",
            "SensitiveFileExposed",
            "information disclosure",
        ],
        owasp_topic="Error_Handling",
    ),
    CWEEntry(
        cwe_id=201,
        name="Information Exposure Through Sent Data",
        description=(
            "The application sends sensitive information in transmitted data to "
            "parties that should not have access."
        ),
        aliases=["EmailSpoofing", "spf misconfiguration"],
        owasp_topic="Transport_Layer_Security",
    ),
    CWEEntry(
        cwe_id=235,
        name="Improper Handling of Extra Parameters",
        description=(
            "The application does not handle or incorrectly handles when the "
            "number of parameters supplied differs from expected."
        ),
        aliases=["HPP", "HTTP Parameter Pollution"],
        owasp_topic="Input_Validation",
    ),
    CWEEntry(
        cwe_id=285,
        name="Improper Authorization",
        description=(
            "The application does not verify that the actor is authorized to "
            "perform an action on the affected resource."
        ),
        aliases=["AuthZ", "authorization", "AccessControlBypass", "broken access control"],
        owasp_topic="Authorization",
    ),
    CWEEntry(
        cwe_id=287,
        name="Improper Authentication",
        description=("The application does not adequately verify the actor's claimed identity."),
        aliases=["AuthN", "authentication"],
        owasp_topic="Authentication",
    ),
    CWEEntry(
        cwe_id=295,
        name="Improper Certificate Validation",
        description=(
            "The application does not validate or incorrectly validates an X.509 certificate."
        ),
        aliases=["TLSMisconfiguration", "tls misconfiguration", "certificate validation"],
        owasp_topic="Transport_Layer_Security",
    ),
    CWEEntry(
        cwe_id=352,
        name="Cross-Site Request Forgery",
        description=(
            "The application does not verify that a request was intentionally "
            "submitted by the user who submitted it."
        ),
        aliases=["CSRF", "csrf"],
        owasp_topic="Cross-Site_Request_Forgery_Prevention",
    ),
    CWEEntry(
        cwe_id=434,
        name="Unrestricted File Upload",
        description=(
            "The application allows the attacker to upload or transfer files of "
            "dangerous types that can be processed by the server."
        ),
        aliases=["UnrestrictedFileUpload", "file upload"],
        owasp_topic="File_Upload",
    ),
    CWEEntry(
        cwe_id=441,
        name="Server-Side Request Forgery",
        description=(
            "The application receives a URL from an upstream component and uses it "
            "to make an arbitrary outbound request, exposing internal resources."
        ),
        aliases=["SSRF", "ssrf", "server-side request forgery"],
        owasp_topic="Server_Side_Request_Forgery_Prevention",
    ),
    CWEEntry(
        cwe_id=601,
        name="Open Redirect",
        description=(
            "The application accepts a user-controlled input that specifies a link "
            "to an external site and uses it in a redirect."
        ),
        aliases=["OpenRedirect", "open redirect"],
        owasp_topic="Unvalidated_Redirects_and_Forwards",
    ),
    CWEEntry(
        cwe_id=611,
        name="XML External Entity",
        description=(
            "The XML parser processes an XML document containing references to "
            "external entities, exposing internal files or causing DoS."
        ),
        aliases=["XXE", "xxe"],
        owasp_topic="XML_External_Entity_Prevention",
    ),
    CWEEntry(
        cwe_id=639,
        name="Insecure Direct Object Reference",
        description=(
            "The application authenticates the user but does not verify that they "
            "are authorised for the specific object the request acts on."
        ),
        aliases=["IDOR", "idor", "insecure direct object reference"],
        owasp_topic="Authorization",
    ),
    CWEEntry(
        cwe_id=798,
        name="Use of Hard-coded Credentials",
        description=(
            "The application contains hard-coded credentials such as passwords, "
            "API keys, or cryptographic keys for inbound authentication."
        ),
        aliases=["hardcoded credentials", "embedded secrets"],
        owasp_topic="Secrets_Management",
    ),
    CWEEntry(
        cwe_id=829,
        name="Inclusion of Functionality from Untrusted Source",
        description=(
            "The application includes functionality (script, library) from a "
            "source outside its trust boundary without integrity verification."
        ),
        aliases=["MissingSRI", "missing sri", "subresource integrity"],
        owasp_topic="Third_Party_Javascript_Management",
    ),
    CWEEntry(
        cwe_id=918,
        name="Server-Side Request Forgery (SSRF)",
        description=(
            "Same root cause as CWE-441 with the canonical SSRF identifier most "
            "report intake systems expect."
        ),
        aliases=[],
        owasp_topic="Server_Side_Request_Forgery_Prevention",
    ),
    CWEEntry(
        cwe_id=942,
        name="Permissive Cross-domain Policy with Untrusted Domains",
        description=(
            "The application uses an overly permissive CORS policy that allows "
            "credentialed access from arbitrary origins."
        ),
        aliases=["CORS", "cors", "cors misconfiguration"],
        owasp_topic="HTML5_Security",
    ),
    CWEEntry(
        cwe_id=1021,
        name="Improper Restriction of Rendered UI Layers",
        description=(
            "The application does not restrict rendering of its UI in frames, "
            "allowing clickjacking."
        ),
        aliases=["HeaderInjection", "clickjacking", "HostHeaderInjection"],
        owasp_topic="Clickjacking_Defense",
    ),
    CWEEntry(
        cwe_id=1321,
        name="Improperly Controlled Modification of Object Prototype Attributes",
        description=(
            "The application receives user input that modifies prototype attributes "
            "of a base object, polluting subsequent object instantiations."
        ),
        aliases=["PrototypePollution", "prototype pollution"],
        owasp_topic="Input_Validation",
    ),
    CWEEntry(
        cwe_id=1336,
        name="Improper Neutralization of Special Elements Used in a Template Engine",
        description=(
            "The application uses user input in a template engine without proper "
            "neutralization, leading to template injection or RCE."
        ),
        aliases=["PromptInjection", "prompt injection"],
        owasp_topic="LLM_Top_10",
    ),
    CWEEntry(
        cwe_id=345,
        name="Insufficient Verification of Data Authenticity",
        description=(
            "The application does not sufficiently verify the origin or authenticity "
            "of data, e.g. JWT signature validation gaps."
        ),
        aliases=["JWT", "jwt", "JWT misconfiguration"],
        owasp_topic="JSON_Web_Token_for_Java",
    ),
    CWEEntry(
        cwe_id=16,
        name="Configuration",
        description=(
            "Weaknesses introduced during the configuration of the software, "
            "covering exposed services, admin panels, and cloud misconfigurations."
        ),
        aliases=[
            "ExposedService",
            "ExposedAdminPanel",
            "CloudMisconfiguration",
            "cloud misconfiguration",
        ],
        owasp_topic="Authorization",
    ),
    CWEEntry(
        cwe_id=943,
        name="Improper Neutralization of Special Elements in Data Query Logic",
        description=(
            "The application uses input in a data-query language (NoSQL, GraphQL) "
            "without sufficient neutralization."
        ),
        aliases=["NoSQLi", "nosqli", "nosql injection"],
        owasp_topic="Injection_Prevention_in_Java",
    ),
]


_BY_ID: dict[int, CWEEntry] = {entry.cwe_id: entry for entry in CWE_CATALOGUE}


def get_by_id(cwe_id: int) -> CWEEntry | None:
    """Return the catalogue entry for ``cwe_id`` or None if unknown."""
    return _BY_ID.get(cwe_id)


def lookup(query: str, limit: int = 5) -> list[CWEEntry]:
    """Return catalogue entries whose CWE name, vuln_class, or aliases match
    ``query`` case-insensitively. Most-specific matches first (exact alias,
    then prefix, then substring). Returns up to ``limit`` entries."""
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
