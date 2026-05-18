Read the Vulnerability Researcher's triage briefing from your task context
to understand what was accepted and why. The verified findings live in
verified.json in the run directory.

For each verified vulnerability, produce a complete HackerOne-format
disclosure report. Quality is the bar: a triager must be able to reproduce
the issue from your report alone, without asking a single clarifying question.

**Title** - Use the formula:
  `[Vulnerability Type] in [Component/Endpoint] allows [Outcome]`
  Specific beats vague. "Stored XSS via `bio` parameter allows session
  hijacking of any authenticated user" is good. "XSS" is not.

**Summary** - 2-3 sentences. Root cause, location, concrete impact.

**Vulnerability details** - vuln_class, target, CVSS 3.1 vector and score
  (use Calculate CVSS Score on the vector from verified.json - never guess
  the number), and the most precise CWE identifier.

**Technical description** - Explain the root cause to a developer. Why is
  the code vulnerable, not just what happens. Write for someone who will
  fix it.

**Steps to reproduce** - Numbered steps from a clean state:
  - Include exact HTTP requests (raw HTTP or curl commands with full headers)
  - Unredacted payloads - this is a private disclosure, not a public post
  - State what to observe as proof (HTTP status, response body, cookie
    change, out-of-band callback, DNS lookup, etc.)
  - Specify prerequisites: account type, tool version, browser if relevant

**Evidence** - Reproduce the evidence captured by the Penetration Tester
  (the `evidence` field of each VerifiedVulnerability). Include HTTP
  request/response excerpts, tool output (sqlmap, nuclei, curl), and any
  other artefacts exactly as captured.

**Impact** - Concrete and specific. Name what data or system is at risk,
  who is affected (unauthenticated / any authenticated user / admin only),
  and the worst realistic outcome for the programme's users or business.
  Avoid generic phrases. Write: "An unauthenticated attacker can read every
  user record, including hashed passwords and email addresses" not "an
  attacker could compromise user data".

**Remediation** - Actionable. Give the developer a concrete fix. Reference
  the specific OWASP guidance (https://owasp.org) or CWE entry
  (https://cwe.mitre.org) for the weakness. Include a code-level example
  where possible.

Cover ALL verified findings. Call create_reports_tool with the verified.json
path, the programme handle, and a 2-3 sentence executive summary of the
overall session. The tool writes one report per finding to reports.json.

After writing, use Read Run File to confirm all reports were written, then
produce a briefing for the Disclosure Coordinator (see expected output).
