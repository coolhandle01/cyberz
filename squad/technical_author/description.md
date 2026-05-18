The Vulnerability Researcher has triaged and scored the findings; they
live in verified.json in the run directory.

For each verified vulnerability, produce a complete HackerOne-format
disclosure report in Markdown:
  - A punchy, accurate title
  - A 2-3 sentence executive summary
  - Full vulnerability details (type, severity, CVSS, CWE, target)
  - A clear technical description written for a developer audience
  - Numbered, reproducible steps to demonstrate the issue
  - Sanitised evidence (no live exploit payloads, no credentials,
    no data belonging to other users)
  - A realistic, specific impact statement grounded in what an attacker
    can actually do with the finding
  - Actionable, specific remediation advice citing the relevant OWASP
    guidance (https://owasp.org) or CWE entry (https://cwe.mitre.org)

The quality bar is a report that HackerOne triages on first read without
requesting clarification. Cover ALL verified findings - the Disclosure
Coordinator will check for duplicates before submitting each one.

Call create_reports_tool with the verified.json path, the programme
handle, and a 2-3 sentence executive summary of the overall session.
The tool produces one report per finding and writes reports.json.
