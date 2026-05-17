The absolute path to findings.json written to the run directory,
e.g. `/home/user/.cybersquad/programs/cloudflare/20260516-143022-a1b2c3/findings.json`.

The file contains a JSON array of RawFinding objects, each with title,
vuln_class (including OWASP Top 10 category where applicable), target,
evidence snippet, tool name, and severity hint. Call save_findings_tool
with the collected findings JSON before returning - the tool gives you
the path to return.
