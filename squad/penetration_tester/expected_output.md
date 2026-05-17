The bare filename `findings.json` returned by save_findings_tool.

The file contains a JSON array of RawFinding objects, each with title,
vuln_class (including OWASP Top 10 category where applicable), target,
evidence snippet, tool name, and severity hint. Call save_findings_tool
with the collected findings JSON before returning - the tool gives you
the filename to return.
