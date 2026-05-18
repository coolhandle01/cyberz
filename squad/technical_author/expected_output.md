The bare filename `reports.json` written to the run directory.

The file contains a JSON array of DisclosureReport dicts - one per
verified finding - each with programme handle, title, vulnerability
detail, summary, full Markdown body, CWE identifier, and impact
statement. The Disclosure Coordinator reads this file and submits each
report independently after a duplicate check.
