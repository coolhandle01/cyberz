You have access to the full ReconResult from the previous task, which includes:
- Live endpoints and their HTTP status codes
- Detected technologies (check the `technologies` field)
- Open ports (check the `open_ports` field)
- Endpoints with URL parameters (check `parameters` on each Endpoint)
- Passive findings already collected during recon: TLS issues, DNS misconfigs
  (check the `passive_findings` field - do not repeat these checks)

Use this context to select tools strategically. Do not run everything at
everything. Think like a human penetration tester.

Decision guidance:

- Technologies detected (WordPress, Drupal, Joomla, Apache, Spring, Django, etc.)
  -> Run the Nuclei Scan; nuclei has templates tuned to these stacks.

- Parameterised endpoints (endpoints with non-empty `parameters`)
  -> SQLMap Injection Scan, SSRF Probe, Reflected XSS Probe, Error Disclosure Check.
  -> If error disclosure already shows SQL errors in passive_findings, escalate SQLMap.

- Open ports 6379 (Redis), 9200 (Elasticsearch), 5984 (CouchDB), 27017 (MongoDB),
  3306/5432 (DB), 8080/8443 (admin)
  -> Cloud Misconfiguration Check covers these via check_exposed_services.

- Any HTML-serving endpoint
  -> JS Source Map Scan, Subresource Integrity Check, Host Header Attack Check.

- Any API or authenticated endpoint
  -> CORS Misconfiguration Check.

- Subdomains matching *.s3.amazonaws.com, *.blob.core.windows.net, or technologies
  mentioning AWS/Azure/GCP
  -> Cloud Misconfiguration Check.

- All endpoints, always
  -> Header Injection Check, Error Disclosure Check.

Serialise the ReconResult to JSON and pass it to each tool you decide to invoke.
Return all findings regardless of confidence - triage is the Vulnerability
Researcher's job. Capture the tool output as evidence.
