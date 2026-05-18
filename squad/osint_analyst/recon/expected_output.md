A short Markdown briefing (roughly 8-15 lines) for the Vulnerability
Researcher, followed by the relative filename of the recon artefact
written to the run directory (e.g. `recon.json`).

The briefing should call out:
  - Top detected technologies with the hostnames they appear on
  - Subdomains worth a closer look (admin/api/internal/staging/dev,
    cloud-storage hostnames)
  - Open ports that hint at running services
  - High-signal passive findings already collected
  - Anything else unusual or high-value

The full inventory lives in recon.json - the Vulnerability Researcher
uses the recon query tools (Recon Subdomains, Recon Endpoints, Recon
Open Ports) and Read Run File to drill into it on demand. The briefing
is what tells them where to look first.

Return the briefing followed on a separate line by the filename string
(no prefix, no surrounding path - just `recon.json`).
