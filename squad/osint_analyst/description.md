Using the programme selected in the previous task, run full OSINT
reconnaissance against all in-scope assets:
  - Enumerate subdomains using subfinder
  - Probe live HTTP/S endpoints with httpx
  - Perform lightweight port scanning on live hosts
  - Identify technology stacks

Strictly enforce scope - do not interact with any asset not listed
as in-scope.

When recon is complete, write a concise briefing for the Vulnerability
Researcher who runs next. The briefing is the headline; recon.json is
the reference. Cover:

  - Top detected technologies and the hostnames they appear on
    (especially WordPress / Spring / Apache / Joomla / Drupal versions
    if known - any version is a starting point for CVE research)
  - Subdomains worth a closer look (admin.*, api.*, internal.*, dev.*,
    staging.*, *.s3.amazonaws.com, *.blob.core.windows.net)
  - Open ports that hint at running services (6379 Redis, 9200 Elastic-
    search, 5984 CouchDB, 27017 MongoDB, 3306/5432 DB, 2082/2083 cPanel,
    10000 Webmin, etc.)
  - Passive findings already collected (TLS issues, DNS misconfigs) -
    flag the high-signal ones, do not enumerate them all
  - Anything else that looks unusual or high-value
