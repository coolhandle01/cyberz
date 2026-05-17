The absolute path to the recon results file written to the run directory,
e.g. `/home/user/.cybersquad/programs/cloudflare/20260516-143022-a1b2c3/recon.json`.

The file contains a serialised ReconResult with subdomains, live endpoints
(status codes and technologies), open ports per host, passive findings,
and notes. Return the path string only - downstream agents read the file.
