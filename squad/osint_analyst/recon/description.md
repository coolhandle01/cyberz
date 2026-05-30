Map the in-scope attack surface for the programme selected in the previous
task. The Vulnerability Researcher reads your output to plan an attack; the
Penetration Tester allocates probe budget against your priorities. A flat
list of subdomains is not useful - the curation is the deliverable.

Your workflow:

  1. Call Run Initial Sweep with the programme handle. The sweep runs
     subfinder, httpx, nmap, ffuf, plus passive TLS and DNS email-security
     checks and writes the inventory to ``attack_graph.json``. Returns the bare
     filename so you can pass it to the query tools.

  2. Inspect the sweep using Recon Subdomains, Recon Endpoints (filtered
     by status, tech, host), and Recon Open Ports. Do not load the whole
     file - the typed queries return focused slices.

  3. Optionally widen the surface:
     - Certificate Transparency Lookup on each seed domain (subdomains that
       hold a valid cert but did not respond to subfinder).
     - Historical URL Discovery on each seed (paths that may no longer be
       linked).
     - Probe FQDNs on net-new hostnames from those discoveries -
       returns live status + tech.
     - Detect Takeover Candidates on the full sweep's subdomains (CNAMEs
       pointing at S3 / Heroku / GitHub Pages / Azure / Vercel / Netlify /
       Fastly, or dangling CNAMEs). Hits warrant a HIGH-priority annotation
       and a note pointing the Penetration Tester at the service-specific
       confirmation fingerprint.
     - LLM Endpoint Detection on the sweep's endpoints - any hit is a
       high-priority annotation candidate for prompt-injection testing.

  4. Optionally pivot on the threads worth following. These are
     follow-ups on what the sweep surfaced, not a second sweep - reach
     for one when there is a concrete reason, and lean on the recon-flow
     skill for when each earns its keep.
     - Lookup IP Assets on IPs the sweep surfaced - composes the AS
       owner, the registrant / abuse contact, and any hostnames that
       reverse-resolve to the same IP. A cohabiting hostname that shares
       the programme apex is a net-new in-scope candidate; scope-check it
       and Probe FQDNs before annotating.
     - Lookup RDAP for ASN when the question is the network itself -
       who owns the AS, who to reach for disclosure - rather than one
       address in it.
     - Deep Scan Host when a host's open-port map shows a non-HTTP
       service (database / SSH / RDP / SMTP / admin port) worth a
       focused service-and-version scan. The banners it returns feed a
       precise HIGH-priority annotation. Skip it where the programme
       forbids scanning or the posture calls for staying quiet.

  5. Annotate the interesting hosts. For each, call Annotate Host with:

     - **role**: ``admin``, ``api``, ``auth``, ``app``, ``cdn``, ``static``,
       ``mail``, ``infra``, ``dev``, or ``unknown``. Pick the closest fit.
     - **priority**: ``high`` (PT spends budget here), ``medium`` (worth a
       probe pass), ``low`` (likely boring), or ``skip`` (do not probe -
       third-party-managed, decoy, sensitive).
     - **notes**: >= 30 chars (>= 60 for high-priority). What the host is,
       what tech runs on it, what makes it interesting - one to three
       sentences. Specific beats vague: "Spring Boot 2.6.3 API gateway
       with /actuator visible; CVE-2022-22965 applies" is good. "API
       host" is not.
     - **detected_tech**: ideally with versions. The gate warns when you
       drop tech the sweep detected.

     Use Lookup CWE / Lookup OWASP Guidance to ground a note in known
     weakness classes for the tech you saw - "WordPress 5.8 -> CWE-79
     stored XSS via plugin admin paths" is the kind of pointer the
     downstream VR consumes directly.

  6. Use Uncovered Hosts to list interesting-status hostnames in the sweep
     that you have not annotated yet. Leaving hosts uncovered is allowed
     but should be deliberate - go back and annotate anything you missed.

  7. Call Finalise Recon with the programme handle. The tool refuses if
     any insight has unresolved errors or if no host has been marked HIGH
     priority on a non-empty surface (the PT needs at least one focus
     target). On success it consolidates the sweep + every insight into
     ``recon.json`` and returns the bare filename.

Scope is non-negotiable. Annotated hosts are scope-checked again at the
gate; out-of-scope hosts must not be annotated. The sweep is already scope-
filtered, but Certificate Transparency / Historical URL Discovery / Probe
FQDNs - and the cohabiting hostnames Lookup IP Assets surfaces - may turn up
candidates that fall outside the programme's structured scope; drop those
before annotating. Deep Scan Host refuses an out-of-scope host outright, so a
deep scan only ever runs against a target already inside scope.

The briefing you return below is the headline; ``recon.json`` is the
reference the downstream agents read directly via their own query tools.
