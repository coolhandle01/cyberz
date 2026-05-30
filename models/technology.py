"""
models/technology.py - one detected technology on an asset.

A ``Technology`` is a single piece of software fingerprinted on a host or
endpoint: a canonical name, an optional version, and an optional CPE 2.3
identifier for CVE matching.

cybersquad classifies nothing and maintains no catalogue. The ``name`` is
whatever the *detecting tool's own vocabulary* returned - a wappalyzer slug
from httpx ``-tech-detect`` (via ProjectDiscovery's ``wappalyzergo``), or a
service / product banner from nmap ``-sV``. The externally-owned string IS
the identifier; a parallel taxonomy would be a maintenance burden that
drifts from the tools and re-derives data wappalyzer / NIST already own.

For CVE matching, ``Technology`` carries an optional ``cpe`` field (CPE 2.3
URI - NIST's product identifier, the key into the NVD CVE database). nmap
emits a CPE per matched service; httpx emits only a name (a name -> CPE
resolution is best-effort, deferred). ``None`` when no tool handed us one.

Persisted shape: when amass lands (#45) each ``Technology`` becomes a group
of properties on the FQDN / IPAddress / Service asset it was observed on,
stamped with the detecting tool as provenance. This module is the in-memory
carrier; the amass Property is the persisted form.

References:
- Wappalyzer catalogue (name vocabulary): https://www.wappalyzer.com/technologies/
- CPE 2.3 spec (NIST IR 7695): https://csrc.nist.gov/pubs/ir/7695/final
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Technology(BaseModel):
    """One detected technology on an asset: name + optional version + CPE.

    ``name`` is the detecting tool's own canonical string, lowercased
    ("django", "redis", "nginx", "openssh") - the recon-side coercer
    (``tools.recon.technology.coerce_technologies``) normalises raw output
    before constructing a Technology. Bare ``str`` (not a primitive): the
    space of technology names is open and tool-owned, so a fixed-shape
    validator does not fit. ``max_length`` caps blast radius if a coercer
    ever lets a malformed name through.
    """

    # Tool-captured from external recon (nmap banner / httpx tech-detect).
    # Defence: coerce-time strip + boundary length cap below.
    name: str = Field(max_length=64)

    # Tool-captured version: nmap banner "2.4.41", httpx "Django:4.2".
    # Defence: coerce-time normalise + length cap. Kept narrow so an
    # injection has no room to manoeuvre if the coercer is ever bypassed.
    version: str | None = Field(default=None, max_length=64)

    # CPE 2.3 URI for CVE matching, e.g.
    # "cpe:2.3:a:djangoproject:django:4.2:*:*:*:*:*:*:*". Populated when a
    # tool hands us one (nmap -sV emits CPEs; httpx does not) or a name ->
    # CPE resolution succeeds; ``None`` otherwise (the VR's CVE lookup can
    # still fuzzy-match by name + version).
    #
    # FIXME(#45 / amass-integration): when amass lands, a Technology persists
    # as amass Property values on the FQDN / IPAddress / Service asset it
    # describes - SimpleProperty{Name: "technology", Value: "<name>:<version>"}
    # plus a sibling VulnProperty for CVE-bearing entries. Also promote ``cpe``
    # to a typed ``Cpe`` primitive in ``models.primitives`` at that point - CPE
    # sits on two fields (here + ``NmapService.cpe``), the multi-field
    # threshold the cybersquad-models skill sets for a primitive; deferred
    # alongside the existing ``CvssVector`` / ``CweId`` primitive plans.
    cpe: str | None = Field(
        default=None,
        max_length=255,
        # CPE 2.3 URI binding: "cpe:2.3:" + 11 colon-separated components.
        # Permits "*" / "-" wildcards. Reject anything that does not at
        # minimum start with the canonical prefix - keeps malformed CPE
        # values out of the typed channel without re-implementing the
        # full NIST IR 7695 grammar here.
        pattern=r"^cpe:2\.3:[aho\-\*]:.+$",
    )


__all__ = ["Technology"]
