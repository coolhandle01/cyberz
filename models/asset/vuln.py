"""
models.asset.vuln - the OAM ``VulnProperty`` hung off vulnerable assets.

OAM models a vulnerability not as a standalone asset but as a property on
the vulnerable asset (an ``Endpoint`` / ``Service`` / ``HostInsight`` /
``ProductRelease``). This is the leaf shape the other asset modules import to
carry their ``vulns`` lists.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class VulnProperty(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``VulnProperty``.

    OAM models a vulnerability not as a standalone asset but as a property
    hung off the vulnerable asset - an ``FQDN`` / ``Service`` / ``Endpoint``.
    This mirrors amass's ``VulnProperty`` field for field (OAM json tag in
    parentheses):

    * ``id`` (``id``) -> the vulnerability identifier, e.g. "CVE-2022-22965".
    * ``description`` (``desc``) -> the human-readable summary.
    * ``source`` (``source``) -> the feed / tool that produced the fact
      ("nvd"); OAM's provenance slot.
    * ``category`` (``category``) -> the weakness class (a CWE id / name).
    * ``enumeration`` (``enum``) -> the scheme ``id`` is drawn from: "CVE",
      "CWE", "GHSA".
    * ``reference`` (``ref``) -> a canonical URL for the entry.

    The OSINT Analyst and Vulnerability Researcher attach these onto the
    asset shapes (``Endpoint`` / ``Service`` / ``HostInsight``) when an
    NVD CVE lookup matches a recon-observed technology or service - the
    cybersquad-native stand-in for the amass hanging property until #45.
    """

    # The vulnerability identifier - "CVE-2022-22965", "CWE-89". The asset's
    # join key into NVD / MITRE, required (a vuln annotation with no id names
    # nothing). Bare str: id-shape validation is deferred to the amass-
    # integration work alongside the planned CweId / CvssVector primitives.
    id: str = Field(min_length=1, max_length=64)

    # Tool-captured from the NVD feed (an external source surfaced through NVD
    # CVE Lookup), not agent-authored. Defence (cybersquad-models skill,
    # tool-captured text): a boundary length cap so a poisoned upstream
    # description cannot smuggle a large injection downstream.
    description: str = Field(default="", max_length=2000)

    # Provenance: the feed / tool that produced this fact ("nvd"). A tool-
    # named closed vocabulary, not free external text, so no injection guard
    # needed; length-capped defensively.
    source: str = Field(default="", max_length=32)

    # The weakness class - a CWE id or name where the lookup carried one.
    category: str = Field(default="", max_length=128)

    # The identifier scheme ``id`` is drawn from: "CVE", "CWE", "GHSA". Kept a
    # str to stay faithful to OAM's open ``enum`` field.
    enumeration: str = Field(default="", max_length=32)

    # Canonical URL for the entry (the NVD / MITRE page). A capped str rather
    # than HttpUrl because OAM's ``ref`` is an open string that round-trips
    # empty and may carry a non-URL advisory reference.
    reference: str = Field(default="", max_length=255)
