"""
models/technology.py - typed shape for a detected technology on an asset.

The cybersquad recon vocabulary for "what software is running here". One
canonical shape replaces the earlier per-bucket enums (web framework /
cloud / service) that were never going to factor cleanly past a handful
of members.

Modelled on **Wappalyzer**'s taxonomy: an open-source catalogue of
fingerprints for ~3,000 web technologies, grouped into ~78 categories.
Wappalyzer is the de-facto standard the recon ecosystem aligns with -
httpx's ``-tech-detect`` flag uses ProjectDiscovery's
``wappalyzergo`` (https://github.com/projectdiscovery/wappalyzergo)
which ships a derivative of the catalogue, and nuclei's tech-detect
templates do the same. The strings ``Endpoint.technologies`` already
carries are Wappalyzer-shape; this module gives them a typed home.

For CVE matching, ``Technology`` carries an optional ``cpe`` field
(CPE 2.3 URI). CPE is NIST/MITRE's standard for identifying software in
the NVD CVE database - the right format at the CVE-lookup boundary, but
not what the agent reasons about day-to-day. The agent reads
``name`` / ``categories`` / ``version``; the VR's CVE lookup builds a
CPE string to query NVD against. Two layers, one type.

References:
- Wappalyzer catalogue: https://www.wappalyzer.com/technologies/
- Wappalyzer technology / category schema:
  https://github.com/wappalyzer/wappalyzer/blob/master/src/drivers/npm/technologies.json
- CPE 2.3 spec (NIST IR 7695): https://csrc.nist.gov/pubs/ir/7695/final
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class TechnologyCategory(StrEnum):
    """Wappalyzer-aligned categorisation of detected software.

    Append-only. Member values are the kebab-case slug shapes Wappalyzer
    uses in its public catalogue (https://www.wappalyzer.com/categories/),
    lower-cased and hyphen-separated.

    The catalogue is deliberately narrower than Wappalyzer's full 78
    categories - we only add a member when at least one recon binary
    (nmap, httpx, nuclei) or one probe targets it. Append as gaps surface.
    """

    # Web-stack frameworks (server-side)
    web_framework = "web-framework"
    web_server = "web-server"

    # Web-stack frameworks (client-side)
    js_framework = "js-framework"
    js_library = "js-library"
    css_framework = "css-framework"

    # Content management
    cms = "cms"

    # Data layer
    database = "database"
    message_queue = "message-queue"

    # Cloud / hosting
    paas = "paas"  # platform-as-a-service: AWS, GCP, Heroku, Vercel
    iaas = "iaas"  # infrastructure: bare cloud VMs, K8s control planes
    cdn = "cdn"

    # System / network services nmap surfaces
    operating_system = "operating-system"
    programming_language = "programming-language"
    ssh_server = "ssh-server"
    mail_server = "mail-server"
    ftp_server = "ftp-server"

    # Operations / observability
    monitoring = "monitoring"
    service_discovery = "service-discovery"
    hosting_panel = "hosting-panel"


class Technology(BaseModel):
    """One detected technology on an asset.

    Mirrors the per-app row in Wappalyzer's catalogue: a canonical
    name, the categories it belongs to, optionally a version string
    when banners / fingerprints carry one, and optionally a CPE 2.3
    URI for CVE matching at the VR boundary.

    ``name`` is the canonical lowercase identifier ("django", "redis",
    "wordpress", "nginx") - the recon-side coercer normalises raw
    strings (nmap banners, httpx tech-detect output) before constructing
    a Technology, so the name is always catalogue-shape by the time it
    reaches a consumer. Bare ``str`` (not a primitive) because the
    canonical-name catalogue is 3,000+ entries and grows - a fixed-shape
    validator does not fit. ``max_length`` caps blast radius if a
    coercer ever lets a malformed name through.

    Multiple categories are valid: WordPress is both ``cms`` and (via
    plugins) ``web_framework``-adjacent; Next.js is both ``js_framework``
    and a hosting platform. List, not enum, so the catalogue is not
    forced to pick.
    """

    # Tool-captured from external recon (nmap banner / httpx tech-detect).
    # Defence: coerce-time strip (recon-side ``coerce_technologies``
    # normalises and rejects anomalous strings) + boundary length cap
    # below.
    name: str = Field(max_length=64)

    categories: list[TechnologyCategory]

    # Tool-captured: nmap banner "2.4.41 ((Ubuntu))", httpx-tech-detect
    # "Django:4.2". Defence: coerce-time normalise + length cap. Kept
    # narrow so an injection has no room to manoeuvre if the coercer is
    # ever bypassed.
    version: str | None = Field(default=None, max_length=64)

    # CPE 2.3 URI for CVE matching, e.g.
    # "cpe:2.3:a:djangoproject:django:4.2:*:*:*:*:*:*:*". Populated when
    # the coercer can confidently build one; left None when only the
    # name / category are known (the VR's CVE lookup can still fuzzy-
    # match by name + version when CPE is absent).
    #
    # FIXME(amass-integration): promote to a typed ``Cpe`` primitive in
    # ``models/primitives.py`` once the CVE-lookup workflow lands - same
    # rationale as the deferred ``CvssVector`` / ``CweId`` primitives in
    # ``models/report.py``. Until then, the ``max_length`` + ``pattern``
    # below shape the value at the boundary.
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


__all__ = ["Technology", "TechnologyCategory"]
