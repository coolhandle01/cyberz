"""
models/framework.py - typed shape for web application frameworks the
squad detects, cites, and targets.

The ``Framework`` StrEnum is the canonical vocabulary the recon pass
emits, the Vulnerability Researcher cites in an attack plan, and the
Penetration Tester probes consume. Member values are the kebab-case
identifiers httpx's ``-tech-detect`` and Wappalyzer surface, so a
``coerce_frameworks`` helper (``tools/framework.py``) can normalise
recon strings into enum members without bespoke per-framework casing.

Why ``models/`` rather than ``tools/pentest/framework.py`` (where the
``@framework(...)`` decorator lives, mirroring ``tools/pentest/owasp.py``):
the enum is consumed across layers - recon emits it, the attack plan
references it, multiple pentest probes target it. ``OWASPCategory``
lives next to ``@owasp`` because it never crosses the recon boundary;
``Framework`` does.

FIXME(#83): this module is the foreseen home for ``DiscoveredMCP``
(see ``models/asset.py:LlmEndpoint`` docstring). The MCP-discipline
conversation from #144 calls for a concrete shape carrying advertised
tool inventory, suspicious-docstring flags, and schema-laxness markers.
Deliberately not landed here - this PR is the framework-aware-PT
refactor; the LlmEndpoint -> DiscoveredMCP promotion is a sibling
follow-up that will append to this module.
"""

from __future__ import annotations

from enum import StrEnum


class Framework(StrEnum):
    """Web-application frameworks the squad detects and targets.

    Member values follow the kebab-case identifier shapes httpx
    ``-tech-detect`` and Wappalyzer emit, so the recon string
    ``"django"`` round-trips to ``Framework.django`` cleanly.

    Append-only catalogue. New frameworks land as new members; never
    rename an existing one - downstream attack plans, probe stamps,
    and persisted recon JSON cite the literal string value.
    """

    angular = "angular"
    django = "django"
    laravel = "laravel"
    nextjs = "nextjs"
    rails = "rails"
    spring = "spring"
    tornado = "tornado"


__all__ = ["Framework"]
