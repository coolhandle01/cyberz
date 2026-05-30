"""
tools/recon/technology.py - normalise raw recon strings into typed
``Technology`` values.

httpx's ``-tech-detect`` flag emits strings like ``"Django:4.2"``,
``"Apache:2.4.41"``, ``"WordPress"``. nmap's ``-sV`` emits service /
product banners; nuclei's tech-detect templates emit similar. All speak
a Wappalyzer-shape ``name[:version]`` vocabulary; this helper is the
single coercion point that maps those strings to the typed ``Technology``
model in ``models/technology.py``.

We classify nothing and drop nothing. Every observed string becomes a
``Technology`` carrying the tool's own name (lowercased) and the version
if present - full situational awareness, the detecting tool's vocabulary
verbatim. There is no catalogue / allow-list: maintaining one re-derives
data wappalyzer already owns and silently discards anything we had not
catalogued yet.
"""

from __future__ import annotations

from models.technology import Technology

# Defence: cap blast radius if a raw recon string is wildly long. Anything
# longer than this is not plausibly a technology name - typically junk or an
# injection attempt riding in on a banner. Skip it before constructing a
# Technology.
_MAX_RAW_LEN = 128


def coerce_technologies(raw_strings: list[str]) -> list[Technology]:
    """Map raw recon strings (httpx tech-detect, nmap banner, nuclei) to typed Technology.

    Input: the strings recon binaries emit (httpx ``-tech-detect`` JSON
    ``tech`` field, nmap ``-sV`` banner text, nuclei tech-detect output).
    Each carries an optional ``:<version>`` suffix per the Wappalyzer
    convention (``"Django:4.2"``, ``"Apache:2.4.41"``, ``"WordPress"``).

    Output: one typed ``Technology`` per distinct ``(name, version)`` - the
    name lowercased, the version parsed off the first ``:``. Nothing is
    dropped for being "unrecognised": the tool's own string is the
    identifier, and full situational awareness is the point. Empty /
    whitespace / over-long entries are skipped (recon binaries occasionally
    emit blanks), and identical ``(name, version)`` pairs are de-duped.
    """
    out: list[Technology] = []
    seen: set[tuple[str, str | None]] = set()
    for raw in raw_strings:
        if not raw or not isinstance(raw, str):
            continue
        if len(raw) > _MAX_RAW_LEN:
            continue
        # Wappalyzer / httpx convention: "Name:Version" or just "Name".
        raw_name, _, raw_version = raw.partition(":")
        name = raw_name.strip().lower()
        version: str | None = raw_version.strip() or None
        if not name:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Technology(name=name, version=version))
    return out


__all__ = ["coerce_technologies"]
