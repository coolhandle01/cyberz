"""Live host probing via the httpx CLI binary (projectdiscovery/httpx).

Wraps the ``httpx`` binary that ProjectDiscovery ships - **not** the
PyPI ``httpx`` HTTP library. The Python HTTP library used throughout
cybersquad is ``requests``. The two share a name; the OS-level binary
is what we shell out to here, the Python lib is what ``tools/http.py``
wraps.

Module is named ``httpx`` to match the binary; the file shadows the
PyPI lib only inside ``tools.recon.*`` if anyone ever does a relative
``from . import httpx``. Absolute ``import httpx`` (what the PyPI lib
expects) still resolves against ``sys.path`` per Python 3's absolute-
import rules, so no real masking risk. If we ever DO need the PyPI
lib in this package, prefer ``import httpx as _httpx_lib`` to make the
intent explicit and avoid any ambiguity.

Two callable surfaces:

* ``httpx_scan(hosts, mode)`` - the rich entry point. Composes flags
  from ``HttpxMode`` (LIVE / TECH_DETECT / WEB_INVENTORY); returns
  ``list[Endpoint]`` with mode-appropriate fields populated.
* ``probe_endpoints(hosts)`` - backwards-compatible thin shim that
  calls ``httpx_scan(hosts, mode=TECH_DETECT)`` to preserve the
  historical signature the recon orchestrator + existing tests use.

Deliberately does NOT expose flags that overlap dedicated recon tools:
``-asn`` defers to ``tools/recon/asn.py`` (Team Cymru); ``-cname``
defers to ``tools/recon/dnsx.py``. One way to get each data point.
"""

from __future__ import annotations

import json
import logging

from config import config
from models import Endpoint
from models.scanner import HttpxMode
from tools._helpers import _require_binary, _run
from tools.recon.technology import coerce_technologies

logger = logging.getLogger(__name__)

# Per-mode httpx flag bundles. Each layer adds to the previous so
# escalation is monotone: WEB_INVENTORY > TECH_DETECT > LIVE in signal
# depth, payload weight, and time-per-host.
_MODE_FLAGS: dict[HttpxMode, list[str]] = {
    HttpxMode.LIVE: [
        "-status-code",
    ],
    HttpxMode.TECH_DETECT: [
        "-status-code",
        "-tech-detect",
        "-server",
        "-title",
    ],
    HttpxMode.WEB_INVENTORY: [
        "-status-code",
        "-tech-detect",
        "-server",
        "-title",
        "-favicon",
        "-tls-grab",
        "-content-type",
        "-method",
    ],
}


def _assemble_flags(mode: HttpxMode) -> list[str]:
    """Compose the final httpx flag list for the given mode.

    Common flags (``-silent`` / ``-json`` / ``-timeout``) are always
    present; ``_MODE_FLAGS[mode]`` adds the per-mode signal flags.
    """
    return [
        "-silent",
        "-json",
        "-timeout",
        str(config.recon.http_timeout),
        *_MODE_FLAGS[mode],
    ]


def httpx_scan(
    hosts: list[str],
    mode: HttpxMode = HttpxMode.TECH_DETECT,
) -> list[Endpoint]:
    """Run httpx against ``hosts`` with the typed ``HttpxMode`` selector.

    Returns one ``Endpoint`` per live host. Mode-dependent fields:

    * **LIVE**: ``url``, ``status_code`` only.
    * **TECH_DETECT** (default): + ``technologies`` (raw httpx
      ``-tech-detect`` strings) + ``detected_technologies`` (typed
      ``Technology`` via ``coerce_technologies``).
    * **WEB_INVENTORY**: + ``favicon_hash`` (MMH3 from ``-favicon``,
      Shodan / Censys ``http.favicon.hash:`` pivot key) +
      ``tls_sans`` (Subject Alternative Names from ``-tls-grab``).

    Degrades gracefully: lines that fail JSON-parse are logged and
    skipped; individual ``Endpoint(...)`` construction failures (e.g.
    a malformed SAN) drop the row's optional fields rather than the row.
    """
    if not hosts:
        return []
    httpx_bin = _require_binary("httpx")
    flags = _assemble_flags(mode)
    input_data = "\n".join(hosts)
    try:
        result = _run(
            [httpx_bin, *flags],
            timeout=300,
            input=input_data,
        )
    except Exception as exc:
        logger.warning("httpx scan failed: %s", exc)
        return []

    endpoints: list[Endpoint] = []
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.debug("Skipping httpx line: %s (%s)", line[:80], exc)
            continue

        raw_tech = entry.get("tech", []) if mode != HttpxMode.LIVE else []
        # httpx emits the favicon MMH3 hash as ``favicon_path`` /
        # ``favicon`` depending on version; v1.6+ uses ``favicon`` key.
        # Treat either as the same signal.
        favicon = entry.get("favicon") or entry.get("favicon_path")
        # TLS SANs live under ``tls.subject_alt_names`` when
        # ``-tls-grab`` ran. Strings only - anything weird is dropped at
        # the per-entry level so a malformed SAN does not blast the row.
        sans_raw: list[object] = []
        tls_block = entry.get("tls") or {}
        if isinstance(tls_block, dict):
            sans_raw = tls_block.get("subject_alt_names") or []
        sans_filtered: list[str] = [san for san in sans_raw if isinstance(san, str)]

        try:
            ep = Endpoint(
                url=entry.get("url", ""),
                status_code=entry.get("status_code"),
                technologies=raw_tech,
                detected_technologies=coerce_technologies(raw_tech),
                favicon_hash=favicon if isinstance(favicon, str) else None,
                tls_sans=sans_filtered,
            )
        except ValueError as exc:
            # One field rejected (likely a SAN not RFC-1123-shaped or a
            # mis-formatted favicon hash). Retry without the optional
            # fields - the LIVE / tech signal is still useful.
            logger.debug("httpx row degraded (dropping optional fields): %s", exc)
            try:
                ep = Endpoint(
                    url=entry.get("url", ""),
                    status_code=entry.get("status_code"),
                    technologies=raw_tech,
                    detected_technologies=coerce_technologies(raw_tech),
                )
            except ValueError as exc2:
                logger.debug("httpx row skipped: %s", exc2)
                continue
        endpoints.append(ep)
    logger.info(
        "httpx %s: %d hosts -> %d live endpoints",
        mode.value,
        len(hosts),
        len(endpoints),
    )
    return endpoints


def probe_endpoints(hosts: list[str]) -> list[Endpoint]:
    """Backwards-compatible shim - ``httpx_scan(hosts, TECH_DETECT)``.

    The historical entry point the recon orchestrator and the legacy
    tests use. Matches the today-default behaviour: tech-detect on
    every probed endpoint. New callers should prefer ``httpx_scan``
    with an explicit ``HttpxMode`` for the broad-then-narrow pattern.
    """
    return httpx_scan(hosts, mode=HttpxMode.TECH_DETECT)


__all__ = ["httpx_scan", "probe_endpoints"]
