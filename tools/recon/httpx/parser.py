"""Httpx NDJSON output parser.

``_parse_ndjson(stdout, mode)`` is the only public function. Each
NDJSON line becomes one ``Endpoint``. Mode controls which fields the
parser pulls off the JSON object:

* ``LIVE``: ``url`` + ``status_code`` only.
* ``TECH_DETECT``: + ``tech`` -> ``technologies`` /
  ``detected_technologies``.
* ``WEB_INVENTORY``: + ``favicon`` + ``tls.subject_alt_names`` ->
  ``favicon_hash`` / ``tls_sans``.

Defensive throughout. A malformed JSON line is logged at DEBUG and
skipped (one bad row does not blast the batch). A ``ValueError`` from
the FQDN validator on a SAN degrades the row's optional fields - we
retry the ``Endpoint(...)`` construction without them so the LIVE /
tech signal is still captured.
"""

from __future__ import annotations

import json
import logging

from models.asset import Endpoint
from models.scanner import HttpxMode
from tools.recon.technology import coerce_technologies

logger = logging.getLogger(__name__)


def _parse_ndjson(stdout: str, mode: HttpxMode) -> list[Endpoint]:
    """Parse httpx's NDJSON output into a list of typed ``Endpoint`` rows."""
    endpoints: list[Endpoint] = []
    for line in stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.debug("Skipping httpx line: %s (%s)", line[:80], exc)
            continue
        if not isinstance(entry, dict):
            continue

        raw_tech = entry.get("tech", []) if mode != HttpxMode.LIVE else []
        # httpx v1.6+ emits the favicon MMH3 hash under ``favicon``;
        # older versions used ``favicon_path``. Accept either.
        favicon = entry.get("favicon") or entry.get("favicon_path")
        # TLS SANs live under ``tls.subject_alt_names`` when ``-tls-grab``
        # ran. Strings only - drop non-string entries up front.
        tls_block = entry.get("tls") or {}
        sans_raw = tls_block.get("subject_alt_names", []) if isinstance(tls_block, dict) else []
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
            # fields - LIVE / tech signal is still useful.
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
    return endpoints


__all__ = ["_parse_ndjson"]
