"""Live host probing via the httpx CLI binary (projectdiscovery/httpx).

Note: this wraps the *binary* `httpx`, not the Python httpx library. The
Python HTTP library used throughout the project is `requests`.
"""

from __future__ import annotations

import json
import logging

from config import config
from models import Endpoint
from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)


def probe_endpoints(hosts: list[str]) -> list[Endpoint]:
    """Use httpx CLI to probe a list of hostnames/URLs for live services."""
    httpx_bin = _require_binary("httpx")
    input_data = "\n".join(hosts)
    # ``-tech-detect`` runs httpx's bundled Wappalyzer-derived fingerprint
    # rules: a catalogue of CSS class names, JS globals, cookie names,
    # response headers, and HTML signatures that map to framework / library
    # / CMS names. See the upstream catalogue at https://www.wappalyzer.com/
    # and projectdiscovery/wappalyzergo for the Go port httpx links against.
    # The resulting strings populate Endpoint.technologies and are the
    # primary source of framework signal for the Penetration Tester.
    result = _run(
        [
            httpx_bin,
            "-silent",
            "-json",
            "-status-code",
            "-tech-detect",
            "-timeout",
            str(config.recon.http_timeout),
        ],
        timeout=300,
        input=input_data,
    )
    endpoints: list[Endpoint] = []
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
            endpoints.append(
                Endpoint(
                    url=entry.get("url", ""),
                    status_code=entry.get("status_code"),
                    technologies=entry.get("tech", []),
                )
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.debug("Skipping httpx line: %s (%s)", line[:80], exc)
    logger.info("httpx probed %d live endpoints from %d hosts", len(endpoints), len(hosts))
    return endpoints
