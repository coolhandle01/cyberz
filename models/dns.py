"""
models/dns.py - typed shapes for DNS-derived recon signals.

The DNS-layer probes (currently dnsx-based takeover detection) return
typed records consumers read against; the data live in ``tools/recon/
dnsx.py``, the contract lives here.
"""

from __future__ import annotations

from pydantic import BaseModel

from models.primitives import Hostname


class TakeoverCandidate(BaseModel):
    """A subdomain flagged as a potential takeover target.

    ``reason`` is one of:
      - ``cname_to_vulnerable_provider``: CNAME points to a service in the
        ``_TAKEOVER_FINGERPRINTS`` catalogue. Probe the host with HTTP and
        look for the service-specific "not found" body.
      - ``dangling_cname``: CNAME exists but the chain does not resolve to
        any A records. The CNAME target may have been deprovisioned.
    """

    hostname: Hostname
    cname: str
    reason: str
    service: str | None = None


__all__ = ["TakeoverCandidate"]
