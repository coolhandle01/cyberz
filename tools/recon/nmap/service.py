"""Translate scanner-internal ``NmapHostResult`` into OAM ``Service`` assets.

This is the OA tool boundary: ``NmapService`` is scanner plumbing (it
mirrors nmap's raw ``<port>`` / ``<service>`` XML, including the port
state), while ``Service`` is the OAM asset that crosses to the agent and
persists to the host directory. Only *open* services become ``Service``
nodes - OAM is a presence graph, so a filtered / closed port is absence,
not a node.
"""

from __future__ import annotations

from models.asset import Service
from models.scanner import NmapHostResult

# OAM ``SourceProperty`` value: the tool that observed these services.
_DETECTED_BY = "nmap"


def services_from_nmap(result: NmapHostResult) -> list[Service]:
    """Map an ``NmapHostResult`` to its open-service ``Service`` assets.

    Each open ``NmapService`` becomes one ``Service`` carrying the host,
    port / protocol, banner detail, the normalised CPE nmap matched, and
    the ``detected_by`` provenance. Closed / filtered ports are dropped:
    a Service exists in the OAM graph only where the scan observed an open
    service.
    """
    return [
        Service(
            host=result.host,
            port=svc.port,
            protocol=svc.protocol,
            name=svc.service,
            product=svc.product,
            version=svc.version,
            extra_info=svc.extra_info,
            cpe=svc.cpe,
            detected_by=_DETECTED_BY,
        )
        for svc in result.services
        if svc.state == "open"
    ]


__all__ = ["services_from_nmap"]
