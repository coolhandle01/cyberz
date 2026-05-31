"""
models.asset - the recon-output / OAM inventory shapes (OSINT Analyst -> PT).

What the OSINT Analyst's sweep / annotation / finalisation produces:
endpoints discovered, hostnames classified by role and priority, open
ports per host, LLM-backed endpoint flags, the OAM asset shapes
(``Service`` / ``Product`` / ``ProductRelease`` / ``TLSCertificate`` /
``IpAsset`` / the registrant shapes in ``network``), and the
``VulnProperty`` annotations hung off them. The bundle that wraps the lot
for downstream agents - ``AttackGraph`` - lives in ``models.attack`` with
its ``AttackTree`` / ``AttackForest`` siblings: it composes these shapes but
is not itself an OAM asset.

Promoted from a single ``models/asset.py`` to a package as the OAM asset
layer grew. One module per cohesive OAM-asset concern; this ``__init__`` is
the public re-export surface, so ``from models.asset import X`` (and the
``from models import X`` re-export in ``models/__init__``) keep working
across every consumer unchanged.

FQDN-typed fields compose the ``FQDN`` primitive so mis-shaped hostnames
reject upstream of any downstream consumer rather than silently flowing
through the scope filter.

| Module | Contents |
|---|---|
| ``models.asset.vuln`` | ``VulnProperty`` |
| ``models.asset.endpoint`` | ``Endpoint``, ``EndpointPage``, ``LlmEndpoint`` |
| ``models.asset.host`` | ``HostRole``, ``HostPriority``, ``HostInsight``, |
|                       | ``HostScore``, ``OpenPortsMap`` |
| ``models.asset.service`` | ``Service``, ``Product``, ``ProductRelease`` |
| ``models.asset.certificate`` | ``TLSCertificate`` |
| ``models.asset.ip`` | ``IpAsset`` |
| ``models.asset.network`` | ``AsnRecord``, ``Contact``, ``ContactRole``, |
|                          | ``RdapRecord``, ``DomainRecord`` |

The intra-package import order is a DAG: ``vuln`` / ``certificate`` /
``network`` are leaves; ``endpoint`` / ``host`` / ``service`` / ``ip`` build
on them. No cycles, so no ``model_rebuild`` is needed.
"""

from __future__ import annotations

from models.asset.certificate import TLSCertificate
from models.asset.endpoint import Endpoint, EndpointPage, LlmEndpoint
from models.asset.host import (
    HostInsight,
    HostPriority,
    HostRole,
    HostScore,
    OpenPortsMap,
)
from models.asset.ip import IpAsset
from models.asset.network import (
    AsnRecord,
    Contact,
    ContactRole,
    DomainRecord,
    RdapRecord,
)
from models.asset.service import Product, ProductRelease, Service
from models.asset.vuln import VulnProperty

__all__ = [
    "AsnRecord",
    "Contact",
    "ContactRole",
    "DomainRecord",
    "Endpoint",
    "EndpointPage",
    "HostInsight",
    "HostPriority",
    "HostRole",
    "HostScore",
    "IpAsset",
    "LlmEndpoint",
    "OpenPortsMap",
    "Product",
    "ProductRelease",
    "RdapRecord",
    "Service",
    "TLSCertificate",
    "VulnProperty",
]
