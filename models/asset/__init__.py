"""
models.asset - the recon-output / OAM inventory shapes (OSINT Analyst -> PT).

The OAM asset shapes the OSINT Analyst's sweep emits and the PT consumes:
endpoints discovered, the ``Service`` / ``Product`` / ``ProductRelease`` /
``TLSCertificate`` / ``IpAsset`` assets and the registrant shapes in
``network``, plus the ``VulnProperty`` annotations hung off them and the
LLM-backed endpoint marker.

Two things deliberately live *outside* this package because they are not OAM
asset types: the OA's *curation* shapes (``HostInsight`` / ``HostScore`` /
``HostRole`` / ``HostPriority`` / ``OpenPortsMap``) in ``models.insight``,
and the bundle that wraps the lot - ``AttackGraph`` - in ``models.attack``
with its ``AttackTree`` / ``AttackForest`` siblings.

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
| ``models.asset.service`` | ``Service``, ``Product``, ``ProductRelease`` |
| ``models.asset.certificate`` | ``TLSCertificate`` |
| ``models.asset.ip`` | ``IpAsset`` |
| ``models.asset.network`` | ``AsnRecord``, ``Contact``, ``ContactRole``, |
|                          | ``RdapRecord``, ``DomainRecord`` |

The intra-package import order is a DAG: ``vuln`` / ``certificate`` /
``network`` are leaves; ``endpoint`` / ``service`` / ``ip`` build on them.
No cycles, so no ``model_rebuild`` is needed.
"""

from __future__ import annotations

from models.asset.certificate import TLSCertificate
from models.asset.endpoint import Endpoint, EndpointPage, LlmEndpoint
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
    "IpAsset",
    "LlmEndpoint",
    "Product",
    "ProductRelease",
    "RdapRecord",
    "Service",
    "TLSCertificate",
    "VulnProperty",
]
