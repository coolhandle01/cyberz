"""
models.asset.relation - the OAM typed relations (edges) between asset nodes.

OAM is a graph: assets are nodes, relations are typed edges that carry a label
(``product_used`` / ``a_record`` / ``port`` / ...) and, for some kinds, extra
structured detail. This module mirrors amass's ``relation`` package. An edge's
endpoints are the two asset ``Key``s it joins, held by whatever composes the
graph - not on the relation itself, exactly as OAM keeps them.

OAM relations:
<https://owasp-amass.github.io/docs/open_asset_model/>
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RelationType(StrEnum):
    """The OAM relation kinds (amass ``RelationType`` constants)."""

    SIMPLE = "SimpleRelation"
    PORT = "PortRelation"
    BASIC_DNS = "BasicDNSRelation"
    PREF_DNS = "PrefDNSRelation"
    SRV_DNS = "SRVDNSRelation"


class RRHeader(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``RRHeader``.

    The DNS resource-record header carried on the DNS relations (OAM json tag
    in parentheses): ``rr_type`` (``rr_type``), ``rr_class`` (``class`` -
    renamed off the Python keyword), ``ttl`` (``ttl``).
    """

    rr_type: int = Field(ge=0)  # rr_type
    rr_class: int = Field(default=0, ge=0)  # class (renamed off the Python keyword)
    ttl: int = Field(default=0, ge=0)  # ttl


class SimpleRelation(BaseModel):
    """OAM ``SimpleRelation`` - a labelled edge with no extra detail.

    The workhorse edge: ``product_used``, ``certificate``, ``registration``,
    ``verified_for`` and the like. ``label`` is OAM's ``Name`` (json ``label``).
    """

    label: str = Field(min_length=1, max_length=64)  # label (OAM ``Name``)


class PortRelation(BaseModel):
    """OAM ``PortRelation`` - a host -> ``Service`` edge carrying the port."""

    label: str = Field(min_length=1, max_length=64)  # label (OAM ``Name``)
    port_number: int = Field(ge=1, le=65535)  # port_number
    protocol: str = Field(default="", max_length=8)  # protocol ("tcp" / "udp")


class BasicDNSRelation(BaseModel):
    """OAM ``BasicDNSRelation`` - a DNS RR edge (A / AAAA / CNAME / PTR / NS)."""

    label: str = Field(min_length=1, max_length=64)  # label (OAM ``Name``)
    header: RRHeader  # header


class PrefDNSRelation(BaseModel):
    """OAM ``PrefDNSRelation`` - a DNS RR edge with a preference (MX)."""

    label: str = Field(min_length=1, max_length=64)  # label (OAM ``Name``)
    header: RRHeader  # header
    preference: int = Field(ge=0)  # preference


class SRVDNSRelation(BaseModel):
    """OAM ``SRVDNSRelation`` - a DNS SRV RR edge (priority / weight / port)."""

    label: str = Field(min_length=1, max_length=64)  # label (OAM ``Name``)
    header: RRHeader  # header
    priority: int = Field(ge=0)  # priority
    weight: int = Field(ge=0)  # weight
    port: int = Field(ge=0, le=65535)  # port
