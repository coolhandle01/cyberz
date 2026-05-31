"""tests/models/asset/test_relation.py - unit tests for models/asset/relation.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    BasicDNSRelation,
    PortRelation,
    PrefDNSRelation,
    RelationType,
    RRHeader,
    SimpleRelation,
    SRVDNSRelation,
)

pytestmark = pytest.mark.unit


class TestRelationType:
    def test_oam_constant_values(self):
        assert RelationType.SIMPLE == "SimpleRelation"
        assert RelationType.PORT == "PortRelation"
        assert RelationType.BASIC_DNS == "BasicDNSRelation"


class TestSimpleRelation:
    def test_labelled_edge(self):
        rel = SimpleRelation(label="product_used")
        assert rel.label == "product_used"

    def test_rejects_empty_label(self):
        with pytest.raises(ValidationError):
            SimpleRelation(label="")


class TestPortRelation:
    def test_carries_port_and_protocol(self):
        rel = PortRelation(label="port", port_number=443, protocol="tcp")
        assert rel.port_number == 443
        assert rel.protocol == "tcp"

    def test_rejects_out_of_range_port(self):
        with pytest.raises(ValidationError):
            PortRelation(label="port", port_number=70000)


class TestDNSRelations:
    def test_basic_dns_carries_header(self):
        rel = BasicDNSRelation(label="a_record", header=RRHeader(rr_type=1, ttl=300))
        assert rel.header.rr_type == 1
        assert rel.header.ttl == 300

    def test_pref_dns_carries_preference(self):
        rel = PrefDNSRelation(label="mx_record", header=RRHeader(rr_type=15), preference=10)
        assert rel.preference == 10

    def test_srv_dns_carries_priority_weight_port(self):
        rel = SRVDNSRelation(
            label="srv_record", header=RRHeader(rr_type=33), priority=1, weight=5, port=5060
        )
        assert (rel.priority, rel.weight, rel.port) == (1, 5, 5060)

    def test_roundtrip_preserves_header(self):
        rel = BasicDNSRelation(label="ptr_record", header=RRHeader(rr_type=12, rr_class=1, ttl=60))
        restored = BasicDNSRelation.model_validate_json(rel.model_dump_json())
        assert restored.header.rr_class == 1
