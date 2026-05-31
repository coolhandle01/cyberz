"""tests/models/asset/test_oam_records.py - unit tests for the OAM org /
contact / people / identifier / network asset structs."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    AutonomousSystem,
    ContactRecord,
    Identifier,
    Location,
    Netblock,
    Organization,
    Person,
    Phone,
)

pytestmark = pytest.mark.unit


class TestAutonomousSystem:
    def test_number(self):
        assert AutonomousSystem(number=15169).number == 15169

    def test_rejects_out_of_range(self):
        with pytest.raises(ValidationError):
            AutonomousSystem(number=5_000_000_000)


class TestNetblock:
    def test_cidr_and_type(self):
        nb = Netblock(cidr="8.8.8.0/24", type="IPv4")
        assert nb.cidr == "8.8.8.0/24"
        assert nb.type == "IPv4"

    def test_rejects_empty_cidr(self):
        with pytest.raises(ValidationError):
            Netblock(cidr="")


class TestOrganization:
    def test_minimal(self):
        org = Organization(name="Google LLC")
        assert org.name == "Google LLC"
        assert org.target_markets == []
        assert org.active is False

    def test_rejects_empty_name(self):
        with pytest.raises(ValidationError):
            Organization(name="")


class TestContactRecord:
    def test_discovered_at(self):
        assert ContactRecord(discovered_at="2026-05-31").discovered_at == "2026-05-31"


class TestPerson:
    def test_full_name(self):
        p = Person(full_name="Jane Doe", first_name="Jane", family_name="Doe")
        assert p.full_name == "Jane Doe"

    def test_rejects_empty_full_name(self):
        with pytest.raises(ValidationError):
            Person(full_name="")


class TestPhone:
    def test_e164(self):
        ph = Phone(raw="+1 650 555 0100", e164="+16505550100", country_code=1)
        assert ph.e164 == "+16505550100"


class TestLocation:
    def test_address(self):
        loc = Location(address="1600 Amphitheatre Pkwy", city="Mountain View", country="US")
        assert loc.city == "Mountain View"


class TestIdentifier:
    def test_email_identifier(self):
        ident = Identifier(id="abuse@example.com", id_type="email")
        assert ident.id == "abuse@example.com"
        assert ident.id_type == "email"

    def test_rejects_empty_id(self):
        with pytest.raises(ValidationError):
            Identifier(id="")
