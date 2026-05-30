"""tests/models/test_network.py - unit tests for models/network.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    Contact,
    ContactRole,
)

pytestmark = pytest.mark.unit


class TestContact:
    def test_role_only_minimum(self):
        # vCard fields are all optional - a Contact with just a role is
        # legal but useless. The parser's _build_contact drops these
        # before they reach RdapRecord; the model itself accepts.
        c = Contact(role=ContactRole.ABUSE)
        assert c.email is None
        assert c.name is None
        assert c.phone is None

    def test_full_contact(self):
        c = Contact(
            role=ContactRole.REGISTRANT,
            email="abuse@example.com",
            name="Example Corp",
            phone="+1-555-0123",
        )
        assert c.role is ContactRole.REGISTRANT
        assert c.email == "abuse@example.com"

    def test_invalid_email_rejects_contact(self):
        # The Email primitive's validator fires on construction; a
        # Contact carrying a mis-shaped email rejects rather than
        # silently swallowing the bad value.
        with pytest.raises(ValidationError):
            Contact(role=ContactRole.ABUSE, email="not-an-email")

    def test_serialise_roundtrip(self):
        original = Contact(role=ContactRole.NOC, email="noc@example.com")
        restored = Contact.model_validate_json(original.model_dump_json())
        assert restored.role is ContactRole.NOC
        assert restored.email == "noc@example.com"
