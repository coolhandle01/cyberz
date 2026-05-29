"""tests/tools/recon/test_rdap.py - unit tests for the RDAP (RFC 7483) wrapper.

Covers the IANA bootstrap walker, the defensive RDAP-JSON parser, and
the public ``lookup_rdap_for_ip`` / ``lookup_rdap_for_asn`` entry
points. HTTP is mocked at the ``tools.http.get`` boundary via the
shared ``make_response`` fixture; no live RDAP queries during tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from models.network import ContactRole, RdapRecord
from tools.recon import rdap

pytestmark = pytest.mark.unit


# Real-shape sample from ARIN's RDAP response for 8.8.8.8. Trimmed to
# the fields the parser reads (entities + events + handle).
_ARIN_IP_PAYLOAD = {
    "objectClassName": "ip network",
    "handle": "NET-8-8-8-0-1",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "entities": [
        {
            "objectClassName": "entity",
            "handle": "GOGL",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Google LLC"],
                    ["kind", {}, "text", "org"],
                ],
            ],
            "entities": [
                {
                    "handle": "ZG39-ARIN",
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Abuse"],
                            ["email", {}, "text", "network-abuse@google.com"],
                        ],
                    ],
                }
            ],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "1992-12-01T05:00:00-05:00"},
        {"eventAction": "last changed", "eventDate": "2014-03-14T16:52:05-04:00"},
    ],
}

# Real-shape sample from ARIN's RDAP response for autnum/15169.
_ARIN_ASN_PAYLOAD = {
    "objectClassName": "autnum",
    "handle": "AS15169",
    "startAutnum": 15169,
    "endAutnum": 15169,
    "name": "GOOGLE",
    "entities": [
        {
            "handle": "GOGL",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "Google LLC"]],
            ],
        }
    ],
    "events": [{"eventAction": "registration", "eventDate": "2000-03-30T00:00:00Z"}],
}

# Trimmed bootstrap registries. The real files carry many more rows;
# these are enough to route the test queries.
_IPV4_BOOTSTRAP = {
    "services": [
        [["8.0.0.0/9"], ["https://rdap.arin.net/registry/"]],
        [["1.0.0.0/8"], ["https://rdap.apnic.net/"]],
    ],
}
_ASN_BOOTSTRAP = {
    "services": [
        [["1-1876", "15169-15169"], ["https://rdap.arin.net/registry/"]],
        [["131072-141625"], ["https://rdap.apnic.net/"]],
    ],
}


@pytest.fixture(autouse=True)
def _clear_bootstrap_cache():
    """Reset the module-level bootstrap cache so tests don't bleed state."""
    rdap._bootstrap_cache.clear()
    yield
    rdap._bootstrap_cache.clear()


# Bootstrap routing


class TestBootstrapRouting:
    def test_base_url_for_ip_routes_to_arin(self, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=_IPV4_BOOTSTRAP)):
            base = rdap._base_url_for_ip("8.8.8.8")
        assert base == "https://rdap.arin.net/registry"

    def test_base_url_for_ip_routes_to_apnic(self, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=_IPV4_BOOTSTRAP)):
            base = rdap._base_url_for_ip("1.1.1.1")
        assert base == "https://rdap.apnic.net"

    def test_base_url_for_ip_returns_none_for_unallocated(self, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=_IPV4_BOOTSTRAP)):
            base = rdap._base_url_for_ip("10.0.0.1")
        assert base is None

    def test_base_url_for_asn_routes_to_arin(self, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=_ASN_BOOTSTRAP)):
            base = rdap._base_url_for_asn(15169)
        assert base == "https://rdap.arin.net/registry"

    def test_base_url_for_asn_returns_none_outside_known_ranges(self, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=_ASN_BOOTSTRAP)):
            base = rdap._base_url_for_asn(99999999)
        assert base is None

    def test_bootstrap_cached_across_calls(self, make_response):
        with patch(
            "tools.recon.rdap.http.get", return_value=make_response(json=_IPV4_BOOTSTRAP)
        ) as g:
            rdap._base_url_for_ip("8.8.8.8")
            rdap._base_url_for_ip("8.8.4.4")
        # Two lookups but only one bootstrap fetch - the registry is cached.
        assert g.call_count == 1

    def test_bootstrap_fetch_failure_returns_none(self):
        with patch("tools.recon.rdap.http.get", side_effect=OSError("network down")):
            base = rdap._base_url_for_ip("8.8.8.8")
        assert base is None

    def test_bootstrap_payload_without_services_array(self, make_response):
        # IANA contract specifies a top-level ``services`` array; a
        # response missing it degrades to no-routing rather than crashing.
        with patch(
            "tools.recon.rdap.http.get",
            return_value=make_response(json={"description": "not a real registry"}),
        ):
            assert rdap._base_url_for_ip("8.8.8.8") is None

    def test_bootstrap_payload_not_a_json_object(self, make_response):
        with patch(
            "tools.recon.rdap.http.get",
            return_value=make_response(json=["unexpected", "shape"]),
        ):
            assert rdap._base_url_for_ip("8.8.8.8") is None

    def test_invalid_ip_returns_none_without_bootstrap(self):
        # ipaddress.ip_address rejects bogus values before we hit the
        # registry - no HTTP request fires.
        with patch("tools.recon.rdap.http.get") as g:
            assert rdap._base_url_for_ip("not.an.ip") is None
        g.assert_not_called()

    def test_malformed_bootstrap_entries_skipped(self, make_response):
        # Entries that don't conform to ``[prefixes, urls]`` shape are
        # quietly skipped; the walker continues looking for valid ones.
        broken_then_good = {
            "services": [
                "not a list",
                [["8.0.0.0/9"], "urls is not a list"],
                [["not a cidr"], ["https://rdap.x.test/"]],
                [["8.0.0.0/9"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=broken_then_good)):
            assert rdap._base_url_for_ip("8.8.8.8") == "https://rdap.arin.net/registry"

    def test_malformed_asn_ranges_skipped(self, make_response):
        broken_then_good = {
            "services": [
                "not a list",
                [["not a range"], ["https://rdap.x.test/"]],
                [["15169-15169"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=broken_then_good)):
            assert rdap._base_url_for_asn(15169) == "https://rdap.arin.net/registry"

    def test_ipv6_routes_via_v6_bootstrap(self, make_response):
        v6_bootstrap = {
            "services": [
                [["2001:4860::/32"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=v6_bootstrap)):
            assert rdap._base_url_for_ip("2001:4860:4860::8888") == "https://rdap.arin.net/registry"

    def test_pick_https_url_falls_back_to_http_only(self):
        # Some bootstrap entries list only http:// URLs; we accept those
        # rather than no-routing the lookup.
        assert rdap._pick_https_url(["http://rdap.x.test/"]) == "http://rdap.x.test"

    def test_pick_https_url_returns_none_for_no_strings(self):
        assert rdap._pick_https_url([42, None, {}]) is None

    def test_rir_from_url_none_input(self):
        assert rdap._rir_from_url(None) is None

    def test_asn_bootstrap_entries_with_non_list_fields_skipped(self, make_response):
        # Defensive: bootstrap rows where ``ranges`` or ``urls`` aren't
        # lists are skipped without crashing the walker.
        broken = {
            "services": [
                ["not a list", "also not a list"],
                [[42, "15169-15169"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=broken)):
            assert rdap._base_url_for_asn(15169) == "https://rdap.arin.net/registry"


# Defensive vCard / entity / event walkers


class TestDefensiveWalkers:
    def test_vcard_properties_not_a_list(self):
        # Outer shape valid, inner property list malformed.
        assert rdap._vcard_field(["vcard", "not a list of props"], "fn") is None

    def test_vcard_property_too_short(self):
        # Each property must be ``[name, params, type, value]`` (len >= 4);
        # short ones are skipped.
        vcard = ["vcard", [["fn", {}, "text"], ["email", {}, "text", "a@b.test"]]]
        # First prop is too short; walker continues to the next.
        assert rdap._vcard_field(vcard, "email") == "a@b.test"

    def test_walk_entities_skips_non_dict_entries(self):
        entities = ["not a dict", {"roles": ["registrant"], "handle": "X"}]
        matches = rdap._walk_entities_for_role(entities, "registrant")
        assert len(matches) == 1
        assert matches[0]["handle"] == "X"

    def test_parse_event_events_not_a_list(self):
        assert rdap._parse_event("not a list", "registration") is None

    def test_parse_event_event_date_not_string(self):
        events = [{"eventAction": "registration", "eventDate": 12345}]
        assert rdap._parse_event(events, "registration") is None

    def test_parse_event_skips_non_dict_entries(self):
        events = [
            "not a dict",
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        ]
        result = rdap._parse_event(events, "registration")
        assert result is not None
        assert result.year == 2020

    def test_registrant_without_fn_leaves_org_none(self):
        payload = {
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", []]},
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.registrant_organisation is None

    def test_abuse_entity_without_email_leaves_email_none(self):
        payload = {
            "entities": [
                {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"]]]},
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.abuse_email is None


# Failure paths on lookup_rdap_for_ip / _for_asn parity coverage


class TestLookupFailurePaths:
    def test_ip_payload_validation_error_returns_none(self, make_response):
        # Force ``_parse_rdap_payload`` to raise ValueError by feeding a
        # ``source_url`` longer than the RdapRecord.source_url length cap.
        long_url = "https://rdap.arin.net/registry/ip/8.8.8.8?" + ("x" * 600)
        get = MagicMock(
            side_effect=[
                make_response(json=_IPV4_BOOTSTRAP),
                make_response(json=_ARIN_IP_PAYLOAD),
            ]
        )
        with (
            patch("tools.recon.rdap.http.get", get),
            patch.object(rdap, "_base_url_for_ip", return_value=long_url.rstrip("/")),
        ):
            # The long base URL produces an over-long source_url that the
            # RdapRecord's max_length=512 rejects, hitting the ValueError
            # fallback in lookup_rdap_for_ip.
            assert rdap.lookup_rdap_for_ip("8.8.8.8") is None

    def test_asn_http_failure_after_bootstrap(self, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=_ASN_BOOTSTRAP),
                OSError("connection refused"),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_asn(15169) is None

    def test_asn_response_not_a_json_object(self, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=_ASN_BOOTSTRAP),
                make_response(json=["unexpected"]),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_asn(15169) is None

    def test_asn_payload_validation_error_returns_none(self, make_response):
        long_url = "https://rdap.arin.net/registry/autnum/15169?" + ("y" * 600)
        get = MagicMock(
            side_effect=[
                make_response(json=_ASN_BOOTSTRAP),
                make_response(json=_ARIN_ASN_PAYLOAD),
            ]
        )
        with (
            patch("tools.recon.rdap.http.get", get),
            patch.object(rdap, "_base_url_for_asn", return_value=long_url.rstrip("/")),
        ):
            assert rdap.lookup_rdap_for_asn(15169) is None


# Contact walking


class TestContactWalking:
    def test_walks_full_contact_set(self):
        payload = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Example Corp"],
                            ["email", {}, "text", "registry@example.com"],
                            ["tel", {}, "text", "+1-555-0001"],
                        ],
                    ],
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "vcardArray": [
                                "vcard",
                                [
                                    ["fn", {}, "text", "Abuse Desk"],
                                    ["email", {}, "text", "abuse@example.com"],
                                ],
                            ],
                        },
                        {
                            "roles": ["technical"],
                            "vcardArray": [
                                "vcard",
                                [
                                    ["fn", {}, "text", "Tech NOC"],
                                    ["email", {}, "text", "tech@example.com"],
                                    ["tel", {}, "text", "+1-555-0002"],
                                ],
                            ],
                        },
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        roles = {c.role for c in record.contacts}
        assert {ContactRole.REGISTRANT, ContactRole.ABUSE, ContactRole.TECHNICAL} <= roles
        # The convenience-access flat fields still derive from the contacts.
        assert record.registrant_organisation == "Example Corp"
        assert record.abuse_email == "abuse@example.com"

    def test_skips_entity_with_no_useful_fields(self):
        # An entity with role but neither name, email, nor phone is
        # filtered upstream of contact construction.
        payload = {
            "entities": [
                {
                    "roles": ["admin"],
                    "vcardArray": ["vcard", []],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.contacts == []

    def test_unknown_role_is_dropped(self):
        # The parser walks ContactRole values only; an entity whose role
        # is outside our catalogue does not project onto an OTHER bucket.
        payload = {
            "entities": [
                {
                    "roles": ["billing"],  # not in ContactRole
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Billing"],
                            ["email", {}, "text", "billing@example.com"],
                        ],
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.contacts == []

    def test_malformed_email_degrades_to_email_less_contact(self):
        # An RDAP server returning a non-shaped email trips the Email
        # validator; _build_contact retries without the email and keeps
        # the rest of the contact intact.
        payload = {
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Abuse Desk"],
                            ["email", {}, "text", "not an email"],
                        ],
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert len(record.contacts) == 1
        assert record.contacts[0].name == "Abuse Desk"
        assert record.contacts[0].email is None

    def test_overlong_name_drops_contact_entirely(self):
        # The Email validator passed; the name length cap rejects on
        # both the initial construction and the email-stripped retry,
        # so the contact drops on the floor.
        payload = {
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "x" * 300],
                            ["email", {}, "text", "abuse@example.com"],
                        ],
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.contacts == []


# Defensive payload parsing


class TestParseRdapPayload:
    def test_extracts_handle_org_abuse_and_events(self):
        record = rdap._parse_rdap_payload(
            _ARIN_IP_PAYLOAD,
            query="8.8.8.8",
            source_url="https://rdap.arin.net/registry/ip/8.8.8.8",
        )
        assert record.handle == "NET-8-8-8-0-1"
        assert record.registrant_organisation == "Google LLC"
        assert record.abuse_email == "network-abuse@google.com"
        assert record.rir == "ARIN"
        assert record.registered_at == datetime(
            1992, 12, 1, 5, 0, 0, tzinfo=timezone(timedelta(hours=-5))
        )
        assert record.last_changed_at == datetime(
            2014, 3, 14, 16, 52, 5, tzinfo=timezone(timedelta(hours=-4))
        )

    def test_empty_payload_yields_record_with_only_query_and_url(self):
        record = rdap._parse_rdap_payload(
            {},
            query="8.8.8.8",
            source_url="https://rdap.arin.net/registry/ip/8.8.8.8",
        )
        assert record.query == "8.8.8.8"
        assert record.source_url == "https://rdap.arin.net/registry/ip/8.8.8.8"
        assert record.handle is None
        assert record.registrant_organisation is None
        assert record.abuse_email is None
        assert record.registered_at is None

    def test_missing_abuse_entity_leaves_email_none(self):
        # Strip the nested abuse entity from the registrant.
        payload = {**_ARIN_IP_PAYLOAD}
        payload["entities"] = [{**payload["entities"][0], "entities": []}]
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.registrant_organisation == "Google LLC"
        assert record.abuse_email is None

    def test_rir_unknown_when_source_url_not_in_catalogue(self):
        record = rdap._parse_rdap_payload(
            {"handle": "X"}, query="x", source_url="https://rdap.example.test/x"
        )
        assert record.rir is None

    def test_malformed_event_date_skipped(self):
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": "not a date"},
                {"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.registered_at is None
        assert record.last_changed_at is not None


# vCard field extraction


class TestVcardField:
    def test_extracts_fn(self):
        vcard = ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Acme Co"]]]
        assert rdap._vcard_field(vcard, "fn") == "Acme Co"

    def test_returns_none_when_field_absent(self):
        vcard = ["vcard", [["version", {}, "text", "4.0"]]]
        assert rdap._vcard_field(vcard, "email") is None

    def test_returns_none_on_malformed_outer_shape(self):
        assert rdap._vcard_field("not a vcard", "fn") is None
        assert rdap._vcard_field([], "fn") is None


# End-to-end lookup paths


class TestLookupRdapForIp:
    def test_returns_record_for_routed_ip(self, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=_IPV4_BOOTSTRAP),
                make_response(json=_ARIN_IP_PAYLOAD),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            record = rdap.lookup_rdap_for_ip("8.8.8.8")
        assert isinstance(record, RdapRecord)
        assert record.query == "8.8.8.8"
        assert record.handle == "NET-8-8-8-0-1"
        assert record.source_url == "https://rdap.arin.net/registry/ip/8.8.8.8"
        assert record.rir == "ARIN"

    def test_returns_none_when_bootstrap_misses(self, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=_IPV4_BOOTSTRAP)):
            assert rdap.lookup_rdap_for_ip("10.0.0.1") is None

    def test_returns_none_on_http_failure_after_bootstrap(self, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=_IPV4_BOOTSTRAP),
                OSError("connection refused"),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_ip("8.8.8.8") is None

    def test_returns_none_when_response_not_a_json_object(self, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=_IPV4_BOOTSTRAP),
                make_response(json=["unexpected", "shape"]),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_ip("8.8.8.8") is None


class TestLookupRdapForAsn:
    def test_returns_record_for_routed_asn(self, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=_ASN_BOOTSTRAP),
                make_response(json=_ARIN_ASN_PAYLOAD),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            record = rdap.lookup_rdap_for_asn(15169)
        assert isinstance(record, RdapRecord)
        assert record.query == "AS15169"
        assert record.handle == "AS15169"
        assert record.registrant_organisation == "Google LLC"
        assert record.source_url == "https://rdap.arin.net/registry/autnum/15169"
        assert record.rir == "ARIN"

    def test_returns_none_outside_known_asn_range(self, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=_ASN_BOOTSTRAP)):
            assert rdap.lookup_rdap_for_asn(99999999) is None
