"""tests/test_cwe_data.py - unit tests for tools/cwe_data.py."""

from __future__ import annotations

import pytest

from tools.cwe_data import CWE_CATALOGUE, get_by_id, lookup

pytestmark = pytest.mark.unit


class TestLookup:
    def test_exact_alias_match(self):
        entries = lookup("SQLi")
        assert entries
        assert entries[0].cwe_id == 89

    def test_case_insensitive(self):
        entries = lookup("sqli")
        assert entries
        assert entries[0].cwe_id == 89

    def test_substring_match(self):
        entries = lookup("cross-site")
        ids = [e.cwe_id for e in entries]
        # CWE-79 (XSS) and CWE-352 (CSRF) both contain "cross-site"
        assert 79 in ids
        assert 352 in ids

    def test_empty_query_returns_empty(self):
        assert lookup("") == []

    def test_unknown_returns_empty(self):
        assert lookup("absolutely-not-a-vuln-class") == []

    def test_limit_respected(self):
        entries = lookup("injection", limit=2)
        assert len(entries) <= 2

    def test_exact_match_ordered_first(self):
        entries = lookup("XXE")
        assert entries[0].cwe_id == 611


class TestGetById:
    def test_returns_entry_for_known(self):
        entry = get_by_id(79)
        assert entry is not None
        assert "Cross-site" in entry.name

    def test_returns_none_for_unknown(self):
        assert get_by_id(999999) is None


class TestCatalogueIntegrity:
    def test_ids_are_unique(self):
        ids = [e.cwe_id for e in CWE_CATALOGUE]
        assert len(ids) == len(set(ids)), "duplicate CWE id in catalogue"

    def test_url_format(self):
        for entry in CWE_CATALOGUE:
            assert entry.url == f"https://cwe.mitre.org/data/definitions/{entry.cwe_id}.html"

    def test_every_entry_has_description(self):
        for entry in CWE_CATALOGUE:
            assert entry.description.strip()
