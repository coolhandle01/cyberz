"""tests/tools/recon/test_technology.py - unit tests for tools/recon/technology.py.

Covers the coercion from raw recon strings (httpx tech-detect, nmap
banner, nuclei) into typed ``Technology`` values.
"""

from __future__ import annotations

import pytest

from models.technology import Technology, TechnologyCategory
from tools.recon.technology import coerce_technologies

pytestmark = pytest.mark.unit


class TestCoerceTechnologies:
    @pytest.mark.parametrize(
        ("raw", "expected_name", "expected_version", "expected_categories"),
        [
            # Bare name (no version)
            ("Django", "django", None, [TechnologyCategory.web_framework]),
            ("React", "react", None, [TechnologyCategory.js_framework]),
            ("WordPress", "wordpress", None, [TechnologyCategory.cms]),
            # Name + version (Wappalyzer-shape)
            ("Django:4.2", "django", "4.2", [TechnologyCategory.web_framework]),
            ("Apache:2.4.41", "apache", "2.4.41", [TechnologyCategory.web_server]),
            (
                "PostgreSQL:14.5",
                "postgresql",
                "14.5",
                [TechnologyCategory.database],
            ),
            # Case-insensitive lookup
            ("DJANGO", "django", None, [TechnologyCategory.web_framework]),
            ("nginx", "nginx", None, [TechnologyCategory.web_server]),
            # Names with dots / spaces in the canonical slug
            (
                "Next.js:13",
                "next.js",
                "13",
                [TechnologyCategory.js_framework, TechnologyCategory.paas],
            ),
            (
                "Vue.js:3.2",
                "vue.js",
                "3.2",
                [TechnologyCategory.js_framework],
            ),
            ("Node.js:18", "node.js", "18", [TechnologyCategory.programming_language]),
            # nmap -sV-style banner strings
            ("OpenSSH:7.6p1", "openssh", "7.6p1", [TechnologyCategory.ssh_server]),
            ("vsftpd:3.0.3", "vsftpd", "3.0.3", [TechnologyCategory.ftp_server]),
        ],
    )
    def test_known_string_coerces(
        self, raw, expected_name, expected_version, expected_categories
    ) -> None:
        result = coerce_technologies([raw])
        assert len(result) == 1
        assert result[0].name == expected_name
        assert result[0].version == expected_version
        assert result[0].categories == expected_categories

    @pytest.mark.parametrize(
        "raw",
        [
            "SomeMystery",
            "X-Powered-By: SuperFramework",
            "vendor:product:thirdthing",  # partition takes first colon only
        ],
    )
    def test_unknown_string_dropped_silently(self, raw) -> None:
        # Strings not in the seed catalogue are dropped without raising.
        # The catalogue grows append-only as new names show up in the wild.
        result = coerce_technologies([raw])
        # "vendor" / first segments are not in the catalogue either, so
        # all three test inputs should resolve to zero Technology values.
        assert result == []

    def test_empty_input(self) -> None:
        assert coerce_technologies([]) == []

    def test_falsy_entries_skipped(self) -> None:
        # Empty / whitespace-only / None-shaped entries are skipped without
        # raising; recon binaries occasionally emit blanks.
        result = coerce_technologies(["", "  ", "Django"])
        assert len(result) == 1
        assert result[0].name == "django"

    def test_deduplicates_identical_name_and_version(self) -> None:
        # Two appearances of the same (name, version) pair are coalesced.
        result = coerce_technologies(["Django:4.2", "Django:4.2"])
        assert len(result) == 1

    def test_different_versions_are_distinct(self) -> None:
        # Same name, different versions stay as distinct Technology rows -
        # the version is part of the identity (you might genuinely see
        # both on a multi-tenant host).
        result = coerce_technologies(["Django:4.2", "Django:5.0"])
        assert len(result) == 2
        assert {t.version for t in result} == {"4.2", "5.0"}

    def test_one_with_version_one_without_are_distinct(self) -> None:
        # "Django" and "Django:4.2" are distinct rows - the version is
        # part of the identity, and "no version" is a legitimate value.
        result = coerce_technologies(["Django", "Django:4.2"])
        assert len(result) == 2

    def test_oversized_raw_string_dropped(self) -> None:
        # Defence: raw strings longer than the 128-char cap are skipped
        # before lookup. Anything that long is implausibly a Wappalyzer
        # name; typically junk or a prompt-injection attempt.
        result = coerce_technologies(["a" * 200])
        assert result == []

    def test_multi_category_entry_keeps_all_categories(self) -> None:
        # Next.js is both a JS framework and a hosting platform - the
        # coercer returns the full list.
        result = coerce_technologies(["Next.js:13"])
        assert len(result) == 1
        assert TechnologyCategory.js_framework in result[0].categories
        assert TechnologyCategory.paas in result[0].categories

    def test_returns_typed_technology_instances(self) -> None:
        # Sanity: result elements ARE the typed model, not dicts.
        result = coerce_technologies(["Django:4.2"])
        assert isinstance(result[0], Technology)

    def test_known_and_unknown_mixed(self) -> None:
        # Mixed input: known names land, unknowns drop, order is preserved
        # for the known subset.
        result = coerce_technologies(["Django:4.2", "MysteryThing", "Apache:2.4", "AnotherMystery"])
        assert [t.name for t in result] == ["django", "apache"]
