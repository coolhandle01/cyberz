"""tests/tools/recon/test_technology.py - unit tests for tools/recon/technology.py.

Covers the coercion from raw recon strings (httpx tech-detect, nmap
banner, nuclei) into typed ``Technology`` values. The coercer classifies
nothing and drops nothing: every observed string becomes a Technology
carrying the tool's own name + optional version.
"""

from __future__ import annotations

import pytest

from models.technology import Technology
from tools.recon.technology import coerce_technologies

pytestmark = pytest.mark.unit


class TestCoerceTechnologies:
    @pytest.mark.parametrize(
        ("raw", "expected_name", "expected_version"),
        [
            # Bare name (no version)
            ("Django", "django", None),
            ("WordPress", "wordpress", None),
            # Name + version (Wappalyzer-shape)
            ("Django:4.2", "django", "4.2"),
            ("Apache:2.4.41", "apache", "2.4.41"),
            ("PostgreSQL:14.5", "postgresql", "14.5"),
            # Case-folded to the lowercase canonical
            ("DJANGO", "django", None),
            # Dots in the name slug survive; only the first ':' splits version
            ("Next.js:13", "next.js", "13"),
            ("Node.js:18", "node.js", "18"),
            # nmap -sV-style banner strings
            ("OpenSSH:7.6p1", "openssh", "7.6p1"),
        ],
    )
    def test_string_coerces_to_name_and_version(self, raw, expected_name, expected_version) -> None:
        result = coerce_technologies([raw])
        assert len(result) == 1
        assert result[0].name == expected_name
        assert result[0].version == expected_version

    @pytest.mark.parametrize(
        ("raw", "expected_name"),
        [
            ("SomeMystery", "somemystery"),
            ("SuperFramework", "superframework"),
        ],
    )
    def test_uncatalogued_string_is_kept_not_dropped(self, raw, expected_name) -> None:
        # No allow-list: a name we have never seen is still the tool's own
        # identifier and is captured verbatim. Full situational awareness.
        result = coerce_technologies([raw])
        assert len(result) == 1
        assert result[0].name == expected_name

    def test_only_first_colon_splits_version(self) -> None:
        # str.partition(":") keeps everything after the first colon as the
        # version - a defensible, lossless split for "name:rest".
        result = coerce_technologies(["vendor:product:thirdthing"])
        assert len(result) == 1
        assert result[0].name == "vendor"
        assert result[0].version == "product:thirdthing"

    def test_empty_input(self) -> None:
        assert coerce_technologies([]) == []

    def test_falsy_entries_skipped(self) -> None:
        # Empty / whitespace-only entries are skipped without raising;
        # recon binaries occasionally emit blanks.
        result = coerce_technologies(["", "  ", "Django"])
        assert len(result) == 1
        assert result[0].name == "django"

    def test_deduplicates_identical_name_and_version(self) -> None:
        result = coerce_technologies(["Django:4.2", "Django:4.2"])
        assert len(result) == 1

    def test_different_versions_are_distinct(self) -> None:
        result = coerce_technologies(["Django:4.2", "Django:5.0"])
        assert len(result) == 2
        assert {t.version for t in result} == {"4.2", "5.0"}

    def test_one_with_version_one_without_are_distinct(self) -> None:
        result = coerce_technologies(["Django", "Django:4.2"])
        assert len(result) == 2

    def test_oversized_raw_string_dropped(self) -> None:
        # Defence: raw strings longer than the 128-char cap are skipped -
        # implausibly a technology name; typically junk or an injection.
        result = coerce_technologies(["a" * 200])
        assert result == []

    def test_returns_typed_technology_instances(self) -> None:
        result = coerce_technologies(["Django:4.2"])
        assert isinstance(result[0], Technology)

    def test_preserves_order_and_keeps_everything(self) -> None:
        # Mixed input: every distinct entry lands, order preserved.
        result = coerce_technologies(["Django:4.2", "MysteryThing", "Apache:2.4", "AnotherMystery"])
        assert [t.name for t in result] == [
            "django",
            "mysterything",
            "apache",
            "anothermystery",
        ]
