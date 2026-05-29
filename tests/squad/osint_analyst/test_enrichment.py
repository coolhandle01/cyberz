"""
tests/squad/osint_analyst/test_enrichment.py - contract + invocation tests
for the OSINT Analyst's post-sweep pivot tools in
``squad/osint_analyst/enrichment.py``.

The pivot tools (``Lookup IP Assets``, ``Lookup RDAP for ASN``, ``Deep
Scan Host``) are the "explore, don't just record" surface from #181:
the agent reaches for them *after* the initial sweep to enrich IPs it
surfaced, pivot on an ASN, or deep-scan a single host's open ports.

This file carries the wrapper-invocation + scope-decision cases; the
generic args_schema contract sweep (explicit schema wired, every field
described, closed-world mapping) is parametrised over ``MEMBER.schemas``
in ``test_args_schemas.py`` and picks these tools up automatically once
they are registered.
"""

from __future__ import annotations

import pytest

from models.asset import IpAsset
from squad.osint_analyst import _LookupIpAssetsArgs, lookup_ip_assets_tool

pytestmark = pytest.mark.unit


class TestLookupIpAssets:
    """``Lookup IP Assets`` wraps ``compose_ip_assets`` - no scope filter.

    The IPs come from the sweep, which was already scope-filtered upstream
    (the programme scope model is FQDN-shaped, so there is no IP-level
    scope alias to apply). The wrapper is a thin typed pass-through.
    """

    def test_schema_accepts_ip_list(self) -> None:
        """A list of dotted-quad IPs validates without raising."""
        instance = _LookupIpAssetsArgs.model_validate({"ips": ["1.2.3.4", "8.8.8.8"]})
        assert instance.ips == ["1.2.3.4", "8.8.8.8"]

    def test_schema_rejects_non_ip(self) -> None:
        """A hostname where an IP was asked for rejects at the boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupIpAssetsArgs.model_validate({"ips": ["not-an-ip"]})

    def test_returns_composed_assets(self, invoke_tool, monkeypatch) -> None:
        """The wrapper returns ``compose_ip_assets``' typed result verbatim."""
        composed = [IpAsset(ip="1.2.3.4"), IpAsset(ip="8.8.8.8")]
        captured: dict[str, object] = {}

        def _fake_compose(ips):
            captured["ips"] = ips
            return composed

        monkeypatch.setattr("squad.osint_analyst.enrichment.compose_ip_assets", _fake_compose)

        result = invoke_tool(lookup_ip_assets_tool, ips=["1.2.3.4", "8.8.8.8"])

        assert result == composed
        assert captured["ips"] == ["1.2.3.4", "8.8.8.8"]
