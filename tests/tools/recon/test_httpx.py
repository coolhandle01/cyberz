"""tests/tools/recon/test_httpx.py - unit tests for the rich httpx surface.

Covers ``httpx_scan`` (mode-driven flag composition, JSON parsing,
mode-dependent Endpoint field population, defensive degradation) +
the legacy ``probe_endpoints`` shim. Subprocess invocations are
mocked; no live httpx queries.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint
from models.network import HttpxMode
from tools.recon.httpx import _assemble_flags, httpx_scan, probe_endpoints

pytestmark = pytest.mark.unit


def _ndjson_line(**kwargs) -> str:
    """Build one httpx NDJSON output line from the kwargs as fields."""
    return json.dumps(kwargs)


class TestAssembleFlags:
    def test_live_minimal(self):
        flags = _assemble_flags(HttpxMode.LIVE)
        assert "-silent" in flags
        assert "-json" in flags
        assert "-status-code" in flags
        # The tech-detect-bundle flags do NOT appear at LIVE mode.
        assert "-tech-detect" not in flags
        assert "-favicon" not in flags
        assert "-tls-grab" not in flags

    def test_tech_detect_adds_signal_flags(self):
        flags = _assemble_flags(HttpxMode.TECH_DETECT)
        assert "-tech-detect" in flags
        assert "-server" in flags
        assert "-title" in flags
        # The web-inventory-only flags stay absent.
        assert "-favicon" not in flags
        assert "-tls-grab" not in flags

    def test_web_inventory_adds_favicon_and_tls(self):
        flags = _assemble_flags(HttpxMode.WEB_INVENTORY)
        # Everything tech-detect has, plus the heavy flags.
        assert "-tech-detect" in flags
        assert "-favicon" in flags
        assert "-tls-grab" in flags
        assert "-content-type" in flags
        assert "-method" in flags

    def test_timeout_always_present(self):
        for mode in HttpxMode:
            flags = _assemble_flags(mode)
            assert "-timeout" in flags

    def test_no_overlapping_recon_flags(self):
        # Skipping -asn (defers to asn.py / Cymru) and -cname (defers
        # to dnsx). Pin the omission so a future "let's just throw all
        # the httpx flags in" patch can't sneak them past review.
        for mode in HttpxMode:
            flags = _assemble_flags(mode)
            assert "-asn" not in flags, f"-asn appears in {mode.value} mode"
            assert "-cname" not in flags, f"-cname appears in {mode.value} mode"


class TestHttpxScanCore:
    def _mock_subprocess_result(self, *lines: str):
        result = MagicMock()
        result.stdout = "\n".join(lines)
        result.returncode = 0
        result.stderr = ""
        return result

    def test_empty_host_list_short_circuits(self):
        with patch("tools.recon.httpx._require_binary") as mock_bin:
            endpoints = httpx_scan([], mode=HttpxMode.LIVE)
        mock_bin.assert_not_called()
        assert endpoints == []

    def test_subprocess_failure_returns_empty(self, target_url):
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", side_effect=OSError("httpx died")),
        ):
            assert httpx_scan([target_url], mode=HttpxMode.LIVE) == []

    def test_malformed_json_line_skipped(self, target_url):
        # One bad line + one good line - the good one survives.
        mock_result = self._mock_subprocess_result(
            "this is not json",
            _ndjson_line(url=target_url, status_code=200, tech=[]),
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result),
        ):
            endpoints = httpx_scan([target_url], mode=HttpxMode.LIVE)
        assert len(endpoints) == 1
        assert all(isinstance(e, Endpoint) for e in endpoints)


class TestHttpxScanLiveMode:
    def test_populates_url_and_status_only(self, target_url):
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=["Django:4.2"]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result),
        ):
            endpoints = httpx_scan([target_url], mode=HttpxMode.LIVE)
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep.url == target_url
        assert ep.status_code == 200
        # LIVE mode does NOT request -tech-detect, so even if httpx
        # echoed a tech field we discard it.
        assert ep.technologies == []
        assert ep.detected_technologies == []


class TestHttpxScanTechDetectMode:
    def test_populates_technologies_and_typed_channel(self, target_url):
        mock_result = MagicMock(
            stdout=_ndjson_line(
                url=target_url,
                status_code=200,
                tech=["Django:4.2", "nginx:1.18.0"],
            ),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result),
        ):
            endpoints = httpx_scan([target_url], mode=HttpxMode.TECH_DETECT)
        ep = endpoints[0]
        assert ep.technologies == ["Django:4.2", "nginx:1.18.0"]
        assert {t.name for t in ep.detected_technologies} == {"django", "nginx"}


class TestHttpxScanWebInventoryMode:
    def test_populates_favicon_and_tls_sans(self, target_url, target_apex):
        mock_result = MagicMock(
            stdout=_ndjson_line(
                url=target_url,
                status_code=200,
                tech=["nginx:1.18.0"],
                favicon="-1234567890",
                tls={
                    "subject_alt_names": [target_apex, f"api.{target_apex}"],
                },
            ),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result),
        ):
            endpoints = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        ep = endpoints[0]
        assert ep.favicon_hash == "-1234567890"
        assert ep.tls_sans == [target_apex, f"api.{target_apex}"]

    def test_handles_alternate_favicon_key_path(self, target_url):
        # Older httpx versions emitted the key as ``favicon_path``;
        # newer ones use ``favicon``. The scanner reads either.
        mock_result = MagicMock(
            stdout=_ndjson_line(
                url=target_url,
                status_code=200,
                favicon_path="-9876543210",
                tech=[],
            ),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result),
        ):
            endpoints = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        assert endpoints[0].favicon_hash == "-9876543210"

    def test_missing_tls_block_yields_empty_sans(self, target_url):
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=[]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result),
        ):
            endpoints = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        assert endpoints[0].tls_sans == []
        assert endpoints[0].favicon_hash is None

    def test_malformed_san_degrades_row_not_drops_it(self, target_url, target_apex):
        # A SAN that isn't RFC-1123-shaped trips the FQDN validator -
        # the scanner should retry the Endpoint construction without the
        # optional fields so we keep the live / tech signal.
        mock_result = MagicMock(
            stdout=_ndjson_line(
                url=target_url,
                status_code=200,
                tech=["nginx"],
                tls={
                    "subject_alt_names": [
                        target_apex,
                        "not a valid hostname with spaces",
                    ],
                },
            ),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result),
        ):
            endpoints = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        # Row still present (degraded); status / tech populated, SANs
        # dropped because one was malformed.
        assert len(endpoints) == 1
        assert endpoints[0].status_code == 200
        assert endpoints[0].tls_sans == []


class TestProbeEndpointsLegacyShim:
    def test_runs_tech_detect_mode_under_the_hood(self, target_url):
        # The historical entry point must remain a drop-in for the
        # recon orchestrator + legacy tests. probe_endpoints == httpx_scan
        # with mode=TECH_DETECT.
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=["Django:4.2"]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx._run", return_value=mock_result) as mock_run,
        ):
            endpoints = probe_endpoints([target_url])

        # Result shape matches what legacy callers expect.
        assert len(endpoints) == 1
        assert endpoints[0].technologies == ["Django:4.2"]
        assert {t.name for t in endpoints[0].detected_technologies} == {"django"}
        # The flags include -tech-detect (i.e. TECH_DETECT mode, not LIVE).
        cmd = mock_run.call_args.args[0]
        assert "-tech-detect" in cmd
