"""tests/tools/recon/test_httpx.py - unit tests for the rich httpx surface.

Covers ``httpx_scan`` (mode-driven flag composition, JSON parsing,
mode-dependent Endpoint field population, defensive degradation, the
evidence-dir toggles ``with_screenshots`` / ``with_responses``) + the
legacy ``probe_endpoints`` shim. Subprocess invocations are mocked;
no live httpx queries.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint
from models.scanner import HttpxMode, HttpxScanResult
from tools.recon.httpx import httpx_scan, probe_endpoints
from tools.recon.httpx.flags import _assemble_flags

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

    def test_rate_retries_threads_from_scan_config(self, monkeypatch):
        """httpx picks ``-rate-limit`` / ``-retries`` / ``-threads`` off
        ``config.scan`` so the operator's stealth dial flows through.

        Patches the singleton via the same import alias ``flags.py``
        binds. ``TestAdaptiveSleep`` reloads ``config``, leaving older
        modules referencing the pre-reload singleton; targeting the
        consumer's alias makes the patch robust to that.
        """
        from tools.recon.httpx import flags as httpx_flags

        monkeypatch.setattr(httpx_flags.config.scan, "httpx_rate_limit", 13)
        monkeypatch.setattr(httpx_flags.config.scan, "httpx_retries", 4)
        monkeypatch.setattr(httpx_flags.config.scan, "httpx_threads", 7)
        flags = _assemble_flags(HttpxMode.LIVE)
        assert flags[flags.index("-rate-limit") + 1] == "13"
        assert flags[flags.index("-retries") + 1] == "4"
        assert flags[flags.index("-threads") + 1] == "7"

    def test_rate_retries_threads_present_in_every_mode(self):
        """The caps apply to every mode, not just LIVE."""
        for mode in HttpxMode:
            flags = _assemble_flags(mode)
            assert "-rate-limit" in flags, f"{mode.value} missing -rate-limit"
            assert "-retries" in flags, f"{mode.value} missing -retries"
            assert "-threads" in flags, f"{mode.value} missing -threads"

    def test_no_overlapping_recon_flags(self):
        # Skipping -asn (defers to asn.py / Cymru) and -cname (defers
        # to dnsx). Pin the omission so a future "let's just throw all
        # the httpx flags in" patch can't sneak them past review.
        for mode in HttpxMode:
            flags = _assemble_flags(mode)
            assert "-asn" not in flags, f"-asn appears in {mode.value} mode"
            assert "-cname" not in flags, f"-cname appears in {mode.value} mode"

    def test_screenshot_toggle_adds_evidence_flags(self):
        flags = _assemble_flags(
            HttpxMode.WEB_INVENTORY,
            with_screenshots=True,
            evidence_dir="/tmp/evidence",
        )
        assert "-screenshot" in flags
        assert "-srd" in flags
        # -srd takes the directory as its argument.
        assert flags[flags.index("-srd") + 1] == "/tmp/evidence"
        # -store-response NOT requested -> absent.
        assert "-store-response" not in flags

    def test_responses_toggle_adds_store_response(self):
        flags = _assemble_flags(
            HttpxMode.TECH_DETECT,
            with_responses=True,
            evidence_dir="/tmp/evidence",
        )
        assert "-store-response" in flags
        assert "-srd" in flags
        assert "-screenshot" not in flags

    def test_evidence_flags_omitted_when_dir_is_none(self):
        # Toggles set but no evidence_dir bound (no pipeline run) -> the
        # scan still runs, just no file-on-disk evidence flags.
        flags = _assemble_flags(
            HttpxMode.WEB_INVENTORY,
            with_screenshots=True,
            with_responses=True,
            evidence_dir=None,
        )
        assert "-screenshot" not in flags
        assert "-store-response" not in flags
        assert "-srd" not in flags


class TestHttpxScanCore:
    def _mock_subprocess_result(self, *lines: str):
        result = MagicMock()
        result.stdout = "\n".join(lines)
        result.returncode = 0
        result.stderr = ""
        return result

    def test_empty_host_list_short_circuits(self):
        with patch("tools.recon.httpx.scanner._require_binary") as mock_bin:
            result = httpx_scan([], mode=HttpxMode.LIVE)
        mock_bin.assert_not_called()
        assert isinstance(result, HttpxScanResult)
        assert result.endpoints == []
        assert result.evidence_dir is None

    def test_subprocess_failure_returns_empty(self, target_url):
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", side_effect=OSError("httpx died")),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.LIVE)
        assert isinstance(result, HttpxScanResult)
        assert result.endpoints == []

    def test_non_dict_json_line_skipped(self, target_url):
        # httpx emits one JSON object per line; a stray JSON array / scalar
        # is structurally valid JSON but not a row - parser skips it.
        mock_result = self._mock_subprocess_result(
            "[1, 2, 3]",
            _ndjson_line(url=target_url, status_code=200, tech=[]),
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.LIVE)
        assert len(result.endpoints) == 1

    def test_double_validation_failure_drops_row(self, target_url):
        # Both Endpoint constructions raise: the first because of a bad
        # SAN, the second (the degraded retry) because the URL itself is
        # invalid. The row drops on the floor entirely; the parser keeps
        # going.
        mock_result = self._mock_subprocess_result(
            _ndjson_line(url="://not a url", status_code=200, tech=[]),
            _ndjson_line(url=target_url, status_code=200, tech=[]),
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.LIVE)
        # Bad row dropped, good row kept.
        assert len(result.endpoints) == 1
        assert result.endpoints[0].url == target_url

    def test_malformed_json_line_skipped(self, target_url):
        # One bad line + one good line - the good one survives.
        mock_result = self._mock_subprocess_result(
            "this is not json",
            _ndjson_line(url=target_url, status_code=200, tech=[]),
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.LIVE)
        assert len(result.endpoints) == 1
        assert all(isinstance(e, Endpoint) for e in result.endpoints)


class TestHttpxScanLiveMode:
    def test_populates_url_and_status_only(self, target_url):
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=["Django:4.2"]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.LIVE)
        assert len(result.endpoints) == 1
        ep = result.endpoints[0]
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
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.TECH_DETECT)
        ep = result.endpoints[0]
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
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        ep = result.endpoints[0]
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
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        assert result.endpoints[0].favicon_hash == "-9876543210"

    def test_missing_tls_block_yields_empty_sans(self, target_url):
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=[]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        assert result.endpoints[0].tls_sans == []
        assert result.endpoints[0].favicon_hash is None

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
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        # Row still present (degraded); status / tech populated, SANs
        # dropped because one was malformed.
        assert len(result.endpoints) == 1
        assert result.endpoints[0].status_code == 200
        assert result.endpoints[0].tls_sans == []

    def test_captures_tls_certificate(self, target_url, target_apex):
        # The tls block becomes a full TLSCertificate asset on the endpoint:
        # issuer / validity / fingerprint / SANs, not just the SAN side-channel.
        mock_result = MagicMock(
            stdout=_ndjson_line(
                url=target_url,
                status_code=200,
                tech=["nginx:1.18.0"],
                tls={
                    "subject_cn": target_apex,
                    "issuer_cn": "Let's Encrypt",
                    "not_after": "2026-09-01T00:00:00Z",
                    "fingerprint_hash": {"sha256": "ab" * 32},
                    "subject_alt_names": [target_apex, f"api.{target_apex}"],
                },
            ),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        cert = result.endpoints[0].tls_certificate
        assert cert is not None
        assert cert.issuer == "Let's Encrypt"
        assert cert.fingerprint_sha256 == "ab" * 32
        assert cert.not_after is not None
        assert cert.subject_alt_names == [target_apex, f"api.{target_apex}"]

    def test_no_tls_block_yields_no_certificate(self, target_url):
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=[]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        assert result.endpoints[0].tls_certificate is None

    def test_cert_keeps_wildcard_san_that_tls_sans_drops(self, target_url, target_apex):
        # A wildcard SAN trips the FQDN-typed tls_sans (whole batch degraded
        # to []), but the cert's list[str] SANs capture it faithfully - the
        # exact reason TLSCertificate.subject_alt_names is not list[FQDN].
        mock_result = MagicMock(
            stdout=_ndjson_line(
                url=target_url,
                status_code=200,
                tech=["nginx"],
                tls={"subject_alt_names": [f"*.{target_apex}", target_apex]},
            ),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.WEB_INVENTORY)
        ep = result.endpoints[0]
        assert ep.tls_sans == []
        assert ep.tls_certificate is not None
        assert f"*.{target_apex}" in ep.tls_certificate.subject_alt_names


class TestHttpxScanEvidence:
    def test_no_evidence_dir_when_toggles_off(self, target_url):
        # Default invocation - no screenshots, no responses.
        # evidence_dir on the result stays None.
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=[]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
        ):
            result = httpx_scan([target_url], mode=HttpxMode.TECH_DETECT)
        assert result.evidence_dir is None

    def test_no_evidence_dir_when_no_run_bound(self, target_url):
        # Toggles set but ``runtime.run_dir()`` raises RuntimeError
        # (no pipeline run bound - tests, library usage). The scan
        # still runs - just no on-disk evidence.
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=[]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result),
            patch("tools.recon.httpx.scanner.runtime.run_dir", side_effect=RuntimeError("no run")),
        ):
            result = httpx_scan(
                [target_url],
                mode=HttpxMode.WEB_INVENTORY,
                with_screenshots=True,
            )
        assert result.evidence_dir is None

    def test_evidence_dir_created_and_returned_when_screenshots_requested(
        self, target_url, run_dir
    ):
        # ``run_dir`` fixture points runtime.run_dir() at tmp_path and
        # returns it - one setattr propagates via ``import runtime``
        # through every consumer including tools.recon.httpx.scanner.
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=[]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result) as mock_run,
        ):
            result = httpx_scan(
                [target_url],
                mode=HttpxMode.WEB_INVENTORY,
                with_screenshots=True,
            )
        # The relative dir-name pointer is set + the directory really
        # got created under the run dir before the subprocess fired.
        assert result.evidence_dir is not None
        assert result.evidence_dir.startswith("httpx-")
        assert (run_dir / result.evidence_dir).is_dir()
        # And the absolute path made it onto the command line via -srd.
        cmd = mock_run.call_args.args[0]
        assert "-srd" in cmd
        assert "-screenshot" in cmd

    def test_evidence_dirname_stable_across_calls(self, tmp_path):
        # Same hosts + same mode -> same hashed dirname (reusable across
        # retries / restarts; no fresh dir on every call).
        from tools.recon.httpx.scanner import _evidence_dirname

        name_a = _evidence_dirname(["a.example.com", "b.example.com"], HttpxMode.LIVE)
        name_b = _evidence_dirname(["b.example.com", "a.example.com"], HttpxMode.LIVE)
        assert name_a == name_b
        # Different mode -> different dirname (keeps evidence sets disjoint).
        name_c = _evidence_dirname(["a.example.com", "b.example.com"], HttpxMode.WEB_INVENTORY)
        assert name_a != name_c


class TestProbeEndpointsLegacyShim:
    def test_runs_tech_detect_mode_under_the_hood(self, target_url):
        # The historical entry point must remain a drop-in for the
        # recon orchestrator + legacy tests. probe_endpoints == httpx_scan
        # with mode=TECH_DETECT, returning ``list[Endpoint]`` not the
        # rich result.
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=["Django:4.2"]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result) as mock_run,
        ):
            endpoints = probe_endpoints([target_url])

        # Shim returns ``list[Endpoint]`` (not HttpxScanResult).
        assert isinstance(endpoints, list)
        assert len(endpoints) == 1
        assert endpoints[0].technologies == ["Django:4.2"]
        assert {t.name for t in endpoints[0].detected_technologies} == {"django"}
        # The flags include -tech-detect (i.e. TECH_DETECT mode, not LIVE).
        cmd = mock_run.call_args.args[0]
        assert "-tech-detect" in cmd
