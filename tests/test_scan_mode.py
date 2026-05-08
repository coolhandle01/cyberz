"""
tests/test_scan_mode.py - unit tests for SCAN_MODE config and adaptive_sleep.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestScanMode:
    def test_invalid_mode_raises(self):
        from config import ScanMode

        with pytest.raises(ValueError):
            ScanMode("turbo")

    def test_stealth_sets_conservative_defaults(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "stealth")
        for var in ("SCAN_DELAY", "NUCLEI_RATE_LIMIT", "DIRFUZZ_RATE_LIMIT",
                    "DIRFUZZ_THREADS", "SQLMAP_LEVEL", "SQLMAP_RISK"):
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.request_delay == 2.0
        assert c.nuclei_rate_limit == 2
        assert c.dirfuzz_rate_limit == 5
        assert c.dirfuzz_threads == 5
        assert c.sqlmap_level == 1
        assert c.sqlmap_risk == 1

    def test_normal_preserves_existing_defaults(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "normal")
        for var in ("SCAN_DELAY", "NUCLEI_RATE_LIMIT", "DIRFUZZ_RATE_LIMIT",
                    "DIRFUZZ_THREADS", "SQLMAP_LEVEL", "SQLMAP_RISK"):
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.request_delay == 0.5
        assert c.nuclei_rate_limit == 10
        assert c.dirfuzz_rate_limit == 20
        assert c.dirfuzz_threads == 40
        assert c.sqlmap_level == 2

    def test_raid_sets_aggressive_defaults(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "raid")
        for var in ("SCAN_DELAY", "NUCLEI_RATE_LIMIT", "DIRFUZZ_RATE_LIMIT",
                    "DIRFUZZ_THREADS", "SQLMAP_LEVEL", "SQLMAP_RISK"):
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.request_delay == 0.05
        assert c.nuclei_rate_limit == 100
        assert c.dirfuzz_rate_limit == 150
        assert c.dirfuzz_threads == 80
        assert c.sqlmap_level == 3
        assert c.sqlmap_risk == 2

    def test_explicit_env_var_wins_over_mode(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "stealth")
        monkeypatch.setenv("NUCLEI_RATE_LIMIT", "50")
        monkeypatch.delenv("SCAN_DELAY", raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.nuclei_rate_limit == 50  # explicit wins
        assert c.request_delay == 2.0     # mode default applies

    def test_default_mode_is_normal(self, monkeypatch):
        monkeypatch.delenv("SCAN_MODE", raising=False)
        for var in ("SCAN_DELAY", "NUCLEI_RATE_LIMIT"):
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.scan_mode == "normal"
        assert c.request_delay == 0.5


class TestAdaptiveSleep:
    def test_sleeps_for_given_delay(self, monkeypatch):
        import importlib

        import config as cfg_module

        importlib.reload(cfg_module)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep") as mock_sleep:
            adaptive_sleep(1.0, 200)
        mock_sleep.assert_called_once_with(1.0)

    def test_429_doubles_delay(self, monkeypatch):
        monkeypatch.delenv("SCAN_MODE", raising=False)
        monkeypatch.delenv("SCAN_DELAY", raising=False)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(1.0, 429)
        assert new_delay == 2.0

    def test_429_caps_at_60_seconds(self, monkeypatch):
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(50.0, 429)
        assert new_delay == 60.0

    def test_200_recovers_elevated_delay(self, monkeypatch):
        monkeypatch.delenv("SCAN_MODE", raising=False)
        monkeypatch.setenv("SCAN_DELAY", "0.5")
        import importlib

        import config as cfg_module

        importlib.reload(cfg_module)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(10.0, 200)
        # should recover towards base (0.5) by 10%
        assert new_delay == pytest.approx(9.0, rel=0.01)

    def test_200_at_base_delay_stays_constant(self, monkeypatch):
        monkeypatch.setenv("SCAN_DELAY", "0.5")
        import importlib

        import config as cfg_module

        importlib.reload(cfg_module)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(0.5, 200)
        assert new_delay == 0.5

    def test_recovery_does_not_go_below_base(self, monkeypatch):
        monkeypatch.setenv("SCAN_DELAY", "0.5")
        import importlib

        import config as cfg_module

        importlib.reload(cfg_module)
        from tools._helpers import adaptive_sleep

        # elevated by only a hair above base
        with patch("time.sleep"):
            new_delay = adaptive_sleep(0.51, 200)
        assert new_delay >= 0.5
