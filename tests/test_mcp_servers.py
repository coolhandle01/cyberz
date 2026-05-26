"""
tests/test_mcp_servers.py - unit tests for the provisioned-MCP module.

Covers the three observable behaviours of ``provisioned_mcp_tools()``:

  1. Yields an empty registry when no MCP is enabled.
  2. Constructs and enters the time adapter when ``time_enabled`` is True
     *and* ``mcp_server_time`` is importable.
  3. Skips the time adapter (with a warning) when ``time_enabled`` is True
     but the vendor package is not importable.

``MCPServerAdapter`` is mocked at the ``mcp_servers`` import boundary so
no subprocess is started; the discipline being checked is that
``provisioned_mcp_tools()`` is the only construction site - the mocks
prove the wiring, not the adapter's runtime behaviour.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _reload_mcp_servers():
    """Reload `mcp_servers` so it picks up the patched env / module state."""
    import importlib

    import config
    import mcp_servers

    importlib.reload(config)
    importlib.reload(mcp_servers)
    return mcp_servers


class TestProvisionedMCPToolsDisabled:
    def test_yields_empty_when_no_mcp_enabled(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        with mcp_servers.provisioned_mcp_tools() as registry:
            assert registry.crew_wide == ()

    def test_does_not_construct_adapter_when_disabled(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        sentinel_adapter = MagicMock()
        monkeypatch.setattr(mcp_servers, "MCPServerAdapter", sentinel_adapter)

        with mcp_servers.provisioned_mcp_tools():
            pass

        sentinel_adapter.assert_not_called()


class TestProvisionedMCPToolsTimeEnabled:
    def test_constructs_time_adapter_when_available(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        # Fake adapter whose __enter__ returns a known tool list.
        fake_tool = MagicMock(name="get_current_time")
        fake_adapter_cm = MagicMock()
        fake_adapter_cm.__enter__ = MagicMock(return_value=[fake_tool])
        fake_adapter_cm.__exit__ = MagicMock(return_value=None)

        adapter_factory = MagicMock(return_value=fake_adapter_cm)
        monkeypatch.setattr(mcp_servers, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers, "_mcp_server_time_available", lambda: True)

        with mcp_servers.provisioned_mcp_tools() as registry:
            assert registry.crew_wide == (fake_tool,)

        adapter_factory.assert_called_once()
        fake_adapter_cm.__enter__.assert_called_once()
        fake_adapter_cm.__exit__.assert_called_once()

    def test_skips_with_warning_when_vendor_package_missing(self, monkeypatch, caplog):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers, "_mcp_server_time_available", lambda: False)

        with caplog.at_level("WARNING", logger="mcp_servers"):
            with mcp_servers.provisioned_mcp_tools() as registry:
                assert registry.crew_wide == ()

        adapter_factory.assert_not_called()
        assert any("mcp_server_time" in r.message for r in caplog.records)

    def test_time_timezone_is_threaded_into_server_params(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_TIMEZONE", "Europe/London")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._time_server_params()

        assert "--local-timezone" in params.args
        tz_index = params.args.index("--local-timezone") + 1
        assert params.args[tz_index] == "Europe/London"


class TestProvisionedMCPToolsRegistryShape:
    def test_default_registry_is_empty(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        registry = mcp_servers.ProvisionedMCPTools()

        assert registry.crew_wide == ()

    def test_registry_is_frozen(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        registry = mcp_servers.ProvisionedMCPTools(crew_wide=(MagicMock(),))

        with pytest.raises((AttributeError, TypeError)):
            registry.crew_wide = ()
