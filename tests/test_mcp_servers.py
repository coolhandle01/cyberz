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
    def _wire_fake_adapter(self, monkeypatch, mcp_servers, fake_tool):
        """Common scaffold: a fake MCPServerAdapter returning ``fake_tool``."""
        fake_adapter_cm = MagicMock()
        fake_adapter_cm.__enter__ = MagicMock(return_value=[fake_tool])
        fake_adapter_cm.__exit__ = MagicMock(return_value=None)

        adapter_factory = MagicMock(return_value=fake_adapter_cm)
        monkeypatch.setattr(mcp_servers, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers, "_mcp_server_time_available", lambda: True)
        return adapter_factory, fake_adapter_cm

    def test_constructs_time_adapter_when_available(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        fake_tool = MagicMock(name="get_current_time")
        adapter_factory, fake_adapter_cm = self._wire_fake_adapter(
            monkeypatch, mcp_servers, fake_tool
        )

        with mcp_servers.provisioned_mcp_tools() as registry:
            assert registry.crew_wide == (fake_tool,)

        adapter_factory.assert_called_once()
        fake_adapter_cm.__enter__.assert_called_once()
        fake_adapter_cm.__exit__.assert_called_once()

    def test_passes_tool_allowlist_to_adapter(self, monkeypatch):
        """The ``*tool_names`` filter pins exactly which vendor tools we expose.

        Defence-in-depth: a vendor version bump that adds a new tool does
        not silently widen the agent's surface. The skill upgrade ritual
        is to extend ``_TIME_MCP_ALLOWED_TOOLS`` after re-vetting the new
        tool's prose - a review event by construction.
        """
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        adapter_factory, _ = self._wire_fake_adapter(monkeypatch, mcp_servers, MagicMock())

        with mcp_servers.provisioned_mcp_tools():
            pass

        # Adapter is called as MCPServerAdapter(params, *tool_names, connect_timeout=...).
        _params, *passed_tool_names = adapter_factory.call_args.args
        assert tuple(passed_tool_names) == ("get_current_time", "convert_time")

    def test_passes_connect_timeout_to_adapter(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_CONNECT_TIMEOUT", "7")
        mcp_servers = _reload_mcp_servers()

        adapter_factory, _ = self._wire_fake_adapter(monkeypatch, mcp_servers, MagicMock())

        with mcp_servers.provisioned_mcp_tools():
            pass

        assert adapter_factory.call_args.kwargs["connect_timeout"] == 7

    def test_logs_intent_and_resolved_tool_names(self, monkeypatch, caplog):
        """Audit trail: declared allowlist logged before adapter start,
        resolved tool names logged after - so a start failure still leaves
        the operator with a record of what was intended."""
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        fake_tool = MagicMock()
        fake_tool.name = "get_current_time"
        self._wire_fake_adapter(monkeypatch, mcp_servers, fake_tool)

        with caplog.at_level("INFO", logger="mcp_servers"):
            with mcp_servers.provisioned_mcp_tools():
                pass

        messages = [r.message for r in caplog.records]
        assert any("starting" in m and "allowed_tools" in m for m in messages)
        assert any("started" in m and "get_current_time" in m for m in messages)

    def test_skips_with_warning_when_time_package_missing(self, monkeypatch, caplog):
        """mcpadapt available but `mcp_server_time` itself is not."""
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers, "MCPServerAdapter", adapter_factory)
        # Pin BOTH availability checks so the test does not depend on
        # whether the venv has `mcpadapt` or `mcp_server_time` installed.
        # CI installs `.[dev]` not `.[mcp]`, so neither is present there;
        # this test pretends the adapter stack is fine but the vendor
        # server module is the only missing piece.
        monkeypatch.setattr(mcp_servers, "_mcp_adapter_stack_usable", lambda: True)
        monkeypatch.setattr(mcp_servers, "_mcp_server_time_available", lambda: False)

        with caplog.at_level("WARNING", logger="mcp_servers"):
            with mcp_servers.provisioned_mcp_tools() as registry:
                assert registry.crew_wide == ()

        adapter_factory.assert_not_called()
        # Underscore form is the `missing` placeholder; matching that
        # rules out the install-hint hyphenated form leaking the assertion.
        assert any("but mcp_server_time is not importable" in r.message for r in caplog.records)

    def test_skips_with_warning_when_mcpadapt_missing(self, monkeypatch, caplog):
        """The whole CrewAI MCP stack is missing (the click.confirm trap).

        This is the failure mode on a fresh `pip install -e .[dev]` -
        crewai-tools is present (so the import at top of `mcp_servers.py`
        succeeds) but mcpadapt is not, so `MCPServerAdapter.__init__`
        would abort with an interactive `click.confirm` install prompt.
        The pre-flight check turns that into a clean warning + skip.
        """
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers, "_mcp_adapter_stack_usable", lambda: False)
        monkeypatch.setattr(mcp_servers, "_mcp_server_time_available", lambda: False)

        with caplog.at_level("WARNING", logger="mcp_servers"):
            with mcp_servers.provisioned_mcp_tools() as registry:
                assert registry.crew_wide == ()

        adapter_factory.assert_not_called()
        assert any("but mcpadapt is not importable" in r.message for r in caplog.records)

    def test_time_timezone_is_threaded_into_server_params(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_TIMEZONE", "Europe/London")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._time_server_params()

        assert "--local-timezone" in params.args
        tz_index = params.args.index("--local-timezone") + 1
        assert params.args[tz_index] == "Europe/London"


class TestAvailabilityChecks:
    """The other tests monkeypatch the two availability functions for
    determinism. These tests exercise the real ``importlib.util.find_spec``
    branches so the production code paths stay covered.

    Returning a bool either way is the contract; the actual True/False
    depends on whether the venv has ``mcpadapt`` / ``mcp_server_time``
    installed (CI: only `.[dev]` => False; dev: `.[dev,mcp]` => True).
    """

    def test_mcp_adapter_stack_usable_returns_bool(self):
        mcp_servers = _reload_mcp_servers()
        assert isinstance(mcp_servers._mcp_adapter_stack_usable(), bool)

    def test_mcp_server_time_available_returns_bool(self):
        mcp_servers = _reload_mcp_servers()
        assert isinstance(mcp_servers._mcp_server_time_available(), bool)


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
