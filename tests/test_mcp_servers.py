"""
tests/test_mcp_servers.py - unit tests for the provisioned-MCP package.

Mock targets land on the per-MCP submodule (today only ``_time``) because
that is where ``MCPServerAdapter`` is imported and the availability
checks live. The package-level ``provisioned_mcp_tools()`` orchestrator
imports a name from ``_common``; monkeypatch the function on the *parent
package's* module-level namespace to control the dispatched branch.

``MCPServerAdapter`` is mocked so no subprocess is started; the discipline
being checked is that ``provisioned_mcp_tools()`` is the only construction
site - the mocks prove the wiring, not the adapter's runtime behaviour.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _reload_mcp_servers():
    """Reload ``mcp_servers`` (and submodules) so env / module state refreshes.

    Reloading the package re-runs ``__init__.py``; the submodules cached
    in ``sys.modules`` keep their identity across reloads, so the
    ``from . import _playwright, _time`` in ``__init__.py`` re-binds the
    same module objects - patches the test makes on ``mcp_servers._time``
    or ``mcp_servers._playwright`` survive through the package-level
    dispatch.
    """
    import importlib

    import config
    import mcp_servers
    import mcp_servers._common as mcp_common
    import mcp_servers._playwright as mcp_playwright
    import mcp_servers._time as mcp_time

    importlib.reload(config)
    importlib.reload(mcp_common)
    importlib.reload(mcp_time)
    importlib.reload(mcp_playwright)
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
        monkeypatch.setattr(mcp_servers._time, "MCPServerAdapter", sentinel_adapter)

        with mcp_servers.provisioned_mcp_tools():
            pass

        sentinel_adapter.assert_not_called()


class TestProvisionedMCPToolsTimeEnabled:
    def _wire_fake_adapter(self, monkeypatch, mcp_servers, fake_tool):
        """Common scaffold: a fake MCPServerAdapter returning ``fake_tool``.

        Patches land on ``mcp_servers._time`` (where MCPServerAdapter is
        imported) and ``mcp_servers._time.available`` (the per-MCP
        availability check).
        """
        fake_adapter_cm = MagicMock()
        fake_adapter_cm.__enter__ = MagicMock(return_value=[fake_tool])
        fake_adapter_cm.__exit__ = MagicMock(return_value=None)

        adapter_factory = MagicMock(return_value=fake_adapter_cm)
        monkeypatch.setattr(mcp_servers._time, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers._time, "available", lambda: True)
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
        is to extend ``_ALLOWED_TOOLS`` in the submodule after re-vetting
        the new tool's prose - a review event by construction.
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

        with caplog.at_level("INFO", logger="mcp_servers._time"):
            with mcp_servers.provisioned_mcp_tools():
                pass

        messages = [r.message for r in caplog.records]
        assert any("starting" in m and "allowed_tools" in m for m in messages)
        assert any("started" in m and "get_current_time" in m for m in messages)

    def test_skips_with_warning_when_time_package_missing(self, monkeypatch, caplog):
        """mcpadapt available but `mcp_server_time` itself is not.

        Pin BOTH availability checks so the test does not depend on
        whether the venv has `mcpadapt` or `mcp_server_time` installed.
        CI installs `.[dev]` not `.[mcp]`, so neither is present there;
        this test pretends the adapter stack is fine but the vendor
        server module is the only missing piece.
        """
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers._time, "MCPServerAdapter", adapter_factory)
        # The orchestrator imports `mcp_adapter_stack_usable` from `_common`
        # into the package-level namespace; patching here is sufficient
        # because the orchestrator only consults its local-name binding.
        monkeypatch.setattr(mcp_servers, "mcp_adapter_stack_usable", lambda: True)
        monkeypatch.setattr(mcp_servers._time, "available", lambda: False)

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
        crewai-tools is present (so the import in `_time.py` succeeds)
        but mcpadapt is not, so `MCPServerAdapter.__init__` would abort
        with an interactive `click.confirm` install prompt. The pre-flight
        check turns that into a clean warning + skip.
        """
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers._time, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers, "mcp_adapter_stack_usable", lambda: False)
        monkeypatch.setattr(mcp_servers._time, "available", lambda: False)

        with caplog.at_level("WARNING", logger="mcp_servers"):
            with mcp_servers.provisioned_mcp_tools() as registry:
                assert registry.crew_wide == ()

        adapter_factory.assert_not_called()
        assert any("but mcpadapt is not importable" in r.message for r in caplog.records)

    def test_time_timezone_is_threaded_into_server_params(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_TIMEZONE", "Europe/London")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._time._server_params()

        assert "--local-timezone" in params.args
        tz_index = params.args.index("--local-timezone") + 1
        assert params.args[tz_index] == "Europe/London"


class TestProvisionedMCPToolsPlaywrightEnabled:
    """Playwright is the first member-specific MCP - tools land on the
    ``penetration_tester`` bucket of the registry, not ``crew_wide``."""

    def _wire_fake_adapter(self, monkeypatch, mcp_servers, fake_tool):
        fake_adapter_cm = MagicMock()
        fake_adapter_cm.__enter__ = MagicMock(return_value=[fake_tool])
        fake_adapter_cm.__exit__ = MagicMock(return_value=None)

        adapter_factory = MagicMock(return_value=fake_adapter_cm)
        monkeypatch.setattr(mcp_servers._playwright, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers._playwright, "available", lambda: True)
        return adapter_factory, fake_adapter_cm

    def test_constructs_playwright_adapter_when_available(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        # Non-navigate fake (the navigate wrapper is exercised by
        # TestPlaywrightScopeWrapper). Pass-through tools land in the
        # registry unchanged.
        fake_tool = MagicMock()
        fake_tool.name = "browser_snapshot"
        adapter_factory, fake_adapter_cm = self._wire_fake_adapter(
            monkeypatch, mcp_servers, fake_tool
        )

        with mcp_servers.provisioned_mcp_tools() as registry:
            assert registry.penetration_tester == (fake_tool,)
            # Playwright is member-specific - crew-wide stays empty.
            assert registry.crew_wide == ()

        adapter_factory.assert_called_once()
        fake_adapter_cm.__enter__.assert_called_once()
        fake_adapter_cm.__exit__.assert_called_once()

    def test_passes_tool_allowlist_to_adapter(self, monkeypatch):
        """The Playwright allowlist excludes ``browser_run_code_unsafe``
        (vendor README labels it RCE-equivalent) and all opt-in capability
        groups. Pin the exact set so adding a tool is a review event."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        adapter_factory, _ = self._wire_fake_adapter(monkeypatch, mcp_servers, MagicMock())

        with mcp_servers.provisioned_mcp_tools():
            pass

        _params, *passed_tool_names = adapter_factory.call_args.args
        expected = (
            "browser_navigate",
            "browser_navigate_back",
            "browser_snapshot",
            "browser_take_screenshot",
            "browser_click",
            "browser_type",
            "browser_press_key",
            "browser_select_option",
            "browser_evaluate",
            "browser_network_requests",
            "browser_network_request",
            "browser_console_messages",
            "browser_wait_for",
            "browser_close",
        )
        assert tuple(passed_tool_names) == expected
        # Defence-in-depth: the RCE-equivalent tool must never appear.
        assert "browser_run_code_unsafe" not in passed_tool_names

    def test_passes_playwright_connect_timeout_to_adapter(self, monkeypatch):
        """Playwright uses its own timeout (default 60s) because first launch
        downloads ~200MB of Chromium. Honour the env override."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_CONNECT_TIMEOUT", "120")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        adapter_factory, _ = self._wire_fake_adapter(monkeypatch, mcp_servers, MagicMock())

        with mcp_servers.provisioned_mcp_tools():
            pass

        assert adapter_factory.call_args.kwargs["connect_timeout"] == 120

    def test_logs_intent_and_resolved_tool_names(self, monkeypatch, caplog):
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        fake_tool = MagicMock()
        fake_tool.name = "browser_snapshot"
        self._wire_fake_adapter(monkeypatch, mcp_servers, fake_tool)

        with caplog.at_level("INFO", logger="mcp_servers._playwright"):
            with mcp_servers.provisioned_mcp_tools():
                pass

        messages = [r.message for r in caplog.records]
        assert any("starting" in m and "allowed_tools" in m for m in messages)
        assert any("started" in m and "browser_snapshot" in m for m in messages)

    def test_skips_with_warning_when_npx_missing(self, monkeypatch, caplog):
        """mcpadapt available but npx is not on PATH.

        Pin BOTH availability checks for determinism. The warning names
        ``npx`` so the operator knows to install Node.js rather than
        chasing a pip extra.
        """
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers._playwright, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers, "mcp_adapter_stack_usable", lambda: True)
        monkeypatch.setattr(mcp_servers._playwright, "available", lambda: False)

        with caplog.at_level("WARNING", logger="mcp_servers"):
            with mcp_servers.provisioned_mcp_tools() as registry:
                assert registry.penetration_tester == ()

        adapter_factory.assert_not_called()
        assert any("but npx is not available" in r.message for r in caplog.records)

    def test_skips_with_warning_when_mcpadapt_missing(self, monkeypatch, caplog):
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers._playwright, "MCPServerAdapter", adapter_factory)
        monkeypatch.setattr(mcp_servers, "mcp_adapter_stack_usable", lambda: False)
        monkeypatch.setattr(mcp_servers._playwright, "available", lambda: False)

        with caplog.at_level("WARNING", logger="mcp_servers"):
            with mcp_servers.provisioned_mcp_tools() as registry:
                assert registry.penetration_tester == ()

        adapter_factory.assert_not_called()
        assert any("but mcpadapt is not available" in r.message for r in caplog.records)

    def test_headless_flag_threaded_into_args(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_HEADLESS", "true")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._playwright._server_params()

        assert params.command == "npx"
        assert "--headless" in params.args

    def test_headless_omitted_when_disabled(self, monkeypatch):
        """Operator override for interactive debugging: ``--headless`` is
        omitted, the browser pops up locally."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_HEADLESS", "false")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._playwright._server_params()

        assert "--headless" not in params.args

    def test_isolated_flag_always_present(self, monkeypatch):
        """``--isolated`` is hardcoded - in-memory profile, no persistence
        between runs. The flag is not env-configurable because turning it
        off would let one programme's cookies / localStorage bleed into
        another, which is the silent variant of cross-engagement
        contamination."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._playwright._server_params()

        assert "--isolated" in params.args

    def test_npx_yes_flag_always_present(self, monkeypatch):
        """``-y`` on npx is mandatory: without it, a fresh cache triggers
        an interactive 'ok to install?' prompt that hangs on stdin in a
        non-TTY environment - the same trap mcpadapt's pre-flight guards
        against for the time MCP."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._playwright._server_params()

        assert params.args[0] == "-y"

    def test_pinned_package_version_in_args(self, monkeypatch):
        """The npm pin lives in the npx arg (the npm package cannot go in
        pyproject.toml). Bumping the constant is the upgrade-ritual review
        event - the test catches a stale package@<old> still being launched
        after the file was changed (or vice versa)."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._playwright._server_params()

        pkg_arg = next(a for a in params.args if a.startswith("@playwright/mcp@"))
        assert pkg_arg == f"@playwright/mcp@{mcp_servers._playwright._PLAYWRIGHT_MCP_VERSION}"

    def test_block_service_workers_flag_always_present(self, monkeypatch):
        """``--block-service-workers`` is hardcoded for the same reason
        ``--isolated`` is: SWs issue background fetches that would bypass
        the agent-side scope discipline on ``browser_navigate``. The vendor
        warns that ``--allowed-origins`` is not a security boundary; blocking
        SWs closes the most obvious circumvention path."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        mcp_servers = _reload_mcp_servers()

        params = mcp_servers._playwright._server_params()

        assert "--block-service-workers" in params.args

    def test_disabled_means_adapter_not_constructed(self, monkeypatch):
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        adapter_factory = MagicMock()
        monkeypatch.setattr(mcp_servers._playwright, "MCPServerAdapter", adapter_factory)

        with mcp_servers.provisioned_mcp_tools() as registry:
            assert registry.penetration_tester == ()

        adapter_factory.assert_not_called()


class TestPlaywrightScopeWrapper:
    """The Playwright MCP layer ships its tools unwrapped from mcpadapt -
    they do not pass through ``@cyber_tool``'s typed ``TargetHostname``
    boundary. ``_ScopedBrowserNavigate`` restores the input-edge symmetry
    on the one tool that takes a URL arg directly. These tests pin the
    enforcement and the pass-through behaviour for everything else."""

    @pytest.fixture()
    def fake_navigate(self):
        """A real ``BaseTool`` standing in for the mcpadapt-shipped
        ``browser_navigate``. Records the kwargs the wrapper forwarded
        on a successful in-scope call."""
        from crewai.tools import BaseTool
        from pydantic import BaseModel, Field

        captured: dict[str, object] = {}

        class _NavArgs(BaseModel):
            url: str = Field(description="URL to navigate to.")

        class _FakeNavigate(BaseTool):
            name: str = "browser_navigate"
            description: str = "Navigate the browser to a URL."
            args_schema: type[BaseModel] = _NavArgs

            def _run(self, **kwargs):
                captured.update(kwargs)
                return "navigated"

        return _FakeNavigate(), captured

    def test_in_scope_url_delegates_to_inner(self, programme_in_workspace, fake_navigate):
        """``BaseTool.run`` validates kwargs against ``args_schema`` then
        calls ``_run``; the agent invocation path always goes through
        ``run`` so the args-schema validation is what we test against."""
        from mcp_servers._playwright import _ScopedBrowserNavigate

        inner, captured = fake_navigate
        wrapper = _ScopedBrowserNavigate(inner)

        # programme_in_workspace's in_scope includes "*.example.com".
        result = wrapper.run(url="https://victim.example.com/login")

        assert result == "navigated"
        assert captured == {"url": "https://victim.example.com/login"}

    def test_out_of_scope_url_raises_without_calling_inner(
        self, programme_in_workspace, fake_navigate
    ):
        from mcp_servers._playwright import _ScopedBrowserNavigate

        inner, captured = fake_navigate
        wrapper = _ScopedBrowserNavigate(inner)

        # BaseTool.run wraps Pydantic's ValidationError in a ValueError
        # prefixed "Tool '<name>' arguments validation failed: ...".
        with pytest.raises(ValueError, match="not in the selected programme's scope"):
            wrapper.run(url="https://bystander.example.org/anything")

        assert captured == {}

    def test_unparseable_url_raises_without_calling_inner(
        self, programme_in_workspace, fake_navigate
    ):
        """``TargetUrl`` stacks on ``HttpUrl`` (URL shape + host
        strictness + empty-authority rejection) so a malformed URL is
        refused by the inner validator before the scope check ever runs.
        ``BaseTool.run`` wraps the ValidationError in a ValueError
        prefixed 'Tool ... arguments validation failed:'."""
        from mcp_servers._playwright import _ScopedBrowserNavigate

        inner, captured = fake_navigate
        wrapper = _ScopedBrowserNavigate(inner)

        with pytest.raises(ValueError, match="arguments validation failed"):
            wrapper.run(url="not-a-real-url")

        assert captured == {}

    def test_missing_url_arg_raises(self, programme_in_workspace, fake_navigate):
        """Pydantic surfaces the missing-required-field error through
        ``BaseTool.run``'s validation envelope."""
        from mcp_servers._playwright import _ScopedBrowserNavigate

        inner, _ = fake_navigate
        wrapper = _ScopedBrowserNavigate(inner)

        with pytest.raises(ValueError, match="arguments validation failed"):
            wrapper.run()

    def test_wrapper_forwards_inner_name_and_description(self, fake_navigate):
        """The agent menu and CrewAI description-generation read these
        fields from the wrapper. ``args_schema`` is intentionally NOT
        forwarded - the wrapper substitutes a scope-typed schema so the
        LLM sees the scope constraint in the URL field's description."""
        from mcp_servers._playwright import (
            _ScopedBrowserNavigate,
            _ScopedBrowserNavigateArgs,
        )

        inner, _ = fake_navigate
        wrapper = _ScopedBrowserNavigate(inner)

        assert wrapper.name == inner.name == "browser_navigate"
        assert wrapper.description == inner.description
        # The scoped args_schema replaces the inner's so the URL field
        # carries the TargetUrl AfterValidator.
        assert wrapper.args_schema is _ScopedBrowserNavigateArgs

    def test_wrap_scope_enforcement_only_wraps_browser_navigate(self, fake_navigate):
        """Every other allowlisted tool reaches the agent unchanged - they
        either take no URL or operate on the already-loaded page, so
        adding a wrapper would be code without enforcement."""
        from crewai.tools import BaseTool
        from pydantic import BaseModel

        from mcp_servers._playwright import _ScopedBrowserNavigate, _wrap_scope_enforcement

        navigate, _ = fake_navigate

        class _NoArgs(BaseModel):
            pass

        class _FakeSnapshot(BaseTool):
            name: str = "browser_snapshot"
            description: str = "Snapshot the current page."
            args_schema: type[BaseModel] = _NoArgs

            def _run(self, **kwargs):
                return "snap"

        class _FakeEvaluate(BaseTool):
            name: str = "browser_evaluate"
            description: str = "Evaluate JS in the page."
            args_schema: type[BaseModel] = _NoArgs

            def _run(self, **kwargs):
                return "eval"

        snapshot = _FakeSnapshot()
        evaluate = _FakeEvaluate()

        wrapped = _wrap_scope_enforcement([navigate, snapshot, evaluate])

        assert isinstance(wrapped[0], _ScopedBrowserNavigate)
        # Snapshot and evaluate are returned by identity - no wrapping.
        assert wrapped[1] is snapshot
        assert wrapped[2] is evaluate

    def test_enter_returns_wrapped_browser_navigate(self, monkeypatch):
        """End-to-end through ``enter(stack)``: the tool list the
        orchestrator hands to ``ProvisionedMCPTools.penetration_tester``
        carries the scoped variant, not the raw mcpadapt tool."""
        monkeypatch.setenv("CYBERSQUAD_MCP_PLAYWRIGHT_ENABLED", "true")
        monkeypatch.setenv("CYBERSQUAD_MCP_TIME_ENABLED", "false")
        mcp_servers = _reload_mcp_servers()

        from crewai.tools import BaseTool
        from pydantic import BaseModel, Field

        class _NavArgs(BaseModel):
            url: str = Field(description="URL to navigate to.")

        class _FakeNavigate(BaseTool):
            name: str = "browser_navigate"
            description: str = "navigate"
            args_schema: type[BaseModel] = _NavArgs

            def _run(self, **kwargs):
                return "fake"

        fake_tool = _FakeNavigate()
        fake_adapter_cm = MagicMock()
        fake_adapter_cm.__enter__ = MagicMock(return_value=[fake_tool])
        fake_adapter_cm.__exit__ = MagicMock(return_value=None)
        monkeypatch.setattr(
            mcp_servers._playwright, "MCPServerAdapter", MagicMock(return_value=fake_adapter_cm)
        )
        monkeypatch.setattr(mcp_servers._playwright, "available", lambda: True)

        with mcp_servers.provisioned_mcp_tools() as registry:
            assert len(registry.penetration_tester) == 1
            assert isinstance(
                registry.penetration_tester[0], mcp_servers._playwright._ScopedBrowserNavigate
            )
            # The wrapper preserves the inner tool's name so the agent
            # menu and CrewAI description-generation see the same surface.
            assert registry.penetration_tester[0].name == "browser_navigate"


class TestAvailabilityChecks:
    """The other tests monkeypatch the availability functions for
    determinism. These tests exercise the real ``importlib.util.find_spec``
    branches so the production code paths stay covered.

    Returning a bool either way is the contract; the actual True/False
    depends on whether the venv has ``mcpadapt`` / ``mcp_server_time``
    installed (CI: only ``.[dev]`` => False; dev: ``.[dev,mcp]`` => True).
    """

    def test_mcp_adapter_stack_usable_returns_bool(self):
        from mcp_servers._common import mcp_adapter_stack_usable

        assert isinstance(mcp_adapter_stack_usable(), bool)

    def test_time_available_returns_bool(self):
        from mcp_servers._time import available

        assert isinstance(available(), bool)

    def test_playwright_available_returns_bool(self):
        from mcp_servers._playwright import available

        assert isinstance(available(), bool)


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
