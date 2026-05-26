"""
mcp_servers._playwright - The Playwright MCP.

Vendor: Microsoft's official ``@playwright/mcp`` server. Source at
https://github.com/microsoft/playwright-mcp and published to npm under
``@playwright/mcp`` (pinned via the npx arg below - the package is npm,
not PyPI, so ``pyproject.toml``'s ``[project.optional-dependencies] mcp``
covers only ``mcpadapt``; the npx pin is the version review event).

Provisioned per-member to the Penetration Tester. Browser-driven recon
and DOM-level checks (rendered XSS reflection, client-side auth flows,
fetch / XHR capture, console-leak inspection) are PT's surface; other
agents do not benefit from a 200MB Chromium dependency and a 60s
first-launch download.

Launch posture, derived from the vendor README and #23's threat model:

  - ``--isolated`` is hardcoded (not env-configurable). In-memory profile
    discarded on ``browser_close``. Persistence between runs would let
    one programme's cookies / localStorage bleed into another - the
    silent variant of cross-engagement contamination.
  - ``-y`` on npx is mandatory. Without it, a fresh machine without the
    package cached triggers an interactive "ok to install?" prompt that
    hangs on stdin in a non-TTY environment - the same trap the time MCP's
    ``mcpadapt`` pre-flight already guards against.
  - ``--headless`` is the default (operator can flip via env for
    interactive debugging).
  - No ``--caps`` flag. The opt-in tool groups (vision / pdf / testing /
    devtools / storage / network) all widen the agent's surface beyond
    what the allowlist below pins. Adding a cap is a review event by
    construction - extend ``_ALLOWED_TOOLS`` and the args together.

The cybersquad-mcp skill's Rule 1 carries a typed-return gap for this
MCP: the vendor publishes TypeScript definitions only; there are no
Python Pydantic models for the tool outputs. The wrapper layer that
consumes Playwright tool returns must apply the prompt-injection-aware
free-text discipline from ``cybersquad-models`` to anything the LLM
will reason over - browser snapshots and console messages are
attacker-influenceable.
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import Sequence
from contextlib import ExitStack

from crewai.tools import BaseTool
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

from config import config

from ._common import mcp_adapter_stack_usable

logger = logging.getLogger(__name__)

# Pinned via the npx arg in ``_server_params``. The npm package, unlike
# the time MCP's PyPI distribution, cannot go in ``pyproject.toml`` - so
# the version constant lives here and the upgrade ritual (re-vet tool
# prose; refresh allowlist) hangs off this file's diff.
_PLAYWRIGHT_MCP_VERSION = "0.0.75"

# Explicit allowlist passed as ``*tool_names`` to the adapter. The vendor
# ships ~60 tools across nine capability groups; we expose the minimum
# core needed for DOM-level recon (#23) and require an explicit ritual
# (extend this tuple, re-vet the new tool's prose, ship a test) for any
# additions.
#
# Deliberately excluded:
#   browser_run_code_unsafe  - vendor README labels it "RCE-equivalent"
#                              (runs Playwright code in the server process,
#                              not the page). Never allowlist.
#   browser_handle_dialog    - dialog-handling can dismiss security warnings;
#                              defer until we have a concrete use case.
#   browser_file_upload      - upload surface deferred; recon-only.
#   browser_drag / browser_drop / browser_hover - advanced interaction
#                              deferred; click + type covers most cases.
#   browser_resize / browser_tabs / browser_fill_form - deferred; not on
#                              the critical path for recon.
#   browser_*  (vision/pdf/testing/storage/network/devtools caps) - opt-in
#                              groups gated behind ``--caps``; we do not
#                              enable any cap by default.
_ALLOWED_TOOLS: tuple[str, ...] = (
    "browser_navigate",
    "browser_navigate_back",
    "browser_snapshot",  # accessibility-tree DOM; preferred for action targeting
    "browser_take_screenshot",  # visual evidence; cannot be used to perform actions
    "browser_click",
    "browser_type",
    "browser_press_key",  # Enter/Tab/Escape for form flows and modal dismissal
    "browser_select_option",  # dropdowns - common in admin panels
    # browser_evaluate runs LLM-generated JS in the *page* context (sandboxed,
    # not in the Playwright server). Useful for inspection (window state, DOM
    # queries); the return value is attacker-controllable - consumers apply
    # the cybersquad-models free-text discipline.
    "browser_evaluate",
    "browser_network_requests",  # list (1-based index) of XHR / fetch traffic
    "browser_network_request",  # headers + body for a given index
    "browser_console_messages",  # JS errors, leaked tokens, debug output
    "browser_wait_for",  # sync on text appear / disappear / time
    "browser_close",  # lifecycle - releases the isolated profile
)


def _server_params() -> StdioServerParameters:
    """``StdioServerParameters`` for ``npx -y @playwright/mcp@<pin>``.

    The ``-y`` flag suppresses npx's interactive install prompt on a
    fresh cache (the same non-TTY trap the mcpadapt pre-flight already
    guards against). The pinned version lives in
    ``_PLAYWRIGHT_MCP_VERSION``; bumping it is the upgrade-ritual review
    event for this MCP.
    """
    args = ["-y", f"@playwright/mcp@{_PLAYWRIGHT_MCP_VERSION}", "--isolated"]
    if config.mcp.playwright_headless:
        args.append("--headless")
    return StdioServerParameters(command="npx", args=args)


def available() -> bool:
    """True iff the Playwright MCP can actually be started.

    Requires both the CrewAI MCP adapter stack (``mcpadapt`` via
    ``crewai-tools[mcp]``) and ``npx`` on PATH (Node.js 18+ ships it).
    If anything is missing the package-level warning fires and the
    server is skipped - mirrors the missing-binary pattern in
    ``tools/pentest/*`` (gitleaks, testssl).
    """
    return mcp_adapter_stack_usable() and shutil.which("npx") is not None


def enter(stack: ExitStack) -> Sequence[BaseTool]:
    """Materialise and start the Playwright MCP, returning its allowed tool list.

    Two-line audit log per the cybersquad-mcp skill: declared allowlist
    before construction (so audit captures intent even on a startup
    failure - a hung Chromium download, an npm registry outage), resolved
    tool names after enter (so audit captures what the server actually
    exposed under our filter).
    """
    logger.info(
        "MCP[playwright]: starting; allowed_tools=%s connect_timeout=%ds version=%s",
        _ALLOWED_TOOLS,
        config.mcp.playwright_connect_timeout_s,
        _PLAYWRIGHT_MCP_VERSION,
    )
    adapter = MCPServerAdapter(
        _server_params(),
        *_ALLOWED_TOOLS,
        connect_timeout=config.mcp.playwright_connect_timeout_s,
    )
    tools = stack.enter_context(adapter)
    logger.info("MCP[playwright]: started; tools=%s", [t.name for t in tools])
    return tools
