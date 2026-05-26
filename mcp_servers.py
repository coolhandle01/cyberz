"""
mcp_servers.py - The provisioned MCP set, wired in at `build_crew()` time.

Per the `cybersquad-mcp` contributor skill, MCPs are attached at construction
time only. ``provisioned_mcp_tools()`` is the one place an
``MCPServerAdapter`` is materialised; the rest of the squad consumes the
tool list it yields. The companion rule is that *discovered* MCPs (URLs
the OSINT Analyst surfaces during a run) never come back through here -
they are recorded as evidence and probed through the dedicated MCP-attack
tool, not attached.

Three properties of CrewAI's adapter shape the design and are load-bearing
for the skill:

  1. ``MCPServerAdapter.__init__`` auto-starts the subprocess (it does not
     wait for ``__enter__``). Construction is the side-effect window -
     anywhere we materialise an adapter is a place a poisoned server can
     reach the agent's prompt menu just by being listed.
  2. The adapter accepts ``*tool_names`` as an allowlist filter. We pass
     every provisioned MCP's tools explicitly so a vendor adding a new
     tool in a version bump does not silently widen the agent's surface.
  3. ``connect_timeout`` is configurable (CrewAI default 30s). We tighten
     to ``config.mcp.connect_timeout_s`` so a hung subprocess does not
     stall the pipeline.

Adapter lifecycle is owned by an ``ExitStack`` inside the context manager:
each enabled MCP enters the stack on ``__enter__`` and its ``stop()`` runs
in reverse on ``__exit__``. ``main.py`` wraps ``crew.kickoff()`` in the
manager so subprocesses are torn down even on KeyboardInterrupt / crash.

Each MCP has a boolean in ``config.mcp``. Defaults are ``false`` so a fresh
checkout does not start subprocesses; flip them on after installing the
vendor package via ``pip install cybersquad[mcp]`` (pin is exact - see the
``[project.optional-dependencies] mcp`` block in ``pyproject.toml``).
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from typing import Any

from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

from config import config

logger = logging.getLogger(__name__)

# Explicit allowlist of tool names per provisioned MCP. Passed as the
# ``*tool_names`` filter on the adapter so a vendor version bump that adds
# a new tool does not silently widen the agent's surface - the new tool
# only appears once a contributor extends this tuple, which is a review
# event by construction. See the cybersquad-mcp skill's upgrade ritual.
_TIME_MCP_ALLOWED_TOOLS: tuple[str, ...] = ("get_current_time", "convert_time")


@dataclass(frozen=True)
class ProvisionedMCPTools:
    """The MCP-sourced tools the crew was provisioned with.

    ``crew_wide`` is the list distributed to every agent via
    ``build_agent(extra_tools=...)``. Member-specific MCP tool lists would
    live as sibling fields here (e.g. ``penetration_tester``) when the
    first non-cross-cutting MCP arrives.

    The class is frozen so a consumer cannot mutate the list in place;
    a `tuple` (not list) is the canonical immutable carrier.
    """

    crew_wide: tuple[Any, ...] = field(default_factory=tuple)


def _mcp_adapter_stack_usable() -> bool:
    """Return True iff CrewAI's MCP adapter stack is fully importable.

    ``mcpadapt`` ships under ``crewai-tools[mcp]``. Without it,
    ``MCPServerAdapter.__init__`` aborts with an interactive
    ``click.confirm`` install prompt - which in a non-TTY environment
    (CI, web session, daemon) crashes the host before our error path
    runs. Pre-checking lets us emit a *clear* warning naming the extra
    instead of letting CrewAI's interactive fallback fire.
    """
    return importlib.util.find_spec("mcpadapt") is not None


def _mcp_server_time_available() -> bool:
    """Return True iff the time MCP server can actually be started.

    Requires both the vendor server module (``mcp_server_time``) and the
    CrewAI MCP adapter stack (``mcpadapt`` via ``crewai-tools[mcp]``).
    Mirrors the missing-binary pattern in `tools/pentest/*` (gitleaks,
    testssl) - if anything is missing, we log a warning and skip rather
    than crash.
    """
    return _mcp_adapter_stack_usable() and importlib.util.find_spec("mcp_server_time") is not None


def _time_server_params() -> StdioServerParameters:
    """``StdioServerParameters`` for `python -m mcp_server_time`.

    Invoked via ``sys.executable`` so we get the same interpreter the rest
    of the squad runs under (rather than whatever ``python`` resolves to
    on PATH).
    """
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server_time", "--local-timezone", config.mcp.time_timezone],
    )


def _enter_time_adapter(stack: ExitStack) -> Sequence[Any]:
    """Materialise and start the time MCP, returning its allowed tool list.

    ``MCPServerAdapter.__init__`` starts the subprocess - construction is
    the side-effect window. We log the declared allowlist *before*
    construction (so the audit trail captures intent even on a start
    failure), then log the resolved tool names after a successful enter
    (so audit captures what the server actually exposed under our filter).
    """
    logger.info(
        "MCP[time]: starting; allowed_tools=%s connect_timeout=%ds",
        _TIME_MCP_ALLOWED_TOOLS,
        config.mcp.connect_timeout_s,
    )
    adapter = MCPServerAdapter(
        _time_server_params(),
        *_TIME_MCP_ALLOWED_TOOLS,
        connect_timeout=config.mcp.connect_timeout_s,
    )
    tools = stack.enter_context(adapter)
    logger.info("MCP[time]: started; tools=%s", [t.name for t in tools])
    return tools


@contextmanager
def provisioned_mcp_tools() -> Iterator[ProvisionedMCPTools]:
    """Construct and run the squad's MCP servers for the lifetime of the block.

    ``main.py`` wraps the entire ``crew.kickoff()`` in this manager.
    Dry-run intentionally bypasses it - the agent menu is shown from a
    no-MCP build so dry-run does not start subprocesses.

    Each adapter's ``__enter__`` connects and yields its tool list; the
    ``ExitStack`` runs ``__exit__`` in reverse on the way out, including
    on exceptions. If a server fails to start the others already started
    are stopped before the exception propagates.
    """
    crew_wide: list[Any] = []
    with ExitStack() as stack:
        if config.mcp.time_enabled:
            if _mcp_server_time_available():
                crew_wide.extend(_enter_time_adapter(stack))
            else:
                missing = "mcpadapt" if not _mcp_adapter_stack_usable() else "mcp_server_time"
                logger.warning(
                    "CYBERSQUAD_MCP_TIME_ENABLED=true but %s is not importable; skipping. "
                    "Install via `pip install -e .[mcp]` (pulls in crewai-tools[mcp] "
                    "and mcp-server-time at the pinned versions) or set "
                    "CYBERSQUAD_MCP_TIME_ENABLED=false.",
                    missing,
                )
        yield ProvisionedMCPTools(crew_wide=tuple(crew_wide))


__all__ = ["ProvisionedMCPTools", "provisioned_mcp_tools"]
