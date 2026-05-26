"""
mcp_servers.py - The provisioned MCP set, wired in at `build_crew()` time.

Per the `cybersquad-mcp` contributor skill, MCPs are attached at construction
time only. ``provisioned_mcp_tools()`` is the one place an
``MCPServerAdapter`` is materialised; the rest of the squad consumes the
tool list it yields. The companion rule is that *discovered* MCPs (URLs
the OSINT Analyst surfaces during a run) never come back through here -
they are recorded as evidence and probed through the dedicated MCP-attack
tool, not attached.

Adapter lifecycle is owned by an ``ExitStack`` inside the context manager:
each enabled MCP enters the stack on ``__enter__`` and its ``stop()`` runs
in reverse on ``__exit__``. ``main.py`` wraps ``crew.kickoff()`` in the
manager so subprocesses are torn down even on KeyboardInterrupt / crash.

Each MCP has a boolean in ``config.mcp``. Defaults are ``false`` so a fresh
checkout does not start subprocesses; flip them on after installing the
vendor package via ``pip install cybersquad[mcp]``.
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


def _mcp_server_time_available() -> bool:
    """Return True if ``mcp_server_time`` is importable in the current env.

    Mirrors the missing-binary pattern in `tools/pentest/*` (gitleaks,
    testssl) - if the operator opted in via env but the vendor package
    is not installed, we log a warning and skip rather than crash.
    """
    return importlib.util.find_spec("mcp_server_time") is not None


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
                time_tools: Sequence[Any] = stack.enter_context(
                    MCPServerAdapter(_time_server_params())
                )
                crew_wide.extend(time_tools)
            else:
                logger.warning(
                    "CYBERSQUAD_MCP_TIME_ENABLED=true but `mcp_server_time` "
                    "is not importable; skipping. "
                    "Install via `pip install cybersquad[mcp]` or set "
                    "CYBERSQUAD_MCP_TIME_ENABLED=false."
                )
        yield ProvisionedMCPTools(crew_wide=tuple(crew_wide))


__all__ = ["ProvisionedMCPTools", "provisioned_mcp_tools"]
