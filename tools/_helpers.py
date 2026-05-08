"""Shared low-level helpers used across tools subpackages."""

from __future__ import annotations

import logging
import shutil
import subprocess

from models import Severity

logger = logging.getLogger(__name__)

_SEVERITY_FLOOR_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _require_binary(name: str) -> str:
    """Return full path to a binary or raise OSError if not found."""
    path = shutil.which(name)
    if not path:
        raise OSError(
            f"Required binary '{name}' not found in PATH. "
            f"Please install it before running the pipeline."
        )
    return path


def _run(
    cmd: list[str],
    timeout: int = 120,
    input: str | None = None,  # noqa: A002
) -> subprocess.CompletedProcess:
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input,
    )
    if result.returncode != 0:
        logger.warning("Command exited %d: %s", result.returncode, result.stderr[:500])
    return result
