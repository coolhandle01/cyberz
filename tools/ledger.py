"""
tools/ledger.py - Filesystem persistence for campaign retrospectives.

Layout under config.reports_dir:
    programs/<handle>/campaigns/<YYYY-MM-DD>/retrospective.md

Retrospectives accumulate across runs so the squad builds institutional
memory about each programme: what worked, what failed, unexplored surface,
programme policy quirks, and tooling gaps surfaced by the suggestion box.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from config import config

logger = logging.getLogger(__name__)


def _campaign_dir(handle: str, campaign_date: str) -> Path:
    return Path(config.reports_dir) / "programs" / handle / "campaigns" / campaign_date


def write_retro(handle: str, content: str, campaign_date: str | None = None) -> Path:
    """Write a retrospective for a campaign. Defaults to today's date."""
    date = campaign_date or datetime.now(UTC).strftime("%Y-%m-%d")
    path = _campaign_dir(handle, date) / "retrospective.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    logger.info("Wrote retrospective -> %s", path)
    return path


def read_retro(handle: str, campaign_date: str) -> str | None:
    """Return the retrospective text for a specific campaign, or None."""
    path = _campaign_dir(handle, campaign_date) / "retrospective.md"
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def read_recent_retros(handle: str, n: int = 3) -> list[tuple[str, str]]:
    """Return the (date, content) for the n most recent retros for a programme."""
    base = Path(config.reports_dir) / "programs" / handle / "campaigns"
    if not base.exists():
        return []
    dated: list[tuple[str, str]] = []
    for d in sorted(base.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        retro_path = d / "retrospective.md"
        if retro_path.exists():
            dated.append((d.name, retro_path.read_text(encoding="utf-8")))
        if len(dated) >= n:
            break
    return dated
