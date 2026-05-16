"""
runtime.py - Mutable pipeline state set by main.py before crew.kickoff().

Tools read run_id and programme_handle to locate the current run folder
without needing those values passed as arguments through the agent layer.
"""

from __future__ import annotations

from pathlib import Path

run_id: str = ""
programme_handle: str = ""


def run_dir() -> Path:
    """Return the run-specific folder: {reports_dir}/programs/{handle}/{run_id}/"""
    from config import config

    if not programme_handle or not run_id:
        raise RuntimeError("runtime.programme_handle and run_id must be set before run_dir()")
    return Path(config.reports_dir) / "programs" / programme_handle / run_id


def programme_cache_path(handle: str) -> Path:
    """Return {reports_dir}/programs/{handle}/programme.json"""
    from config import config

    return Path(config.reports_dir) / "programs" / handle / "programme.json"
