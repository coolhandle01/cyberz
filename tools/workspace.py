"""
tools/workspace.py - read-only access to the per-run shared workspace.

Agents pass artefact paths through their task context (recon.json,
findings.json, verified.json, ...). These helpers let any agent list and
sample those files on demand without pulling the whole payload into
context - which is what motivated writing files in the first place.

Two safety invariants:

  1. Path containment. Any name passed to read_run_file is resolved under
     runtime.run_dir(). Anything that escapes (../, absolute paths to /etc,
     symlinks pointing outside) is refused. The shared workspace is a
     sandbox; these tools must not become an arbitrary-file-read primitive.
  2. Size cap. read_run_file enforces a default byte limit, plus a hard
     ceiling, so an agent cannot undo the file-path optimisation by
     slurping a 4MB recon.json in one call.
"""

from __future__ import annotations

from pathlib import Path

import runtime

# Default returned slice when the caller does not specify limit_bytes.
# Sized to fit a useful slice of typical artefacts (JSON object preview,
# first page of endpoints) without flooding the agent's context window.
DEFAULT_READ_BYTES = 8 * 1024

# Hard ceiling per call. Callers asking for more should paginate via offset
# instead of disabling the cap.
MAX_READ_BYTES = 256 * 1024


def _resolve_under_run_dir(name: str) -> Path:
    """Resolve ``name`` relative to runtime.run_dir(); refuse paths that escape.

    The check uses ``Path.resolve()`` on both ends so symlink-based escapes
    are caught too: a symlink inside run_dir pointing to /etc/passwd would
    resolve outside the run root and be refused.
    """
    run_root = runtime.run_dir().resolve()
    candidate = (run_root / name).resolve()
    if not candidate.is_relative_to(run_root):
        raise ValueError(f"refusing to read {name!r}: path escapes the run directory")
    return candidate


def list_run_files() -> list[dict]:
    """List files in the run directory (recursive) with byte sizes.

    Returns a list of {"name": <path relative to run_dir>, "size_bytes": int}
    sorted by name. Agents use this to discover what their teammates have
    written before deciding which file to sample.
    """
    run_root = runtime.run_dir().resolve()
    if not run_root.is_dir():
        return []
    out: list[dict] = []
    for path in sorted(run_root.rglob("*")):
        if not path.is_file():
            continue
        out.append(
            {
                "name": str(path.relative_to(run_root)),
                "size_bytes": path.stat().st_size,
            }
        )
    return out


def read_run_file(
    name: str,
    offset: int = 0,
    limit_bytes: int = DEFAULT_READ_BYTES,
) -> dict:
    """Read a byte slice of ``name`` from the run directory.

    Reads up to ``limit_bytes`` starting at ``offset``. Returns a dict
    containing the decoded slice (utf-8, errors=replace), the byte range
    read, the file's total size, and whether the read was truncated -
    so the caller knows whether to paginate.

    Refuses paths outside the run directory. Refuses ``limit_bytes`` above
    MAX_READ_BYTES; callers needing more should issue successive reads
    with increasing ``offset``.
    """
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit_bytes < 1 or limit_bytes > MAX_READ_BYTES:
        raise ValueError(f"limit_bytes must be between 1 and {MAX_READ_BYTES} (got {limit_bytes})")
    path = _resolve_under_run_dir(name)
    if not path.is_file():
        raise FileNotFoundError(f"{name!r} not found in run directory")
    total_size = path.stat().st_size
    with path.open("rb") as fh:
        fh.seek(offset)
        raw = fh.read(limit_bytes)
    end = offset + len(raw)
    return {
        "name": name,
        "offset": offset,
        "end": end,
        "size_bytes": total_size,
        "truncated": end < total_size,
        "content": raw.decode("utf-8", errors="replace"),
    }
