"""
tools/workspace.py - read-only access to the per-run shared workspace.

Agents pass artefact basenames through their task context (recon.json,
findings.json, verified.json, ...). These helpers let any agent list and
sample those files on demand without pulling the whole payload into
context - which is what motivated writing files in the first place.

The API is deliberately narrow: inputs are paths *relative to* the run
directory, full stop. No absolute paths, no parent traversal. The shape
itself communicates the contract; we are not in the business of providing
arbitrary-read primitives to LLM-driven agents.

Size cap: read_run_file enforces a default byte limit plus a hard ceiling,
so an agent cannot undo the file-path optimisation by slurping a 4MB
recon.json in one call.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import runtime

# Default returned slice when the caller does not specify limit_bytes.
# Sized to fit a useful slice of typical artefacts (JSON object preview,
# first page of endpoints) without flooding the agent's context window.
DEFAULT_READ_BYTES = 8 * 1024

# Hard ceiling per call. Callers asking for more should paginate via offset
# instead of disabling the cap.
MAX_READ_BYTES = 256 * 1024


def _validate_relative_path(relative_path: str) -> PurePosixPath:
    """Validate ``relative_path`` as a relative path with no parent traversal.

    Raises ValueError on anything that is not a plain relative path. The check
    is on the *input shape*, not the resolved location: the API contract is
    "relative path under the run directory", and shapes that do not match are
    a contract violation, not a near-miss to repair.
    """
    if not relative_path:
        raise ValueError("relative_path must not be empty")
    parsed = PurePosixPath(relative_path)
    if parsed.is_absolute():
        raise ValueError(f"relative_path must be relative, not absolute: {relative_path!r}")
    if ".." in parsed.parts:
        raise ValueError(f"relative_path must not contain '..': {relative_path!r}")
    return parsed


def resolve_run_path(relative_path: str) -> Path:
    """Resolve ``relative_path`` under runtime.run_dir() with the same contract
    read_run_file enforces: relative-only, no parent traversal, no symlink
    escape. Use this in every tool that reads an inter-agent artefact - it
    keeps the "agents pass relative paths" invariant true end-to-end."""
    _validate_relative_path(relative_path)
    run_root = runtime.run_dir().resolve()
    path = (run_root / relative_path).resolve()
    if not path.is_relative_to(run_root):
        raise ValueError(f"relative_path resolves outside the run directory: {relative_path!r}")
    return path


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
    relative_path: str,
    offset: int = 0,
    limit_bytes: int = DEFAULT_READ_BYTES,
) -> dict:
    """Read a byte slice of a file in the run directory.

    ``relative_path`` is a path *relative to* runtime.run_dir() (e.g.
    "recon.json"). Absolute paths and parent traversal are not accepted.

    Reads up to ``limit_bytes`` starting at ``offset``. Returns a dict
    containing the decoded slice (utf-8, errors=replace), the byte range
    read, the file's total size, and whether the read was truncated -
    so the caller knows whether to paginate. ``limit_bytes`` above
    MAX_READ_BYTES is refused; paginate via ``offset`` instead.
    """
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit_bytes < 1 or limit_bytes > MAX_READ_BYTES:
        raise ValueError(f"limit_bytes must be between 1 and {MAX_READ_BYTES} (got {limit_bytes})")
    path = resolve_run_path(relative_path)
    if not path.is_file():
        raise FileNotFoundError(f"{relative_path!r} not found in run directory")
    total_size = path.stat().st_size
    with path.open("rb") as fh:
        fh.seek(offset)
        raw = fh.read(limit_bytes)
    end = offset + len(raw)
    return {
        "name": relative_path,
        "offset": offset,
        "end": end,
        "size_bytes": total_size,
        "truncated": end < total_size,
        "content": raw.decode("utf-8", errors="replace"),
    }
