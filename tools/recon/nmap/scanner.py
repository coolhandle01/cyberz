"""Nmap orchestration: invocation, evidence persistence, public surface.

Two callable surfaces re-exported through ``tools/recon/nmap/__init__.py``:

* ``nmap_scan(hosts, mode, banner, scripts, persist_evidence)`` - the
  rich entry point. Returns ``NmapScanResult`` with per-host services,
  derived ``Technology`` rows, and (optional) evidence-XML path.
* ``port_scan(hosts)`` - backwards-compatible shim for the historical
  ``dict[host, list[ports]]`` shape consumed by ``run_recon`` and the
  legacy tests.

Composes flags via ``tools.recon.nmap.flags._assemble_flags``; parses
XML via ``tools.recon.nmap.parser._parse_xml``. This file owns only
the subprocess invocation, the rundir evidence write, and the public
function signatures.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import runtime
from config import config
from models.network import NmapBanner, NmapMode, NmapScanResult, NmapScripts
from tools._helpers import _require_binary, _run
from tools.recon.nmap.flags import _assemble_flags
from tools.recon.nmap.parser import _parse_xml

logger = logging.getLogger(__name__)


def _evidence_filename(hosts: list[str], mode: NmapMode) -> str:
    """Stable filename for the persisted XML evidence."""
    host_hash = hashlib.sha256("\n".join(sorted(hosts)).encode()).hexdigest()[:12]
    return f"nmap-{host_hash}-{mode.value}.xml"


def _resolve_evidence_path(filename: str) -> Path | None:
    """Resolve the absolute path for evidence; None if no run is bound.

    During tests (and CLI / library usage outside a pipeline run) the
    programme + run_id binding is absent. We return None so callers
    skip persistence gracefully rather than raising.
    """
    try:
        return runtime.run_dir() / filename
    except RuntimeError:
        return None


def nmap_scan(
    hosts: list[str],
    mode: NmapMode = NmapMode.QUICK_PORTS,
    banner: NmapBanner = NmapBanner.NONE,
    scripts: NmapScripts = NmapScripts.NONE,
    persist_evidence: bool = True,
) -> NmapScanResult:
    """Run nmap against ``hosts`` with typed mode / banner / scripts knobs.

    Composes the final flag list from ``(mode, banner, scripts,
    config.scan.scan_mode)`` - the OA reasons in modes, the wrapper
    handles the CLI shape. Returns a typed ``NmapScanResult`` carrying
    per-host services + derived ``Technology`` rows.

    When ``persist_evidence=True`` and a pipeline run is bound, the
    nmap XML output is also written to ``runtime.run_dir()`` and the
    relative path is set on ``NmapScanResult.evidence_path`` - the VR /
    Technical Author cite that file. When no run is bound (tests,
    library usage) the XML stays in memory only.

    Degrades gracefully on subprocess failure / parse failure -
    returns a ``NmapScanResult`` with empty hosts list. Recon should
    keep moving with whatever signal IS available.
    """
    if not hosts:
        return NmapScanResult(mode=mode, hosts=[])

    nmap_bin = _require_binary("nmap")
    flags = _assemble_flags(mode, banner, scripts, config.scan.scan_mode)
    cmd = [nmap_bin, *flags, "-oX", "-", *hosts]

    try:
        result = _run(cmd, timeout=600)
    except Exception as exc:
        logger.warning("nmap scan failed: %s", exc)
        return NmapScanResult(mode=mode, hosts=[])

    parsed = _parse_xml(result.stdout)

    evidence_rel: str | None = None
    if persist_evidence and result.stdout:
        filename = _evidence_filename(hosts, mode)
        target = _resolve_evidence_path(filename)
        if target is not None:
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(result.stdout, encoding="utf-8")
                evidence_rel = filename
            except OSError as exc:
                logger.warning("Failed to persist nmap evidence to %s: %s", target, exc)

    logger.info(
        "nmap %s: %d hosts -> %d host-results (evidence=%s)",
        mode.value,
        len(hosts),
        len(parsed),
        evidence_rel or "none",
    )
    return NmapScanResult(mode=mode, hosts=parsed, evidence_path=evidence_rel)


def port_scan(hosts: list[str]) -> dict[str, list[int]]:
    """Backwards-compatible thin shim over ``nmap_scan``.

    Calls ``nmap_scan(mode=QUICK_PORTS, persist_evidence=False)`` and
    flattens the typed result to the historical ``{host: [open_ports]}``
    shape consumed by ``tools.recon.run_recon`` and the legacy tests.
    """
    result = nmap_scan(
        hosts,
        mode=NmapMode.QUICK_PORTS,
        banner=NmapBanner.NONE,
        scripts=NmapScripts.NONE,
        persist_evidence=False,
    )
    out: dict[str, list[int]] = {host: [] for host in hosts}
    for host_result in result.hosts:
        open_ports = [s.port for s in host_result.services if s.state == "open"]
        out[host_result.host] = open_ports
    return out


__all__ = ["nmap_scan", "port_scan"]
