"""Nmap orchestration: typed modes, XML evidence to rundir, banner -> Technology.

Two callable surfaces:

* ``nmap_scan(hosts, mode, banner, scripts, persist_evidence)`` is the
  rich entry point - returns a typed ``NmapScanResult`` carrying
  per-host services, derived ``Technology`` rows from banner strings,
  and (when ``persist_evidence=True``) the relative path to the nmap
  XML file written under ``runtime.run_dir()``. Used by everything that
  wants the full nmap signal.

* ``port_scan(hosts)`` stays as a backwards-compatible shim over
  ``nmap_scan(..., mode=QUICK_PORTS, persist_evidence=False)`` -
  returns the historical ``dict[host, list[ports]]`` shape so the
  existing recon orchestrator and tests keep working.

Flag assembly composes from four axes:

* ``NmapMode`` - the kind of scan (ports / version / scripts / OS)
* ``NmapBanner`` - banner-grab depth via ``--version-intensity``
* ``NmapScripts`` - NSE bundle via ``--script=``
* ``config.scan.scan_mode`` - operator's stealth dial; sets ``-T``,
  ``--max-retries``, ``--host-timeout``, ``--min-rate``

XML output is parsed via ``defusedxml.ElementTree`` (security-hardened
parser, already in the dep chain via the XXE probe). Cybersquad does
NOT shell out to ``python-nmap`` - that wraps subprocess + XML parsing
in one library, losing both our ``tools._helpers._run`` integration
and the rundir XML evidence we want regardless.

Banner strings (service / product / version) are coerced into typed
``Technology`` values via ``tools.recon.technology.coerce_technologies``
at parse time - the same Wappalyzer-shape vocabulary the httpx
tech-detect path already speaks.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from defusedxml import ElementTree as ET

import runtime
from config import ScanMode as ConfigScanMode
from config import config
from models.network import (
    NmapBanner,
    NmapHostResult,
    NmapMode,
    NmapScanResult,
    NmapScripts,
    NmapService,
)
from tools._helpers import _require_binary, _run
from tools.recon.technology import coerce_technologies

logger = logging.getLogger(__name__)


# Per-mode base flags. Banner / scripts / scan_mode layer on top.
_MODE_FLAGS: dict[NmapMode, list[str]] = {
    NmapMode.QUICK_PORTS: ["-sS", "--open", "-F"],
    NmapMode.SERVICE_VERSION: ["-sS", "--open", "-F", "-sV"],
    NmapMode.FULL_INVENTORY: ["-sS", "--open", "-F", "-sV"],
    NmapMode.OS_DETECT: ["-O"],
}

# Banner depth maps to nmap's --version-intensity (0-9). Only applies
# when the mode runs -sV (SERVICE_VERSION / FULL_INVENTORY).
_BANNER_INTENSITY: dict[NmapBanner, str | None] = {
    NmapBanner.NONE: None,
    NmapBanner.LIGHT: "2",
    NmapBanner.FULL: "9",
}

# Script bundles. Each value is the argument to --script=.
_SCRIPTS_EXPR: dict[NmapScripts, str | None] = {
    NmapScripts.NONE: None,
    NmapScripts.HTTP_HEADERS: "banner,http-server-header,http-title",
    NmapScripts.SAFE: "safe",
    NmapScripts.VULN: "vuln",
}

# Per-scan-mode timing knobs. Maps the operator's stealth dial
# (config.scan.scan_mode) to nmap's -T timing template + retry /
# timeout / rate caps.
_SCAN_MODE_FLAGS: dict[ConfigScanMode, list[str]] = {
    ConfigScanMode.STEALTH: ["-T2", "--max-retries", "1", "--host-timeout", "60s"],
    ConfigScanMode.NORMAL: ["-T3"],
    ConfigScanMode.RAID: ["-T4", "--min-rate", "1000", "--max-retries", "3"],
}


def _assemble_flags(
    mode: NmapMode,
    banner: NmapBanner,
    scripts: NmapScripts,
    scan_mode: ConfigScanMode,
) -> list[str]:
    """Compose the final nmap flag list from the four axes.

    Refuses incompatible combinations at the boundary rather than
    letting nmap surface them mid-scan:

    * ``NmapScripts.VULN`` under ``ScanMode.STEALTH`` - loud script
      bundle against an explicit stealth posture; raise ``ValueError``
      so the OA sees the refusal and can dial back.
    """
    if scripts == NmapScripts.VULN and scan_mode == ConfigScanMode.STEALTH:
        raise ValueError(
            "NmapScripts.VULN is incompatible with ScanMode.STEALTH "
            "(vuln scripts are loud; pick SAFE or HTTP_HEADERS for stealth runs)"
        )

    flags = list(_MODE_FLAGS[mode])

    # Banner intensity only meaningful when -sV is in the base flag list.
    if "-sV" in flags:
        intensity = _BANNER_INTENSITY[banner]
        if intensity is not None:
            flags += ["--version-intensity", intensity]

    scripts_expr = _SCRIPTS_EXPR[scripts]
    if scripts_expr is not None:
        flags += [f"--script={scripts_expr}"]

    flags += _SCAN_MODE_FLAGS[scan_mode]
    return flags


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


def _parse_xml(xml_text: str) -> list[NmapHostResult]:
    """Parse nmap's XML output into ``NmapHostResult`` rows.

    Defensive - skips hosts / ports / services with mis-shaped fields
    rather than failing the whole scan. Nmap's XML format is stable
    (the DTD has not changed materially since nmap 5.x), but real-world
    runs occasionally produce truncated output (timeout mid-scan, host
    going down mid-probe).
    """
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("nmap XML parse failed: %s", exc)
        return []

    results: list[NmapHostResult] = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host_addr = addr_el.get("addr")
        if not host_addr:
            continue

        services: list[NmapService] = []
        banner_strings: list[str] = []
        for port_el in host_el.findall("ports/port"):
            try:
                port_num = int(port_el.get("portid") or "")
            except ValueError:
                continue
            protocol = port_el.get("protocol") or "tcp"
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"

            svc_el = port_el.find("service")
            service_name = svc_el.get("name") if svc_el is not None else None
            product = svc_el.get("product") if svc_el is not None else None
            version = svc_el.get("version") if svc_el is not None else None
            extra = svc_el.get("extrainfo") if svc_el is not None else None

            try:
                services.append(
                    NmapService(
                        port=port_num,
                        protocol=protocol,
                        state=state or "unknown",
                        service=service_name,
                        product=product,
                        version=version,
                        extra_info=extra,
                    )
                )
            except ValueError as exc:
                logger.debug("nmap port row skipped: %s", exc)
                continue

            # Build a Wappalyzer-shape string for the coercer. Prefer
            # ``product:version`` (richer); fall back to ``service`` (the
            # nmap-side guess from the port number when no banner ran).
            if product:
                banner_strings.append(f"{product}:{version}" if version else product)
            elif service_name:
                banner_strings.append(service_name)

        detected = coerce_technologies(banner_strings)

        try:
            results.append(
                NmapHostResult(
                    host=host_addr,
                    services=services,
                    detected_technologies=detected,
                )
            )
        except ValueError as exc:
            logger.debug("nmap host row skipped (addr %s): %s", host_addr, exc)
            continue
    return results


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
    out: dict[str, list[int]] = {}
    # Backfill keys for hosts nmap returned no row for, so callers see
    # the same "every input host has an entry" contract the old shim
    # provided.
    for host in hosts:
        out[host] = []
    for host_result in result.hosts:
        # Map by the addr nmap put in <address> - this is the IP for
        # name-only inputs, so we match against the requested host list
        # by membership.
        open_ports = [s.port for s in host_result.services if s.state == "open"]
        if host_result.host in out:
            out[host_result.host] = open_ports
        else:
            out[host_result.host] = open_ports
    return out


__all__ = ["nmap_scan", "port_scan"]
