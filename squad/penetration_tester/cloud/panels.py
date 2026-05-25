"""
Hosting control-panel exposure probes - cPanel/WHM, Plesk,
DirectAdmin, Webmin. Each derives candidate host:port pairs from
recon and checks for the panel's signature login page; a confirmed
exposed admin panel is a credentialled-attack target rather than a
direct vulnerability.

See the package-level scope-of-target FIXME in ``cloud/__init__.py``
(tracked in #156).
"""

from pydantic import BaseModel, Field

from models import RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _recon_from_path
from tools.cloud import check_cpanel, check_directadmin, check_plesk, check_webmin


class _CpanelArgs(BaseModel):
    """Explicit args_schema for the cPanel/WHM Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 2082, 2083, 2086, or 2087, or when the"
            " target appears to be a shared / managed hosting environment."
            " Probes cPanel (2082/2083) and WHM (2086/2087) on every"
            " discovered hostname."
        ),
    )


@cyber_tool("cPanel/WHM Check", args_schema=_CpanelArgs)
def cpanel_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed cPanel hosting control panel (ports 2082/2083) and
    WHM (WebHost Manager) panel (ports 2086/2087) on all discovered hostnames.
    Use when open_ports shows 2082, 2083, 2086, or 2087, or when the target
    appears to be a shared/managed hosting environment.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_cpanel(recon))


class _PleskArgs(BaseModel):
    """Explicit args_schema for the Plesk Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 8880 or 8443, or when the target is a"
            " managed hosting or VPS provider. Probes Plesk on 8880 (HTTP)"
            " and 8443 (HTTPS)."
        ),
    )


@cyber_tool("Plesk Check", args_schema=_PleskArgs)
def plesk_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed Plesk web hosting control panel on ports 8880 (HTTP)
    and 8443 (HTTPS). Use when open_ports shows 8880 or 8443, or when the
    target is a managed hosting or VPS provider.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_plesk(recon))


class _DirectadminArgs(BaseModel):
    """Explicit args_schema for the DirectAdmin Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 2222 on a target that appears to be shared"
            " hosting."
        ),
    )


@cyber_tool("DirectAdmin Check", args_schema=_DirectadminArgs)
def directadmin_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed DirectAdmin hosting control panel on port 2222.
    Use when open_ports shows 2222 on a target that appears to be shared hosting.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_directadmin(recon))


class _WebminArgs(BaseModel):
    """Explicit args_schema for the Webmin Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 10000, or when the target is a self-hosted"
            " Linux server."
        ),
    )


@cyber_tool("Webmin Check", args_schema=_WebminArgs)
def webmin_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed Webmin Linux server administration panel on port 10000.
    Use when open_ports shows 10000, or when the target is a self-hosted Linux server.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_webmin(recon))
