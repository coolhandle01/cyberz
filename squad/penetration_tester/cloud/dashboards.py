"""
Monitoring / orchestration dashboard probes - Grafana, Kibana,
Portainer. Each derives candidate host:port pairs from recon and
looks for the dashboard's signature unauthenticated landing page;
default-credential / anonymous-access flavours are reported with the
specific exposure mode.

See the package-level scope-of-target FIXME in ``cloud/__init__.py``
(tracked in #156).
"""

from pydantic import BaseModel, Field

from models import RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _recon_from_path
from tools.cloud import check_grafana, check_kibana, check_portainer


class _GrafanaArgs(BaseModel):
    """Explicit args_schema for the Grafana Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 3000, technologies mention Grafana, or the"
            " target is a DevOps / SRE-heavy organisation. Also probes"
            " /grafana reverse-proxy paths on existing endpoints."
        ),
    )


@cyber_tool("Grafana Check", args_schema=_GrafanaArgs)
def grafana_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed Grafana metrics dashboard on port 3000 and via /grafana
    reverse-proxy path on existing endpoints.
    Use when open_ports shows 3000, or when technologies mention Grafana, or when
    the target is a DevOps/SRE-heavy organisation.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_grafana(recon))


class _KibanaArgs(BaseModel):
    """Explicit args_schema for the Kibana Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 5601 or 9200 (Elasticsearch stack), or when"
            " technologies mention Kibana or Elasticsearch. Also probes"
            " /kibana reverse-proxy paths on existing endpoints."
        ),
    )


@cyber_tool("Kibana Check", args_schema=_KibanaArgs)
def kibana_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed Kibana log/data visualisation dashboard on port 5601 and
    via /kibana reverse-proxy path on existing endpoints.
    Use when open_ports shows 5601 or 9200 (Elasticsearch stack), or when
    technologies mention Kibana or Elasticsearch.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_kibana(recon))


class _PortainerArgs(BaseModel):
    """Explicit args_schema for the Portainer Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 9000, or when technologies mention Docker /"
            " containerised infrastructure. Also probes /portainer"
            " reverse-proxy paths on existing endpoints."
        ),
    )


@cyber_tool("Portainer Check", args_schema=_PortainerArgs)
def portainer_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed Portainer Docker management UI on port 9000 and via
    /portainer reverse-proxy path on existing endpoints.
    Use when open_ports shows 9000, or when technologies mention Docker or
    containerised infrastructure.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_portainer(recon))
