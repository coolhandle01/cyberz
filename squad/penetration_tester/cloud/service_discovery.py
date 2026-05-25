"""
Service-discovery exposure probes - HashiCorp Consul and Vault
unauthenticated UIs. Looks for the signature consul-ui / vault-ui
endpoint at predictable ports against the recon-discovered hosts.

See the package-level scope-of-target FIXME in ``cloud/__init__.py``
(tracked in #156).
"""

from pydantic import BaseModel, Field

from models import RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _recon_from_path
from tools.cloud import check_consul_vault


class _ConsulVaultArgs(BaseModel):
    """Explicit args_schema for the Consul/Vault Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 8500 (Consul) or 8200 (Vault), or when the"
            " target is a cloud-native / microservices environment. Also"
            " probes /consul/ui and /vault/ui reverse-proxy paths on"
            " existing endpoints."
        ),
    )


@cyber_tool("Consul/Vault Check", args_schema=_ConsulVaultArgs)
def consul_vault_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an exposed HashiCorp Consul UI (port 8500) or Vault UI (port 8200),
    and via /consul/ui and /vault/ui reverse-proxy paths on existing endpoints.
    Use when open_ports shows 8500 or 8200, or when the target is a cloud-native
    or microservices environment.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_consul_vault(recon))
