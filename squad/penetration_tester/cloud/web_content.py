"""
Web-content exposure probes - look for sensitive files served
unintentionally (env / config / backups / VCS metadata / build
artefacts) and for admin-panel login pages exposed at predictable
paths.

Unlike the other cloud / infra wrappers in this package these take
typed ``list[Endpoint]`` (the agent picks which endpoints to ask
about) rather than a recon path - they are HTTP path probes, not
host-derived service checks.
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _parse_endpoints
from tools.cloud import check_admin_panels, check_sensitive_files


class _SensitiveFilesArgs(BaseModel):
    """Explicit args_schema for the Sensitive Files Check tool (#147)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects. Pass a representative set of live endpoints;"
            " the tool deduplicates by origin so many can be passed without"
            " redundant probes. High-value finds on any target (.git/HEAD,"
            " .env, phpinfo.php, Apache server-status, .DS_Store) - run"
            " broadly."
        ),
    )


@cyber_tool("Sensitive Files Check", args_schema=_SensitiveFilesArgs)
def sensitive_files_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Probe for exposed .git/HEAD, .env, phpinfo.php, Apache server-status, and
    .DS_Store files. Run broadly - these are high-value finds on any target.

    endpoints: list of endpoint objects. Pass a representative set of
      live endpoints; the tool deduplicates by origin so you can pass many without
      redundant probes.
      Example: [{"url": "https://example.com/", "status_code": 200}]


    """
    return list(check_sensitive_files(_parse_endpoints(endpoints)))


class _AdminPanelsArgs(BaseModel):
    """Explicit args_schema for the Admin Panels Check tool (#147)."""

    endpoints: list[Endpoint] = Field(
        description=(
            "Endpoint objects. The tool deduplicates by origin so passing"
            " many is safe. Probes common admin paths (/admin, /wp-admin,"
            " /phpmyadmin, /adminer, /manager/html, /_admin) - run broadly"
            " on all live endpoints."
        ),
    )


@cyber_tool("Admin Panels Check", args_schema=_AdminPanelsArgs)
def admin_panels_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Probe common admin panel paths: /admin, /wp-admin, /phpmyadmin, /adminer,
    /manager/html, /_admin. Run broadly on all live endpoints.

    endpoints: list of endpoint objects. The tool deduplicates by origin.
      Example: [{"url": "https://example.com/", "status_code": 200}]


    """
    return list(check_admin_panels(_parse_endpoints(endpoints)))
