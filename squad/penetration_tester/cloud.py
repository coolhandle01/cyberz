"""
squad/penetration_tester/cloud.py - the 18 @cyber_tool cloud / infra
wrappers on the Penetration Tester.

Each wrapper checks an exposed cloud service or admin panel against the
hosts surfaced in recon. Co-locates every check's args_schema with its
wrapper (the cybersquad-tool skill's "schema lives inline in the same
module as the wrapper" rule). The file is just over the per-module
line budget pylint enforces; the suppression below carries the
rationale - this is the canonical cloud / infra check registry, one
cohesive responsibility per #147, and splitting per-engine would
obscure the per-check contract.
"""

# pylint: disable=C0302  # registry of every @cyber_tool cloud / infra wrapper

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _parse_endpoints, _recon_from_path
from tools.cloud import (
    check_admin_panels,
    check_azure_storage,
    check_consul_vault,
    check_couchdb,
    check_cpanel,
    check_directadmin,
    check_elasticsearch,
    check_grafana,
    check_kibana,
    check_mongodb,
    check_mysql,
    check_plesk,
    check_portainer,
    check_postgresql,
    check_redis,
    check_s3_buckets,
    check_sensitive_files,
    check_webmin,
)


class _S3CheckArgs(BaseModel):
    """Explicit args_schema for the S3 Bucket Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Buckets are"
            " derived from the programme handle and any S3 subdomains the"
            " OSINT Analyst surfaced. Worth firing when the target is known"
            " to use AWS or when *.s3 / *.s3.amazonaws.com subdomains appear"
            " in recon."
        ),
    )


@cyber_tool("S3 Bucket Check", args_schema=_S3CheckArgs)
def s3_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for publicly accessible or listable AWS S3 buckets derived from the
    programme handle and any S3 subdomains in the recon surface.
    Use when the target is known to use AWS, or when S3 subdomains appear in recon.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_s3_buckets(recon))


class _AzureStorageCheckArgs(BaseModel):
    """Explicit args_schema for the Azure Blob Storage Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when the"
            " target is known to use Azure, or when"
            " *.blob.core.windows.net subdomains appear in recon. Probes for"
            " public containers and SAS-token leakage in endpoint URLs."
        ),
    )


@cyber_tool("Azure Blob Storage Check", args_schema=_AzureStorageCheckArgs)
def azure_storage_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for publicly accessible Azure Blob Storage containers and exposed SAS
    tokens in endpoint URLs. Use when the target is known to use Azure, or when
    *.blob.core.windows.net subdomains appear in recon.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_azure_storage(recon))


class _ElasticsearchCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated Elasticsearch Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 9200, or when technologies mention"
            " Elasticsearch. Probes /_cluster/health; a 200 with"
            " cluster_name confirms no auth."
        ),
    )


@cyber_tool("Unauthenticated Elasticsearch Check", args_schema=_ElasticsearchCheckArgs)
def elasticsearch_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an unauthenticated Elasticsearch instance on port 9200.
    Probes /_cluster/health - a 200 response with cluster_name confirms no auth.
    Use when open_ports shows 9200, or when technologies mention Elasticsearch.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    findings = []
    for host, ports in recon.open_ports.items():
        if 9200 in ports:
            findings.extend(check_elasticsearch(host))
    return list(findings)


class _CouchdbCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated CouchDB Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 5984. Probes /_all_dbs; a 200 listing"
            " databases confirms no auth."
        ),
    )


@cyber_tool("Unauthenticated CouchDB Check", args_schema=_CouchdbCheckArgs)
def couchdb_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an unauthenticated CouchDB instance on port 5984.
    Probes /_all_dbs - a 200 response listing databases confirms no auth.
    Use when open_ports shows 5984.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    findings = []
    for host, ports in recon.open_ports.items():
        if 5984 in ports:
            findings.extend(check_couchdb(host))
    return list(findings)


class _RedisCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated Redis Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 6379. Sends a PING; a +PONG without AUTH"
            " confirms no password is set."
        ),
    )


@cyber_tool("Unauthenticated Redis Check", args_schema=_RedisCheckArgs)
def redis_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an unauthenticated Redis instance on port 6379 via a PING command.
    A +PONG response without sending AUTH confirms no password is set.
    Use when open_ports shows 6379.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    findings = []
    for host, ports in recon.open_ports.items():
        if 6379 in ports:
            findings.extend(check_redis(host))
    return list(findings)


class _MongodbCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated MongoDB Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 27017. Sends a minimal isMaster wire query;"
            " a valid response without error confirms unauthenticated"
            " access."
        ),
    )


@cyber_tool("Unauthenticated MongoDB Check", args_schema=_MongodbCheckArgs)
def mongodb_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for an unauthenticated MongoDB instance on port 27017.
    Sends a minimal isMaster wire-protocol query - a valid response without
    error confirms the instance accepts connections without credentials.
    Use when open_ports shows 27017.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    findings = []
    for host, ports in recon.open_ports.items():
        if 27017 in ports:
            findings.extend(check_mongodb(host))
    return list(findings)


class _PostgresqlCheckArgs(BaseModel):
    """Explicit args_schema for the Exposed PostgreSQL Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 5432. CRITICAL if trust authentication"
            " allows connection without a password; MEDIUM if the port is"
            " exposed but credentials are required (unnecessary internet"
            " exposure)."
        ),
    )


@cyber_tool("Exposed PostgreSQL Check", args_schema=_PostgresqlCheckArgs)
def postgresql_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for PostgreSQL on port 5432. Returns CRITICAL if trust authentication
    allows connection without a password; MEDIUM if the port is exposed but
    credentials are required (unnecessary internet exposure).
    Use when open_ports shows 5432.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    findings = []
    for host, ports in recon.open_ports.items():
        if 5432 in ports:
            findings.extend(check_postgresql(host))
    return list(findings)


class _MysqlCheckArgs(BaseModel):
    """Explicit args_schema for the Exposed MySQL/MariaDB Check tool (#147)."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Fire when"
            " open_ports shows 3306. MEDIUM if the port is reachable and"
            " the server responds with a valid handshake (unnecessary"
            " internet exposure; verify anonymous login is disabled)."
        ),
    )


@cyber_tool("Exposed MySQL/MariaDB Check", args_schema=_MysqlCheckArgs)
def mysql_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for MySQL or MariaDB on port 3306. Returns MEDIUM if the port is
    reachable and the server responds with a valid handshake (unnecessary
    internet exposure; verify anonymous login is disabled).
    Use when open_ports shows 3306.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    findings = []
    for host, ports in recon.open_ports.items():
        if 3306 in ports:
            findings.extend(check_mysql(host))
    return list(findings)


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


class _ConsulVaultArgs(BaseModel):
    """Explicit args_schema for the Consul/Vault Check tool (#147)."""

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
