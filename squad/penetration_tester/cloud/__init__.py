"""squad/penetration_tester/cloud - ``@cyber_tool`` cloud / infra checks.

Split per-family across sibling sub-modules so each file owns one
cohesive exposure mechanism:

- ``storage`` - S3, Azure Blob.
- ``databases`` - Elasticsearch, CouchDB, Redis, MongoDB, PostgreSQL,
  MySQL / MariaDB.
- ``web_content`` - Sensitive Files Check, Admin Panels Check
  (endpoint-driven path probes).
- ``panels`` - cPanel/WHM, Plesk, DirectAdmin, Webmin (hosting
  control panels).
- ``dashboards`` - Grafana, Kibana, Portainer; each split into
  ``Port Check`` (typed ``list[Hostname]``) + ``Path Check`` (typed
  ``list[Endpoint]``) so each wrapper carries a single
  ``scope_filter``.
- ``service_discovery`` - Consul / Vault, same split as dashboards.

This module re-exports every wrapper + args_schema class so the parent
agent ``squad.penetration_tester.__init__`` keeps a single import site
(``from squad.penetration_tester.cloud import ...``) and the public
surface of the agent module does not change.

FIXME (third-party-infrastructure scope): the storage sub-module
(``s3_check_tool``, ``azure_storage_check_tool``) still derives its
target from ``recon.json`` because S3 / Azure buckets live on
third-party infrastructure that is not in the programme's structured
scope - ``filter_in_scope`` against ``programme.in_scope`` would
reject every candidate. The scope-of-discovery boundary there is
workspace state (``recon.programme.handle`` plus the S3 / Azure
subdomains ``finalise_recon`` already scope-filtered into
``recon.subdomains``). The broader scope-semantics work (third-party
infrastructure: storage today, Entra / on-prem DCs tomorrow) is the
``#83`` framework follow-on. Every other cloud wrapper carries a
wrapper-level ``scope_filter`` and is structurally aligned.
"""

from squad.penetration_tester.cloud.dashboards import (
    _GrafanaPathArgs,
    _GrafanaPortArgs,
    _KibanaPathArgs,
    _KibanaPortArgs,
    _PortainerPathArgs,
    _PortainerPortArgs,
    grafana_path_check_tool,
    grafana_port_check_tool,
    kibana_path_check_tool,
    kibana_port_check_tool,
    portainer_path_check_tool,
    portainer_port_check_tool,
)
from squad.penetration_tester.cloud.databases import (
    _CouchdbCheckArgs,
    _ElasticsearchCheckArgs,
    _MongodbCheckArgs,
    _MysqlCheckArgs,
    _PostgresqlCheckArgs,
    _RedisCheckArgs,
    couchdb_tool,
    elasticsearch_tool,
    mongodb_tool,
    mysql_tool,
    postgresql_tool,
    redis_tool,
)
from squad.penetration_tester.cloud.panels import (
    _CpanelArgs,
    _DirectadminArgs,
    _PleskArgs,
    _WebminArgs,
    cpanel_tool,
    directadmin_tool,
    plesk_tool,
    webmin_tool,
)
from squad.penetration_tester.cloud.service_discovery import (
    _ConsulVaultPathArgs,
    _ConsulVaultPortArgs,
    consul_vault_path_check_tool,
    consul_vault_port_check_tool,
)
from squad.penetration_tester.cloud.storage import (
    _AzureStorageCheckArgs,
    _S3CheckArgs,
    azure_storage_check_tool,
    s3_check_tool,
)
from squad.penetration_tester.cloud.web_content import (
    _AdminPanelsArgs,
    _SensitiveFilesArgs,
    admin_panels_tool,
    sensitive_files_tool,
)

__all__ = [
    # dashboards
    "_GrafanaPathArgs",
    "_GrafanaPortArgs",
    "_KibanaPathArgs",
    "_KibanaPortArgs",
    "_PortainerPathArgs",
    "_PortainerPortArgs",
    "grafana_path_check_tool",
    "grafana_port_check_tool",
    "kibana_path_check_tool",
    "kibana_port_check_tool",
    "portainer_path_check_tool",
    "portainer_port_check_tool",
    # databases
    "_CouchdbCheckArgs",
    "_ElasticsearchCheckArgs",
    "_MongodbCheckArgs",
    "_MysqlCheckArgs",
    "_PostgresqlCheckArgs",
    "_RedisCheckArgs",
    "couchdb_tool",
    "elasticsearch_tool",
    "mongodb_tool",
    "mysql_tool",
    "postgresql_tool",
    "redis_tool",
    # panels
    "_CpanelArgs",
    "_DirectadminArgs",
    "_PleskArgs",
    "_WebminArgs",
    "cpanel_tool",
    "directadmin_tool",
    "plesk_tool",
    "webmin_tool",
    # service_discovery
    "_ConsulVaultPathArgs",
    "_ConsulVaultPortArgs",
    "consul_vault_path_check_tool",
    "consul_vault_port_check_tool",
    # storage
    "_AzureStorageCheckArgs",
    "_S3CheckArgs",
    "azure_storage_check_tool",
    "s3_check_tool",
    # web_content
    "_AdminPanelsArgs",
    "_SensitiveFilesArgs",
    "admin_panels_tool",
    "sensitive_files_tool",
]
