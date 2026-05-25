"""squad/penetration_tester/cloud - 18 ``@cyber_tool`` cloud / infra checks.

Split per-family across sibling sub-modules so each file owns one
cohesive exposure mechanism:

- ``storage`` - S3, Azure Blob.
- ``databases`` - Elasticsearch, CouchDB, Redis, MongoDB, PostgreSQL,
  MySQL / MariaDB.
- ``web_content`` - Sensitive Files Check, Admin Panels Check
  (endpoint-driven path probes).
- ``panels`` - cPanel/WHM, Plesk, DirectAdmin, Webmin (hosting
  control panels).
- ``dashboards`` - Grafana, Kibana, Portainer.
- ``service_discovery`` - Consul, Vault.

This module re-exports every wrapper + args_schema class so the parent
agent ``squad.penetration_tester.__init__`` keeps a single import site
(``from squad.penetration_tester.cloud import ...``) and the public
surface of the agent module does not change.

FIXME #156: every check here derives its target (bucket / container
name, host:port pair) from recon rather than from the agent's explicit
pick, so a check can probe a third-party tenant that happens to share
a name with the in-scope programme. The structural fix is a
Programme-aware pre-flight gate on every cloud wrapper; tracked in
#156 alongside the related ``recon_path`` -> typed-target direction.
"""

from squad.penetration_tester.cloud.dashboards import (
    _GrafanaArgs,
    _KibanaArgs,
    _PortainerArgs,
    grafana_tool,
    kibana_tool,
    portainer_tool,
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
    _ConsulVaultArgs,
    consul_vault_tool,
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
    "_GrafanaArgs",
    "_KibanaArgs",
    "_PortainerArgs",
    "grafana_tool",
    "kibana_tool",
    "portainer_tool",
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
    "_ConsulVaultArgs",
    "consul_vault_tool",
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
