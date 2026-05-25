"""
Exposed database / search-index probes - look for unauthenticated
admin / data endpoints on Elasticsearch, CouchDB, Redis, MongoDB,
PostgreSQL, MySQL / MariaDB. Each check derives candidate
host:port pairs from recon's open-port map and probes for the
service's signature unauthenticated endpoint.

FIXME: same caveat as cloud storage - DB endpoints should only be
probed when explicitly in scope or when the programme is the DB
provider itself. Guessing DB exposure from open-port heuristics
risks probing tenants that share infrastructure with the in-scope
programme. Track in a follow-up.
"""

from pydantic import BaseModel, Field

from models import RawFinding
from squad import cyber_tool
from squad.penetration_tester._decorator import _recon_from_path
from tools.cloud import (
    check_couchdb,
    check_elasticsearch,
    check_mongodb,
    check_mysql,
    check_postgresql,
    check_redis,
)


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
