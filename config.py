"""
config.py - Central configuration for the Bounty Squad pipeline.
Load secrets from environment variables; never hardcode credentials.
"""

import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

# crewai.LLM accepts reasoning_effort as one of these four strings (or None).
# Mirroring the Literal here lets mypy verify the value end-to-end at the
# LLM call site, instead of widening to str and casting later.
ReasoningEffort = Literal["none", "low", "medium", "high"]
_REASONING_EFFORT_VALUES: frozenset[str] = frozenset(("none", "low", "medium", "high"))


def _read_reasoning_effort() -> ReasoningEffort:
    raw = os.getenv("CREWAI_REASONING_EFFORT", "medium")
    if raw not in _REASONING_EFFORT_VALUES:
        valid = sorted(_REASONING_EFFORT_VALUES)
        raise ValueError(f"CREWAI_REASONING_EFFORT must be one of {valid}; got {raw!r}")
    return cast(ReasoningEffort, raw)


class ScanMode(StrEnum):
    STEALTH = "stealth"  # slow and quiet - conservative delays, low rate limits
    NORMAL = "normal"  # balanced defaults
    RAID = "raid"  # fast - aggressive rate limits, 429-adaptive backoff


_BUNDLE_WORDLIST = str(Path(__file__).parent / "data" / "wordlists" / "common.txt")


@dataclass
class H1Config:
    """HackerOne API configuration."""

    api_username: str = field(default_factory=lambda: os.environ["H1_API_USERNAME"])
    api_token: str = field(default_factory=lambda: os.environ["H1_API_TOKEN"])
    base_url: str = "https://api.hackerone.com/v1"
    # FIX: use default_factory so os.getenv is called at instantiation time,
    # not at class-definition time - allows monkeypatch to work in tests
    min_bounty_threshold: int = field(
        default_factory=lambda: int(os.getenv("H1_MIN_BOUNTY", "500"))
    )
    max_programmes: int = field(default_factory=lambda: int(os.getenv("H1_MAX_PROGRAMMES", "10")))


@dataclass
class LLMConfig:
    """LLM / CrewAI configuration."""

    model: str = field(
        default_factory=lambda: os.getenv("CREWAI_MODEL", "anthropic/claude-sonnet-4-20250514")
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("CREWAI_TEMPERATURE", "0.2"))
    )
    max_tokens: int = field(default_factory=lambda: int(os.getenv("CREWAI_MAX_TOKENS", "4096")))
    # Extended thinking via litellm. CrewAI maps reasoning_effort -> the
    # provider's native thinking budget; "none" disables, the others scale
    # thinking tokens. Off via env by setting CREWAI_REASONING_ENABLED=false.
    reasoning_enabled: bool = field(
        default_factory=lambda: os.getenv("CREWAI_REASONING_ENABLED", "true").lower() == "true"
    )
    reasoning_effort: ReasoningEffort = field(default_factory=_read_reasoning_effort)


@dataclass
class MemoryConfig:
    """CrewAI memory configuration.

    Long-term memory persists task outcomes across pipeline runs so the squad
    can learn (e.g. PM avoiding programmes the squad has recently exhausted,
    DC tracking submission status post-handover). Off by default - flipping
    it on requires an embedder, writes a LanceDB store to disk, and
    introduces non-determinism into agent reasoning. Operator override is to
    delete the storage path and set CREWAI_MEMORY_LONG_TERM_ENABLED=false.
    """

    long_term_enabled: bool = field(
        default_factory=lambda: (
            os.getenv("CREWAI_MEMORY_LONG_TERM_ENABLED", "false").lower() == "true"
        )
    )
    # Project-scoped storage so different cybersquad checkouts do not bleed
    # into each other (CrewAI's default is user-global at ~/.crewai/...).
    storage_path: str = field(
        default_factory=lambda: os.getenv("CREWAI_MEMORY_STORAGE", ".cybersquad/memory")
    )


@dataclass
class MCPConfig:
    """Provisioned MCP servers - the disjoint set owned by `build_crew()`.

    Per the cybersquad-mcp contributor skill, MCPs are wired in at
    construction time, never attached at runtime. One boolean per
    server, default ``false`` so a fresh checkout starts without
    subprocess dependencies. Flip ``<name>_enabled=true`` once the
    vendor package is installed (see ``pyproject.toml``'s
    ``[project.optional-dependencies] mcp``).
    """

    time_enabled: bool = field(
        default_factory=lambda: os.getenv("CYBERSQUAD_MCP_TIME_ENABLED", "false").lower() == "true"
    )
    # IANA tz name the server assumes when the agent omits one. UTC is the
    # conservative default so cross-programme reasoning stays comparable.
    time_timezone: str = field(
        default_factory=lambda: os.getenv("CYBERSQUAD_MCP_TIME_TIMEZONE", "UTC")
    )


@dataclass
class ReconConfig:
    """Tuning parameters for the OSINT & recon phase."""

    wordlist_path: str = field(
        default_factory=lambda: os.getenv(
            "RECON_WORDLIST",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        )
    )
    dns_resolvers: list[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    http_timeout: int = field(default_factory=lambda: int(os.getenv("RECON_HTTP_TIMEOUT", "10")))
    max_subdomains: int = field(
        default_factory=lambda: int(os.getenv("RECON_MAX_SUBDOMAINS", "200"))
    )


@dataclass
class ScanConfig:
    """Tuning parameters for the penetration testing phase."""

    scan_mode: ScanMode = field(default_factory=lambda: ScanMode(os.getenv("SCAN_MODE", "normal")))
    nuclei_templates_path: str = field(
        default_factory=lambda: os.getenv("NUCLEI_TEMPLATES", "~/.local/nuclei-templates")
    )
    nuclei_rate_limit: int = field(
        default_factory=lambda: int(os.getenv("NUCLEI_RATE_LIMIT", "10"))
    )
    sqlmap_level: int = field(default_factory=lambda: int(os.getenv("SQLMAP_LEVEL", "2")))
    sqlmap_risk: int = field(default_factory=lambda: int(os.getenv("SQLMAP_RISK", "1")))
    sqlmap_output_dir: str = field(
        default_factory=lambda: os.getenv(
            "SQLMAP_OUTPUT_DIR", str(Path.home() / ".cache" / "cybersquad" / "sqlmap")
        )
    )
    min_severity: str = field(default_factory=lambda: os.getenv("MIN_SEVERITY", "medium"))
    request_delay: float = field(default_factory=lambda: float(os.getenv("SCAN_DELAY", "0.5")))
    nvd_api_key: str | None = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    dirfuzz_wordlist: str = field(
        default_factory=lambda: os.getenv("DIRFUZZ_WORDLIST", _BUNDLE_WORDLIST)
    )
    dirfuzz_threads: int = field(default_factory=lambda: int(os.getenv("DIRFUZZ_THREADS", "40")))
    dirfuzz_rate_limit: int = field(
        default_factory=lambda: int(os.getenv("DIRFUZZ_RATE_LIMIT", "20"))
    )
    dirfuzz_timeout: int = field(default_factory=lambda: int(os.getenv("DIRFUZZ_TIMEOUT", "120")))
    dirfuzz_max_targets: int = field(
        default_factory=lambda: int(os.getenv("DIRFUZZ_MAX_TARGETS", "10"))
    )
    tls_max_targets: int = field(default_factory=lambda: int(os.getenv("TLS_MAX_TARGETS", "10")))
    testssl_timeout: int = field(default_factory=lambda: int(os.getenv("TESTSSL_TIMEOUT", "300")))
    waybackurls_timeout: int = field(
        default_factory=lambda: int(os.getenv("WAYBACKURLS_TIMEOUT", "180"))
    )

    def __post_init__(self) -> None:
        # Per-mode rate defaults. Explicit env vars always win; this only fills
        # in fields that were not set via their own env var.
        _MODES: dict[ScanMode, dict[str, object]] = {
            ScanMode.STEALTH: {
                "request_delay": 2.0,
                "nuclei_rate_limit": 2,
                "dirfuzz_rate_limit": 5,
                "dirfuzz_threads": 5,
                "sqlmap_level": 1,
                "sqlmap_risk": 1,
            },
            ScanMode.NORMAL: {
                "request_delay": 0.5,
                "nuclei_rate_limit": 10,
                "dirfuzz_rate_limit": 20,
                "dirfuzz_threads": 40,
                "sqlmap_level": 2,
                "sqlmap_risk": 1,
            },
            ScanMode.RAID: {
                "request_delay": 0.05,
                "nuclei_rate_limit": 100,
                "dirfuzz_rate_limit": 150,
                "dirfuzz_threads": 80,
                "sqlmap_level": 3,
                "sqlmap_risk": 2,
            },
        }
        _ENV_MAP = {
            "SCAN_DELAY": "request_delay",
            "NUCLEI_RATE_LIMIT": "nuclei_rate_limit",
            "DIRFUZZ_RATE_LIMIT": "dirfuzz_rate_limit",
            "DIRFUZZ_THREADS": "dirfuzz_threads",
            "SQLMAP_LEVEL": "sqlmap_level",
            "SQLMAP_RISK": "sqlmap_risk",
        }
        mode_vals = _MODES.get(self.scan_mode, _MODES[ScanMode.NORMAL])
        for env_var, attr in _ENV_MAP.items():
            if os.getenv(env_var) is None:
                setattr(self, attr, mode_vals[attr])


@dataclass
class AppConfig:
    """Top-level application config - compose all sub-configs here."""

    h1: H1Config = field(default_factory=H1Config)
    llm: LLMConfig = field(default_factory=LLMConfig)
    mcp: MCPConfig = field(default_factory=MCPConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    # Operator contact email surfaced in the outbound User-Agent so SOC teams
    # can reach the operator directly instead of banning the IP. See #46.
    contact_email: str = field(default_factory=lambda: os.environ["CYBERSQUAD_CONTACT_EMAIL"])
    reports_dir: str = field(default_factory=lambda: os.getenv("REPORTS_DIR", "./reports"))
    verbose: bool = field(default_factory=lambda: os.getenv("VERBOSE", "false").lower() == "true")
    human_input: bool = field(
        default_factory=lambda: os.getenv("CYBERSQUAD_HUMAN_INPUT", "true").lower() == "true"
    )


# Singleton - import this everywhere rather than re-instantiating
config = AppConfig()
