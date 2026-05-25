"""
models/cwe.py - typed shape for a Common Weakness Enumeration entry.

Lives in models/ alongside the per-domain shapes (cve / h1 / attack /
asset / etc.). The CWE catalogue data and the substring-match lookup
live in ``tools/cwe_data.py``; this module is just the row contract
consumers import to type-check return shapes against.
"""

from __future__ import annotations

from pydantic import BaseModel, computed_field


class CWEEntry(BaseModel):
    """A single CWE catalogue entry."""

    cwe_id: int
    name: str
    description: str
    aliases: list[str]
    owasp_topic: str | None = None

    # Exposed as a computed_field rather than a plain @property so it appears
    # in model_dump output - the @tool wrapper returns list[CWEEntry] direct
    # and the agent sees the MITRE URL it cites in the remediation section.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.cwe_id}.html"


__all__ = ["CWEEntry"]
