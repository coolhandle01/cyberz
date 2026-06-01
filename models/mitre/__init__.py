"""
models.mitre - the MITRE weakness-taxonomy vocabulary.

Distinct from the OAM asset graph (``models.asset``) and from NIST's NVD /
CVSS scoring domain (``models.nvd``). Houses the MITRE shapes - currently the
``CWEEntry`` Common Weakness Enumeration record (and the CWE-id primitive when
it lands).

Leaf package: depends only on pydantic / stdlib, so any model module can import
from it without a cycle.
"""

from __future__ import annotations

from models.mitre.cwe import CWEEntry

__all__ = ["CWEEntry"]
