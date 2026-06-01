"""
models.mitre.cwe_id - the CWE-identifier typed-int primitive.

A ``CweId`` validates the *shape* of a Common Weakness Enumeration id at the
boundary - a positive integer in the assigned CWE range - so a nonsensical id
(0, negative, absurdly large) rejects at args_schema validation time.

It deliberately does **not** validate membership in cybersquad's local CWE
catalogue (``tools/cwe_data.py``): that catalogue is a curated convenience
subset, not the full CWE corpus, and a real CWE id we simply have not vendored
is still a valid id. ``tools/report_tools`` already treats "not in the local
catalogue" as a *warning*, not an error, and that stays the right behaviour -
``CweId`` must not turn it into a hard reject. Shape at the boundary, catalogue
as a soft convenience: two layers, no false rejects of valid ids.

Runtime stays ``int`` so consumers that do ``cwe_get_by_id(cwe_id)`` or
``f"CWE-{cwe_id}"`` keep working unchanged.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator

# MITRE assigns CWE ids as small positive integers. The published corpus tops
# out in the low four digits; cap generously at 100000 to reject obvious
# garbage (a CVSS score mis-typed into the field, a hash, etc.) without
# guessing at MITRE's exact high-water mark - the catalogue lookup is the layer
# that knows which ids are real, this layer only rejects non-ids.
_CWE_ID_MAX = 100_000


def _validate_cwe_id(value: int) -> int:
    """Validate that ``value`` is a shape-valid CWE id (positive, in range).

    Does not check catalogue membership - an id we have not vendored is still a
    valid CWE id; ``tools/report_tools`` warns (not errors) on a catalogue miss.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"CWE id must be an integer, got {type(value).__name__}")
    if value < 1:
        raise ValueError(f"CWE id must be a positive integer, got {value}")
    if value > _CWE_ID_MAX:
        raise ValueError(f"CWE id {value} is implausibly large (> {_CWE_ID_MAX})")
    return value


CweId = Annotated[int, AfterValidator(_validate_cwe_id)]
