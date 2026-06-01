"""
models.nvd.cvss - the CVSS vector typed-string primitive.

A ``CvssVector`` validates the *structure* of a CVSS 3.x vector string at the
boundary - the ``CVSS:3.0`` / ``CVSS:3.1`` prefix and well-formed ``KEY:VALUE``
metric tokens - so a malformed vector rejects at args_schema validation time
rather than deep in score computation. It deliberately does **not** re-encode
the metric value tables or recompute the score: ``tools.report_tools.calculate_cvss_score``
remains the single source of truth for metric-value correctness and scoring.
Two checks, two layers - shape here, semantics there - with no duplicated tables
to drift.

Runtime stays ``str`` to match the ``FQDN`` / ``IpAddr`` convention, so existing
consumers that pass the vector to ``calculate_cvss_score`` or interpolate it into
a report keep working unchanged.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator

# A CVSS 3.x vector: the version prefix then one or more ``KEY:VALUE`` metric
# tokens, slash-separated. Keys/values are uppercase alnum (e.g. ``AV:N``,
# ``S:C``). This pins the *shape*; the metric tables that say which keys/values
# are meaningful live in ``calculate_cvss_score``.
_CVSS_TOKEN_RE = re.compile(r"^[A-Z]+:[A-Z0-9]+$")


def _validate_cvss_vector(value: str) -> str:
    """Validate that ``value`` is a structurally well-formed CVSS 3.x vector.

    Enforces: a ``CVSS:3.0`` / ``CVSS:3.1`` prefix, at least one metric token,
    and every token shaped ``KEY:VALUE``. Returns the stripped value. Does not
    validate metric semantics or the score - ``calculate_cvss_score`` owns that.
    """
    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"CVSS vector must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("CVSS vector cannot be empty")
    parts = cleaned.split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise ValueError(f"CVSS vector must start with CVSS:3.0 or CVSS:3.1, got {value!r}")
    if len(parts) < 2:
        raise ValueError(f"CVSS vector carries no metric tokens: {value!r}")
    for token in parts[1:]:
        if not _CVSS_TOKEN_RE.match(token):
            raise ValueError(f"malformed CVSS metric token {token!r} in {value!r}")
    return cleaned


CvssVector = Annotated[str, AfterValidator(_validate_cvss_vector)]
