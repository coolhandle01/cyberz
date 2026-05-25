"""
squad/osint_analyst/_helpers.py - shared programme loader used by the
sweep entry point and the recon-finalisation tool.

Lives in its own submodule so both ``discovery.py`` (``Run Initial
Sweep``) and ``curation.py`` (``Finalise Recon``) can call it without
the two modules cross-importing.
"""

from models.h1 import Programme
from tools import http
from tools.h1_api import h1


def _load_programme(programme_handle: str | None) -> Programme:
    """Fetch and parse the Programme - the scope guard in validate_insight
    needs a real Programme to check against."""
    if not programme_handle:
        raise ValueError("programme_handle is required")
    http.set_programme(programme_handle)
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    return h1.parse_programme(policy["data"], scope)
