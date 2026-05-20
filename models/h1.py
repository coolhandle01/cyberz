"""
models.h1 - HackerOne API shapes.

The Programme Manager and the H1 client (tools/h1_api.py) exchange these
types directly with the H1 API:
  - ScopeType enumerates H1's asset_type field;
  - ScopeItem is one in/out-of-scope entry;
  - ProgrammePreview is the /hackers/programs list-endpoint shape;
  - Programme is the hydrated detail shape;
  - SubmissionStatus enumerates H1's report state taxonomy;
  - SubmissionResult is the outcome of POSTing a report to /reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from models import Severity


class ScopeType(StrEnum):
    URL = "url"
    WILDCARD = "wildcard"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    DOWNLOADABLE_EXECUTABLES = "downloadable_executables"
    GOOGLE_PLAY_APP_ID = "google_play_app_id"
    APPLE_STORE_APP_ID = "apple_store_app_id"
    WINDOWS_APP_STORE_APP_ID = "windows_app_store_app_id"
    OTHER_APK = "other_apk"
    OTHER_IPA = "other_ipa"
    TESTFLIGHT = "testflight"
    OTHER = "other"


class ScopeItem(BaseModel):
    """A single in-scope or out-of-scope asset."""

    asset_identifier: str
    asset_type: ScopeType
    eligible_for_bounty: bool = True
    instruction: str | None = None
    max_severity: Severity | None = None


class ProgrammePreview(BaseModel):
    """A lightweight programme summary from the H1 /hackers/programs list endpoint.

    Returned by browse_programmes_tool so the Programme Manager can survey the
    full accessible catalog without paying the per-programme detail-fetch cost
    that Programme hydration incurs. The PM picks shortlisted handles from the
    preview list and hydrates each one with hydrate_programme_tool.

    Only `handle` is required - the list endpoint's payload shape is not pinned
    against a captured response, so any individual attribute may be absent for
    a given programme.
    """

    handle: str
    name: str | None = None
    offers_bounties: bool | None = None
    submission_state: str | None = None
    state: str | None = None
    bookmarked: bool | None = None


class Programme(BaseModel):
    """A HackerOne bug bounty programme selected by the Programme Manager."""

    handle: str
    name: str
    url: str
    bounty_table: dict[Severity, int]
    in_scope: list[ScopeItem]
    out_of_scope: list[ScopeItem]
    offers_bounties: bool = True
    accepts_new_reports: bool = True
    response_efficiency_pct: float | None = None
    avg_time_to_bounty_days: float | None = None
    avg_time_to_first_response_days: float | None = None
    total_bounties_paid_usd: int | None = None
    triage_active: bool | None = None
    last_updated_at: datetime | None = None
    # HackerOne's access-state attribute. "public_mode" denotes publicly
    # listed, openly accessible programmes; "private_mode" denotes
    # invitation-only access. H1 may emit other values for variants of
    # invitation-only programmes - the full enum has not been verified
    # against a captured /hackers/programs response (see #43). The field
    # is surfaced verbatim so the Programme Manager treats any value other
    # than "public_mode" as non-public rather than relying on a Python-side
    # categorisation that might miss a value H1 emits.
    state: str | None = None
    policy_text: str = ""
    priority_score: float = 0.0
    selected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SubmissionStatus(StrEnum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    INFORMATIVE = "informative"


class SubmissionResult(BaseModel):
    """Result of a HackerOne report submission."""

    report_id: str | None = None
    status: SubmissionStatus = SubmissionStatus.PENDING
    h1_url: str | None = None
    submitted_at: datetime | None = None
    error: str | None = None
