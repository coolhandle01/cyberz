"""tests/models/test_briefing.py - unit tests for models/briefing.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import OperationBriefing

pytestmark = pytest.mark.unit


class TestOperationBriefing:
    def test_minimal_record(self):
        # summary is the only floor: the VR can hand off a bare executive
        # frame and let the other narrative slots fill in as the research
        # warrants. citations default empty.
        briefing = OperationBriefing(summary="Two admin surfaces dominate the risk.")
        assert briefing.summary.startswith("Two admin")
        assert briefing.scope_read == ""
        assert briefing.methodology == ""
        assert briefing.risks_called_out == ""
        assert briefing.citations == []

    def test_carries_full_narrative(self, target_apex):
        # The shape the VR emits beside attack_forest.json: every prose slot
        # plus recon-evidence citations drawn from the same vocabulary the
        # attack forest cites.
        briefing = OperationBriefing(
            summary="The engagement centres on the authenticated API tier.",
            scope_read=f"In scope: *.{target_apex}; the marketing CDN is out.",
            surface_summary="OSINT inventoried 12 hosts; 3 run an admin panel.",
            methodology="Prioritised the Spring4Shell hypothesis on the API host first.",
            risks_called_out="The auth host handles PII - avoid destructive payloads.",
            citations=[f"host:api.{target_apex}", "tech:Spring Boot 2.3", "port:8080"],
        )
        assert briefing.methodology.startswith("Prioritised")
        assert f"host:api.{target_apex}" in briefing.citations
        assert len(briefing.citations) == 3

    def test_serialise_roundtrip(self, target_apex):

        original = OperationBriefing(
            summary="Surface is small but the admin panel is unauthenticated.",
            citations=[f"endpoint:https://admin.{target_apex}/"],
        )
        restored = OperationBriefing.model_validate_json(original.model_dump_json())
        assert restored.summary == original.summary
        assert restored.citations == [f"endpoint:https://admin.{target_apex}/"]

    def test_rejects_empty_summary(self):
        # A briefing with no executive frame is not a briefing - summary is
        # required non-empty where the other prose slots are optional.

        with pytest.raises(ValidationError):
            OperationBriefing(summary="")

    def test_rejects_oversize_methodology(self):
        # The max_length cap on the agent-authored prose slots is the boundary
        # defence keeping a runaway narrative from bloating the handoff.

        with pytest.raises(ValidationError):
            OperationBriefing(summary="ok", methodology="x" * 8001)
