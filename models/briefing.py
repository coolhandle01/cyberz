"""
models.briefing - the OperationBriefing workspace document (VR -> PT / TA / DC).

The narrative companion to the Vulnerability Researcher's machine-readable
``attack_forest.json``. Where ``AttackForest`` is the typed hit-list the
Penetration Tester iterates (the *V* - enumerated attack targets), this is the
*R* - the research narrative: the methodology and recon-evidence chain that led
to each prioritised attack. Triage / Technical Author / Disclosure Coordinator
read it alongside the typed artefacts so reports explain the reasoning rather
than only enumerating the findings.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class OperationBriefing(BaseModel):
    """The VR's narrative companion to ``AttackForest`` - the R in VR.

    ``AttackForest`` (``attack_forest.json``) is the machine-readable hit
    list: the typed ``AttackTree`` items the Penetration Tester iterates.
    ``OperationBriefing`` is the *why* - the methodology, the
    scope-of-engagement narrative, and the recon-evidence chain that led to
    each prioritised attack. Today that narrative exists only as the
    research task's raw output dumped into the next task's context, which no
    downstream agent can re-cite; this is its typed, re-readable home.

    Written by the VR's research handoff as ``operation_briefing.json``
    next to ``attack_forest.json``, and read back through this model by the
    ``Read Operation Briefing`` slicer the downstream agents carry:

    * Triage re-cites the methodology that picked an attack instead of
      seeing only the typed item.
    * The Technical Author anchors the report in how the engagement was
      framed, not just an enumeration of findings.
    * The Disclosure Coordinator can answer "what did the VR conclude about
      the surface?" for a context-rich follow-up.

    Every field is free-text but typed: the agent sees named prose slots
    rather than "write something", which constrains *where* prose goes
    without constraining *how* it reads. All slots carry agent-authored text
    (the VR wrote them, drawing on recon it had already read), so they sit on
    the lower-risk side of the prompt-injection split - length-capped at the
    model boundary, no capture-time sanitisation needed.
    """

    # 1-2 paragraph executive frame for the engagement. The one required
    # slot: a briefing with no summary is not a briefing.
    summary: str = Field(min_length=1, max_length=4000)

    # How the VR read the programme scope - what is in / out and why the
    # boundary fell where it did.
    scope_read: str = Field(default="", max_length=4000)

    # What the OSINT Analyst inventoried, paraphrased by the VR - the surface
    # the engagement was planned against.
    surface_summary: str = Field(default="", max_length=4000)

    # How attacks were chosen and sequenced - the methodology the PT and the
    # Technical Author cite. The natural home for "which exploits were chained
    # and why" once #88's @attack interface lands.
    methodology: str = Field(default="", max_length=8000)

    # Engagement-level risks called out: PII exposure, availability concerns,
    # anything cred-stuffing-adjacent the downstream agents must handle with
    # care.
    risks_called_out: str = Field(default="", max_length=4000)

    # Recon-evidence references the briefing leans on - the same
    # RECON_EVIDENCE_KINDS vocabulary (host / tech / port / endpoint) the
    # attack forest cites. Agent-authored pointers into recon.json, not
    # captured external text.
    citations: list[str] = Field(default_factory=list)


__all__ = ["OperationBriefing"]
