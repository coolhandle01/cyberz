"""
models/attack.py - The Vulnerability Researcher's typed attack plan.

Lives in its own submodule so that the agent boundary the data crosses (VR
research pass -> PT, then re-loaded by VR at triage) is legible from the
import line. Future per-agent fixtures (#121) and the typed Exploit
interface (#88) attach here too.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from models.primitives import Severity


class AttackTree(BaseModel):
    """One probe-target hypothesis from the VR's research pass.

    Rooted at a goal (probe + target) the PT searches for. Today a
    degenerate tree - the root IS the leaf, all fields describe both
    the goal and the only executable step. The ``Tree`` name is
    forward-looking: once the VR starts emitting AND/OR subgoal
    decomposition ("RCE on api.example.com" -OR-> "SSRF -> internal
    Redis" / "auth bypass -> admin panel" / ...), an explicit
    ``children: list[AttackTree]`` slot lands here with a
    ``decomposition: Literal["AND", "OR"]`` discriminator (Schneier
    1999 attack-tree shape). The PT's kill chain becomes a derived
    path search from the root down to a viable leaf (backwards
    shortest-path / A* on the AttackForest, online re-planned as
    probes succeed or fail).
    """

    probe: str  # CVE id or vulnerability-class name, e.g. "CVE-2022-22965" or "reflected XSS"
    target: str  # hostname or URL drawn from recon
    expected_ceiling: Severity  # CRITICAL / HIGH / MEDIUM / LOW the probe could reach
    rationale: str  # 1-2 sentence "why and what to look for"
    recon_evidence: list[str]  # references to recon signals that justified this hypothesis

    @field_validator("recon_evidence")
    @classmethod
    def _strip_and_filter_evidence(cls, value: list[str]) -> list[str]:
        """Strip whitespace from every entry and drop empties.

        Lives on the model so every constructor (CrewAI args_schema
        validation, ``model_validate_json`` on a re-loaded attack plan,
        a direct ``AttackTree(...)`` call) sees the same cleaned
        list. Pairs with ``validate_attack_forest``'s
        ``if not tree.recon_evidence:`` hard error - a tree that was
        passed whitespace-only entries ends up with an empty list and
        the validator catches it, instead of the persisted artefact
        carrying junk the PT then has to reason around.
        """
        return [entry.strip() for entry in value if entry.strip()]


class AttackForest(BaseModel):
    """The VR's attack plan - a forest of AttackTrees, one per goal.

    The OA describes the asset graph (``AttackGraph``); the VR finds
    the trees rooted at goals worth pursuing on that graph; the PT
    searches the forest for the shortest viable path to each goal
    (the kill chain - a derived projection, not a stored type).

    The PT's reasoning is closer to A* with a domain heuristic plus
    MDPs over attack graphs (Sheyner et al. 2002, *Automated Generation
    and Analysis of Attack Graphs*) than literal travelling-salesman,
    but the salesman intuition holds: optimise a route through a
    discovered topology, working backwards from the goal, with online
    re-planning as probes succeed or fail.

    Today a flat ``trees`` list with no inter-tree relations. Two
    forward-looking expansions land here when the VR matures:

    * Per-tree AND/OR subgoal decomposition (see ``AttackTree``).
    * Tree overlap sorting - trees sharing nodes on the underlying
      ``AttackGraph`` get ranked together so the PT's search amortises
      shared subgoals across goals (probe once, satisfy multiple
      kill-chain prerequisites).
    """

    programme_handle: str
    drafted_at: datetime
    trees: list[AttackTree]


class AttackForestValidationIssue(BaseModel):
    """One issue produced by attack-plan validation."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class AttackForestValidationReport(BaseModel):
    """Result of validating an AttackForest."""

    ok: bool
    issues: list[AttackForestValidationIssue] = Field(default_factory=list)


class AttackForestFinalisationError(RuntimeError):
    """Raised when an AttackForest cannot be persisted to attack_forest.json."""


__all__ = [
    "AttackForest",
    "AttackForestFinalisationError",
    "AttackForestValidationIssue",
    "AttackForestValidationReport",
    "AttackTree",
]
