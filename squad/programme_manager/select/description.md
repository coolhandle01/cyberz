Call find_programmes_tool once. It returns every accessible programme
fully hydrated with structured scope, bounty table, response stats, and
policy text - no second per-programme lookups needed.

Step 0 - Access authorisation (operative invariant, applies to every candidate):
  find_programmes_tool returns only programmes accessible to the authenticated
  hacker. The HackerOne hacker API filters by account authorisation, so
  appearance in this list is the necessary precondition for any work the
  squad will perform. Treat that as load-bearing.

  For each candidate, read the state field on the Programme dict:
    - "public_mode" - publicly listed and openly accessible. Proceed.
    - "soft_launched" / "sandboxed" / "private_mode" - invitation-only.
      Appearance in find_programmes_tool's output is necessary but not
      sufficient; you also require corroborating evidence of admission in
      the hydrated programme (e.g. policy_text describing the invited
      researcher's role, scope item instructions naming participating
      researchers). Cannot find corroboration -> reject.
    - Missing or unrecognised - treat as non-public and apply the same
      evidence-of-admission requirement.

  Independently, scan for any signal in the hydrated programme that
  contradicts the access assumption - policy_text declaring the programme
  private, invitation-only, confidential, or "do not share"; scope item
  instructions describing out-of-band approval requirements; a programme
  name explicitly marked confidential. Any such signal means reject the
  programme regardless of bounty, scope, or policy permissiveness. You
  are the gate, not a Python predicate downstream of you.

Step 1 - Hard filters (discard immediately, do not score):
  - offers_bounties is false (VDP - no payment)
  - accepts_new_reports is false (closed programme)
  - policy_text contains any prohibition on automated tools, scanners,
    fuzzing, brute force, or rate testing

Step 2 - Policy review (read policy_text in full for each remaining candidate):
  Read carefully. You are not looking for reasons to proceed - you are
  looking for clear permission or clear silence. If the policy is ambiguous
  about whether automated testing is allowed, discard the programme.
  Note any per-asset restrictions in scope item instructions as well.

Step 3 - Score remaining candidates on:
  1. Maximum bounty for critical/high severity (weight: 40%)
     Adjust downward for assets whose max_severity cap is below critical.
  2. Attack surface breadth (weight: 20%)
     Count in-scope URL and WILDCARD assets.
  3. Programme financial health (weight: 20%)
     total_bounties_paid_usd signals an active, well-funded programme.
  4. Response efficiency and speed (weight: 20%)
     response_efficiency_pct, avg_time_to_first_response_days, and
     avg_time_to_bounty_days combined. A programme that ignores reports
     for months scores poorly here. triage_active=true is a strong
     positive signal.

Select the single highest-scoring programme that passed all filters.
Call save_programme_tool with the chosen handle to record the selection
and create the run directory the downstream agents will write into.
Document your access authorisation, policy reading, and scoring in
selection_rationale - the access reasoning must be stated explicitly,
not left implicit.
