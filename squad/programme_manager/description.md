Query the HackerOne API to retrieve available bug bounty programmes.
For each programme, fetch its structured scope, policy, and stats.

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
     response_efficiency_pct and avg_time_to_bounty_days combined.
     A programme that ignores reports for months scores poorly here.

Select the single highest-scoring programme that passed all filters.
Document your policy reading and scoring in selection_rationale.
