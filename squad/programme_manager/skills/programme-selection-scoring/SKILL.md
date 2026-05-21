---
name: programme-selection-scoring
description: The weighted rubric the Programme Manager uses to rank hydrated HackerOne programmes - four factors with explicit weights, and the order in which they apply. Activate during the score-and-select step of a programme survey, after hard filters have already culled VDPs and closed programmes.
---

# Programme selection scoring

You apply this rubric only to programmes that have already passed the
hard filters (offers_bounties, accepts_new_reports, triage_active,
policy permits automated tools, access authorisation per
access-authorisation skill). Scoring an unqualified programme wastes
the operator's time - it will be rejected regardless of score.

## The four factors

| Weight | Factor | Source field(s) |
|---|---|---|
| 40% | Maximum bounty for critical/high | `bounty_table` (severity -> USD max) |
| 20% | Attack surface breadth | count of `in_scope` items where `asset_type` in {URL, WILDCARD} |
| 20% | Programme financial health | `total_bounties_paid_usd` |
| 20% | Response efficiency and speed | composite of `response_efficiency_pct`, `avg_time_to_first_response_days`, `avg_time_to_bounty_days` |

## Applying the weights

1. Compute each factor as a normalised 0-100 score across the
   shortlisted candidates. Normalisation is relative within the
   shortlist, not against a fixed scale - the best candidate on a
   factor gets 100, the worst gets 0, others linearly interpolated.
2. Adjust the bounty factor downward for assets whose `max_severity`
   cap is below "critical" - a programme paying $20k critical but
   capping its in-scope assets at "high" is effectively a high-bounty
   programme, not a critical-bounty one. Use the cap-adjusted bounty
   ceiling for normalisation.
3. Multiply each normalised score by its weight; sum.
4. Select the single highest-scoring programme.

## Tiebreaks

If two candidates land within 5 points, prefer:
- The one with the smaller (more focused) scope - fewer assets means
  the squad spends less attention budget triaging out-of-scope noise.
- The one with the more recent `last_updated_at` - active maintenance
  beats stale-but-historically-rich.
