A JSON object with the following fields:
  - handle: the programme's HackerOne handle
  - name: the programme's display name
  - offers_bounties: true (always true - VDPs are pre-filtered)
  - accepts_new_reports: true (always true - closed programmes are pre-filtered)
  - bounty_table: object mapping severity to maximum payout in USD
  - response_efficiency_pct: percentage (float or null)
  - avg_time_to_bounty_days: average days to payment (float or null)
  - total_bounties_paid_usd: lifetime payout total in USD (int or null)
  - in_scope: list of asset objects, each with asset_identifier, asset_type,
    eligible_for_bounty, and max_severity (null means uncapped)
  - selection_rationale: 2-3 sentences explaining why this programme scored
    highest over the alternatives considered
