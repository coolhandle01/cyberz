A JSON object with the following fields:
  - handle: the programme's HackerOne handle
  - name: the programme's display name
  - offers_bounties: true (always true - VDPs are pre-filtered)
  - accepts_new_reports: true (always true - closed programmes are pre-filtered)
  - bounty_table: object mapping severity to maximum payout in USD
  - response_efficiency_pct: percentage (float or null)
  - avg_time_to_bounty_days: average days to payment (float or null)
  - avg_time_to_first_response_days: average days to first programme response (float or null)
  - total_bounties_paid_usd: lifetime payout total in USD (int or null)
  - triage_active: whether the programme currently has active triage (bool or null)
  - in_scope: list of asset objects, each with asset_identifier, asset_type,
    eligible_for_bounty, and max_severity (null means uncapped)
  - state: the programme's H1 access-state attribute, copied verbatim
    from the input (e.g. "public_mode", "soft_launched", "sandboxed",
    "private_mode", or null if H1 did not supply one). Recorded so the
    downstream artefact carries the same signal the PM reasoned about.
  - authorisation_basis: 1-2 sentences confirming why the squad is
    authorised to scan this programme. State the access signal (returned
    by find_programmes_tool, i.e. accessible to this hacker account),
    name the value of state and how you handled it (public -> proceed;
    non-public -> name the corroborating evidence of admission), and
    confirm policy_text contains no contradicting private/invite-only
    restriction.
  - selection_rationale: 2-3 sentences explaining why this programme scored
    highest over the alternatives considered
  - run_dir: the absolute path to the run folder created by
    save_programme_tool (downstream agents write their outputs there)
