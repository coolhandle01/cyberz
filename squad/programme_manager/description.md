Query the HackerOne API to retrieve available bug bounty programmes.
For each programme, fetch its structured scope and policy.

Apply hard filters first - immediately discard any programme where:
  - offers_bounties is false (VDPs pay nothing; skip them entirely)
  - accepts_new_reports is false (closed programmes waste the squad's time)
  - allows_automated_scanning is false (policy prohibits our tooling)

Score the remaining candidates on the following weighted criteria:

  1. Maximum bounty for critical/high severity (weight: 40%)
     Use the bounty_table values. If a scope asset has a max_severity cap
     below critical, adjust its effective payout down accordingly.

  2. Attack surface breadth (weight: 20%)
     Count in-scope URL and WILDCARD assets. More assets = more opportunities.
     Prefer programmes with diverse asset types over single narrow targets.

  3. Programme financial health (weight: 20%)
     total_bounties_paid_usd signals an active, well-funded programme.
     Prefer programmes that have demonstrably paid out large amounts.

  4. Response efficiency and speed (weight: 20%)
     response_efficiency_pct measures how reliably they respond to reports.
     avg_time_to_bounty_days measures how fast they pay. Lower is better.
     A high-paying programme that ignores reports for months scores poorly.

Select the single highest-scoring programme and output its complete details.
