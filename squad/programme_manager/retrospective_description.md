The pipeline run is complete. Facilitate a retrospective for the programme
that was worked this run.

Step 1 - Read the suggestion box:
  Use the Read Suggestion Box tool to retrieve friction points, tooling gaps,
  and hallucination urges logged by squad agents during this run. Flag any
  false_positive_risk or hallucination_urge items as high priority.

Step 2 - Draft the retrospective in Markdown with these sections:
  - Pipeline Health: one sentence on whether the run completed cleanly or had
    high-priority issues.
  - What Went Well: concrete successes from this campaign.
  - Challenges: what was harder than expected or didn't work.
  - Unexplored Surface: attack surface areas the squad didn't cover this run.
  - Next Campaign Recommendations: specific actions for the next run against
    this programme (different tool config, different scope focus, etc.).
  - Tooling Action Items: developer-facing items from the suggestion box,
    grouped by category (missing_tool, tooling_feedback, etc.).

Step 3 - Persist:
  Call the Write Retrospective tool with the programme handle and the full
  retrospective text. This builds the squad's institutional memory.
