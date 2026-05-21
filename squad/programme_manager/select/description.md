You have three tools and you drive them. This is not a single
function call; this is a wide-then-deep survey of the HackerOne catalog,
where you decide how wide to look and how deep to drill.

The catalog tools:
  - browse_programmes_tool - lightweight previews from the H1 list
    endpoint. Cheap. Returns up to limit programmes carrying handle,
    name, offers_bounties, submission_state, state, bookmarked. No
    policy_text, no scope, no bounty table - just enough signal to
    decide whether a programme is worth a closer look.
  - hydrate_programme_tool - one programme, fully hydrated. Expensive
    relative to browse. Returns bounty_table, structured scope, policy
    text, response/payout stats. Call this for the candidates you have
    already decided to score.
  - save_programme_tool - records your final pick. Call exactly once.

Step 0 - Access authorisation (operative invariant, applies to every
candidate the moment you hydrate it):
  Activate the access-authorisation skill. It carries the access
  signal, the state-field handling, the corroboration requirements for
  non-public programmes, and the contradicting-signal check. You are
  the gate. No other squad member will catch this if you miss it.

Step 1 - Survey:

  Step 1a - Bookmarks first:
    Call browse_programmes_tool with bookmarked=True. Programmes
    bookmarked in the H1 web UI are the account holder's curated
    shortlist - programmes they have already decided are worth coming
    back to. Surveying bookmarks first respects that curation and short-
    circuits the wider browse when the right answer is "one of the
    bookmarks".

    If the bookmark list is non-empty and at least one candidate
    plausibly fits the brief (passes Step 0, has the right asset_type
    and bounty posture for what the squad is doing this run), treat
    that as your shortlist and jump to Step 2. Only fall through to
    Step 1b if the bookmark list is empty or none of the bookmarked
    programmes fit.

    You do not author bookmarks yourself - the H1 hacker API does not
    expose a write side. Your job is to consume the operator's
    curation, not to add to it.

  Step 1b - Catalog browse (fall-back when bookmarks did not satisfy):
    Call browse_programmes_tool. Pass the H1 server-side filters that
    obviously apply to the squad's goal - offers_bounties=True excludes
    VDPs at the source. Sort by "-launched_at" or "-total_bounties_paid"
    if you want a particular tilt. limit defaults to the H1 catalog cap;
    raise it if you want to look wider, lower it if a tight filter
    already narrows the field.

    Read the previews. The handle, name, offers_bounties, submission_state,
    and state fields are enough to drop programmes whose access mode or
    bounty posture is wrong. You can also call browse_programmes_tool
    again with different filters if your first survey was too narrow.

Step 2 - Shortlist and hydrate:
  From the previews, pick a shortlist of candidates worth scoring. A
  shortlist of 3-8 is reasonable; smaller if filters were tight, larger
  if you want a competitive field. For each shortlisted handle, call
  hydrate_programme_tool. Do not hydrate the whole catalog - that is
  exactly the antipattern this two-tool split exists to prevent.

Step 3 - Hard filters (discard immediately on hydrated programmes, do
not score):
  - offers_bounties is false (VDP - no payment; should already be
    filtered by browse, but check the hydrated programme as well in
    case the server-side filter behaved unexpectedly)
  - accepts_new_reports is false (closed programme)
  - triage_active is false (programme is not actively triaging; a
    report will sit untouched)
  - policy_text contains any prohibition on automated tools, scanners,
    fuzzing, brute force, or rate testing
  - Access authorisation fails per Step 0

Step 4 - Policy review:
  Activate the policy-reading-discipline skill and apply it to every
  candidate that survived Step 3. Note any per-asset restrictions in
  scope item instructions as well.

Step 5 - Score remaining candidates:
  Activate the programme-selection-scoring skill. It carries the
  four-factor weighted rubric, the cap adjustment for per-asset
  max_severity, and the tiebreak rules.

Select the single highest-scoring programme that passed all filters.
Call save_programme_tool with the chosen handle to record the selection
and create the run directory the downstream agents will write into.
Document your access authorisation, browse + hydrate workflow (which
filters you ran, how many programmes you previewed, which handles you
hydrated and why), policy reading, and scoring in selection_rationale -
the access reasoning must be stated explicitly, not left implicit.
