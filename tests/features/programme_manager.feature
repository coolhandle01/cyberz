Feature: Programme Manager respects programme access state

  The Programme Manager treats H1's access-state signal as load-bearing.
  A programme in state public_mode is the default safe case. A programme
  in any other state, or with state missing, requires positive evidence
  of hacker admission in the hydrated programme - or it is rejected even
  if the bounty is generous and the policy is permissive. This is the
  prose-only access gate the PM is the sole enforcer of (the H1 API
  filters at the account boundary; everything past that is the PM's
  call). A scenario here is the regression net for prompt drift that
  silently removes Step 0 from select/description.md.

  Scenario: Rejects a non-public programme with no admission evidence
    Given the H1 API returns a single non-public programme with no admission evidence
    When the Programme Manager agent runs
    Then the Programme Manager does not save the non-public programme
