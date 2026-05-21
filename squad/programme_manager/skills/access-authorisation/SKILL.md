---
name: access-authorisation
description: How the Programme Manager establishes the squad is authorised to scan a HackerOne programme - the access signal, the state field, the corroboration requirements for non-public programmes, and the contradicting-signal check. Activate at Step 0 of programme selection and again on every hydrated candidate before scoring.
---

# Access authorisation

Two H1 signals look adjacent but mean different things and must not be
conflated:

- `accepts_new_reports` answers "is the submission window open?"
  (open vs. closed). The hard filter at selection time discards
  closed programmes.
- `state` answers "who is admitted to this programme?" (public vs.
  invite-only). This skill is about that question.

The HackerOne hacker API filters the catalogue by account
authorisation - it only returns programmes accessible to the
authenticated hacker (public programmes plus accepted private
invitations). Appearance in `browse_programmes_tool`'s output is
therefore the necessary precondition for any work the squad will
perform. Treat that signal as load-bearing, not optional.

## The `state` field

Read `state` on every preview and again on every hydrated programme:

- `"public_mode"` - publicly listed and openly accessible. Proceed.
- Anything else (e.g. `"private_mode"`), or `state` missing or `null` -
  treat as non-public.

For a non-public programme, appearance in the catalogue is necessary
but not sufficient. You also require **corroborating evidence of
admission** in the hydrated programme. Acceptable corroboration
includes:

- `policy_text` that describes the invited researcher's role
  ("invited researchers may..." or similar).
- A scope item's `instructions` field naming participating researchers
  or describing an out-of-band approval flow that names you.
- A programme name that matches an invitation you (the operator) are
  expecting.

If you cannot point to corroboration, reject the programme.

## The contradicting-signal check

Independently of state, scan the hydrated programme for any signal
that contradicts the access assumption:

- `policy_text` declaring the programme private, invitation-only,
  confidential, or "do not share".
- Scope item `instructions` describing out-of-band approval
  requirements you have not satisfied.
- A programme name explicitly marked confidential.

Any such signal means reject the programme regardless of bounty,
scope, or how permissive other policy language is. You are the gate,
not a Python predicate downstream of you.

## Recording the basis

The selected programme's `authorisation_basis` (1-2 sentences) must:

1. Cite the access signal (programme returned by
   `browse_programmes_tool`, i.e. accessible to this hacker account).
2. Name the value of `state` and how you handled it - public_mode
   proceeds, non-public names the corroborating evidence of admission.
3. Confirm `policy_text` contains no contradicting private /
   invite-only / confidential restriction.

A downstream agent reading `authorisation_basis` must be able to
satisfy themselves the squad is authorised without re-hydrating the
programme.
