# PR #696 Review — Refuse a malformed actor in the two siblings of the credential guard

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/696
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-09 (`855c17f9`, branch `fix/actor-shape-in-status-and-confirmation` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-09
**Scope:** 3 files, +190 / −12, 1 commit.

---

## Verdict

**Correct and complete. No new defects.** It generalises the actor-shape rule
from #691 to `update_user_status/3` and `toggle_user_confirmation/2`, reusing the
`target_label/1` helper added in that review, and it corrects a test of mine that
was worse than useless. Details below, including the part that is my error.

### "The two siblings" is exhaustive — checked

The claim to verify is not that these two are fixed but that no third one is
left. Two independent checks:

- `rg "_system ->"` in `auth.ex` returns **nothing**; all three actor-gated
  writes now use the same three-branch `%User{}` / `nil` / `_malformed` shape.
- The other two `current_user`-taking sites are `delete_user/2` and
  `log_user_deletion/3`. `delete_user/2` was **already fail-closed by a different
  mechanism** — `validate_can_delete_user/2`'s fallback clause returns
  `{:error, :invalid_current_user}` for any non-`%User{}`, and unlike the three
  above it refuses `nil` too, so deletion has no system path at all.
  `log_user_deletion/3` is only reachable after that gate.

So the surface is genuinely closed, and the PR's severity ordering is right:
`toggle_user_confirmation/2` is the serious one, because its unchecked path
reaches `admin_unconfirm_user/1` and clears `confirmed_at`, locking the target
out of every confirmation-gated page.

### The consistency call is the right one

An explicit `actor: nil` still takes the system path, in all three, because
`Map.get`/`Keyword.get` cannot distinguish it from an absent key. The commit says
so and declines to change it unilaterally: *"making it fail closed is a decision
for all three at once, not one."* Agreed — and `PhoenixKit.Users.Referrals`
genuinely expires accounts with no actor, so the system path has a real caller.

---

## Correction to my own work — the #692 test I added was inverted, not just weak

This PR rewrites `test/integration/users/user_form_authority_test.exs`'s
"every field the context routes into the schema is dropped" test, which **I wrote
in the #692 review pass**. Tim's diagnosis is right and it is worse than his
commit message needed to claim.

What I wrote poisoned all five identity fields in one payload:

```elixir
poisoned = Map.new(Auth.updatable_profile_fields(), fn field ->
  {Atom.to_string(field), "attacker-#{field}"}
end)

render_submit(view, "save_user", %{
  "user" => %{"first_name" => "Harmless", "custom_fields" => poisoned}
})
```

`Auth.update_user_fields/2` routes every recognised schema field into a **single**
`profile_changeset`, and `"attacker-user_timezone"` fails `validate_user_timezone/1`.
One invalid member invalidates the whole changeset. So:

- **With the filter working** — `custom_fields` is emptied, the poison never
  reaches the changeset, and the top-level `"first_name" => "Harmless"` (which is
  *not* a credential field and is not dropped for an out-of-rank actor) is
  written. My own assertion `after_submit.first_name == owner.first_name` then
  **fails**.
- **With `drop_schema_identity_fields/2` deleted** — the poison reaches the
  changeset, it is invalid, the `with` chain aborts, nothing is written at all,
  and every assertion **passes**.

The test therefore failed when the fix was present and passed when the
vulnerability was, and it had been red on `main` since I added it. Tim verified
the second half directly ("with `drop_schema_identity_fields/2` deleted, the old
form still passed").

That is precisely the defect I spent three reviews naming in other people's
tests — a test whose stated discriminator does not discriminate — introduced by
me, in a test written specifically to pin a security filter, in an environment
where I could not run it. The general lesson stands and now applies to my own
output: **a DB-requiring test I cannot execute is a hypothesis, and it should be
labelled as one rather than reported as coverage.**

The replacement is sound: one poisoned field per submission with a fresh mount,
and `poison_for/1` supplying values that are hostile *and* schema-valid
(`user_timezone` → `"0"`, `email` → a real address), so the changeset is never
rejected for a reason unrelated to the filter. The added
`assert after_submit.first_name == "Renamed"` in the stale-authority test is a
good catch of the same class in the other direction: without it, a regression
that abandons the entire write satisfies the "nothing was rewritten" assertions.

---

## Gate

No code changes in this pass. `mix precommit` passes. `mix test` is 1943 tests,
2 failures — both the stale `chain_hash`, unrelated to this PR (see the #695
review).

The integration tests this PR adds and fixes still have not executed anywhere I
can see: no PostgreSQL is reachable in this environment. The corrected test is
correct by reading, which is exactly the standard of evidence that produced the
broken one, so it deserves a real run before anyone counts it as coverage.
