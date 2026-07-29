# PR #671 — Fix an existing user being renamed when the admin form rebuilds its changeset

**Author:** Timujeen · **Merged:** 2026-07-29 (`118c34f4`) · **Reviewed:** 2026-07-29

`maybe_generate_username_from_email/1` ran on every registration changeset and
minted a username whenever the params carried none — which is what the admin
edit form sends. `maria` became `maria_1`, then `maria_2`. The fix skips
generation for a saved user that already has one, and teaches the uniqueness
walk to ignore the user's own row.

**Verdict: the fix is correct and the guard is in the right place.** The
`get_change` head collapsing `nil`/`""` into one clause is a genuine
simplification of duplicated code. Two notes below, one fixed.

---

## IMPROVEMENT - MEDIUM — a generated username reaches the database with no uniqueness guard on it

`lib/phoenix_kit/users/auth/user.ex:694-760`

`registration_changeset/3` runs `validate_username/2` at step 2 and
`maybe_generate_username_from_email/1` **last**. So by the time a username is
generated, `maybe_validate_unique_username/2` has already looked at the
changeset, seen no `:username` change, and returned it untouched — the generated
name carries neither `unsafe_validate_unique` nor `unique_constraint`.

`ensure_unique_username/3` reads committed rows only. Two registrations from
`maria@a.com` and `maria@b.com` racing each see `maria` free, both take it, and
the loser gets an `Ecto.ConstraintError` **raised** out of `Repo.insert/1`
rather than an `{:error, changeset}` — a 500 on the registration form instead of
a field error. This predates the PR, but the PR is what made the walk's
semantics explicit, and the `own_uuid` argument now threading through it is what
made the gap legible.

**Fixed** — the generation branch re-attaches
`unique_constraint(:username, name: :phoenix_kit_users_username_uidx)`, so the
race lands as a normal validation failure. Deliberately did **not** reorder the
changeset pipeline: moving generation above `validate_username/2` would also
subject generated names to the format/length rules for the first time, and
`generate_username_from_email/1`'s output is not guaranteed to satisfy them for
every email shape. That is a larger change than this PR's blast radius.

## NITPICK — the `own_uuid` clause in `ensure_unique_username/3` is unreachable

`user.ex:744-756`. The commit describes two causes; the second fix is
load-bearing only in theory. Generation is now reached exclusively when
`present?(changeset.data.username)` is **false** — the user has no username. A
user with no username cannot own the row that holds the generated name, so
`get_by(username: …)` can never return `%__MODULE__{uuid: ^own_uuid}`. The only
way in is a stale/partially-selected `changeset.data`.

Left in place: it is cheap, correct, and defends the invariant if the guard above
it is ever loosened. Recording it so nobody reads the test suite as covering it —
it does not, and cannot.

---

## Verified, not changed

- **Clearing a username is not silently accepted.** Params `%{"username" => ""}`
  put a `""` change that survives `maybe_put_generated_username/1`'s early
  return. `validate_username/2` has already run by then and Ecto's
  `validate_length` does not skip `""` (only `nil`), so it errors with "should be
  at least 3 character(s)" rather than blanking the field. Behaviour is the same
  as before the PR.
- **Legacy rows still get a username.** A saved user whose `username` is `nil` or
  blank still generates — `present?/1` trims, so `" "` counts as absent.
- The seven `Logger.info` calls are gone; `require Logger` in `user_form.ex` is
  still earned by the avatar log at line 977.
- `test/phoenix_kit/users/user_org_changeset_test.exs` uses `PhoenixKit.DataCase`,
  so the DB-touching setup the PR added is auto-tagged `:integration` and skips
  cleanly without PostgreSQL. Correct file to have put these in.
