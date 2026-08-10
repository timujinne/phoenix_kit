# PR #691 Review — Fix the credential rank rule being bypassable through custom_fields

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/691
**Author:** Timujeen (timujinne)
**Merged:** 2026-08-09 (`2eadb6e9`, branch `fix/credential-bypass-custom-fields` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-09
**Scope:** 4 files, +313 / −8. 1 new test file (4 tests), 3 tests strengthened.

---

## Verdict

**The vulnerability is real, correctly diagnosed, and closed.** I traced the
whole path rather than taking the PR description on trust:

| Claim | Verified against |
|---|---|
| `update_user_fields/2` routes `custom_fields` keys into the schema | `auth.ex:1844-1880` — `safe_string_to_existing_atom/1` + `updatable_profile_fields` → `maybe_update_profile/2` → `profile_changeset` |
| …and writes `:email` with no confirmation-token flow | `update_user_profile/2` (`auth.ex:1623`) is a plain `Repo.update` |
| The form fed it `params["custom_fields"]` verbatim | pre-PR `user_form.ex:557` |
| `username` is a second sign-in credential | `get_user_by_email_or_username_and_password/3` |
| The drop list matches the context's list exactly | `~w(email username first_name last_name user_timezone)` vs `[:first_name, :last_name, :email, :username, :user_timezone]` — same five |
| No other core caller feeds untrusted keys to `update_user_fields/2` | `confirmation.ex`, `registration.ex`, `user_settings.ex` all pass fixed literal keys; `bulk_update_user_fields/2` has no `lib/` caller |
| `user_settings.ex` (self-service) is a different mechanism, not a second hole | it passes `custom_fields` nested to `Auth.update_user_profile/2`, where it is cast as JSONB — never re-routed to the schema |

The three sub-fixes are each at the right layer: the params filter in the form
(where the params arrive), the rank rule in the context (where the write
happens), and the `{:error, :insufficient_permissions}` clauses that stop the
refusal from being decoded as a changeset.

Five defects found. One is a crash the PR introduced on its own fail-closed
path; two are load-bearing comments that state things about this codebase that
are not true, one of which a test's stated discriminator rests on. All five are
addressed in this pass; three are locked in by four new tests.

**Verification caveat:** no PostgreSQL is reachable here, so the integration
tests — the PR's 4 and my 4 — did not execute. `mix precommit`, the project's
stated bar, passes.

---

## BUG - MEDIUM — the fail-closed refusal path raises instead of refusing

**File:** `lib/phoenix_kit/users/auth.ex` (`admin_update_user_password/3`)

`admin_update_user_password/3` takes `user` **unguarded**. Both branches the PR
added assume it is a `%User{}`:

```elixir
defp refuse_credential_write(%User{} = user, %User{} = actor) do   # ← head narrows
  Logger.warning("… for #{user.uuid} by #{actor.uuid} …")
end

_malformed ->
  Logger.warning("… for #{user.uuid} — :admin_user was present but not a %User{}")
```

`can_manage_user_credentials?/2` has a catch-all returning `false` for a
non-`%User{}` target, so a host that passes a JSON-decoded map as the *target*
reaches `refuse_credential_write/2` and gets a **`FunctionClauseError`**; the
`_malformed` branch gets a `KeyError` from `%{"uuid" => …}.uuid`. Pre-PR that
same call returned `{:error, :insufficient_permissions}` — the old `else` was
unconditional — so this is a regression, and it is on the branch whose entire
justification is that a library cannot see its hosts' callers and must fail
closed. A guard that raises has failed differently, not safely.

It is the same shape as the case the PR just decided to defend against, applied
to the other operand: the `_malformed` clause exists precisely because a host
might pass "a map decoded from JSON by a host controller" as the actor. Nothing
makes the target less exposed to that mistake.

**Fixed:** `refuse_credential_write/2` no longer pattern-matches the target, and
both branches take the uuid through a `target_label/1` that degrades to `"an
unrecognised target"`. Pinned by a new test that mirrors the PR's
malformed-actor test onto the target operand.

---

## IMPROVEMENT - HIGH — the drop list was a second hand-maintained copy of a security whitelist

**Files:** `lib/phoenix_kit_web/users/user_form.ex`, `lib/phoenix_kit/users/auth.ex`

The fix hinges on two lists agreeing:

```elixir
# user_form.ex
@schema_identity_fields ~w(email username first_name last_name user_timezone)

# auth.ex, update_user_fields/2
updatable_profile_fields = [:first_name, :last_name, :email, :username, :user_timezone]
```

They agree **today** — I checked all five, in both directions. Nothing keeps
them agreeing. Add a profile field to the context (the natural place to add
one; `update_user_fields/2` is where that list lives) and the form's copy is
silently one short — and the symptom is not a compile error or a failing test,
it is that one field becoming writable through `custom_fields` again, i.e. this
exact vulnerability re-opened for a subset. The PR's own tests would stay green:
they submit `email` and `username` by name.

This is the single most likely way the fix decays.

**Fixed:** the list is now `@updatable_profile_fields` in `Auth` with a public
reader `Auth.updatable_profile_fields/0`; `update_user_fields/2` and the form's
filter both read it (at runtime — a compile-time attribute would put a
compile-time dependency on `auth.ex`, which changes constantly). Pinned by a new
test that poisons `custom_fields` with **every** name in the list and asserts
none reached the schema, so coverage grows with the list instead of lagging it.

Also added to `update_user_fields/2`'s `@doc` an explicit warning that it does
not authorize and that `:email`/`:username` are credentials — it is public API,
and the PR fixed the one caller rather than the function.

---

## IMPROVEMENT - HIGH — `credential_authority_now/2`'s justification is not true of this codebase

**File:** `lib/phoenix_kit_web/users/user_form.ex`

The comment introducing the new write-time check:

> The reload is the load-bearing part. `socket.assigns.user` carries a `:roles`
> list preloaded at mount, and `Auth.has_system_role?/2` reads that list when it
> is loaded rather than querying — so passing the mounted struct re-asks the
> question against the same stale answer and agrees with itself.

Every step of that is checkable, and the first one is false:

- `load_user_data/3` loads the target with `Auth.get_user!/1` = `Repo.get!(User, uuid)` (`auth.ex:276`). **No preload.** `:roles` is `%Ecto.Association.NotLoaded{}`, not a list.
- So `has_system_role?/2` skips its `when is_list(roles)` clause and takes the querying one.
- `Roles.user_has_role?/2` keys on `user.uuid` alone (`roles.ex:187-197`) — the struct's age is irrelevant.
- The actor is the same story: `get_user_by_session_token/1` does not preload roles either.

So the rank answer was already fresh from the mounted struct, and the reload
changes nothing about it. The check is still worth keeping — it catches a target
deleted since mount, and it holds if `load_user_data/3` ever *does* start
preloading — but it is belt-and-braces, not the load-bearing thing, and the
extra `Repo.get` per save is the price.

Why this matters more than a wrong comment usually would: this comment is the
stated reason the code exists, and it is written to be persuasive. The next
person to read it either propagates the "preloaded at mount" belief to code
where it is false too, or deletes the reload for being redundant without knowing
which of the two reasons was the real one.

**Fixed:** comment rewritten to say what the reload actually buys.

---

## IMPROVEMENT - MEDIUM — the new test's stated discriminator does not discriminate

**File:** `test/integration/users/user_form_authority_test.exs`

Downstream of the above. The "stale authority assign" test says:

> the address is dropped only by the form — and only if the form asks the rank
> question against the target as it is now rather than as it was at mount.
> **Revert the reload and this assertion goes red.**

It does not. Revert `credential_authority_now/2` to
`Auth.can_manage_user_credentials?(user, actor)` on the mounted struct and the
test stays green, for the reasons above. What the test genuinely pins is the
write-time *re-ask* versus reading the mount-time `@can_manage_credentials`
assign — which is valuable, and is the part worth stating.

Worth calling out because the immediately preceding commit on this branch
(`7946b7ed`, "build the actor three tests only claimed") was fixing exactly this
class of problem: a test that reads as covering more than it does. The same
review pass that caught it in the old tests introduced it in the new one.

**Fixed:** comment corrected to claim only what the assertion pins.

---

## IMPROVEMENT - MEDIUM — the form drops silently while the context logs

**File:** `lib/phoenix_kit_web/users/user_form.ex`

The PR argues the point itself, in `auth.ex`:

> A refusal that leaves no trace is a guard nobody can tell fired.

…and then the form's filter is a bare `Map.drop`. By the filter's own comment,
"the form renders a real input for every one of these, so a `custom_fields`
entry carrying one is never a legitimate submission from this page" — which
makes it a strictly *stronger* signal than the context's rank refusal. The rank
refusal can fire on an honest race (the "stale authority" test is one). A
`custom_fields[email]` on the wire cannot: it means a client composed its own
payload. That is the one event an operator would want in the log, and it was the
one being discarded without a word.

**Fixed:** the filter logs the dropped key names, the target uuid and the
submitting actor when it removes anything, and stays silent on the overwhelmingly
common no-op path.

---

## NITPICK — the partial write on the disagreement path survives

**File:** `lib/phoenix_kit_web/users/user_form.ex` (`update_profile_and_password/3`)

The PR's comment describes the pre-fix bug as the LiveView dying "after the
profile write had already committed, leaving a partial update behind", and the
new `{:error, :insufficient_permissions}` clause fixes the crash. The partial
write is still there: `Auth.update_user_profile/2` commits, *then*
`admin_update_user_password/3` refuses, and the user sees only "You don't have
permission to manage this user's credentials" with no hint that the name change
went through.

Not fixed, deliberately. Making it atomic means wrapping profile + password in
one `Ecto.Multi` — a real restructuring of a function three other paths call,
to improve the messaging on a branch that the comment itself says "should not
happen". The flash is misleading rather than wrong, and the credential fields —
the ones that matter — are not written. Recorded so the limitation is on record
rather than mistaken for covered.

---

## Verified and left alone

- **`nil` vs `_malformed` clause ordering** — correct. `Map.get(context, :admin_user)` returns `nil` both when the key is absent and when it is explicitly `nil`; both are the documented system path.
- **The filter's non-map fallthrough** — `custom_fields=1` passes through to `validate_custom_fields/2`, which is where it belongs. Confirmed no crash.
- **Case/whitespace variants** (`"Email"`, `" email"`) — cannot bypass. `String.to_existing_atom/1` fails on them in the context, so they stay custom fields either way; the string `Map.drop` and the atom lookup agree because both require an exact match.
- **Atom-keyed `custom_fields`** — impossible on this path. Params arrive string-keyed from the wire, and the only key added afterwards (`"avatar_file_uuid"`) is a string literal.
- **Actor staleness** — the mirror worry to the target one, and it does not apply: no preload on the session-token lookup, so a demoted actor is caught on the next save.
- **The `users_permission_holder/0` helper** — genuinely stronger than the `plain_user()` it replaced, and the three renamed tests now test what they say.

---

## Changes in this pass

| File | Change |
|---|---|
| `lib/phoenix_kit/users/auth.ex` | `target_label/1`; `refuse_credential_write/2` no longer narrows the target; `@updatable_profile_fields` + public `updatable_profile_fields/0`; authorization warning on `update_user_fields/2`'s `@doc` |
| `lib/phoenix_kit_web/users/user_form.ex` | filter reads `Auth.updatable_profile_fields/0`; logs what it drops; `credential_authority_now/2` comment corrected |
| `test/integration/users/security_authority_test.exs` | +1 test: malformed target refuses cleanly |
| `test/integration/users/user_form_authority_test.exs` | +2 tests: every listed field dropped; a legitimate custom field still saves. Stale-authority comment corrected |

## Gate

`mix precommit` — format, `compile --warnings-as-errors`,
`deps.unlock --check-unused`, `credo --strict`, dialyzer, JS tests: **passing**.
Integration tests not executed (no PostgreSQL in this environment).
