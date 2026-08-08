# PR #686 Review — Fix four account-takeover paths found by a security review

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/686
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-07 (`4def5ea9`, branch `fix/security-p0` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-07
**Scope:** 24 files, +1492 / −167. 3 new test files (19 new tests), 1 new module.

---

## Verdict

The five paths the PR claims to close are real, correctly diagnosed, and closed
at the right layer — in the context, not in the template. The reasoning comments
are unusually good and I verified the load-bearing ones against their sources
rather than taking them on trust:

| Claim | Verified against |
|---|---|
| `raw_info` is `%{token:, user:}` with **atom** keys, `user` string-keyed | `deps/ueberauth_{google,github,facebook}/…/strategy.ex` — `extra/1` |
| GitHub's default scope is `""`, so `/user/emails` never populates `"emails"` | `deps/ueberauth_github/lib/ueberauth/strategy/github.ex:76,254` |
| `(provider, provider_uid)` is UNIQUE and the conflict is handled | `v16.ex:85-88` + `OAuthProvider.changeset/2` `unique_constraint` |
| The new `log_in_user/3` halt-clause cannot hit `Plug.Conn.AlreadySentError` | all four callers use it as the terminal call in their pipe |
| `readonly` reaches the rendered `<input>` | `core/input.ex:60` — it is in the `:rest` `include:` list |
| `ensure_active_user/1` passes `nil` through | `auth.ex:1127` |

Five defects found: one security gap the PR walked past in the very function it
cites as its model, a broken sign-up flow it introduced, seven locales rendering
the wrong text for its new strings, a performance regression in a hot admin list,
and a UI/server disagreement from gating one of two twin controls. All five are
fixed in this pass; the first two are locked in by new tests.

**Verification caveat:** no PostgreSQL is reachable in this environment, so the
integration tests — the PR's 19 and my 8 — did not execute here. They compile and
load (39 collected, all excluded). `mix precommit`, which is the project's stated
bar, passes: format, `compile --warnings-as-errors`, unused-deps,
`credo --strict`, dialyzer, JS tests.

---

## BUG - HIGH — `can_delete_user?/2` never got the rank rule it is cited as the model for

**Files:** `lib/phoenix_kit/users/auth.ex` (`validate_can_delete_user/2`)

The PR's `can_manage_user_credentials?/2` docstring says the new rule "mirrors
`can_delete_user?/2` … so the three account-takeover surfaces agree." They do
not agree — `can_delete_user?/2` is two rules weaker than the one built to
mirror it:

```elixir
# Rule 3: Only Owner can delete Admin users
Roles.user_has_role_admin?(user) and not Roles.user_has_role_owner?(current_user) ->
  {:error, :insufficient_permissions}

# Rule 4: Only Admin/Owner can delete (checked via scope in controller/LiveView)
true -> :ok
```

1. **The only protected target is an *Admin*.** An Owner holds only the `Owner`
   role — `ensure_first_user_is_owner/1` calls `assign_role_internal(user,
   roles.owner)` and nothing adds `Admin` alongside it — so
   `user_has_role_admin?(owner)` is `false` and rule 3 does not fire. The last
   Owner is protected by rule 2; **any other Owner is not**. An Admin can delete
   an Owner outright.
2. **The actor's rank is never checked here at all.** Rule 4 defers it to "the
   controller/LiveView" — which is the `can_access_admin_area?/1`-shaped gate
   that finding #1 of this very PR was written to discredit: true for any holder
   of a single permission. `Auth.delete_user/2` is the only thing standing
   between a `users`-permission role and `execute_user_deletion/1`, and it says
   yes.

So the same Manager the PR just stopped from *setting an Owner's password* could
still **delete the Owner's account**. Deletion is at least as final as takeover,
and unlike deactivation it is not reversible.

**Fix applied.** `validate_can_delete_user/2` now keeps its two target-only
rules (self, last Owner — checked first so `:cannot_delete_last_owner` keeps its
own message) and delegates the rest to the PR's own
`validate_admin_authority_over/2`. The two LiveViews gained an explicit clause
for the rank refusals so they read as a permission decision instead of falling
through to "Failed to delete user".

**Tests added** — `security_authority_test.exs`, `"deletion answers to the same
rank rule"`: Admin→Owner refused while another Owner remains, staffless
`users`-holder refused, Admin→Admin refused, Admin→ordinary allowed,
Owner→Admin allowed, and the last-Owner guard keeping its own reason.

---

## BUG - MEDIUM — a new OAuth account that is not auto-confirmed is never sent the confirmation mail

**Files:** `lib/phoenix_kit/users/oauth.ex` (`register_oauth_user/3`)

The PR's own comment on the branch it added says:

> A new account whose address the provider did not vouch for goes through the
> ordinary confirmation mail instead

It does not. `Auth.register_user/2` does not deliver confirmation instructions —
only `PhoenixKitWeb.Users.Registration` and `UserForm.create_user/2` ever call
`deliver_user_confirmation_instructions/2`, and the OAuth path goes through
neither. Before this PR the point was moot, because every OAuth user was
auto-confirmed; the PR made a branch where they are not, and left the branch
without a mail.

The result for the concrete case (a Facebook sign-up — see the note below —
or any provider that does not surface a claim): the account is created, the user
is signed in with *"Successfully signed in with Facebook!"*, and then
`require_email_confirmation` (default `true`, honoured at eleven gates) bounces
them off every protected page. Their inbox is empty. The only way through is to
find `/users/confirmation-instructions` unaided.

**Fix applied.** The `else` branch now calls
`Auth.deliver_user_confirmation_instructions/2`, logging and continuing on a
delivery failure — the account exists either way and the confirmation page can
resend. Placed in the context beside the decision rather than in the controller,
because only the context knows the account was *just created and left unproven*;
the controller cannot tell that state from "an already-linked user who happens to
be unconfirmed", which must not be re-mailed on every sign-in.

**Tests added** — `oauth_email_verification_test.exs`: an unvouched new account
has exactly one `"confirm"` token row; a vouched one has none.

---

## IMPROVEMENT - HIGH — the new row guard is an N+1 on a list that already preloads what it needs

**Files:** `users.html.heex`, `user_details.html.heex`, `auth.ex`

`Auth.can_manage_user_status?(user, @phoenix_kit_current_user)` was added inside
the per-row loop of the users list. Every evaluation runs
`validate_admin_authority_over/2`, and every role question in it is
`Roles.user_has_role?/2` — an uncached `repo.exists?`. Up to four per row:

- actor is Owner? / actor is Admin?  (same struct, re-asked for every row)
- target is Owner? / target is Admin?

On a 50-row page that is up to 200 extra round trips, repeated on **every**
re-render — sort, filter, search, and each `user_updated` PubSub broadcast. The
neighbouring `can_delete_user?/2` has the same shape, so the PR roughly doubled
an existing cost rather than creating it, but it did so on the hot path.

Both halves of it are avoidable, and the data is already in hand:

- `Auth.list_users_paginated/1` **already** `preload([:roles, …])`s every row
  (`auth.ex:2275`). The LiveView even has a private `get_user_roles/1` that
  prefers the preload — the new guard just doesn't use it.
- The actor is one struct for the whole render.

**Fix applied.** A private `has_system_role?/2` in `Auth` reads a preloaded
`:roles` association when it is loaded and queries only when it is not; the rank
rule and the delete rule both go through it. The two list templates hand in an
`@actor_with_roles` loaded once in `mount/3`. Per-row query cost drops to zero
in the normal case, and the rule itself stays in one place — I deliberately did
not re-express it in the template, which is how the whitelist-vs-registry drift
this PR fixes gets reintroduced.

Preloaded assignments are the live set (an inactive assignment is deleted, not
flagged — see the existing comment at `users.ex:856`), so the two paths agree.

---

## IMPROVEMENT - MEDIUM — the confirmation switch was left advertising an action the server now refuses

**Files:** `users.html.heex`, `user_details.html.heex`

`toggle_user_confirmation/2` gained the rank check — and the PR's own comment
explains why it deserves one: `require_email_confirmation` is honoured at eleven
gates, so **unconfirming** an account locks it out of every protected page. It is
a denial of service against a target that outranks the actor.

But only the *status* button was gated in the templates. Its twin, sitting
directly above it in the same menu and governed by the same predicate, still
renders. An Admin opening another Admin sees "Unconfirm Email", clicks it, and
gets an error flash. The server is correct; the UI disagrees with it — which is
the exact "two lists drifting apart" shape the rest of this PR is careful about.

**Fix applied.** Both buttons now sit under the single
`can_manage_user_status?/2` check, in all three menus (list table view, list card
view, detail page).

---

## BUG - MEDIUM — the gettext catalogs were left stale, and the merge guessed four wrong translations

**Files:** `priv/gettext/**`

The PR added six new `gettext` strings (four permission-refusal flashes, plus the
`oauth_require_verified_email` label and its help paragraph) and changed **zero**
files under `priv/gettext` — `mix gettext.extract --check-up-to-date` was red on
the merge commit. The repo's own note is that the `.pot` goes stale silently, and
this is the shape it takes.

The consequence is worse than "untranslated". Running the merge, all four
refusal strings fuzzy-matched onto the same pre-existing entry — and a fuzzy
entry *renders*:

```po
#, elixir-autogen, elixir-format, fuzzy
msgid "You don't have permission to delete this user"
msgstr "Sie sind nicht berechtigt, Berechtigungen zu verwalten"   # "…to manage permissions"
```

Same in all seven translated locales. Every one of the new refusals — status,
confirmation, credentials, delete — would have told a German, Spanish, Estonian,
French, Italian, Polish or Russian operator they lack permission to *manage
permissions*, which is not what happened and does not point at the fix.

**Fix applied.** Extracted, merged, wrote real translations for all six strings
in all seven locales, and cleared the fuzzy flags (including on `en`, whose
`msgstr` stays empty and falls back to the msgid by design). All seven translated
locales are back to 2190/2190; `mix gettext.extract --check-up-to-date` is green.

---

## NITPICK — the PR as merged does not pass `mix precommit`

`test/integration/users/oauth_email_verification_test.exs` fails
`mix credo --strict` (which `quality.ci`, and therefore `precommit`, runs) with a
`Credo.Check.Design.AliasUsage` on the inline
`PhoenixKit.Settings.Setting.SettingsForm.__schema__(:fields)` call. The PR
description reports `mix credo --strict` clean — it was clean for `lib/`, but the
project's `.credo.exs` includes `test/`, so the gate as the repo defines it was
red on merge. Fixed here by aliasing `SettingsForm`.

---

## NITPICK — Facebook's `verified` will not satisfy the gate, and the escape hatch is global

**File:** `lib/phoenix_kit/users/oauth.ex`

`provider_asserts_verified_email?(%{provider: "facebook"})` reads `verified` from
the user payload. `ueberauth_facebook`'s default `profile_fields` does request
it, so the plumbing is right — but `verified` is an account-level Graph API field
that current API versions do not return for most apps. If it is absent for a
given deployment, **every** Facebook sign-in into a pre-existing local account is
refused, permanently, and the only lever is `oauth_require_verified_email`, which
is all-or-nothing across providers — turning it off to unblock Facebook also
disables the gate for Google and GitHub, where it works and matters.

Not fixed: I cannot verify the field's behaviour against a live Facebook app from
here, and guessing at a per-provider setting is a design decision for the author.
Recorded so the first "Facebook login is broken" report is cheap to diagnose. If
it is confirmed, the shape to add is a per-provider override rather than
loosening the shared default.

---

## NITPICK — `CssValue.color/1` refuses CSS Color 4 slash-alpha, and the error message doesn't say so

**File:** `lib/phoenix_kit/utils/css_value.ex`

`@color_charset` excludes `/`, so `rgb(30 41 59 / 50%)` and
`hsl(217 33% 17% / .5)` — the forms design tools copy out today — are rejected.
The operator-facing message suggests `rgb(30 41 59)`, one character away from the
form that just failed, so the near miss is silent.

`/` looks safe to admit (`*` is not in the charset, so `/*` cannot be spelled,
and `url(` is refused by name), but **I have deliberately not changed it.**
Loosening an allowlist that exists because of a live stored-XSS finding, in a
post-merge review, without the author, is the wrong trade for a cosmetic win. The
alternative — mentioning the limitation in the message — is churn on a string
that is already about to be translated. Left as-is, on record.

---

## Verified and NOT a finding

Checked and cleared, so the next reviewer doesn't re-walk them:

- **`log_in_user/3`'s new halting clause and `Plug.Conn.AlreadySentError`.** All
  four callers (`session.ex:77`, `magic_link_verify.ex:57`,
  `qr_login_complete.ex:30`, `oauth.ex:275`) use it as the last call in their
  pipe, so nothing runs against a sent conn.
- **`Settings.update_setting/2` in an `async: true` test.** It *invalidates* the
  cache rather than writing through it, and every other test re-reads inside its
  own sandbox connection, so the OAuth switch test cannot leak a value into a
  concurrent run. (It costs a cache miss; that is all.)
- **Role escalation via the user form.** `Roles.sync_user_roles/3`'s
  `authorize_role_changes/2` already drops system-role grants from a non-Owner
  actor, so the credential fix does not leave a "just promote yourself" door open
  beside it.
- **`var()` through `CssValue.color/1`.** Spellable within the charset, but an
  attacker cannot define a custom property, and the value still cannot leave its
  declaration (`;`, `{`, `}`, `<`, `>`, quotes and `\` are all excluded).
- **The stale `@can_manage_credentials` assign** in `UserForm` (computed in
  `mount/3`, not recomputed after `apply_roles`). Only exploitable if a target is
  promoted *above* the actor mid-session, which a non-Owner actor cannot cause;
  and the write path re-drops the fields regardless.

---

## Files changed by this review

| File | Change |
|---|---|
| `lib/phoenix_kit/users/auth.ex` | delete rule routed through the shared rank rule; preload-aware `has_system_role?/2` |
| `lib/phoenix_kit/users/oauth.ex` | confirmation mail for a new, unvouched account |
| `lib/phoenix_kit_web/live/users/users.ex` | `@actor_with_roles`; named flash for rank refusals on delete |
| `lib/phoenix_kit_web/live/users/user_details.ex` | named flash for rank refusals on delete |
| `lib/phoenix_kit_web/live/users/users.html.heex` | confirmation switch gated; guards use `@actor_with_roles` |
| `lib/phoenix_kit_web/live/users/user_details.html.heex` | confirmation switch gated |
| `test/integration/users/security_authority_test.exs` | +6 deletion-authority tests; setup returns the sandbox Owner |
| `test/integration/users/oauth_email_verification_test.exs` | +2 confirmation-mail tests; credo alias fixes |
| `priv/gettext/**` | `.pot` re-extracted; 6 strings translated in 7 locales; fuzzy flags cleared |
| `mix.exs`, `CHANGELOG.md`, `mix.lock` | 1.7.235; changelog entry; postgrex 0.22.3 → 0.22.4 (clears the `mix hex.audit` advisory) |
