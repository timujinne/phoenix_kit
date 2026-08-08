# PR #683: Admin UI and i18n corrections; surface sign-in-as-user in the users menus

**Author**: @timujinne
**Reviewer**: Claude (post-merge)
**Status**: ✅ Merged, reviewed, fixes applied on `main`
**Commit**: `a825e9a7` (merge of `feature/admin-ui-i18n-and-impersonation-entry-points`)
**Date**: 2026-08-05
**Shipped in**: 1.7.232

## Goal

Two related pieces of admin-surface work:

1. Required-field markers, the user-detail Edit action, the `Person` → `Personal` account-type
   label, and the admin-nav role badge.
2. UI entry points for `MultiSession.impersonate/2`, which shipped in #672 with nothing in any
   template reaching it.

## What Was Changed

| File | Change |
|------|--------|
| `lib/phoenix_kit_web/users/multi_session.ex` | `role_label/1` made public + `role_label_from_roles/1`; new `impersonation_actor/1`, `impersonable?/2`, `impersonable_uuids/2`; authority rule extracted to `decide_impersonation/4` |
| `lib/phoenix_kit_web/components/admin_nav.ex` | Role badge derives from `MultiSession.role_label_from_roles/1` over `cached_roles` instead of `Scope.can_access_admin_area?/1` |
| `lib/phoenix_kit_web/components/core/table_row_menu.ex` | `table_row_menu_link` passes `method`, `csrf_token`, `data-confirm` through |
| `lib/phoenix_kit_web/live/users/users.{ex,html.heex}` | `impersonable_uuids` assign; "Sign in as user" in both the table and card row menus |
| `lib/phoenix_kit_web/live/users/user_details.{ex,html.heex}` | Edit moves from the breadcrumb `page_action` into the actions menu; "Sign in as user" added |
| `lib/phoenix_kit/users/auth/user.ex` | `generate_username_from_email/1` transliterates before stripping non-ASCII |
| `roles.html.heex`, `user_form.html.heex`, `registration.html.heex` | Six hand-appended `" *"` markers removed; `Organization Name` gains `required` |
| `priv/gettext/**` | `Person` → `Personal`, the two new impersonation strings, Estonian/Russian repairs |

## Review Findings

### BUG - MEDIUM — the menu offered impersonation of deactivated accounts, which the POST always refuses

`impersonable?/2` and `impersonable_uuids/2` asked `authorize_impersonation/2`, which decides
*authority* only. The `:inactive` refusal is raised later, by `add_authenticated_user/2`. So every
deactivated row in the admin list carried a "Sign in as user" item — next to the status badge
saying the account is deactivated — and clicking it came back "That account is deactivated."

The PR's own docstring frames the refusals it deliberately leaves to the controller as *transient*
("the stack being full, or the target already sitting in it") — reasons that change between one
click and the next. Deactivation is not one of those; it is a stable property of the target, and
`user.is_active` is already on the struct the list renders, so no extra query is needed to respect
it.

**Fixed** in `multi_session.ex`: both predicates now answer false for an inactive target
(`impersonable?/2` by clause head, `impersonable_uuids/2` by generator pattern), with the reasoning
recorded on `impersonable?/2`. `impersonate/2` is untouched — it still re-decides everything
server-side.

### BUG - MEDIUM (i18n, pre-existing, surfaced by this PR's .po edits) — `default.pot` was stale, and four reworded entries were rendering the *old* translation

`mix gettext.extract --check-up-to-date` failed on the merge commit. Two distinct problems:

- **18 msgids never extracted.** Strings from the SEO/robots.txt settings page, the hex.pm package
  browser and the referral gate ("Enter your referral code", "This site is invite-only…") were in
  the source but not in `default.pot`, and therefore in no `.po` file. They rendered as English in
  every locale.
- **4 reworded msgids kept a stale translation.** `Continue`, `Log out`, `Referral code` and
  `SEO settings` matched fuzzily against older entries. Fuzzy entries **do** render, so German
  users saw **"online"** on a Continue button and "Abmeldung" (a noun) where a verb belongs.

This PR did not cause the drift — it inherited it and hand-edited the `.po` files around it, which
is also why every reference line in the `.pot` was off by the lines this PR added. Left alone it
would have shipped in the release.

**Fixed**: full `mix gettext.extract --merge` round-trip, then the 18 new + 4 reworded entries
translated in all seven locales (de, es, et, fr, it, pl, ru), reusing the terminology already in
each file (`Empfehlungscode`, `Code de parrainage`, `Código de referencia`, `Codice di invito`,
`Kod polecający`, `Реферальный код`, `Soovituskood`; `Sitemap`/`Plan du site`/`Mapa witryny`/
`Карта сайта`/`Saidikaart`). Technical tokens (`priv/static/robots.txt`, `Sitemap:`, `noindex`,
`PhoenixKit`, `hex.pm`) left verbatim. All seven locales are back to 0 untranslated / 0 fuzzy;
`--check-up-to-date` is green; a placeholder audit across every `.po` (both directions) reports 0
mismatches.

### IMPROVEMENT - MEDIUM (i18n) — the Russian `Personal` is the calque the PR set out to avoid

The PR's reasoning for renaming the msgid is right, and six of the seven locales followed it:
`Eraisik`, `Privatperson`, `Particulier`, `Particular`, `Privato`, `Osoba prywatna` — the
private-individual noun that pairs with `Organization`.

Russian went the other way. `Физическое лицо` — the exact legal counterpart of *юридическое лицо*,
and the term Russian account-type selectors actually use — was replaced with **`Личный`**, a
masculine adjective ("personal") that reads as a translation of the English word rather than a name
for the kind of account, and sits oddly next to `Организация`.

**Fixed**: `Физическое лицо` restored.

### IMPROVEMENT - MEDIUM — the user detail page re-queried roles on every render

`users.ex` is careful: `impersonable_uuids/2` reads the actor's roles once and each target's from
the `:roles` preload `list_users_paginated/1` already returns. `user_details.html.heex` calls
`impersonable?/2` inline instead, and that went through `authorize_impersonation/2` → two
`get_roles/1` queries **per render** — on a page with note CRUD, tab switches and a role modal.

Computing it once in `mount/3` would go stale: the role-management modal on that same page changes
the answer.

**Fixed** without giving up the freshness: `impersonable?/2` now reads the target's roles from the
`:roles` preload when the caller has one. `user_details.ex` loads its user through
`get_user_with_roles/1` at every site that assigns `@user`, so the target lookup disappears and the actor
lookup remains — halved, and still recomputed on every render, so a role change on the page is
still reflected.

### NITPICK — a comment was orphaned onto the wrong function

`current_role_badge/1` was inserted between `# OAuth buttons for the "Add account" modal.` and the
rest of that comment, leaving the badge introduced as OAuth buttons and
`add_account_oauth_buttons/1` with its first line missing. **Fixed** — the line rejoined its
function.

### Test gap — the new public API shipped untested

`multi_session.ex` has a thorough suite (`test/integration/users/multi_session_test.exs`, ~30 tests
including one per impersonation refusal). The PR added three public functions and a new decision
path over preloaded roles without touching it. `impersonable_uuids/2` is exactly where a drift bug
hides: it reaches the rule by a different route than the request does.

**Added** (integration, `multi_session_test.exs`):

- `impersonable?/2` agrees with `impersonate/2` target by target — plain user, Owner, another
  Admin, self, Owner→Admin, a non-staff permission holder, `nil` actor.
- A deactivated target is not offered, and `impersonate/2` refuses it — the regression above.
- `impersonable_uuids/2` and `impersonable?/2` agree over a mixed list (the drift assertion).
- `impersonable_uuids/2` works off a preloaded `:roles`.
- `impersonation_actor/1` is the ROOT account after a switch, `nil` when `multi_session_enabled`
  is off, `nil` when anonymous.

**Added** (unit, `test/phoenix_kit/users/auth/username_from_email_test.exs`) for the transliteration
fix, which had no coverage at all: accents folded rather than deleted (`Ülo.Kask@` → `ulo_kask`,
the PR's own example), a Cyrillic local part (`Иван@` → `ivan`), plus the pre-existing `user_`
prefix and minimum-length paths. Needs no database — **run and passing** (6 tests).

## Verified and Found Correct

- **`<.link method="post">` from inside a portalled row menu works.** The RowMenu hook moves the
  `<ul>` to `<body>` while open; `phoenix_html`'s `data-method` / `data-confirm` handlers are
  delegated on `document` and build their form on `body`, so the portal is irrelevant. `<.link>`
  generates the CSRF token itself, and the same pattern is already used in `root.html.heex`,
  `admin_nav.ex` and `user_dashboard_nav.ex`. A `phx-click` genuinely could not do this — it never
  touches the session cookie.
- **`impersonable_uuids/2` really does avoid the N+1.** `list_users_paginated/1` preloads `:roles`,
  and the `many_to_many :roles` set is identical to what `Roles.get_user_roles/1` returns (both are
  all assignments, neither filters on activity), so the list path and the request path cannot
  disagree about a user's roles.
- **The role badge is not a regression for Owners.** `Scope.owner?/1` also reads `cached_roles`, so
  the new `case` covers the same ground; the empty/absent-roles fallback ("User") matches the old
  `else` branch.
- **The required-marker sweep is complete.** No `label=` in the tree still carries an asterisk. The
  four remaining hand-written `*` in `settings/users.html.heex` are on raw `<span class="label-text">`
  labels, not `<.input>`, so they are not doubled. `<.select>` and `<.textarea>` render the same
  marker as `<.input>`, so nothing lost one.
- **`Person` → `Personal` is applied at every call site** (users filter, registration select, user
  form radio, user detail badge); no `gettext("Person")` survives.
- **`Organization Name` gaining `required` matches the changeset**, which requires it for
  organization accounts, and the field only renders for that account type.

## Accepted, Not Changed

- **`impersonation_actor/1` runs in `mount/3`**, so its settings read and root-token lookup happen
  twice per page load. Both LiveViews already do substantially more work in `mount/3`
  (`get_project_title`, batched settings, `load_stats`), so moving one call to `handle_params/3`
  would single out the cheapest offender without changing the page's shape. Worth a sweep of its
  own, not a one-line exception here.
- **`page_action` and its `:action` slot are now unused** but kept on `LayoutWrapper` as public API,
  as the PR states. Host apps may be using them.

## Validation

- `mix precommit` — green (compile warnings-as-errors, `deps.unlock --check-unused`, format,
  `credo --strict`, dialyzer, JS tests).
- `mix compile --force --warnings-as-errors` after the `.po` edits — green (this is what validates
  `.po` syntax; `msgfmt` is not available here and would not catch placeholder drift anyway).
- `mix gettext.extract --check-up-to-date` — green.
- `mix test test/phoenix_kit/users/auth/username_from_email_test.exs` — 6 tests, 0 failures.
- The new integration tests need PostgreSQL, which this environment has none of; they are excluded
  here and will run under `mix test.setup && mix test` or a CI dispatch.
