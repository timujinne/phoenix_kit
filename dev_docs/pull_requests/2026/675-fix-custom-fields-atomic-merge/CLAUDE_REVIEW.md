# PR #675 — Guard the atomic custom_fields merge/delete against a NULL column

- **Author:** timujinne
- **Branch:** `fix-custom-fields-atomic-merge` → `main`
- **Merge commit:** `1e31b8bb` (single branch commit `224a4eb9`)
- **Reviewed:** 2026-07-31
- **Scope:** `lib/phoenix_kit/users/auth.ex`, `test/integration/users/profile_test.exs`

## What the PR does

Follow-up hardening on the atomic `custom_fields` primitives introduced earlier:

1. `merge_user_custom_fields/3` — wraps the left operand in `COALESCE(?, '{}'::jsonb)`,
   because `custom_fields` is nullable (V18) and `NULL || jsonb` is `NULL`. Without it a
   NULL row silently swallowed the additions with no error.
2. `delete_user_custom_field/3` — same guard for `NULL - key`, which also preserves the
   old `Map.delete(nil || %{}, key)` side effect of normalizing the column to `'{}'`.
3. Docs: the locale path's switch to the atomic primitives (and its deliberate
   `ensure_definitions: false`), plus `set_user_custom_field/3`'s `{:error, :not_found}`.
4. Two integration tests covering the NULL column on both paths.

**Verdict: correct and well-targeted.** The `COALESCE` idiom matches what V30 already
does for its own atomic merge (`v30.ex:42`), V18 confirms the column is nullable with a
`%{}` default, and a repo-wide sweep found no other `||` / `- key` jsonb fragment that
still lacks the guard (`merge_user_custom_fields/3` is the only `||` fragment in `lib/`;
V76's rename is protected by its `WHERE custom_fields ? 'avatar_file_id'`, which does not
match NULL rows). No bug in the diff itself.

The findings below are gaps the PR's own premise exposes but did not close.

---

## BUG - MEDIUM — `Notifications.Prefs.write/2` still replaces the whole column, from a stale snapshot

**File:** `lib/phoenix_kit/notifications/prefs.ex:92`

```elixir
defp write(%User{} = user, prefs_map) do
  merged = Map.put(user.custom_fields || %{}, @prefs_key, prefs_map)
  Auth.update_user_custom_fields(user, merged)
end
```

Every other core writer of a sibling key in `custom_fields` now writes atomically —
`ChannelConfig.put/3` and `delete/2`, `update_user_locale_preference/2` (this PR),
`set_user_custom_field/3`. `Prefs.write/2` was the one left doing read-modify-write, and
it is the **worst-placed** one: unlike `media_browser.ex` / `media_canvas_viewer.ex`,
which re-read the user with `Auth.get_user(uuid)` immediately before writing (tiny
window), it rebuilds the column from the `%User{}` the caller has been holding for the
lifetime of the page — `settings.ex:33` loads it in `mount/3`, `user_settings.ex` keeps
it in component assigns.

**Failure scenario.** Open `/admin/notifications/settings`. In another tab (or from any
page — the language-switcher hook fires `update_user_locale_preference/2` on every
switch) something writes a sibling key: connect Telegram → `notification_channel:telegram`,
or switch language → `preferred_locale`. Return to the settings tab and press Save. The
save writes back the mount-time map: the Telegram channel config is gone and the locale
is reverted. No error, no conflict — exactly the lost-update class this PR series exists
to close.

This also contradicts `ChannelConfig`'s own moduledoc (`channel_config.ex:6-11`), which
justifies the one-key-per-channel layout by saying the atomic merge updates a channel
"without clobbering another channel or the unrelated `notification_preferences` map."
That guarantee only held in one direction.

**Fixed.** `write/2` now goes through `Auth.merge_user_custom_fields/3` with
`ensure_definitions: false` (internal blob, same rationale as `ChannelConfig.put/3`).
The `@spec`s on `update/2` and `merge/2` were corrected from
`{:error, Ecto.Changeset.t()}` to `{:error, :not_found}`; both call sites
(`settings.ex:128`, `user_settings.ex:482`) already match `{:error, _}`, so no caller
changes were needed. Regression test added in `prefs_test.exs`: a sibling
`notification_channel:telegram` key written after the caller's snapshot survives a
`Prefs.merge/2`.

**Deliberately not fixed:** `Prefs.merge/2` still computes its overlay from the passed
user's prefs, so a concurrent write to the *same* `notification_preferences` key can
still be lost. That is a genuinely narrower race (same key, same settings page) and
closing it needs a jsonb deep-merge primitive — over-engineering for the current call
sites. Documented in the `merge/2` docstring alongside `ChannelConfig.update/3`'s
identical caveat.

---

## BUG - LOW — Internal UI-preference keys auto-register as admin-visible custom fields

**Files:** `lib/phoenix_kit_web/components/media_browser.ex:2955,3000`,
`lib/phoenix_kit_web/components/media_canvas_viewer.ex:228,254,442`

`update_user_custom_fields/3` defaults to `ensure_definitions: true`, and
`CustomFields.ensure_definitions_exist/1` (`custom_fields.ex:522`) registers a definition
for **every key in the map it is handed** — not just the one the caller changed. Since
these callers pass the whole merged column, one sidebar toggle registers definitions for
whatever else happens to live in that user's `custom_fields`.

`users.ex:821` and `activity/index.ex:198` pass `ensure_definitions: false` for exactly
this reason; the five media sites did not. Result: `media_view_mode`,
`media_expanded_folders`, `media_sidebar_collapsed`, `etcher_colors`,
`etcher_line_params` and `media_viewer_info_collapsed` show up in the admin Custom Fields
list and the users-table column customizer as user-facing fields.

**Fixed.** All five now pass `ensure_definitions: false`. Reads go through
`Auth.get_user_field/2` (`auth.ex:1967`), which never consults definitions, so turning
registration off is read-safe. Note this does not retro-remove definitions already
registered on existing installs — an admin can delete them; not worth a migration.

`broadcast:` was left at its default at these sites: `users.ex` disables it to avoid
reloading every admin's user list on a view toggle, but the media components' own
comments state that hosts rely on the `phoenix_kit_user_updated` fan-out to refresh
`current_user`. Changing it is a behavioural call for the maintainer, not a review fix.

---

## NITPICK — `update_user_locale_preference/2` had an undocumented error union

**File:** `lib/phoenix_kit/users/auth.ex:1588`

After the switch to the atomic primitives the function returns `{:error, String.t()}`
(validation) *or* `{:error, :not_found}` (row deleted concurrently). The docstring showed
only the string form and there was no `@spec`. Added a `@spec` and a sentence naming both
shapes. The only caller (`phoenix_kit_web/users/auth.ex:816`) discards the result, so
nothing breaks either way.

---

## NITPICK — `set_user_custom_field/3`'s new documented contract had no test

**File:** `test/integration/users/profile_test.exs`

The PR documents that `set_user_custom_field/3` returns `{:error, :not_found}` rather
than a changeset error, but only `merge_user_custom_fields/3` and
`delete_user_custom_field/3` have that test. Added the matching case for the delegating
function so the documented contract is locked in.

---

## Validation

`mix precommit` (format + `compile --warnings-as-errors` + `credo --strict` + dialyzer).
Integration tests are not run in this repo standalone — no PostgreSQL — per
`CLAUDE.md`; the gate is the bar.
