# PR #716 Phase 1 Review — phoenix_kit

**Title:** Theme system overhaul, tab auto-hide, shared pagination math
**Author:** Max Don (mdon)
**Verdict:** APPROVE WITH NOTES

---

## Summary

Substantial, well-executed PR across four arcs. Test coverage is thorough (3645 tests, 0
failures per PR body). The theme work is the largest arc — three divergent inline scripts
consolidated into two components (`ThemeBootstrap` + `ThemeControllerScript`), injection
hardening done correctly at both the CSS and JSON sinks, and the toggle picker is a solid
a11y improvement. Tab auto-hide and pagination are clean bug-fix extractions.

The main things to flag before ship: **removed public API functions** need a CHANGELOG
entry and semver bump (explicitly deferred by mdon, but must happen before tagging); the
`ensure_theme_bootstrap/1` installer helper bypasses Igniter's staging model; and the old
static `phoenix_kit_themes.js` used a different localStorage key than the new system.

---

## Findings

### Blockers

**None that block merging.** The items below need to be handled before the release tag.

### Non-blockers

**1. Removed public API — breaking change needs CHANGELOG + semver bump before tag**

Seven functions removed from `PhoenixKit.ThemeConfig`:

- `get_theme/0`
- `theme_data_attributes/0`
- `modern_css_variables/0` — docstring said "kept for backwards compatibility"
- `slider_targets/1`
- `slider_target_map/0`
- `slider_primary_theme/1`
- `slider_primary_map/0`

Also removed: `data-admin-theme-base` HTML attribute from `LayoutWrapper` body/html.
Any host app calling these gets a compile error on upgrade. The PR body explicitly says "no
CHANGELOG or version changes" — that's the right call for the merge, but the release commit
needs to record these removals and bump the minor or major version accordingly.

**2. `ensure_theme_bootstrap/1` bypasses Igniter's staged-change pipeline**

`lib/phoenix_kit/install/js_integration.ex` writes directly to the host filesystem with
`File.read!` / `File.write!` rather than going through Igniter's change-staging API. All
other installer helpers in `JsIntegration` use Igniter. The direct write:

- skips Igniter's dry-run support
- cannot be rolled back if `mix phoenix_kit.update` fails mid-run
- bypasses Igniter's code formatter and diff preview

The idempotency logic (marker string check) is sound, but the write mechanism is
inconsistent. Consider replacing with `Igniter.update_file/3` or an equivalent Igniter
primitive in a follow-up.

**3. Storage key migration: `phoenix_kit_themes.js` used a different key**

The deleted `priv/static/assets/phoenix_kit_themes.js` persisted the user's theme under
`phoenix_kit_theme` (line ~49 of the deleted file). The new system uses `phx:theme`. Any
user who had a saved preference via the old static JS file will see their preference reset
to system default after upgrade. Likely low impact (the static file was a legacy path), but
worth a migration note or a one-time read-and-migrate in the bootstrap script.

**4. `extends` chaining is limited to built-in themes**

`build_theme_variables/1` does `Map.fetch!(@custom_theme_variables, extends)`, which only
looks at compile-time built-ins. A host that defines `brand-light` and then tries to extend
it with `brand-light-high-contrast` will crash at `Map.fetch!`. Reasonable v1 limitation
but should be documented in the `:theme_definitions` config docs.

**5. Referral arc depends on `phoenix_kit_referrals#7` for full effect**

`historically_redeemed?/1` dispatches `:signup_use_exists?` — if that function isn't
exported by the installed referrals module, dispatch returns an error tuple and the gate
behaves as before. Merge order is safe per PR description. Just ensure `referrals#7` ships
in the same release window or the backfill story is incomplete.

### Nitpicks

- `ThemeDefinitionsTest` setup erases the specific persistent_term keys it uses — correct.
  The warning-latch tests (`system_pair_warned`) have `after` blocks to clean up. Good.

- `parameterized_path?/1` regex `^:[A-Za-z_]\w*$|^\*` uses `^`/`$` anchors on a
  per-segment basis after `String.split("/")` — technically `\A`/`\z` would be more
  precise, but segment strings from `split` can't contain newlines, so it doesn't matter.

- The `module.ex` filter in `live/modules.ex` was `tab.visible != false` and is now
  `not Tab.hard_hidden?(tab)` — correct, as `nil` with a parameterized path is now
  also hidden.

- `toggle_icon_css/1` has a belt-and-suspenders regex guard even though theme names are
  already validated upstream. Fine; harmless.

---

## Stats

| | |
|---|---|
| **Tests** | New: `pagination_test.exs` (48 lines), `theme_definitions_test.exs` (242 lines), `theme_controller_test.exs` (148 lines), `theme_bootstrap_test.exs` (60 lines), `theme_controller_script_test.exs` (97 lines) + tab_test additions. Well covered. |
| **Migrations** | None |
| **Version bump** | None (intentionally deferred per PR body — required before release tag) |
| **Dependency changes** | None in mix.exs |
| **Files changed** | 28 (+1751 / -554) |
| **Suite** | 3645 tests, 0 failures (per PR body) |

---

## Security Observations

Theme injection hardening is thorough and correctly applied:

- Theme names: `~r/\A[a-z0-9][a-z0-9_-]*\z/` (anchored with `\A`/`\z`, not `^`/`$`)
- CSS variable names: allowlist (`--color-`, `--radius-`, `--size-` prefixes + named
  exceptions) plus `~r/\A--[a-z0-9-]+\z/` to block injection via the name itself
- CSS values: `~r"\A[^;{}<>\\]*\z"` + explicit substring blocks for `url(`, `@import`,
  `/*`, `*/` + backslash forbidden outright (kills CSS escape bypass)
- JSON sinks: `Jason.encode!(…, escape: :html_safe)` at both bootstrap and controller script
- Validation is in `build_host_theme_meta/1` so CSS and JS embeds share the same pass
- Tests cover all named panel findings: unvalidated meta path, variable-NAME injection,
  CSS escape-sequence bypass

The single-quoted JS interpolations for `@light`/`@dark` are safe because validated theme
names are `[a-z0-9_-]` only — no characters that need HTML escaping or could break a JS
string literal.
