# PR #716 — Theme system overhaul, tab auto-hide, shared pagination math

- **Author:** Max Don (`mdon`)
- **Merged:** 2026-08-14 as `a052718b` (from `mdon:main`)
- **Reviewed:** 2026-08-14, post-merge, against `main`
- **Scope reviewed:** the whole `1d5e8d25..0b06bae5` range (theme controller
  consolidation, host `:theme_definitions`, tab auto-hide, pagination extract,
  referral 0.4 backfill, button status variants).

Verdict: **the four arcs are well designed and the panel's hardening notes
were closed for real.** The findings below are things the merge left wrong
or unfinished — two of them (F1, F2) make the new theme story fail for the
default host configuration.

---

## BUG - HIGH

### F1. Host `:theme_definitions` never appeared in the default picker

`PhoenixKit.ThemeConfig.dropdown_themes/1` `:all` / `nil` mapped only the
compile-time `@dropdown_order`. New host themes flowed into CSS, labels,
`base_map/0`, and `system_pair/0` — every lookup the PR claimed — except
the one the picker actually renders when the host has not also set
`:dashboard_themes`.

That is the default. Admin and dashboard both call
`Config.get(:dashboard_themes, :all)`. A host that did exactly what the
moduledoc shows:

```elixir
config :phoenix_kit, theme_definitions: %{
  "brand-light" => %{label: "Brand Light", base: :light, extends: "phoenix-light", ...}
}
```

got the palette in the page and no way to select it.

**Fixed.** `:all` appends host names (minus any that collide with the
built-in catalogue) after `@dropdown_order`. `all_theme_names/0` now
reads `label_map/0` so it stays in sync. Test in
`theme_definitions_test.exs`.

### F2. Pre-paint stamp without the palettes — `color-scheme: dark` over light variables

`ThemeBootstrap` stamped `data-theme="phoenix-dark"` (and
`color-scheme: dark`) from `<head>`. The `[data-theme=phoenix-*]`
variables lived in a later `<style>`: kit root / dashboard had them in
`<head>` (fine), but the standalone admin shell and every host layout the
installer injects into did not. First paint was the exact failure the PR
documented for auth pages — dark color-scheme over daisyUI's light
variables — until the admin chrome's body `<style>` arrived.

**Fixed.** `ThemeBootstrap` now emits the custom-theme `<style>` next to
the script, so wherever the stamp goes the palettes go with it. A
`window.__pkThemeBootstrap` guard stops a host+kit double render from
attaching the storage listener twice.

---

## BUG - MEDIUM

### F3. Dropdown options had no `data-phx-theme`

The toggle was given `JS.dispatch("phx:set-theme")` + `data-phx-theme`
so it works in a host layout that never renders `ThemeControllerScript`.
The test comment said the dropdown options share that contract. They did
not: they put the name only in `JS.dispatch` `detail`.

phx.new 1.8's stock script is `setTheme(e.target.dataset.phxTheme ||
"system")`. On a host that kept that script, every dropdown click reset
the theme to system. Listener order made the kit script usually win
*afterwards* on kit-layout pages (flash), and lose entirely on a host
that embeds only the picker.

**Fixed.** Options now carry `data-phx-theme={theme.value}`. Test added.

### F4. Installer skipped the bootstrap on every phx.new 1.8 host

`ensure_theme_bootstrap/1` treated any `phx:theme` substring as "the
host already does this job". That is every 1.8 template, and that
script's `"system"` path *removes* `data-theme` — the opposite of
resolving the configured pair. Combined with F2, the FOUC the component
exists to kill never reached the most common host layout.

Worse: injecting at the *top* of `<head>` in front of that script would
have been undone by it. The skip was protecting a broken placement.

**Fixed.** `phx:theme` is no longer a skip. Those layouts get the
bootstrap just before `</head>`, so it runs after the stock script and
the configured pair wins. Layouts with no stock script still inject at
the top of `<head>`. The `<head>` matcher no longer also matches
`<header>`. `theme_bootstrap_plan/1` is public (`@doc false`) and
tested.

### F5. Pagination extract missed the unfloored siblings

`PhoenixKit.Utils.Pagination.total_pages/2` exists because unfloored
`ceil(total / per_page)` fed `1..0` decreasing ranges on empty lists.
The PR converted media_browser, the selector *modal*, and activity. It
left:

- `media_selector.ex` — still `ceil(total_count / per_page)`
- `Auth.list_users_paginated/1` — still `div(total + size - 1, size)`
  with no floor

Same bug, same family. The already-floored `jobs/index.ex` and
`live_sessions.ex` copies were converted too so the helper is the one
place.

**Fixed.**

### F6. `Referrals.dispatch/2` used `function_exported?/3` without `Code.ensure_loaded?/1`

The new `signup_use_exists?` backfill is the whole reason 0.4-era
redeemers are not parked. `function_exported?/3` is `false` for an
unloaded module under a release (the rule in `AGENTS.md` / the
notifications registry). Dispatch then returns `:error`, which
`historically_redeemed?/1` reads as "cannot confirm, do not admit" —
the feature silently does not fire in the environment it was written
for.

**Fixed.** `Code.ensure_loaded?/1` is now in the `with` chain. Helps
every other dispatch (expiry, usage limit, `get_config`) the same way.

---

## IMPROVEMENT - MEDIUM

### F7. Deleted `phoenix_kit_themes.js` wrote a different localStorage key

The static file persisted under `phoenix_kit_theme`. The new system
reads `phx:theme`. An upgrade reset every saved choice that had gone
through the old file.

**Fixed.** Bootstrap promotes the legacy key once; the controller
script falls back to it on read.

### F8. `:extends` only accepts the two built-in phoenix-* palettes

`build_theme_variables/1` does `Map.fetch!(@custom_theme_variables,
extends)`. A host that defines `brand-light` and then tries
`brand-light-high-contrast` extending it crashes at fetch. Reasonable
v1 limit; it was undocumented.

**Fixed** as documentation on the `:theme_definitions` comment, not as
a chain walker. Chaining host themes is a feature, not a bugfix.

---

## NITPICK

- `group_header` / divider `visible: nil` with `path: nil` is visible.
  Correct. `parameterized_path?/1` is per-segment; `mailto:` / ports /
  `https://` stay visible. Tests cover this.
- Button's docstring still told callers to pass `class="btn-error"`
  after the same commit made `variant="error"` first-class. Comment
  updated.
- `pk_link_button/1` still has the smaller variant vocabulary. Left
  alone — it was not in this PR, and interpolates `btn-#{@variant}`.
- Igniter staging: `ensure_theme_bootstrap/1` writes with `File.write!`
  like every other helper in `JsIntegration`. Not introduced uniquely;
  not rewritten here.
- Removed public `ThemeConfig` functions (`get_theme/0`,
  `theme_data_attributes/0`, `modern_css_variables/0`, the slider
  helpers) have no remaining in-repo callers. Breaking for hosts;
  record on the 2.6.0 changelog when that version is tagged. No callers
  to restore.

---

## What was not wrong

- Tab auto-hide: `visible: nil` meaning "auto", `hard_hidden?/1` for
  the nil-scope registry path, `visible: true` as the opt-out. The
  two leaks the PR named (nil-scope unfiltered, `modules.ex`
  `visible != false`) are closed.
- Referral 0.4 backfill: last in the chain, stamps on a hit, fail-closed
  when the package does not export the function. Tests cover both
  directions.
- Button status variants: additive, literal classes, existing calls
  unchanged.
- Theme injection hardening (`\A..\z` names, variable-name regex,
  backslash ban, `Jason.encode!(…, escape: :html_safe)`) holds.
  Re-checked, not re-opened.

---

## Tests

- `theme_definitions_test.exs` — host theme in `:all` picker +
  `all_theme_names/0`
- `theme_controller_test.exs` — dropdown options carry `data-phx-theme`
- `theme_bootstrap_test.exs` — palettes travel with the stamp; legacy
  key; idempotency guard
- `theme_controller_script_test.exs` — legacy key fallback
- `js_integration_theme_bootstrap_test.exs` — placement plan
  (`:already_present` / `:before_head_close` / `:top_of_head`)
