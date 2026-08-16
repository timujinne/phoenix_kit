# PR #708 — Locale and priority options on the country selects

**Reviewed:** 2026-08-13 · **Author:** @timujinne · **Verdict:** merged, with one
defensive follow-up applied on main.

> A `PINCER_REVIEW.md` from another agent sits alongside this file. This review
> was written independently and does not append to or restate it.

## Summary

`countries_for_select/1`, `eu_countries_for_select/1` and `get_country_name/2`
gain `:locale` and `:priority` options, sorting moves to the localized name with
NFD accent folding, and — not mentioned anywhere in the PR description — the
Organization settings page gains a whole "Main countries" card: a drag-reorder
list, keyboard move buttons, a searchable picker, and a neighbour suggestion
derived from the host's own country.

**Scope note:** the description covers only `CountryData`. Roughly half the diff
(`organization.ex`, `organization.html.heex`, and a 275-line integration test) is
the settings UI that stores the `country_select_priority` setting the new option
reads. That is a coherent pairing — the option needs somewhere to be set — but a
reviewer going by the description alone would not know to look at it.

## Checked leads that came back clean

- **No dissolved countries leak into the select.** `countries_for_source(:all)`
  is `BeamLabCountries.all()` where the old code used `list_countries()`. Those
  are the same set — `list_countries/0` is `BeamLabCountries.all() |> Enum.sort_by(& &1.name)`,
  a sort and nothing more. No filter was lost.
- **The `:persistent_term` cache key is bounded.** `sorted_entries/2` writes one
  entry per `{source, locale}` on a miss, and `:persistent_term.put/2` triggers a
  global GC scan — so an attacker-controlled locale would be a cheap DoS. It is
  not reachable: the locale comes from `Gettext.get_locale/1`, which core sets in
  `auth.ex:1173-1191` only after `DialectMapper.valid_base_code?/1` checks the URL
  segment against the predefined-language table, falling back to the default
  otherwise. Bounded by that table, so at most a few hundred writes over a node's
  life.
- **`get_country_name/2`'s arity change is safe.** The old `get_country_name(_)`
  catch-all is now `get_country_name(code, _opts) when not is_binary(code)`, so
  non-binary codes still return nil. `get_country_name("EE", %{})` raises
  `FunctionClauseError` instead — deliberate and documented in the `@doc`.
- **`fetch_opt/3` over `Keyword.get/3` is a real optimisation, not a stylistic
  one.** The defaults are a Gettext lookup and a settings read that can miss to a
  database; `Keyword.get/3` would evaluate them eagerly and discard the result
  whenever a caller passed the option explicitly.

## IMPROVEMENT - MEDIUM: unguarded flag concatenation in the settings LiveView

**Applied on main after merge.**

`CountryData.select_entry/2` treats `country.flag` as nilable and blank-able:

```elixir
case country.flag do
  nil -> name
  "" -> name
  flag -> flag <> " " <> name
end
```

The new `main_country_rows/1` and `main_country_suggestion/2` in
`organization.ex` build the same label without that guard:

```elixir
label: CountryData.get_flag(code) <> " " <> CountryData.get_country_name(code)
```

`nil <> " "` is an `ArgumentError`, and it would be raised in `load_settings/1` —
so the whole Organization settings page would fail to mount, not just the row.

I checked before treating this as live: all 250 rows in beamlab_countries 1.1.0
carry a non-empty flag, so **this cannot fire today**. It is a latent dependency
on a dataset invariant that the module it copied from deliberately does not rely
on, one `beamlab_countries` release away from mattering.

**Fix:** both call sites now go through a shared `country_label/1` that mirrors
`select_entry/2`'s `nil` / `""` handling and falls back to the bare code if the
name is somehow missing.

## Sorting: the caveat is documented, and worth repeating here

NFD folding is explicitly an approximation, and the moduledoc says so at length.
It is correct for locales that treat accents as variants of the base letter and
wrong for the ones that give them their own alphabet position — Estonian (Ü last,
after W, Õ, Ä, Ö) and Swedish (Å, Ä, Ö after Z) among them. That is a real
mis-sort in `et`, which is one of this ecosystem's actual locales.

Not a blocker and not something to fix here: proper collation needs ICU, which
the BEAM does not ship. But "sorted by localized name" reads as stronger than
what it delivers for exactly the locale the PR's own examples use, and a host
that needs it must sort the returned list itself.

## NITPICK — not changed

- The new `## Examples` blocks (`suggested_priority("EE", limit: 2)` →
  `["EE", "LV", "AX"]`, the `ru` select output) are never executed: the module's
  examples are written against the bare `CountryData.` alias, which doctests
  cannot resolve, and the PR follows that house style deliberately. They are
  documentation whose accuracy nothing enforces.
- `assign_main_countries/3` reads settings from `load_settings/1`. If that is
  reached from `mount/3` it adds a settings read to the twice-called path — but
  it is the pattern the whole file already follows and reads through the ETS
  cache, so this PR does not make it worse.

## Good calls worth preserving

- `priority: []` on the picker's own option list, so the dropdown you use to
  change the pinned set is not itself reordered by it.
- Priority is deliberately kept **out** of the `sorted_entries/2` cache key, so a
  settings change takes effect immediately with nothing to invalidate.
- `reorder_main_countries` intersects the pushed order against what is already
  pinned, so a forged SortableGrid payload can neither add a country nor silently
  drop one.
- Keyboard move buttons kept alongside drag: SortableJS is a CDN fetch a strict
  CSP can block, and dragging has no keyboard path.
