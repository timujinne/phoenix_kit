# PR #708: Add locale and priority options to the country selects

**Author**: @timujinne (Tymofii Shapovalov)  
**Reviewer**: Pincer 🦀  
**Status**: 🔄 Phase 1 Surface Review  
**Branch**: `feature/country-select-locale-priority` → `main`  
**Date**: 2026-08-13

---

## Phase 1: Surface Check

### Goal

Extend `CountryData.countries_for_select/0` and `eu_countries_for_select/0` to accept `:locale` and `:priority` options, enabling localized country name display and configurable pinning of priority countries to the top of selects.

### Files Changed

| File | Change |
|------|--------|
| `lib/phoenix_kit/utils/country_data.ex` | Major refactor of two public functions + new private helpers |
| `test/phoenix_kit/utils/country_data_test.exs` | New test file with comprehensive coverage |

### Suspicious File Check

- ✅ No build artifacts
- ✅ No secrets or credentials
- ✅ No `mix.exs` dependency changes (uses already-declared `beamlab_countries` dep)
- ✅ No unrelated files touched

### Implementation Review

**New behaviour of `countries_for_select(opts \\ [])`:**
- `:locale` — reads from `Gettext.get_locale(PhoenixKitWeb.Gettext)` if not passed; normalizes dialect (`"ru-RU"` → `"ru"`); falls back to English for unsupported locales
- `:priority` — pins alpha-2 codes to the top in given order; case-normalizes and deduplicates; skips unknown codes silently
- Sort: NFD-normalized lowercase sort, so accented characters (Ö, Ü, etc.) collate correctly instead of sorting after Z

**Helper quality:**
- `split_priority/2` uses a Map index for O(1) lookups — efficient
- `sort_by_name/1` uses `:unicode.characters_to_nfd_binary/1` — correct approach for cross-locale sort
- `normalize_priority/1` filters non-binaries and deduplicates — defensive, good
- `translated_name/2` falls back gracefully through a `with` chain

### Flags for Awareness

#### 1. Silent behavioral change for existing callers (medium concern)

Before this PR, `countries_for_select()` with no args always returned English names. After this PR, it returns names in whatever locale `Gettext.get_locale(PhoenixKitWeb.Gettext)` returns. Any host app that previously relied on the no-args call for English names and now has a non-English Gettext locale will silently receive translated names. This is almost certainly the *intended* behavior (the locale option exists for this), but it is a behavior change without a version bump note.

**Not a blocker**, but worth confirming with Dmitri that downstream usages are aware.

#### 2. `list_countries()` → `BeamLabCountries.all()` substitution ✅ Verified

`list_countries()` (line 48) is `BeamLabCountries.all() |> Enum.sort_by(& &1.name)` — a simple English-name sort wrapper. The new implementation replaces that intermediate sort with the locale-aware NFD sort applied at the end via `sort_by_name/1`. This is correct and actually an improvement: the old English sort was being silently discarded anyway (the old `countries_for_select` never re-sorted). No hidden logic, substitution is safe.

#### 3. `PhoenixKitWeb.Gettext` hardcoding

`active_locale/0` hardcodes `PhoenixKitWeb.Gettext`. This is standard for this library's architecture (already used elsewhere), so not a new concern — just noted for awareness.

### Test Coverage

New test file `test/phoenix_kit/utils/country_data_test.exs`:
- `async: false` correctly set (modifies Application env)
- Teardown via `on_exit` correctly restores application env
- Tests locale translation, dialect reduction, English fallback, full-list size consistency
- Tests priority pinning order, deduplication, case normalization, config-based default
- Tests NFD sort order (both English and Russian locale)
- Tests `eu_countries_for_select/1` with locale + priority

Coverage is thorough. No gaps visible.

---

## Verdict

✅ **RECOMMEND MERGE** — Well-implemented feature with comprehensive tests and no suspicious changes. Two items to be aware of:

1. **Behavioral change** for no-arg callers: they now get locale-sensitive output. Almost certainly intentional — confirm no host callsites need `locale: "en"` added explicitly.
2. ~~Verify `list_countries()` is a no-op wrapper~~ ✅ Confirmed safe — it was just an English sort wrapper, cleanly superseded by NFD sort.

Neither is a blocker — just confirm understanding before merging.

**Awaiting Dmitri's approval to proceed.**
