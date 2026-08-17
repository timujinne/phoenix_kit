# Review: PR #722 — Multilang: resolve translations across dialect/bare-code mismatches

Merge commit: `09114fc9` (squash-merge of `ff088bc6` + `3efe1f82`), author mdon.

Files touched: `lib/phoenix_kit/utils/multilang.ex`, `lib/phoenix_kit_web/components/multilang_form.ex`,
`lib/phoenix_kit_web/users/auth.ex`, plus tests in `test/phoenix_kit/utils/multilang_test.exs` and
`test/phoenix_kit_web/components/multilang_form_test.exs`.

## BUG - CRITICAL: `same_base?/2` collapses genuinely distinct sibling dialects, causing silent data loss

**File:** `lib/phoenix_kit/utils/multilang.ex`

The PR's core fix (bare code ↔ full dialect fallback, e.g. "en" resolving to a record stored under
"en-US") is correct on the *read* path (`language_entry/3`, `fetch_same_base/3`). But the *write*
path used a too-broad equivalence:

```elixir
defp same_base?(a, b) when is_binary(a) and is_binary(b),
  do: DialectMapper.extract_base(a) == DialectMapper.extract_base(b)
```

This treats **any two codes that merely share a base language** as interchangeable — not just a
bare/dialect naming-drift pair for the *same* language slot (`"en"` vs `"en-US"`), but also two
genuinely distinct, independently co-enabled sibling dialects such as `"en-US"` (primary) and
`"en-GB"` (secondary). The codebase explicitly supports co-enabling multiple sibling dialects with
independent content — `Multilang.compute_short_code/2` exists specifically to disambiguate tab
labels when this happens (`dev_docs/2026-06-15-unify-phoenix-kit-locale.md` and the PR
#555/#714 reviews document `en-US` + `en-GB` as a real, supported configuration), and
`build_language_tabs/0` renders a separate editable tab per enabled code with no base-deduping.

Consequences of the over-broad `same_base?/2`, all reachable through normal `put_language_data/3`
calls made when a user saves the multilang form for a secondary dialect tab:

1. **`put_language_data/3` primary branch** — saving the `"en-GB"` tab when primary is `"en-US"`
   satisfied `same_base?("en-GB", "en-US") == true`, so the code executed
   `Map.put(base_data, primary, new_field_data)` — i.e. it silently **overwrote the primary
   `"en-US"` entry with the `"en-GB"` tab's content**, destroying whatever the primary language
   held.
2. **`drop_base_siblings/3`** (secondary branch) — saving `"en-US"` while a distinct `"en-GB"`
   secondary override existed **deleted the `"en-GB"` entry** as a "stale sibling," even though it
   was independently maintained content, not a naming-drift ghost.
3. **`recompute_all_secondaries/4`** (via `rekey_primary/2`) — promoting `"en-US"` to primary
   deleted any other sibling of the same base (e.g. a real `"en-GB"` entry) as a "ghost," instead
   of recomputing its overrides against the new primary like every other secondary language.
4. **`maybe_rekey_data/1`** — skipped re-keying whenever the embedded and global primaries shared a
   base, even when they were two genuinely different enabled dialects (e.g. host default flips from
   `"en-GB"` to `"en-US"`), leaving the record's embedded primary stale.

**Fix applied:** narrowed `same_base?/2` so it is true only when the two codes name the *same*
conceptual language at different precision — identical strings, or one is literally the bare
base-code form of the other:

```elixir
defp same_base?(a, b) when is_binary(a) and is_binary(b) do
  a == b or a == DialectMapper.extract_base(b) or b == DialectMapper.extract_base(a)
end

defp same_base?(_, _), do: false
```

`drop_base_siblings/3` now calls this narrowed `same_base?/2` instead of a raw
`extract_base/1 == extract_base/1` comparison, so it only clears a naming-drift ghost of the
*exact* code being written, never an unrelated sibling dialect.

Verified this preserves every pre-existing test's expected behavior (bare "en" write onto an
"en-US" primary still updates the primary; bare "en" write still drops a stale "en-GB" ghost of
itself) while no longer collapsing/deleting real siblings. Also dropped the previous
`same_base?(a, a), do: true` clause — it was dead code, fully shadowed by the first clause's guard
for binary arguments (only reachable for non-binary equal terms, which the module never passes).

**Tests added** (`test/phoenix_kit/utils/multilang_test.exs`):
- `put_language_data/3`: "genuinely distinct sibling dialects are never collapsed into one another
  (regression)" — asserts saving `"en-GB"` next to primary `"en-US"` stores its own override rather
  than clobbering the primary, and that saving a third sibling (`"en-CA"`) doesn't delete an
  existing `"en-GB"` secondary.
- `rekey_primary/2`: "promoting a sibling of the new primary keeps OTHER real siblings intact
  (regression)" — promoting `"en-US"` to primary must not sweep away an unrelated `"en-GB"`
  secondary as a ghost.

## Review of `auth.ex` changes (no auth/session/redirect logic touched)

Per the task brief, `auth.ex`'s ~140-line diff was checked hunk-by-hunk against session
persistence, `remember_me`, post-auth redirect resolution, and confirmation gating. All of it is
confined to locale/Gettext resolution:

- `resolve_active_dialect/1` (new) — resolves a base code to the host's actually-*enabled* default
  dialect (falling back to `DialectMapper.resolve_dialect/1`'s hardcoded table), replacing direct
  `DialectMapper.resolve_dialect/1` calls at every one of the plug's locale-setting call sites.
  Deterministic (`Enum.sort/1` before `Enum.find/2`), takes no user (preserves the documented
  URL-is-authoritative invariant — a user's `preferred_locale` still cannot upgrade a base code).
- `put_gettext_locale/1` (new) — de-duplicates the `Gettext.put_locale(PhoenixKitWeb.Gettext, …)` +
  `Gettext.put_locale(…)` pair that was previously repeated at 7 call sites, downgrading to the
  base code when the backend has no catalog for the full dialect.
- `maybe_update_locale_from_params/2` (LiveView `handle_params` hook) gained a new first `cond`
  clause so a full-dialect URL segment (`/en-GB/`) is honored during live navigation the same way
  the HTTP plug already honors it via `enabled_full_dialect/1` — previously only base-code segments
  updated the LV's locale assigns, so a live-navigated dialect URL would snap back to the default on
  WS connect.

None of these functions read or write `remember_me`, session tokens, redirect destinations
(`return_to`, `post_auth_path`), or the confirmation-gate checks — confirmed by reading the full
surrounding context (lines ~950–1120 and ~2610–2930), not just the diff hunks. No behavioral change
outside locale resolution. No fix needed here.

## Read-path correctness (`language_entry/3`, `fetch_same_base/3`)

Traced the fallback chain (exact key → base code → any same-base sibling, preferring the primary,
else lexicographically-first) against: case variance (`"en-us"` vs stored `"en-US"` — resolved
correctly via `extract_base/1`'s downcasing, even though the direct key lookups are
case-sensitive), three-part codes (`"zh-Hans-CN"` — `extract_base/1` already handles this,
unchanged by this PR), and locales absent from the configured set entirely (degrades to `%{}`,
merged onto primary — no crash). No bugs found on the read side; this part of the PR is sound and
`test/phoenix_kit/utils/multilang_test.exs`'s "dialect locale resolves bare-code translations
(tim-dev shape)" and "sibling fallback is deterministic and primary-preferring (sweep)" tests
exercise it end-to-end with real dialect/bare-code mismatches (not just exact-match happy paths).

## `multilang_form.ex` — wrapper scope rule respected

None of the changed functions (`preserve_translatable_primaries/4`, `safe_existing_atom/1`,
`lang_override_value/3`, the `preserve_field_value/4` nil-atom clause) touch
`<.multilang_fields_wrapper>` or any non-translatable field rendering; the one template-facing
change (`lang_value` assign in `translatable_field/1`) is entirely inside the
translatable-field-only component. No violation of the "wrapper wraps translatable fields only"
rule, and no interaction with the language-switch debounce hook.

## NITPICK: stale doc comment (fixed in place)

The original comment on the `put_language_data/3` secondary branch claimed the record "never
accumulates two entries for one base language" — no longer accurate now that genuinely distinct
sibling dialects are correctly preserved. Comment reworded alongside the `same_base?/2` fix to
describe the narrowed, precision-drift-only drop condition.

## Summary

| Finding | Severity | Status |
|---|---|---|
| `same_base?/2` collapses distinct sibling dialects → primary overwrite / sibling deletion on save or rekey | BUG - CRITICAL | Fixed in `lib/phoenix_kit/utils/multilang.ex`; regression tests added |
| `auth.ex` diff scope (locale-only, no auth/session/redirect changes) | — | Verified clean, no fix needed |
| Read-path dialect fallback correctness (case, 3-part codes, unknown locales) | — | Verified correct, existing tests adequate |
| `multilang_form.ex` wrapper-scope rule | — | Verified compliant |
| Stale doc comment on secondary-write branch | NITPICK | Fixed alongside the CRITICAL fix |
