# Phase 1 Review — PR #694

**Title:** Stop reporting a comment-less database as version 1  
**Author:** Tymofii Shapovalov (timujinne)  
**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/694  
**Reviewed:** 2026-08-09  
**Reviewer:** Pincer 🦀

---

## Summary

Three surgical fixes following the post-merge review of the migration work from #689. The PR description is unusually thorough — it names the exact callsite that was wrong, explains the failure mode, cites the sibling code that was already hardened, and even documents two findings it deliberately leaves out (decisions for the maintainer, not patches). Clean signal-to-noise.

---

## Files Changed (5 files, +113 / -17)

| File | Change |
|------|--------|
| `lib/mix/tasks/phoenix_kit.update.ex` | New `handle_installation_status({:unknown_version}, ...)` clause; bridge version string now sourced from `bridge_version/0` |
| `lib/phoenix_kit/install/common.ex` | `parse_version_comment/1` helper; `normalize_query_result` routes `:unknown_version`; `query_version_directly` returns `:unknown_version` instead of `1` |
| `lib/phoenix_kit/migrations/postgres.ex` | `bridge_version/0` public function exposing `@bridge_version` |
| `lib/phoenix_kit/migrations/postgres/v163.ex` | `cond` branch reorder: row-count catalog check before full-table `castable?` scan |
| `lib/phoenix_kit/migrations/repair/probe.ex` | `String.to_integer/1` → `Integer.parse(String.trim(...))` — never raises |

No suspicious files, no secrets, no unrelated changes, no dependency changes in `mix.exs`.

---

## Fix 1: Comment-less database → `:unknown_version` (the main fix)

**Before:** `Common.query_version_directly/2` fell through to:
```elixir
_ ->
  # Table exists but no version comment - assume version 1
  1
```
This caused `{:current_version, 1}`, which is below the floor, so `mix phoenix_kit.update` told the operator to install the 1.7.x bridge — but `Postgres.migrated_version/1` refuses that exact state for good reason: the bridge's backfill (`UUIDFKColumns.set_not_null/4`) would overwrite legitimately-NULL columns with invented UUIDs, and `cleanup_orphaned_fk_refs/5` would then delete those rows. Two halves of the same release gave opposite instructions, and the destructive one was encountered first.

**After:** Returns `:unknown_version` (atom), which `normalize_query_result/3` wraps into `{:unknown_version}` (following the `{:current_version, v}` / `{:unreachable, r}` tuple convention). The update task routes it to `doctor` + restamp — safe, reversible, informative.

**Assessment:** Correct. The fix matches the migrator's own reasoning and aligns both halves of the release.

**Minor note:** `parse_version_comment/1` in `common.ex` guards `n > 0`, but the inline version in `probe.ex` does not. In practice, version 0 cannot legitimately appear, so this is a non-issue — but worth noting for future consistency.

---

## Fix 2: `Repair.Probe.read_comment/2` crash on anomalous comments

**Before:** `String.to_integer(version)` — raises `ArgumentError` on comments like `'v164'` or `' 164'`, despite the moduledoc promising "Never raises". The exact comments the migrator documents as hand-edited used to crash `mix phoenix_kit.repair` with a bare stack trace and no guidance.

**After:** `Integer.parse(String.trim(version))` — returns `nil` on parse failure (already handled by all callers). The module docstring promise is now kept.

**Assessment:** Correct. The choice of returning `nil` (matching existing callers) rather than `:unknown_version` is appropriate — `Probe` has a narrower contract than `Common`.

---

## Fix 3: `fk_exists?` in V164 — `AND c.contype = 'f'` added

**Before:** The FK existence query matched by constraint name + table + namespace only. A same-named CHECK constraint or FK to a different column would be found, `fk_shape_present/5` would see `:absent`, the ADD would fail with `42710` (swallowed by `EXCEPTION WHEN OTHERS`), `validate_fk/7` would issue a no-op VALIDATE, and the outcome would be logged as `:created` — with the declared FK still absent. That is exactly the class of defect V164 exists to repair, inside the repair itself.

**After:** `AND c.contype = 'f'` filters to only actual foreign keys. The collision scenario is now correctly detected.

**Assessment:** Correct and important. The failure mode described is silent, so it would have been hard to spot without knowing what to look for.

---

## Fix 4: V163 `cond` branch ordering

**Before:** `castable?/3` (full-table sequential scan, potentially minutes on PgBouncer-fronted pools) was checked before `estimated_rows/3` (catalog read, cheap). Tables destined to be skipped on row count still paid the full scan cost first.

**After:** Row-count check (`estimated_rows/3`) runs first; `castable?/3` only runs if the table is small enough to be processed. Performance-only change, no semantic difference.

**Assessment:** Correct. Not a bug fix per se, but a real operational improvement for large-table scenarios.

---

## What Is NOT in This PR (deliberately)

The PR documents two open findings left for the maintainer:
1. `repair` can't converge when pgcrypto lives in a non-public schema (manifest pins `public.gen_random_bytes` in `prosrc`).
2. Manifest pre-164 revisions for `idx_publishing_posts_group_slug` carry `predicate: nil` next to a comment saying "Every real install has the predicate" — these two claims cannot both be true.

These are noted but are out of scope for this PR.

---

## Red Flags

- None. No build artifacts, no secrets, no unrelated changes, no dependency bumps.

---

## Test Coverage

The PR author notes no test run was performed because these code paths are exercised against a real database (not the test suite), and the shared PostgreSQL was at its connection ceiling. `mix compile --warnings-as-errors`, `mix format --check-formatted`, and `mix credo --strict` are reported clean.

This is a known gap in this codebase's test coverage for migration paths — not introduced by this PR.

---

## Verdict

**✅ Approve — recommend merge**

All three fixes are correct, minimal, and well-explained. The main fix eliminates a genuine silent data corruption path (fabricated UUIDs + orphan deletion) by replacing a dangerous assumption with an honest unknown state. The other two fix a crash-on-input and a silent FK verification gap. No suspicious content.
