# GLM Review — PR #675 (COALESCE the atomic custom_fields merge/delete)

Model: glm-5.2 via the z.ai endpoint, reviewer persona (two-stage: spec compliance, then code quality). Read-only pass over `git diff upstream/main...fix-custom-fields-atomic-merge`, with the SQL semantics checked against a live Postgres.

---

## Stage 1: Spec Compliance

`lib/phoenix_kit/users/auth.ex:1704` — **PASS**: The merge fragment is correctly rewritten as `COALESCE(u.custom_fields, '{}'::jsonb) || type(^additions, :map)`. COALESCE wraps only the nullable column operand; the `^additions` parameter (always a map) is correctly left outside. Verified empirically: `NULL::jsonb || '{"survives":"yes"}'` → `NULL` (the bug), and `COALESCE(NULL,'{}') || '{"survives":"yes"}'` → `{"survives":"yes"}` (the fix).

`lib/phoenix_kit/users/auth.ex:2080` — **PASS**: The delete fragment is correctly rewritten as `COALESCE(u.custom_fields, '{}'::jsonb) - ?::text`. Verified: `NULL::jsonb - 'x'` → `NULL` (bug), `COALESCE(NULL,'{}') - 'x'` → `{}` (fix).

**Non-NULL path unchanged — CONFIRMED.** Empirically `'{"existing":1}'::jsonb || additions` and `COALESCE('{"existing":1}', '{}') || additions` return byte-identical results. The `updated_at: ^UtilsDate.utc_now()` lines in both clauses are unchanged context in the diff — this PR does not touch them, so the upstream-added timestamp bump is preserved exactly.

`lib/phoenix_kit/users/auth.ex:1569-1575` (locale doc) — **PASS**: Matches code at `auth.ex:1597-1603` — set goes through `merge_user_custom_fields/3` with `ensure_definitions: false`; clear goes through `delete_user_custom_field/3` (which never registered definitions, so the `ensure_definitions` opt is irrelevant there). "The first write no longer auto-registers a field definition" is accurate.

`lib/phoenix_kit/users/auth.ex:2041-2043` (set_user_custom_field doc) — **PASS**: Matches code at `auth.ex:2050`; it delegates to `merge_user_custom_fields/3`, which returns `{:error, :not_found}` on `{0, _}` at `auth.ex:1719-1720`.

`test/integration/users/profile_test.exs:191-207` and `:256-272` — **PASS, and the tests prove the claimed behavior** (they do not pass for the wrong reason): each forces the column to NULL via `update_all(set: [custom_fields: nil])` (Ecto `:map` serializes `nil` → SQL NULL, and the column is genuinely nullable per V18 `add :custom_fields, :map, null: true`). The merge assertion `merged.custom_fields == %{"survives" => "yes"}` would yield `nil` (FAIL) without COALESCE, since `update_all(... select: u)` uses `RETURNING` on Postgres. Same for the delete assertion `== %{}`. The `update: [...]`-in-query + `[]`-updates call shape mirrors the production function at `auth.ex:1694-1711`.

**No other NULL-jsonb write gaps left unfixed.** The only application-code atomic jsonb mutations on `custom_fields` in all of `lib/` are the two sites this PR fixes. The remaining `custom_fields || %{}` hits (`auth.ex:1791,1973,1978,1987,2005`, `custom_fields.ex:382`) are Elixir-level map reads with nil-coalescing — not SQL. `digest_worker.ex:147` is a read-side `?` existence check (NULL → false, the desired filter behavior). Migration V76's `custom_fields - 'avatar_file_id'` is guarded by `WHERE custom_fields ? 'avatar_file_id'` (NULL rows excluded) and is a one-time migration anyway.

**Spec Verdict:** PASS

---

## Stage 2: Code Quality

### NITPICK: New tests duplicate the NULL-column setup, and the delete path subtly changes NULL semantics vs. the immediate upstream state
**File**: `test/integration/users/profile_test.exs:191-207` and `256-272`; `lib/phoenix_kit/users/auth.ex:2077-2080`
**Problem**: Two observations, neither a defect:
1. Both new tests inline an identical `import Ecto.Query` + `update_all(set: [custom_fields: nil])` block. A private `force_custom_fields_nil/1` helper would remove the duplication — though the file's adjacent `updated_at` tests (lines 175-189, 240-254) inline their own `update_all` setup the same way, so this matches local convention.
2. Worth a conscious reviewer sign-off: on the immediately-preceding upstream/main atomic implementation, `delete_user_custom_field` on a NULL row left it NULL (`NULL - key` = NULL). This PR changes that to normalize NULL → `{}`. The choice is deliberate (comment at `auth.ex:2078-2079`, test at `:268-271`), restores the pre-atomic-refactor Elixir behavior, and matches the column's declared `default: %{}` — so it is the right call — but it is a behavior change on the NULL path, not purely a no-op fix.
**Suggestion**: Optional: extract the setup into a small helper for DRY. No action needed on item 2 beyond awareness.
**Rationale**: `%{}` is the correct neutral value here (matches column default, matches documented historical behavior, and the merge path can't produce NULL either, so it removes nil-vs-empty ambiguity for readers). Leaving NULL on delete would be more "minimal" but would preserve the very ambiguity the fix targets.

**Quality Summary:** 0 critical, 0 major, 0 minor, 1 nitpick
**Quality Verdict:** Ship

---

## Overall Verdict: PASS

The fix is correct, minimal, and empirically verified: COALESCE on both the `||` merge and the `-` delete operators resolves the silent NULL-swallow, leaves the non-NULL path byte-identical (so the `updated_at` bump upstream added in the same clauses is unaffected), the two new tests genuinely fail without the fix, the doc edits accurately describe the code, and no other application-code atomic jsonb write on `custom_fields` was left unfixed. No action required before merge; the two nitpick observations are informational.
