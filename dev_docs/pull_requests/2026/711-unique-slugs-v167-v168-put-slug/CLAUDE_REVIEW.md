# PR #711 Review — Make slugs unique: V167, V168, and `put_slug/3` in core

**Author:** Max Don (mdon)
**Reviewed:** 2026-08-14 (post-merge sweep)
**Verdict:** APPROVED — merged, with two corrections applied on `main`

---

## Scope

Three separable topics arrived on one branch (the author flagged this in the PR body):

1. `PhoenixKit.Utils.Slug.put_slug/3` — the changeset glue that was hand-rolled 14 times
   across 8 packages, plus a `:max_length` fix to `ensure_unique/2`.
2. **V167 / V168** — the two slug unique indexes an audit found missing.
3. **V169** — nullable `phoenix_kit_entity_data.created_by_uuid`, one duplicate FK dropped,
   and eleven `foreign_key_constraint/2` declarations given the `:name` they need to match.

---

## Verification performed

I did not take the PR's own verification on trust. Every schema-level claim was
re-checked against the live `phoenix_kit_test` database at chain version 166
(i.e. the pre-migration state), via `psql`:

| Claim in PR | Independently measured | Verdict |
|---|---|---|
| `phoenix_kit_posts_slug_index` is a plain btree | `indisunique = f` | ✅ |
| `phoenix_kit_tickets_slug_index` is a plain btree | `indisunique = f` | ✅ |
| `phoenix_kit_post_groups` has no slug index at all | 0 rows in `pg_indexes` matching | ✅ |
| `prompt_uuid` carries a duplicate FK | both `fk_ai_requests_prompt_uuid` and `phoenix_kit_ai_requests_prompt_uuid_fkey` present, identical definitions | ✅ |
| `phoenix_kit_entity_data.created_by_uuid` is NOT NULL on a fresh DB | `is_nullable = NO` | ✅ |
| All eleven corrected constraint names exist under those exact names | all 11 returned by `pg_constraint` | ✅ |

The eleven-name check is the one most worth having done: the PR asserts these names
were read off a real migrated database rather than inferred from the chain, and that
one of them (`phoenix_kit_file_instances_file_id_fkey`, sitting on a `file_uuid`
column) is a name reading v135 alone would get wrong. Both hold.

`create: nil` on the newly-`legacy_optional` object is not merely acceptable but
required — `ExpectedSchema.Object`'s moduledoc documents that the generator emits
`create: nil` for every `:legacy_optional` object and that `valid?/1` enforces it,
so a `legacy_optional` carrying SQL would have been rejected.

---

## Findings

### BUG - MEDIUM — `V169.down/1` locks a table it never checks exists *(fixed on main)*

`up/1` wraps its `phoenix_kit_entity_data` work in a `pg_class`/`pg_namespace`
existence guard, and its comment explains exactly why: "an unconditional ALTER is
what turns a partial install into a failed migration." `down/1` then reached
straight for:

```sql
LOCK TABLE #{p}phoenix_kit_entity_data IN EXCLUSIVE MODE;
```

with no guard at all.

`LOCK TABLE` has no `IF EXISTS` form. On an install that never created the entity
tables, `up/1` correctly skips the relaxation and `down/1` aborts the entire
rollback with `relation "phoenix_kit_entity_data" does not exist` — and because
`up/1` skipped it, there was nothing there to undo in the first place.

**Fix applied:** the `down/1` body now sits inside the same schema-anchored
existence guard `up/1` uses.

**Test added:** `test/phoenix_kit/migrations/lock_table_guard_test.exs` pins the
*rule* rather than this instance — every `LOCK TABLE` in the chain must sit inside a
table-existence check **in the same `DO $$ … $$` block** (a guard in a different
`execute/1` call protects nothing). Confirmed non-vacuous: reverting the fix makes it
fail naming `v169.ex: phoenix_kit_entity_data`.

### NITPICK — V164 comment cites the wrong version *(fixed on main)*

The new `@relaxed_after_v57` entry described "the `not_null_violation` **V167** exists
to end". V167 is the post-slug index; the migration meant is **V169**. Same slip in
`v164_relaxed_columns_test.exs`'s regex comment (`ALTER COLUMN "created_by_uuid"` in
V167). Both corrected — these comments are the provenance trail the exclusion list is
navigated by, so a wrong version number there costs real time later.

### IMPROVEMENT - HIGH — the adopter pin in the PR body is off by a minor

The PR says adopters need `{:phoenix_kit, "~> 2.3"}`. That was true when written, but
**2.3.0 was already published without `put_slug/3`** — so `~> 2.3` resolves to a core
that lacks the function, and every `Template.changeset/2`-style adopter raises
`UndefinedFunctionError` in the consumer's app, not here.

This ships as **2.4.0**, so adopters must pin **`~> 2.4`**. Two-segment, per the
umbrella rule that a three-segment `~> 2.4.0` cannot resolve a later core minor.

Carried into the downstream module PRs that adopt `put_slug/3`
(`phoenix_kit_document_creator#39`, `phoenix_kit_posts#17`) — both had left the pin at
`~> 2.0`.

### NITPICK — `trim_for/3` can still exceed a pathologically small `:max_length`

With `max_length: 2` and a suffix of `-10`, `keep` goes negative, `Kernel.max(keep, 0)`
truncates the base to `""`, and the candidate is `-10` — three characters, and leading
with a separator. Not reachable from any current call site (no schema caps a slug
anywhere near the suffix width) and not worth guarding at the cost of complicating the
common path; recorded so it isn't rediscovered as a mystery.

### NITPICK — suffix separator is hardcoded

`increment_slug/4` always joins with `-`, and `trim_for/3` strips only `-`, even when
`slugify/2` was given `separator: "_"`. Pre-existing behaviour, unchanged by this PR,
and no caller passes a non-default separator today.

---

## Deliberately not changed

- **`put_slug/3` returns an explicitly-supplied slug without probing uniqueness.**
  Documented as intent ("an explicit, non-blank slug always wins") and correct: the
  mandatory `unique_constraint/3` is the integrity boundary, and silently rewriting a
  slug an operator typed is worse than a changeset error.
- **The probe runs inside the changeset.** Unusual, but it matches
  `Ecto.Changeset.unsafe_validate_unique/4` and the moduledoc argues the alternative
  convincingly. Not a defect.
- **V167 treats `"scheduled"` as live.** `Post.published?/1` counts only
  `public`/`unlisted`, so this refuses in slightly more cases than strictly necessary.
  Refusing more often is the safe direction for an unattended migration.
- **Three topics on one branch.** The author offered to split them. Splitting after the
  fact would mean re-testing three chains against a database for no behavioural gain;
  the moduledocs keep them separable in the history.
