# PR #783 — Annotations anchor to a target; canvas viewer draws a board

**Author:** mdon (`mdon/pr/projects-arc-core`) · **Merged:** 2026-09-05 (`95d4a898`) · **Reviewed:** 2026-09-05

**Verdict: PASS** — one `IMPROVEMENT - MEDIUM` and one `NITPICK`, neither
blocking. **Both were applied after this review** and shipped in 2.14.2: the
`target_type` regex moved onto the changeset (the adapter now reads it from
`Annotation.target_type_format/0`), and V183's constraint check became the
mandated `pg_class` + `pg_namespace` JOIN. The manifest `chain_hash` was
restamped for the V183 edit — legitimate here because the change is a comment
plus an existence guard that produces an identical constraint, which is the
one class `restamp_chain_hash.exs` permits. 22 files, +2311/−511, including a V183 migration.

Reviewed `e2073287..95d4a898`. The merged tree compiles with
`--warnings-as-errors`, `mix precommit` is green, and the full suite is
**4488 tests, 0 failures** — including `test/integration/prefix_migration_test.exs`,
the oracle that runs the whole chain into a scratch named schema, so V183 is
proven prefix-safe rather than assumed to be.

> ⚠️ **Not in any release.** Merged 16:03 UTC; `2.14.1` was published at
> 15:06 UTC. The published package contains none of this.

---

## Stage 1 — does it do what it says

Yes. Every annotation row pointed at a `phoenix_kit_files` row through a
`NOT NULL file_uuid`, which is right for the media viewer and wrong for a
whiteboard with no image — the projects module was minting a solid-white PNG
per board just to have something to anchor to. Etcher's own API has always
been keyed by `target_type` + `target_uuid`; V183 lets the table say the same.

Three shapes had to stay true at once and all three do:

- **existing rows are untouched in meaning** — `file_uuid` is still there and
  still the file, and the backfill sets `target_uuid = file_uuid` for every
  row before the CHECK is added, so nothing pre-existing can violate it
  (`file_uuid` was `NOT NULL`, so the backfill's `WHERE` matches all of them);
- **a file target carries the file in BOTH columns**, which is what lets the
  file-side features — the thumbnail job, `has_annotations?/1`, the comment
  threads — keep keying on the hard FK;
- **any other target carries no file at all**, pinned by the CHECK.

`list_for_target("file", uuid)` delegating to `list_for_file/1` (querying
`file_uuid`, not the new pair) is correct rather than an oversight: for a file
target the two columns hold the same value, and the FK is the better-indexed
path.

---

## Stage 2 — quality

### IMPROVEMENT - MEDIUM — the `target_type` guard lives in the adapter, not the schema · `annotation.ex:66`

`etcher_adapter.ex` validates the type against
`~r/\A[a-z][a-z0-9_]{0,31}\z/` before building attrs. The **changeset does
not**: `target_type` is cast, and nothing checks its length or shape.

That is fine while the adapter is the only writer, and it is not — `Annotations.create/1`
is public, and a board is exactly the case this PR exists to enable, so
`phoenix_kit_projects` will call it directly. A `target_type` longer than 32
characters then reaches `character varying(32)` and comes back as a raw
Postgres error instead of a changeset error.

That is the precise failure mode the PR already went out of its way to prevent
for the sibling invariant — `validate_target/1` exists, in its own words, "so
the error is a changeset error and not a constraint exception". The same
argument applies one field over. The regex belongs on the changeset, where both
entry points pass through it; the adapter can then keep or drop its copy.

Not a security issue: Ecto parameterises, so there is no injection here, only
error quality.

### NITPICK — V183's constraint check uses `::regclass`, which the prefix rules forbid · `v183.ex:63`

```sql
conrelid = '#{p}phoenix_kit_annotations'::regclass
```

`AGENTS.md` → "Prefix-safe migrations" is explicit: *"name-based `pg_class` +
`pg_namespace` JOIN for `pg_constraint` (never `'p.table'::regclass` in an
IMMEDIATE check — it raises when the relation doesn't exist yet and aborts the
whole transaction)"*. V180 does it the mandated way at `:127` and `:275`.

**Not a live bug here.** `phoenix_kit_annotations` is created by V135, the
migration floor, so the relation always exists by the time V183 runs — and the
prefix oracle passes, which is the empirical confirmation. The cost is that
V183 is now the most recent migration, and therefore the one the next author
copies, into a case where that guarantee may not hold. The rule exists because
of an incident, not a preference.

---

## Verified, not assumed

- **Version comment is right in both directions** — `'183'` up, `'182'` down.
  This is the V106 class of bug (the comment is the source of truth for the
  migrated version, and an off-by-one makes `up` replay on every deploy).
- **Idempotent** — `IF NOT EXISTS` on both columns and the index, `DO` block
  for the constraint, and `DROP NOT NULL` is naturally re-runnable.
- **Index naming follows the prefix rules** — bare on `CREATE`, qualified on
  `DROP INDEX`.
- **`down/1` is destructive and says so** — non-file annotations have no home
  in the old shape and are deleted. Documented in the moduledoc *and* at the
  statement. Honest rather than surprising.
- **A forged event payload cannot claim a target.** `@adapter_writable_fields`
  subtracts `:target_type` and `:target_uuid` alongside `:file_uuid` and
  `:creator_uuid`, so the adapter sets them server-side from the Etcher
  envelope, never from the client's payload.
- **`put_file_target/1` runs before `validate_required/2`**, so pre-V183
  callers that know only a file still satisfy the now-required target columns.
- **`PkUrlMirror` hardening** (`0900b0ea`) refuses `//host`, `/\host`, control
  characters and fragments — the same guard shape as core's
  `Routes.local_path?/1`, and the commit is right that the browser blocks the
  cross-origin `replaceState` anyway; what was false was the guard's contract.
- **The merge did not drop the concurrent sidebar work.** `layout_wrapper.ex`
  and `layout_wrapper_admin_header_test.exs` were edited on both sides;
  `admin_sidebar_compact_bootstrap`, `show_admin_panel_label`,
  `pk-sidebar-flyout`, `data-pk-branch-active` and all three of that work's
  test blocks are present and passing after the merge.
- **JS is tested** — four new `test/js/*.test.cjs` files (close guard, phx-value
  payload, shift-enter, url mirror), run by `mix precommit`'s `test.js` step.
