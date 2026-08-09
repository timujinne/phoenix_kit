# PR #688 — Add V163: repair uuid columns that are not primary keys

**Author:** Max Don (`mdon/main`)
**Merged:** 2026-08-08 (`85b14b61`, commits `c768e024` + `7c4f38f8`)
**Reviewer:** Claude
**Scope:** `lib/phoenix_kit/migrations/uuid_integrity.ex` (new),
`lib/phoenix_kit/migrations/postgres/v163.ex` (new),
`lib/mix/tasks/phoenix_kit.repair_uuid.ex` (new),
`lib/mix/tasks/phoenix_kit.doctor.ex`, `lib/phoenix_kit/migrations/postgres.ex`,
`test/integration/v163_uuid_integrity_test.exs` (new), `.dialyzer_ignore.exs`

## Verdict

The diagnosis is right and the design is the right one — catalog-driven detection
instead of yet another hand-kept table list is exactly the lesson the three
failed prior attempts teach. Detection, quoting, statement ordering, the
castability pre-check, the prefix-safe `pg_class`/`pg_namespace` join, and the
`flush/0` fix in `7c4f38f8` are all correct.

Five findings, four fixed. The significant one is that the size guard — the whole
reason this migration is safe to ship to a fleet — only covered one of the three
operations it needed to cover.

---

## BUG - HIGH — the row-count guard only deferred the type rewrite, not the primary-key build

`v163.ex:127` (as merged)

```elixir
UUIDIntegrity.rewrite_needed?(table) and
    UUIDIntegrity.estimated_rows(repo(), prefix, name) > limit ->
```

The moduledoc states the premise correctly:

> `ALTER COLUMN … TYPE uuid` rewrites the table under an `ACCESS EXCLUSIVE` lock,
> and `ADD PRIMARY KEY` builds a unique index under the same lock. **Both are
> O(rows).**

The code then guards only the first. `rewrite_needed?/1` is `type != "uuid"`, so
a table that is already `uuid`-typed but has **no primary key** — one of the three
states `needs_repair?/1` exists to catch, and the state the new test at
`v163_uuid_integrity_test.exs:103` was specifically written to prove is detected —
skips the guard entirely at any size and goes straight to `run_isolated/3`. That
runs, on an unbounded table:

1. `DELETE FROM t a USING t b WHERE a.ctid < b.ctid AND a.uuid = b.uuid` — a
   self-join over every row,
2. `ALTER TABLE t ALTER COLUMN uuid SET NOT NULL` — a full scan under `ACCESS
   EXCLUSIVE` (Postgres only skips it when a validated `CHECK (col IS NOT NULL)`
   exists, and nothing here creates one),
3. `ALTER TABLE t ADD PRIMARY KEY (uuid)` — a unique index built over every row,
   under `ACCESS EXCLUSIVE`.

That is precisely the "connection-pool exhaustion during `mix ecto.migrate`, not a
pause" outcome the limit was added to prevent, and it lands on the same class of
table: `phoenix_kit_email_events` is an events table, and the reported host was
one `V56` window away from having it `uuid`-typed-but-keyless rather than
`varchar`-and-keyless. The guard would then have been a no-op on the exact
database that motivated the migration.

**Fixed** — the limit now gates every repair class:

```elixir
UUIDIntegrity.estimated_rows(repo(), prefix, name) > limit ->
```

`rewrite_needed?/1` is kept (it is genuine information for the operator-facing
output), but it no longer decides whether a table is safe to touch during a
deploy. The moduledoc's "setting the default and backfilling … always run" claim
was also wrong in the merged code — the deferral branch skipped `run_isolated/3`
wholesale, so a deferred table got nothing — and now says so.

## BUG - MEDIUM — an interrupted `CREATE INDEX CONCURRENTLY` left the mix task permanently stuck

`uuid_integrity.ex:196` (as merged)

```elixir
"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS #{index_name} ON #{qualified} (uuid)",
"ALTER TABLE #{qualified} ADD PRIMARY KEY USING INDEX #{index_name}"
```

`CREATE INDEX CONCURRENTLY` that is interrupted — cancelled, deploy killed,
connection dropped, a conflicting transaction — leaves an **`INVALID` index**
behind rather than nothing. On the retry `IF NOT EXISTS` sees that relation, logs
`relation already exists, skipping`, and `ADD PRIMARY KEY USING INDEX` then fails
on the invalid index. The operator is one statement from done, in a maintenance
window, with an error that does not name the cause, and re-running the task never
fixes it. This is the documented failure mode of `CONCURRENTLY`, and it is
reachable on the only path that emits it (`mix phoenix_kit.repair_uuid`, which is
the path taken for the biggest, slowest, most interruptible tables).

**Fixed** — the concurrent branch drops any leftover index first, so a retry
starts from a known state:

```elixir
"DROP INDEX CONCURRENTLY IF EXISTS #{quote_ident(prefix)}.#{index_name}",
"CREATE UNIQUE INDEX CONCURRENTLY #{index_name} ON #{qualified} (uuid)",
```

The drop is `CONCURRENTLY` (the task runs outside a transaction) and
schema-qualified, per the chain's "bare on CREATE, qualified on DROP INDEX" rule.
`IF NOT EXISTS` is dropped from the create since the drop now precedes it.

## BUG - MEDIUM — `mix phoenix_kit.repair_uuid <table>` reported the global all-clear when the argument matched nothing

`phoenix_kit.repair_uuid.ex:64`

`filter_requested/2` narrows the broken list to the named tables, and an empty
result printed:

> ✓ Every phoenix_kit table has a proper uuid primary key.

V163's own log tells the operator to run `mix phoenix_kit.repair_uuid
phoenix_kit_email_events`. A typo in that name, a `--prefix` that does not match
the install, or a table someone already repaired all produce the same empty list —
and answer with a green check mark asserting something about *every* table that
was never checked. On the deferred-large-table path that is the difference between
"the maintenance window did its job" and "the maintenance window did nothing".

**Fixed** — the named-tables case is now distinct from the nothing-is-broken case,
names what was asked for, and states the prefix in play.

## IMPROVEMENT - MEDIUM — the destructive step was silent

The de-duplicating `DELETE` is the only statement in V163 that destroys data, and
neither caller said how much. In the migration it ran inside a queued batch with
no row count in the deploy log; in the mix task `--dry-run` printed the DELETE's
SQL, which does not tell an operator whether it removes zero rows or nine hundred.
Rows deleted here can also take `ON DELETE CASCADE` children with them.

**Fixed** — `UUIDIntegrity.duplicate_rows/2` counts the affected rows before any
DDL runs, and both callers announce it: `Logger.warning` from V163, a yellow line
from the task (so `--dry-run` now answers the question it exists to answer). The
count uses `lower(uuid::text)`, which is what the cast to `uuid` actually
collapses — two `varchar` rows differing only in case are one row afterwards — and
works whatever the column's current type is. It is scoped to keyless tables, which
are the only ones the DELETE is emitted for, and those are now bounded by the
row-count guard above.

## IMPROVEMENT - MEDIUM — `has_pk` means "has a key", not "uuid is the key" (documented, not changed)

`broken_tables/2`'s `has_pk` is `EXISTS (… pc.contype = 'p')` — any primary key on
the table. So a table keyed on some *other* column, with a broken `uuid` column
alongside it, gets its type and `NOT NULL` repaired, `pk_statements/4` returns `[]`
because `has_pk` is true, and `needs_repair?/1` then reports it healthy — while
`uuid` is still not the primary key, which is the thing the module is named after.

Deliberately not changed. Repairing it means dropping the existing key, which a
library must not do unasked, and tightening the predicate to "the key is on uuid"
would permanently flag any composite-keyed table in an external module package
with no repair path to offer it. No table in the chain is in this shape — V74
removed the last legacy `id` keys, and the composite keys in V111
(`phoenix_kit_cat_pdf_pages`, `phoenix_kit_cat_pdf_page_contents`) have no column
named `uuid` and so are never matched. The limitation is now stated in
`needs_repair?/1`'s doc rather than left for the next person to rediscover.

## NITPICK — the new doctor check was inserted between a comment and the function it documents

`phoenix_kit.doctor.ex:420`. The three-line comment describing
`check_uuid_column_types/1` ("A varchar uuid column on `phoenix_kit_settings`
crashes the Ecto schema loader on startup") ended up above the newly added
`check_uuid_primary_keys/1`, which does not check column types at all. **Fixed** —
each comment sits above its own function.

## Correct, and worth recording as correct

- **`flush/0` in `7c4f38f8`.** `Ecto.Migration.execute/1` queues; without the
  flush the per-table `rescue` could never fire and one locked table would have
  taken down every repair after it *and* skipped the version marker. Ecto's runner
  clears the pending list before executing it, so a raise mid-flush drops only the
  rest of that table's statements — which is exactly what the isolation wants.
- **Version marker written unconditionally.** Right call, and for the stated
  reason: a skipped table stays visible in the doctor, whereas an unwritten marker
  is how this codebase has previously had migrations skipped permanently.
- **`estimated_rows/3` uses a name-based `pg_class`/`pg_namespace` join**, not
  `'schema.table'::regclass`, per the prefix-safety rules — `regclass` raises when
  the relation is absent and would abort the surrounding transaction.
- **Statement order** (type → default → backfill → NOT NULL → dedupe → key) is
  correct and each dependency is real; the ordering test pins it.
- **Identifier quoting** of catalog-derived names, and deriving the index name
  from `table.name` rather than parsing it back out of the quoted qualified
  string (also `7c4f38f8`).
- **`castable?/3` is stricter than Postgres' uuid parser** (it rejects the
  brace-wrapped and hyphen-less forms Postgres accepts). That errs toward
  skipping a repairable table, never toward attempting an unrepairable one — the
  safe direction, since a failed cast aborts the transaction.

## Known gap left open

No test exercises `V163.up/1` itself. The suite covers `UUIDIntegrity` thoroughly
but not the flush/rescue isolation, the size deferral, or the always-write-the-
marker behaviour — and the flush bug fixed in `7c4f38f8` is exactly the class of
defect a test there would have caught. Doing it properly needs an
`Ecto.Migration.Runner` context, which `PhoenixKit.DataCase` does not stand up;
noted for a future migration-harness sweep rather than bolted on here.

## Tests added

`test/integration/v163_uuid_integrity_test.exs`:

- the concurrent branch drops a leftover index before rebuilding, in that order,
  with a schema-qualified name, and no longer emits `IF NOT EXISTS`
- `duplicate_rows/2` counts what the DELETE removes — including `varchar` rows
  that differ only in case, which collide once cast — and reports 0 when clean
- `describe/1` names every defect, and only the defects actually present

## Gate

`mix precommit` — compile (warnings as errors), `deps.unlock --check-unused`,
format check, `credo --strict`, dialyzer, JS tests.
