# PR #624: Add V140 migration — `phoenix_kit_warehouse` tables

**Author**: @timujinne
**Reviewer**: @claude (Opus 4.8)
**Status**: ✅ Merged (post-merge review)
**Commit**: `867ad50a` (merged as `ef62360a`)
**Date**: 2026-07-09

## Goal

Ship the storage layer for the standalone `phoenix_kit_warehouse` package: six
`phoenix_kit_warehouse_*` tables (`stock`, `inventory_documents`,
`internal_orders`, `supplier_orders`, `goods_receipts`, `goods_issues`), plus a
bump of `@current_version` 139 → 140.

The tables are extracted from a host application's existing warehouse schema,
with every FK to a host-specific table removed. The `sub_order_uuid` FK on
`internal_orders` / `goods_issues` is replaced by a generic `source_refs` JSONB
column resolved through a host-registered callback, so the package has no
dependency on any particular "order" concept.

## Verdict

The migration is structurally sound: FK-safe create/drop ordering, `IF NOT
EXISTS` throughout, `uuid_generate_v7()` per project convention, correct
`COMMENT ON TABLE ... IS '140'` / `'139'` version stamping, and the dispatcher
needs no registry update (`Module.concat([__MODULE__, "V140"])` resolves by
name).

One real bug, two indexing gaps that undo a guarantee the PR's own design
depends on, and one moduledoc that is both inaccurate and leaks a private
downstream app's table names into published hexdocs. All fixed in place —
**V140 has never shipped** (hex latest and local `@version` were both `1.7.179`
at review time), so amending it is safe and no V141 fixup is needed.

## Findings

### BUG - HIGH — CHECK-constraint guard is not scoped to the table

`lib/phoenix_kit/migrations/postgres/v140.ex:60`

```sql
IF NOT EXISTS (
  SELECT 1 FROM pg_constraint
  WHERE conname = 'phoenix_kit_warehouse_stock_quantity_non_negative'
) THEN
```

`pg_constraint.conname` is **not globally unique** — it is unique only per
`(connamespace, conrelid)`. PhoenixKit explicitly supports installing into a
non-`public` schema via the `prefix` option, and multiple prefixes can coexist
in one database.

**Failure scenario:** install PhoenixKit into `public`, then into `tenant_a` in
the same database. When V140 runs for `tenant_a`, the guard finds `public`'s
constraint, takes the `IF NOT EXISTS` false branch, and **silently skips**
`ADD CONSTRAINT`. `tenant_a.phoenix_kit_warehouse_stock` ends up with no
`quantity >= 0` check, and negative stock balances become insertable. The
migration reports success.

Every other constraint guard in this repo scopes correctly — `v41.ex:55`,
`v72.ex:116`, `v78.ex:50` all carry `AND conrelid = '<prefixed table>'::regclass`.
V140 is the only one that omits it.

**Fixed** — added `AND conrelid = '#{p}phoenix_kit_warehouse_stock'::regclass`,
matching the established pattern.

### IMPROVEMENT - HIGH — `source_refs` reverse lookup is unindexed

`v140.ex` — `internal_orders`, `supplier_orders`, `goods_receipts`, `goods_issues`

The PR's central design move is dropping the `sub_order_uuid` FK column in
favour of `source_refs` JSONB. But `sub_order_uuid` was an indexed column, and
`source_refs` shipped with no index at all. The forward direction (read
`source_refs` off a row you already hold, hand it to the host callback) is
fine. The reverse direction — "which goods issues reference this order?", the
query any warehouse UI needs to render an order's fulfilment history — degrades
from an index lookup to a full sequential scan with a `@>` containment filter.

This is exactly the kind of capability regression that hides behind a schema
change: nothing fails, it just gets slower as the table grows, and by then the
migration has shipped.

GIN-on-JSONB is already the established pattern here (`v45.ex:165`,
`v46.ex:95`, `v59.ex:240`).

**Fixed** — added `USING GIN (source_refs)` on all four tables that carry the
column. (`inventory_documents` correctly has no `source_refs`.)

### IMPROVEMENT - HIGH — `stock` has no index on `location_uuid`

`v140.ex:55`

`stock` gets one index: `UNIQUE (item_uuid, location_uuid)`. A composite btree
only serves leading-column lookups, so `WHERE location_uuid = $1` — "what is
stored at this location", the most natural query against a stock table — cannot
use it and falls back to a sequential scan.

Every *other* warehouse table in this migration got a standalone
`location_uuid` index. `stock`, the one where it matters most, did not.

**Fixed** — added `phoenix_kit_warehouse_stock_location_uuid_index`.

### BUG - MEDIUM — Four columns have no FK, on a rationale that does not hold

`v140.ex` moduledoc + `item_uuid` / `location_uuid` / `storage_folder_uuid` /
`supplier_uuid`

The moduledoc justified these as plain UUID columns by calling them
**cross-package references**:

> `location_uuid`, `storage_folder_uuid`, and `supplier_uuid` are plain UUID
> columns (no cross-package FK) — resolved through `phoenix_kit_locations`,
> core's Storage module, and `phoenix_kit_catalogue` respectively, matching the
> established pattern for cross-package references elsewhere in this schema.

That is not accurate. **All four target tables are created by this same core
migration set, in the same schema:**

| Column | Target table | Created by |
|---|---|---|
| `item_uuid` | `phoenix_kit_cat_items` | V87 |
| `location_uuid` | `phoenix_kit_locations` | V91 |
| `storage_folder_uuid` | `phoenix_kit_media_folders` | core Storage module |
| `supplier_uuid` | `phoenix_kit_cat_suppliers` | V87 |

An FK is physically possible for every one of them, and core already does
exactly this: `v122.ex:108` declares `location_uuid` as
`references(:phoenix_kit_locations, column: :uuid, on_delete: :delete_all)`
with `null: false` — the same column name, the same target, with an FK.

So the columns are not FK-less because they *can't* be; they're FK-less by
omission. `location_uuid` is `NOT NULL`, which guarantees a value is present but
not that it points at a row that exists — a typo'd or stale location uuid
inserts cleanly and is only discovered when a join returns nothing.

**Not fixed — deliberately.** Adding the FK requires choosing `ON DELETE`
semantics, and both plausible answers are product decisions this package hasn't
made: `RESTRICT` (refuse to delete a location that still holds stock — probably
correct for a warehouse) versus `CASCADE` (delete the location, lose its stock
history — what V122's existing `delete_all` would imply if copied
unthinkingly). Picking one silently on the module owner's behalf, inside a
review, is the wrong call. Recorded here so the gap is on the record rather than
resting on a rationale that reads as principled but isn't.

The moduledoc has been **rewritten to say what is actually true**: an FK is
possible, it is omitted pending a delete-semantics decision, and referential
integrity for these four columns is not enforced by the database.

### NITPICK — Private downstream app leaked into published hexdocs

The moduledoc named a private host application and its internal tables
(`<app>_warehouse_stock`, `<app>_inventory_documents`, `<app>_internal_orders`,
`<app>_supplier_orders`, `<app>_goods_receipts`, `<app>_goods_issues`) six times.
`phoenix_kit` is a public Hex package; these moduledocs render on hexdocs.pm,
where that app's name is meaningless to every reader and shouldn't be advertised.

**Fixed** — genericised to "the host-application tables the module was extracted
from".

### NITPICK — `deleted_at` indexes are non-partial

All five document tables index `deleted_at` as a plain btree. The dominant query
against a soft-delete column is `WHERE deleted_at IS NULL`, which matches nearly
every row and will seq-scan regardless. The index does serve purge jobs hunting
deleted rows, so it isn't dead weight — but a partial index
(`... WHERE deleted_at IS NULL` on `status` or `location_uuid`) is what would
actually accelerate the list views.

**Not fixed** — speculative without knowing the package's real query shapes, and
no other core migration establishes the pattern. Noted for when the LiveViews
land and the access patterns are known.

### NITPICK — Sequences are not `OWNED BY` their column

`number BIGINT NOT NULL DEFAULT nextval('..._number_seq')` with a separately
created sequence means the sequence is not owned by the column. `down/1`
correctly drops each one explicitly, so this is not a leak today — but anyone
who drops a warehouse table outside this migration orphans its sequence. An
`ALTER SEQUENCE ... OWNED BY <table>.number` would make the lifetime automatic
and let `down/1` shed six statements.

**Not fixed** — cosmetic, and `down/1` is already correct.

## Verified as correct (no action)

- **Create/drop ordering.** `internal_orders` precedes `supplier_orders` and
  `goods_issues`; `supplier_orders` precedes `goods_receipts`. `down/1` reverses
  it exactly (issues → receipts → supplier_orders → internal_orders →
  inventory_documents → stock). No FK violation in either direction.
- **Dispatcher.** `@current_version` 139 → 140 is the only change needed;
  `execute_migration_steps/4` resolves modules by name via
  `Module.concat([__MODULE__, "V140"])`, so there is no version list to keep in
  sync. The `⚡ LATEST` marker moved from the V139 heading to V140 correctly.
- **`uuid_generate_v7()` unqualified.** Matches V136/V138 and the rest of the
  repo; not a V140 regression.
- **`phoenix_kit_users(uuid)` FK.** Valid — ten other migrations reference the
  same target.
- **Version stamping.** `up` → `'140'`, `down` → `'139'`. Correct.
- **Identifier lengths.** Longest generated name
  (`phoenix_kit_warehouse_supplier_orders_internal_order_uuid_index`, 62 chars)
  is under PostgreSQL's 63-byte limit; the indexes added by this review are all
  shorter.

## Testing

- [x] `mix format`
- [x] `mix precommit` (format + `compile --warnings-as-errors` + `credo --strict` + dialyzer)
- [ ] Migration executed against PostgreSQL — not run; per `CLAUDE.md`,
      `phoenix_kit` is not standalone-testable and `mix precommit` is the gate.
- [x] Backward compatibility — V140 was unpublished at review time (hex latest
      `1.7.179` == local `@version`), so amending it in place breaks no installed
      database.

## Related

- Migration: `lib/phoenix_kit/migrations/postgres/v140.ex`
- Dispatcher: `lib/phoenix_kit/migrations/postgres.ex`
- Constraint-guard precedent: `v41.ex:55`, `v72.ex:116`, `v78.ex:50`
- FK-to-locations precedent: `v122.ex:108`
- GIN-on-JSONB precedent: `v45.ex:165`, `v46.ex:95`, `v59.ex:240`
- Previous PR: [#623](../623-v139-dashboards-config-viewport-daisyui/)
