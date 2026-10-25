# PR #981 — Add V223: AI request cost in dollars; clear the AI tables' leftovers

**Author:** mdon · **Merged:** 2026-10-24 (435bcd70e) · **Reviewer:** Claude

## Summary

`phoenix_kit_ai_requests.cost_cents` (integer, really millionths of a dollar)
becomes `cost` (`numeric(28,18)`, dollars), every stored cost converted; an
unreleased `cost_nanodollars` and an earlier unreleased `numeric(20,10)` `cost`
are converted too. The same `DO` block widens `model` to `varchar(150)`, drops
`phoenix_kit_ai_accounts` + `account_uuid`, and drops the unique `uuid` indexes
beside the AI tables' primary keys (found by shape), dropping and re-adding
every foreign key bound to one so it rebinds to the primary key. Down restores
the V222 shape (accounts empty, keys left on the pkeys).

Verdict: correct; one release-ordering blocker outside this repo.

Checked:

- **Atomic and prefix-safe.** One `DO` block, so the chain's
  no-transaction wrappers can't leave it half done. `V203.prefix_str/1` returns
  `public.` for public, so every name stays qualified under the emptied
  `search_path`; `information_schema.*` is written qualified, `pg_catalog` is
  always implicitly searched. Every existence check is anchored on
  `table_schema` / `nspname`.
- **FK rebinding.** `conrelid::regclass::text` and `pg_get_constraintdef` render
  schema-qualified with the path empty, and the definition carries `NOT VALID` /
  `DEFERRABLE` / `ON DELETE` as they were, so a re-added key is the same key.
  The accounts table is dropped before the index loop, so its own keys are gone
  before they could be collected.
- **Spend indexes.** The rename keeps the attribute number, so the two V193
  `INCLUDE (cost_cents)` indexes follow automatically; the manifest gets
  `{223, …}` revisions, and repair rebuilds an index from the revision shape,
  not the newest `create:` (`Repair.Executor.create_action/2`), so a database
  below 223 missing one is not handed `INCLUDE (cost)`.
- **Down.** `round(cost * 1000000)::integer` raises on overflow (tested), and the
  `length(model) > 100` guard runs before the narrowing.
- `Adoption`'s `@core_legacy_table_comments` still lists
  `phoenix_kit_ai_accounts` — correct, it describes pre-squash comments a host
  below 223 still carries.
- `v223_test.exs`, `v193_test.exs` and `prefix_migration_test.exs` pass against
  the real test DB (21 tests).

## Findings

### BUG - HIGH — `phoenix_kit_ai` 0.25.5 breaks against the next core release (not fixed here)

`phoenix_kit_ai` (workspace `main`, 0.25.5) still reads and writes `cost_cents`
(`lib/phoenix_kit_ai.ex` — usage insert, spend sums, stats) and pins core
`~> 2.63`, which admits the next core release. A host that runs
`mix phoenix_kit.update` on that release without a new `phoenix_kit_ai` gets
every AI usage insert failing on the missing column — spend uncounted, the
spend caps reading errors. The moduledoc says so ("Needs the `phoenix_kit_ai`
release that writes `cost`"), and failing loudly instead of storing costs a
million times too large is the right choice, but nothing enforces the order.

Release order: publish the core release carrying V223 only together with a
`phoenix_kit_ai` release that writes `cost`, drops `account_uuid`, and raises
its core floor to that core version (`>= 2.64.0`); call the pairing out in the
CHANGELOG entry. Core cannot gate this itself (it does not depend on
`phoenix_kit_ai`).

### IMPROVEMENT - MEDIUM — the `search_path` restore was untested (fixed)

Both blocks set `search_path` to `''` with `is_local = true` and put the
caller's value back at the end; inside a caller's transaction a missed restore
would leave every later unqualified statement in that transaction failing.
Added `"leaves the caller's search_path as it found it, up and down"` to
`v223_test.exs` (runs inside the sandbox transaction with a non-default path).

### NITPICK — a foreign key *to* `phoenix_kit_ai_accounts` from another table stops the migration

`DROP TABLE` has no `CASCADE`, so a host table referencing the accounts would
abort V223. Nothing in the kit or its modules does, and stopping is better than
cascading into a host's table; left as is.
