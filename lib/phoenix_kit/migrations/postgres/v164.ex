defmodule PhoenixKit.Migrations.Postgres.V164 do
  @moduledoc """
  V164: Repair for the V56/V57 flush-order bug's fallout on already-migrated
  single-shot installs.

  ## Root cause (fixed at the source in V56/V57/V72; this version is the
  cleanup for installs that ran the buggy versions before those fixes)

  V56 called `UUIDFKColumns.up/1` (queues `ADD COLUMN` for ~80 `*_uuid` FK
  columns) immediately followed by `UUIDFKColumns.add_constraints/1` (whose
  `set_not_null/4` and `add_fk_constraint/7` guard themselves with immediate
  `column_exists?`/`table_exists?` `information_schema` queries) with no
  `flush()` between them, and V57 (which re-runs the same pair) had no
  `flush()` at all. V56 and V57 are not separate Ecto migration modules —
  they are sub-calls inside one parent `up/1` that share a single command
  buffer — so ANY chain run crossing V56/V57 within one migrator invocation
  hits this, whether it came from a fresh `mix phoenix_kit.install` (one
  unpinned wrapper for the whole chain) or from an update wrapper whose
  range happens to span those versions. The buffer is not flushed by an
  immediate `repo().query`, so
  `add_constraints/1`'s guards ran against `information_schema` state that
  had not seen the columns `UUIDFKColumns.up/1` had *just* queued moments
  earlier in the same call — every guard failed closed:

    * ~46 `*_uuid` columns across ~33 tables were silently left nullable
      instead of NOT NULL.
    * ALL ~70 declared FK constraints (`UUIDFKColumns.fk_constraints/0`)
      failed the same closed guard, not just the one this version used to
      single out. Live evidence from a production database that crossed
      V56/V57 in one migrator invocation: 155 foreign keys existed on
      `phoenix_kit_*` tables, but only a handful carried the `fk_` naming
      convention these declarations use — every sampled expected name
      (`fk_users_tokens_user_uuid`, `fk_role_permissions_role_uuid`,
      `fk_orders_user_uuid`, …) was absent. An earlier revision of this
      migration repaired only `phoenix_kit_comments.fk_comments_user_uuid`
      (item 3 below) on the mistaken premise that it was the sole
      casualty — understating the fallout by roughly 67 constraints.

  `phoenix_kit_comments.fk_comments_user_uuid` specifically was never
  created at all (the same guard gap). V72, running later and finding that
  FK genuinely missing, added it back with a guessed `ON DELETE CASCADE`
  instead of matching V56/V57's own already-declared `SET NULL` intent
  (`UUIDFKColumns.@fk_constraints`) — comments behave like tickets/
  ai_requests (orphaned-author rows survive, blanked), not like the
  `*_likes`/`*_dislikes` junction tables, which genuinely should vanish
  with their user.

  V56 and V57 now each have the missing `flush()`, and V72's entry is now
  `SET NULL` — so every chain run *from here on*, single-shot or
  incremental, produces the correct shape and this version is a no-op on
  it. This version exists only to repair installs whose single-shot run
  already happened before those fixes landed.

  ## What this does

  1. For every `{table, column}` pair `UUIDFKColumns.add_constraints/1`
     sets NOT NULL on (`UUIDFKColumns.not_null_uuid_fks/0` — the exact same
     list, not a second copy of it) **minus `@relaxed_after_v57`** (below):
     if the column currently has zero NULL rows, sets NOT NULL — matching
     the shape a correctly-flushed V56/V57 run would already have
     produced, a no-op if it's already NOT NULL. If NULL rows exist, this
     does **not** guess: those NULLs may be legitimate application data
     (e.g. an FK reference to a deleted row with no CASCADE, or a
     genuinely optional relation) rather than purely an artifact of the
     flush bug, so it raises a warning naming the table/column/row count
     and leaves the column nullable for an operator to investigate — never
     backfills a live column with a random value to force the constraint
     through (unlike `UUIDFKColumns`' own conversion-era backfill, which
     only ever ran against columns it had *just* created moments earlier
     in the same call, never live data). A column skipped via
     `@relaxed_after_v57` stays nullable permanently — that is the point of
     the list. A column skipped via the WARN path is different, and the text
     here used to say otherwise: the NULL count is re-read on every run, so
     once an operator resolves those rows a re-run DOES enforce NOT NULL.
     Re-running is free for everything already enforced (the nullability probe
     short-circuits before any ALTER), which is what makes it safe to re-run
     after a partial failure.

  ### `@relaxed_after_v57` — columns a LATER version deliberately made nullable again

  `not_null_uuid_fks/0` is V56/V57's own declared list — a snapshot of
  intent as of V57. Later versions can and do legitimately relax a column
  on that list for reasons that have nothing to do with the flush bug
  (V164 blindly re-enforcing NOT NULL on those would silently break
  whatever feature needed the relaxation — on a *fresh* install, the table
  starts empty, so the zero-NULL-rows check would not catch this at all).
  Found by grepping every `DROP NOT NULL` in `v58.ex`..`v162.ex` — after
  V57, where the flush fix landed — and intersecting the touched
  `{table, column}` pairs against `not_null_uuid_fks/0` (checked both raw
  SQL `ALTER COLUMN ... DROP NOT NULL` and the Ecto `modify ..., null:
  true` DSL form; only the former appears anywhere in this range):

    * `{:phoenix_kit_files, "user_uuid"}` — V113 (`v113.ex`): system-managed
      media rows (DZI tiles/manifests) have no human owner, only a
      `parent_file_uuid`; `phoenix_kit_files_user_or_parent_check` enforces
      "one of the two is set" at the CHECK-constraint level instead.
      Re-imposing NOT NULL here would break `Storage.store_system_file`'s
      tile generation on any install whose run hit the flush bug.

  A THIRD case exists that belongs in neither category: an entry that was
  simply WRONG in `not_null_uuid_fks/0` from the start.
  `{:phoenix_kit_users_tokens, "user_uuid"}` was removed from that list
  outright on 2026-08-08 rather than excluded here, because V64's
  `user_uuid_required_for_non_registration_tokens` CHECK deliberately permits
  NULL for magic-link REGISTRATION tokens (no user exists yet) — so enforcing
  NOT NULL breaks registration on a fresh install as surely as on a repaired
  one, and the fix has to reach the baseline and the manifest too, not just
  this repair. Removing it at the source makes every path agree; excluding it
  here would have left V56/V57 still imposing it. The relaxation was invisible
  to the `DROP NOT NULL` grep this list was built from because it was expressed
  as a CHECK — `v164_relaxed_columns_test.exs` now scans for that shape too.

  The list also carries one entry that is not a later relaxation but a
  contradiction inside V56/V57's own declarations —
  `phoenix_kit_ticket_status_history.changed_by_uuid` is claimed by
  `@not_null_uuid_fks` while `@fk_constraints` gives its FK
  `ON DELETE SET NULL`, which NOT NULL makes unsatisfiable. See its inline
  comment; `uuid_fk_columns_test.exs` asserts no other pair contradicts.

  `test/phoenix_kit/migrations/v164_relaxed_columns_test.exs` statically
  scans `v58.ex`..the current HEAD version for this exact pattern and fails
  if it finds a `not_null_uuid_fks/0` member relaxed by a later version
  that is not listed here — a future relaxation cannot silently make this
  list stale again.

  2. For every `{table, uuid_fk, ref_table, ref_col, on_delete}` tuple in
     `UUIDFKColumns.fk_constraints/0` (the exact same ~70-entry list, not a
     second copy): if the FK's own table/column or its referenced
     table/column is absent, the whole tuple is skipped (feature-module
     tables can legitimately be missing on an install that never enabled
     that module) and folded into one aggregate warning naming every
     skipped tuple. Otherwise, if the named constraint
     (`UUIDFKColumns.fk_constraint_name/2` — the identical name
     `add_fk_constraint/7` itself would have used) does not already exist,
     it is added the same way `PhoenixKit.Migrations.Repair.Executor` adds
     any FK (spec §6.2/§6.3, the repair engine's own rule, not a new one
     invented here): `NOT VALID` first — metadata-only, no table scan,
     brief lock — then a separate `VALIDATE CONSTRAINT` — `SHARE UPDATE
     EXCLUSIVE`, does not block reads or writes, but does scan the table.
     If validation fails because live rows violate it, the constraint is
     left `NOT VALID` (new writes are still checked going forward) and a
     warning names the table, column and the orphan row count — a real
     `COUNT(*)` diagnostic query, never a guess. Nothing here ever deletes
     a row or nulls out a reference to force a constraint through: V72's
     own historical fix for the one comments FK did that, and so does
     `UUIDFKColumns.add_fk_constraint/7` itself when it first lays down
     these constraints on a fresh install — both are safe there only
     because they act on data they just created moments earlier in the
     same call, never on live, already-deployed data, which is exactly
     what this repair runs against. Idempotent: a constraint that already
     exists, `NOT VALID` or fully validated, is left exactly as-is on every
     re-run — a second run finds everything this pass would have created
     already present and does nothing.

  3. `phoenix_kit_comments.fk_comments_user_uuid`: if it currently has `ON
     DELETE CASCADE` (V72's guess, made under the buggy single-shot
     shape), drops and re-adds it `ON DELETE SET NULL`. No orphan cleanup
     is needed for that transition — rows cannot be orphaned under an
     already-enforced CASCADE constraint (every row whose referenced user
     was deleted would already be gone). If the constraint is absent
     entirely — reachable now only if item 2 above also failed to create
     it (e.g. a validation failure left it `NOT VALID`, which this branch
     does not treat as "absent"; item 2 always runs first and already
     covers the ordinary "missing entirely" case with the correct `SET
     NULL` action) — adds it `SET NULL` with the same orphan cleanup V72's
     own `add_fk_constraint/7` does. If already `SET NULL`, no-op.

  ## down/1

  This is a repair, not a feature — rolling back does not undo the NOT
  NULL constraints or the FK correction (same precedent as V57: "don't
  undo V56's work on rollback"). `down/1` only restamps the version
  comment.

  ## Core 3.0

  Everything this version did belonged to a module's tables and now lives in
  that module's own migration chain (`PhoenixKit.Migrations.ModuleOwnedTables`,
  plan `dev_docs/plans/2026-10-25-module-table-ownership.md`, step 8): core no
  longer creates or changes them. The version is kept so the chain stays
  numbered; it only moves the marker. Hosts below V225 cannot upgrade to this
  release (`BelowFloorError`), so nobody replays what the text above describes.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '164'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '163'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
