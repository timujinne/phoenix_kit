defmodule PhoenixKit.Migrations.Postgres.V144 do
  @moduledoc """
  V144: Manufacturing/Warehouse module tables consolidation.

  Consolidates tables previously created by `phoenix_kit_manufacturing`'s
  and `phoenix_kit_warehouse`'s own `migration_module/0` into core's
  migration chain — see PR body for the manual-migration note on non-empty
  legacy directory tables.

  Five objects, each idempotent (safe to re-run):

    * `phoenix_kit_machines` — machine reference-book records. V1 identity
      columns (`name`, `code`, `manufacturer`, `serial_number`,
      `description`, `location_note`, `status`, `data`, `metadata`) plus
      the V2 passport/soft-location columns (`model`, `manufacture_year`,
      `commissioned_on`, `warranty_until`, `to_last_on`,
      `to_interval_days`, `to_next_on`, `notes`, `location_uuid`,
      `space_uuid`), in their final (module V5-equivalent) shape.
    * `phoenix_kit_machine_type_assignments` — machine<->machine_type join.
      `machine_uuid` is a real FK to `phoenix_kit_machines`; `machine_type_uuid`
      is a soft reference to `phoenix_kit_entity_data.uuid` (no FK) — machine
      types now live in `phoenix_kit_entities`, a separate package this
      migration doesn't own. On a host upgrading from the published
      `phoenix_kit_manufacturing` 0.2.0 (module V1), this table already
      exists with a *live* FK on `machine_type_uuid` (pointing at the
      `phoenix_kit_machine_types` directory table below) — `CREATE TABLE IF
      NOT EXISTS` is a no-op there, so the FK is dropped by a separate,
      unconditional step.
    * `phoenix_kit_machine_operations` — machine<->operation join, same
      soft-reference shape on `operation_uuid`. Never published with a live
      FK on any known external host (0.2.0 predates this table entirely),
      but the drop is attempted unconditionally anyway, for symmetry with
      `machine_type_uuid` above.
    * `phoenix_kit_warehouse_transfers` (+ its `number` sequence) and
      `phoenix_kit_warehouse_min_stock` — fresh-install-only DDL. The
      published `phoenix_kit_warehouse` 0.1.0 shipped no migrations at all
      (no `phoenix_kit_warehouse_transfers`/`min_stock` on any external
      host), so there is no upgrade path to account for here, unlike the
      manufacturing tables above.

  `phoenix_kit_machine_types`, `phoenix_kit_operations`, and
  `phoenix_kit_defect_reasons` — the pre-V5 manufacturing directory tables —
  are **not** re-created by this migration; they are not one of the five
  objects it owns. If a host still has one of them (realistic only on an
  external `phoenix_kit_manufacturing` 0.2.0 install — our own dev database
  has never had them, since the module's local migration already carried it
  to V5), `up/1` drops it when empty and leaves it in place (with a
  `RAISE NOTICE`) when it still holds rows, so real directory data is never
  silently destroyed. See the core PR body for the manual data-migration
  note on such hosts.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '144'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '143'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
