defmodule PhoenixKit.Migrations.Postgres.V140 do
  @moduledoc """
  V140: Warehouse module tables.

  Creates the six `phoenix_kit_warehouse_*` tables that back the standalone
  `phoenix_kit_warehouse` package: `stock`, `inventory_documents`,
  `internal_orders`, `supplier_orders`, `goods_receipts`, `goods_issues`.

  These mirror the shape of the host-application tables the module was
  extracted from, minus every FK that pointed at a host-specific table:

  - `internal_orders` and `goods_issues` drop the `sub_order_uuid` FK — that
    relationship now lives exclusively in the generic `source_refs` JSONB
    column (`[%{"kind" => "sub_order", "uuid" => ...}, ...]`), resolved by a
    host-registered callback rather than a hard FK to an order table this
    package doesn't own. A GIN index on `source_refs` stands in for the index
    the dropped FK column used to provide, so the reverse lookup ("which
    documents reference this order?") stays off a sequential scan.
  - Intra-module FKs are kept: `supplier_orders.internal_order_uuid` →
    `internal_orders`, `goods_receipts.supplier_order_uuid` →
    `supplier_orders`, `goods_issues.internal_order_uuid` → `internal_orders`.
  - `performed_by_uuid` stays FK'd to `phoenix_kit_users` on every document
    table (core-to-core reference, unchanged from the originals).
  - `item_uuid`, `location_uuid`, `storage_folder_uuid`, and `supplier_uuid`
    are plain UUID columns. Their targets (`phoenix_kit_cat_items`,
    `phoenix_kit_locations`, `phoenix_kit_media_folders`,
    `phoenix_kit_cat_suppliers`) are all created by this same core migration
    set, so an FK would be physically possible. It is omitted because the
    delete semantics — restrict a location that still holds stock, versus
    cascade the documents away with it — are a product decision the warehouse
    package has not made yet. Until it does, referential integrity for these
    four columns is **not** enforced by the database, and a dangling
    `location_uuid` will not be rejected on insert.

  This migration ships the tables only — no application code reads or writes
  them yet, and no data is copied from the host's legacy tables (that is a
  separate, later host-side data migration, run only after the new package
  and its LiveViews are built and verified).

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '140'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '139'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
