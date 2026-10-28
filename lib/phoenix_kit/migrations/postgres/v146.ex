defmodule PhoenixKit.Migrations.Postgres.V146 do
  @moduledoc """
  V146: `primary_supplier_uuid` on catalogue items.

  Backs `phoenix_kit_catalogue`'s per-item default supplier (upstream
  catalogue commit 2e47cdf): lets an item specify a supplier directly,
  independent of manufacturer — needed for generic/unbranded materials
  that have no brand to resolve a supplier through, and to break ties
  when a manufacturer has more than one linked supplier.

  - Nullable `primary_supplier_uuid` FK → `phoenix_kit_cat_suppliers(uuid)`
    with `ON DELETE SET NULL` — the pointer is an optional default; the
    item must survive its supplier (mirrors `category_uuid`'s nilify
    semantics, deliberately NOT `manufacturer_uuid`'s delete_all).
  - Partial index on `(primary_supplier_uuid) WHERE NOT NULL` for the
    "items defaulting to this supplier" reverse lookup.

  Idempotent + prefix-safe: bare index name on CREATE, all existence
  checks schema-anchored, FK constraint checked via `pg_constraint`
  anchored to the prefixed table (the V51 idiom).

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '146'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '145'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
