defmodule PhoenixKit.Migrations.Postgres.V149 do
  @moduledoc """
  V149: Catalogue item-supplier sourcing info + CRM cross-refs.

  Two additive changes that let the `phoenix_kit_catalogue` plugin carry
  per-supplier sourcing detail per item and, later, federate those
  suppliers against CRM — without changing anything warehouse depends on.

  The item's scalar `primary_supplier_uuid` is **not** created here — it
  ships upstream in V146 (a hard FK to `phoenix_kit_cat_suppliers`). This
  junction is the richer, per-supplier pricing layer alongside it.

  ## phoenix_kit_cat_item_supplier_info
  New junction table: one item can be sourced from several suppliers, each
  with its own SKU, unit cost/currency, lead time, and MOQ. `supplier_uuid`
  is a **soft ref** (no FK) — it resolves to a CRM party or a local
  `cat_supplier`; this is where CRM federation actually lands. There is no
  "primary" among these rows — the item's default supplier is the V146
  `primary_supplier_uuid` scalar (a hard FK to `cat_suppliers`); this table
  is purely the per-supplier pricing layer alongside it.

  ## `phoenix_kit_cat_suppliers.crm_company_uuid`
  Nullable UUID **soft** cross-module xref from a local supplier record to a
  CRM company, letting a supplier be gradually federated into CRM without
  losing its catalogue-local identity.

  All operations are idempotent.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '149'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '148'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
