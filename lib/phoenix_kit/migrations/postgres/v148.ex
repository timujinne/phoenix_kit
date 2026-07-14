defmodule PhoenixKit.Migrations.Postgres.V148 do
  @moduledoc """
  V148: Catalogue item-supplier sourcing info + CRM cross-refs.

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
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # ── Item ↔ supplier sourcing info (CRM federation lands here) ───────
    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_cat_item_supplier_info (
      uuid UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
      item_uuid UUID NOT NULL REFERENCES #{p}phoenix_kit_cat_items(uuid) ON DELETE CASCADE,
      supplier_uuid UUID NOT NULL,
      supplier_sku VARCHAR(100),
      supplier_name_snapshot VARCHAR(255),
      unit_cost NUMERIC(14,4),
      currency VARCHAR(3),
      lead_time_days INTEGER,
      min_order_qty NUMERIC(14,4),
      valid_from DATE,
      valid_to DATE,
      position INTEGER NOT NULL DEFAULT 0,
      metadata JSONB NOT NULL DEFAULT '{}',
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_cat_item_supplier_info_item_index
    ON #{p}phoenix_kit_cat_item_supplier_info (item_uuid)
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_cat_item_supplier_info_supplier_index
    ON #{p}phoenix_kit_cat_item_supplier_info (supplier_uuid)
    """)

    # ── Soft CRM xref on local suppliers ─────────────────────────────────
    execute("""
    ALTER TABLE #{p}phoenix_kit_cat_suppliers
    ADD COLUMN IF NOT EXISTS crm_company_uuid UUID
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '148'")
  end

  @doc """
  Rolls V148 back by dropping the item-supplier-info table and the supplier
  CRM xref column, in reverse order.

  **Lossy rollback:** all per-supplier item sourcing info (cost, SKU, lead
  time, CRM links) is lost. Items, suppliers, and the V146 scalar
  `primary_supplier_uuid` are untouched.
  """
  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_cat_item_supplier_info CASCADE")

    execute("""
    ALTER TABLE #{p}phoenix_kit_cat_suppliers
    DROP COLUMN IF EXISTS crm_company_uuid
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '147'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
