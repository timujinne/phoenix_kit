defmodule PhoenixKit.Migrations.Postgres.V151 do
  @moduledoc """
  V151: supplier-info source/primary columns + CRM email normalization.

  Completes the V149 `phoenix_kit_cat_item_supplier_info` junction with the
  two columns the merged `phoenix_kit_catalogue` sourcing layer (catalogue
  PR #44) reads and writes — without them every junction INSERT/UPDATE
  crashes on an undefined column:

    * `supplier_source` — `'crm_company' | 'crm_contact' | 'local'` (CHECK).
      Disambiguates the polymorphic soft `supplier_uuid` (a CRM company, a
      CRM contact, or a local `cat_suppliers` row) so the resolver and the
      `phoenix_kit_catalogue.audit_supplier_refs` consistency report route
      lookups without a trial cascade.
    * `is_primary` + partial-unique index (at most one primary row per
      item). The catalogue context auto-promotes the first linked supplier
      and offers "make primary"; `Suppliers.primary_for_item/1` backs the
      warehouse resolver.

  The V146 scalar `phoenix_kit_cat_items.primary_supplier_uuid` is left
  untouched (V149's design keeps it); the merged catalogue schema simply no
  longer maps it.

  Also normalises the CRM party email columns to `citext`
  (`phoenix_kit_crm_contacts.email`, `phoenix_kit_crm_companies.email`):
  case-insensitive matching is a prerequisite for the CRM v2 backfill
  (match-by-email) and the user↔contact bridge (`connect_user/2` finds or
  creates auth users by email). citext is a core dependency since V01
  (`phoenix_kit_users.email`), so `ensure_extension!/1` is a no-op on any
  existing install.

  **citext conversion cost:** `ALTER COLUMN … TYPE citext` takes an ACCESS
  EXCLUSIVE lock and rewrites the table — plan a maintenance window for
  large CRM tables. Neither email column carries an index or a unique
  constraint anywhere in the chain, so no index rebuild happens and no
  latent case-duplicate can surface as a violation; if a unique index on
  email is ever added later, case-variant duplicates must be resolved
  first (citext compares case-insensitively).

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '151'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '150'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
