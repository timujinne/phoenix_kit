defmodule PhoenixKit.Migrations.Postgres.V179 do
  @moduledoc """
  V179: an item's manufacturer becomes a federated reference — `{source, uuid}`
  — instead of a hard foreign key into the catalogue's local directory.

  ## Why

  CRM owns party identity, and a manufacturer that is a real company is a CRM
  party. `phoenix_kit_cat_items.manufacturer_uuid` was a FOREIGN KEY onto
  `phoenix_kit_cat_manufacturers`, so a party's uuid physically could not be
  stored in it: the catalogue could only ever point at a local row. That is the
  same shape `phoenix_kit_cat_item_supplier_info` already uses for suppliers
  (soft uuid + `supplier_source` + a name snapshot), and this brings
  manufacturers into line with it.

  Three changes:

    * `manufacturer_source` — `'local'` (a `phoenix_kit_cat_manufacturers` row)
      or `'crm_company'` (a CRM party). Existing rows are all `'local'`, which
      is what the default backfills.
    * `manufacturer_name_snapshot` — a TOMBSTONE, not a cache. It is read only
      when the reference resolves to nothing (party deleted, CRM uninstalled,
      dangling uuid) so a product page can still say what it used to be. It is
      never the display source: the resolver is.
    * the FK is DROPPED.

  ## What replaces the FK

  Nothing, deliberately. `ON DELETE SET NULL` cannot span an optional-module
  boundary — the CRM tables need not exist — so integrity moves to the
  application, exactly as it already has for `item_supplier_info.supplier_uuid`
  and the warehouse document columns. `mix phoenix_kit_catalogue.audit_supplier_refs`
  is the precedent for auditing soft references; manufacturers now want the
  same treatment.

  ## Rollback

  `down/1` re-creates the FK, and it will FAIL if any item points at a CRM
  party by then — that uuid has no matching local row, which is the whole
  point of the column. Repoint those items first (unlink the manufacturer in
  the catalogue UI) and the rollback succeeds. Better to fail loudly here than
  to silently drop the offending references.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '179'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '178'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
