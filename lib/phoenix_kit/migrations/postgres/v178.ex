defmodule PhoenixKit.Migrations.Postgres.V178 do
  @moduledoc """
  V178: soft CRM cross-references on the catalogue's party-like directories —
  `phoenix_kit_cat_manufacturers.crm_company_uuid`, plus the partial unique
  indexes that keep BOTH directories one-to-one against a CRM party.

  ## Why

  CRM is the party master (see the CRM v2 parties design doc): "supplier" and
  "manufacturer" are roles on a CRM company/contact. The catalogue's local
  `phoenix_kit_cat_suppliers` / `phoenix_kit_cat_manufacturers` rows are
  demoted to a *projection* of that party — kept, not deleted, because
  catalogue-standalone installs have no CRM and because
  `phoenix_kit_cat_items.manufacturer_uuid` is still a hard FK onto the local
  manufacturer row. `crm_company_uuid` is the transition cross-reference (the
  SAP CVI pattern): nullable, no FK (optional-module boundary — the CRM tables
  may not exist), stamped when a human links the two.

  Suppliers got their column in V149. Manufacturers get theirs here, and the
  uniqueness both have always needed lands for both at once.

  ## The unique indexes are the point, not decoration

  Without them nothing stops two local rows claiming the same CRM party, which
  is the split-brain this projection design invites: the picker would list one
  party twice and "which projection is authoritative" would have no answer.
  Partial (`WHERE ... IS NOT NULL`) so the unlinked majority stays unconstrained
  — many rows may have no CRM party, but a party has at most one projection per
  directory.

  **Precondition:** an install that already stamped duplicate `crm_company_uuid`
  values onto `phoenix_kit_cat_suppliers` would fail index creation here. That
  column has been unmapped in the Ecto schema since V149 — only the opt-in
  backfill task could write it — so resolve duplicates before upgrading if a
  run of that task ever produced them.

  Additive only: no drops, no reshapes of anything core's ExpectedSchema
  manifest already declares.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '178'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '177'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
