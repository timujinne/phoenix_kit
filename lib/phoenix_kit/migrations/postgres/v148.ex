defmodule PhoenixKit.Migrations.Postgres.V148 do
  @moduledoc """
  V148: CRM v2 — party roles (suppliers, clients).

  One table for the `phoenix_kit_crm` plugin's commercial party typing: a
  polymorphic role edge that marks an existing CRM company **or** contact as
  a `supplier`, `client`, or other commercial counterparty role. This is the
  Odoo `supplier_rank`/`customer_rank` / SAP Business-Partner-roles property
  expressed as rows: one party can hold several roles simultaneously (a
  company that is both supplier and client has two rows).

  ## phoenix_kit_crm_party_roles
  `roleable_type` + `roleable_uuid` point at `phoenix_kit_crm_companies` or
  `phoenix_kit_crm_contacts` (sole-trader suppliers are contacts). The pair
  carries **no FK** — a single FK cannot express the polymorphic target;
  integrity lives in the CRM changesets, mirroring the `staff_person_uuid`
  soft-ref precedent in V138's `interaction_parties`.

  `role` is a free string (initial vocabulary: supplier/client/partner) so
  the set can grow without a migration; the CRM module validates allowed
  values. `valid_from`/`valid_to` give roles a lifecycle ("former supplier")
  without deleting history; `is_active` is the quick filter. `metadata`
  absorbs role-scoped commercial attributes (payment terms, tax id, account
  number, default currency) until they stabilize into typed columns.

  Design doc: `phoenix_kit_crm` `dev_docs/design/crm_v2_parties_suppliers_clients.md`.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '148'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '147'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
