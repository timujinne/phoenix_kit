defmodule PhoenixKit.Migrations.Postgres.V143 do
  @moduledoc """
  V143: CRM v2 — party roles (suppliers, clients).

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
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_crm_party_roles (
      uuid UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
      roleable_type VARCHAR(20) NOT NULL,
      roleable_uuid UUID NOT NULL,
      role VARCHAR(30) NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      valid_from DATE,
      valid_to DATE,
      metadata JSONB NOT NULL DEFAULT '{}',
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    # Guarded CHECK: roleable_type is a closed set (the polymorphic targets
    # are CRM-owned tables; adding a third target is a migration anyway).
    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'phoenix_kit_crm_party_roles_roleable_type_check'
        AND conrelid = '#{p}phoenix_kit_crm_party_roles'::regclass
      ) THEN
        ALTER TABLE #{p}phoenix_kit_crm_party_roles
        ADD CONSTRAINT phoenix_kit_crm_party_roles_roleable_type_check
        CHECK (roleable_type IN ('company', 'contact'));
      END IF;
    END $$;
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_crm_party_roles_uniq
    ON #{p}phoenix_kit_crm_party_roles (roleable_type, roleable_uuid, role)
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_crm_party_roles_role_active_idx
    ON #{p}phoenix_kit_crm_party_roles (role, is_active)
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_crm_party_roles_roleable_idx
    ON #{p}phoenix_kit_crm_party_roles (roleable_type, roleable_uuid)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '143'")
  end

  @doc """
  Rolls V143 back by dropping the party-roles table.

  **Lossy rollback:** all supplier/client role assignments are lost. The
  underlying companies/contacts (V138) are untouched.
  """
  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_crm_party_roles CASCADE")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '142'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
