defmodule PhoenixKit.Migrations.Postgres.V138 do
  @moduledoc """
  V138: CRM v1 — interaction tracker (contacts, companies, interactions).

  Five tables for the `phoenix_kit_crm` plugin's first real data model: a
  Contact (cloned in spirit from staff `Person`, but the user link is
  **optional**), a Company, the contact↔company membership (carrying free-form
  role + department on the edge), and the interaction log (entries + their
  resolvable "involved parties" with an as-of-then profile snapshot).

  ## phoenix_kit_crm_contacts
  A CRM contact (client/customer). Unlike staff `Person`, `user_uuid` is
  **nullable** — most contacts never log in. A partial unique index keeps it
  1:1 (one contact per user) only among the rows that *are* linked.

  ## phoenix_kit_crm_companies
  A company/organization record (its own data; not a login user).

  ## phoenix_kit_crm_company_memberships
  Contact↔company link, many-to-many, with free-form `role_in_company` and
  `department` on the edge + an `is_primary` flag (drives the headline display
  and the interaction snapshot).

  ## phoenix_kit_crm_interactions
  A logged interaction ("client called, discussed X"): type, when, body,
  the subject contact, and the staff user who logged it.

  ## phoenix_kit_crm_interaction_parties
  Flat, resolvable "who was involved" list per interaction. `raw_name` is
  always kept; `contact_uuid` / `staff_person_uuid` resolve to records when
  matched (exclusive-arc: at most one set). `party_snapshot` freezes the
  party's profile as it was at log time. `staff_person_uuid` is a **soft ref**
  (no FK) so the optional staff module stays optional.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '138'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '137'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
