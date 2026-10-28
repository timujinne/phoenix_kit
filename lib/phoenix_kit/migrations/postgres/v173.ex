defmodule PhoenixKit.Migrations.Postgres.V173 do
  @moduledoc """
  V173: Catalogue attribute groups — reusable, translatable product options.

  Four additive objects for the `phoenix_kit_catalogue` module. A group
  ("Idea doors") owns attributes ("Color", "Trim"), each attribute owns
  ordered values ("White", "Oak"); an item is linked to a group through an
  assignment table and inherits everything the group defines. This replaces
  nothing: the hand-typed per-item metadata in `cat_items.data["meta"]`
  stays untouched and is surfaced read/editable by the module UI.

  ## phoenix_kit_cat_attribute_groups
  Global (cross-catalogue) definition roots. `name` is the primary-language
  display text; other languages live in `data` per the module's JSONB
  translation convention. `status` archived ≠ deleted: an archived group
  stays readable on items that hold it but leaves the assignment picker.

  ## phoenix_kit_cat_attributes
  One row per characteristic in a group. `key` is a stable slug unique
  within its group — the durable identity translations can never change.
  `kind` semantics come from the product design: `'fixed'` = a single
  value shown on the product card; `'multi'` = a list of options, one of
  which is chosen downstream (per order line, in the parent app).

  ## phoenix_kit_cat_attribute_values
  Ordered values per attribute. `is_default` is explicit — display order
  and commercial default are independent (finishes may sort alphabetically
  while Oak is the standard) — with a partial unique index allowing at
  most one default per attribute.

  ## phoenix_kit_cat_item_attribute_groups
  Item↔group assignment. A join table from day one — the current
  one-group-per-item business rule is carried by the `UNIQUE (item_uuid)`
  index, so the planned multi-group future is "drop one index", not a data
  migration. `ON DELETE RESTRICT` on the group side makes archive (not
  delete) the only path for a group any item still references. The
  definition-tree FKs are RESTRICT as well — the module convention is
  app-level cascades (`permanently_delete_*` deletes values → attributes →
  group in one transaction, gated on no remaining assignments), never a
  silent DB cascade, because future exception rules and parent-app order
  lines will hold value UUIDs.

  Downstream contract (documented, not enforced here): order lines in the
  parent app that record a chosen value must snapshot the resolved labels
  and keys at order time — the UUID reference alone is identity, not
  history, and later renames/translation fixes must not rewrite old orders.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '173'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '172'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
