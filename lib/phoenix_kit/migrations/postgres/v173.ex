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
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.Helpers

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    Helpers.ensure_uuid_v7_function(prefix)
    uuid_default = Helpers.uuid_v7_call(prefix)

    # ── Definition roots ─────────────────────────────────────────────
    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_cat_attribute_groups (
      uuid UUID PRIMARY KEY DEFAULT #{uuid_default},
      name VARCHAR(255) NOT NULL,
      data JSONB NOT NULL DEFAULT '{}',
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      position INTEGER NOT NULL DEFAULT 0,
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT phoenix_kit_cat_attribute_groups_status_check
        CHECK (status IN ('active', 'archived'))
    )
    """)

    # ── Attributes within a group ────────────────────────────────────
    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_cat_attributes (
      uuid UUID PRIMARY KEY DEFAULT #{uuid_default},
      group_uuid UUID NOT NULL
        REFERENCES #{p}phoenix_kit_cat_attribute_groups(uuid) ON DELETE RESTRICT,
      key VARCHAR(100) NOT NULL,
      name VARCHAR(255) NOT NULL,
      data JSONB NOT NULL DEFAULT '{}',
      kind VARCHAR(20) NOT NULL DEFAULT 'multi',
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      position INTEGER NOT NULL DEFAULT 0,
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT phoenix_kit_cat_attributes_kind_check
        CHECK (kind IN ('fixed', 'multi')),
      CONSTRAINT phoenix_kit_cat_attributes_status_check
        CHECK (status IN ('active', 'archived'))
    )
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_cat_attributes_group_key_index
      ON #{p}phoenix_kit_cat_attributes (group_uuid, key)
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_cat_attributes_group_position_index
      ON #{p}phoenix_kit_cat_attributes (group_uuid, position)
    """)

    # ── Values within an attribute ───────────────────────────────────
    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_cat_attribute_values (
      uuid UUID PRIMARY KEY DEFAULT #{uuid_default},
      attribute_uuid UUID NOT NULL
        REFERENCES #{p}phoenix_kit_cat_attributes(uuid) ON DELETE RESTRICT,
      key VARCHAR(100) NOT NULL,
      value VARCHAR(255) NOT NULL,
      data JSONB NOT NULL DEFAULT '{}',
      is_default BOOLEAN NOT NULL DEFAULT FALSE,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      position INTEGER NOT NULL DEFAULT 0,
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT phoenix_kit_cat_attribute_values_status_check
        CHECK (status IN ('active', 'archived'))
    )
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_cat_attribute_values_attr_key_index
      ON #{p}phoenix_kit_cat_attribute_values (attribute_uuid, key)
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_cat_attribute_values_attr_position_index
      ON #{p}phoenix_kit_cat_attribute_values (attribute_uuid, position)
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_cat_attribute_values_default_index
      ON #{p}phoenix_kit_cat_attribute_values (attribute_uuid) WHERE is_default
    """)

    # ── Item ↔ group assignment ──────────────────────────────────────
    execute("""
    CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_cat_item_attribute_groups (
      uuid UUID PRIMARY KEY DEFAULT #{uuid_default},
      item_uuid UUID NOT NULL
        REFERENCES #{p}phoenix_kit_cat_items(uuid) ON DELETE CASCADE,
      attribute_group_uuid UUID NOT NULL
        REFERENCES #{p}phoenix_kit_cat_attribute_groups(uuid) ON DELETE RESTRICT,
      position INTEGER NOT NULL DEFAULT 0,
      inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    # One group per item is the CURRENT business rule, deliberately carried
    # by this index alone. Multi-group support = replace this with a
    # UNIQUE (item_uuid, attribute_group_uuid) index; no data moves.
    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_cat_item_attr_groups_item_index
      ON #{p}phoenix_kit_cat_item_attribute_groups (item_uuid)
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_cat_item_attr_groups_group_index
      ON #{p}phoenix_kit_cat_item_attribute_groups (attribute_group_uuid)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '173'")
  end

  @doc """
  Rolls V173 back by dropping the four tables in dependency order.

  **Lossy rollback:** all attribute groups, attributes, values, and
  item↔group assignments are lost. Items themselves — including their
  legacy hand-typed `data["meta"]` metadata — are untouched.
  """
  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Plain drops in dependency order — CASCADE could silently take out
    # FKs or views a parent application hung off these tables later.
    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_cat_item_attribute_groups")
    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_cat_attribute_values")
    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_cat_attributes")
    execute("DROP TABLE IF EXISTS #{p}phoenix_kit_cat_attribute_groups")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '172'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
