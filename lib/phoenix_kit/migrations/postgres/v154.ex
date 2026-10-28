defmodule PhoenixKit.Migrations.Postgres.V154 do
  @moduledoc """
  V154: OpenGraph templates + hierarchical assignments
  (`phoenix_kit_og` plugin).

  ## phoenix_kit_og_templates

  Reusable OG canvas designs. `canvas` is JSONB so the structure can
  grow new element types without a schema change. `preview_image_uuid`
  is an optional pointer to a rendered cached preview.

  ## phoenix_kit_og_assignments

  Binds a template to a scope inside a consumer module's hierarchy. The
  `(module_key, scope_type, scope_uuid)` triple is unique — enforced via
  a partial-index pair because PostgreSQL treats `NULL` as distinct:

  - one row per `(module, scope_type)` when `scope_uuid IS NULL` (the
    module-wide default tier)
  - one row per `(module, scope_type, scope_uuid)` when not null

  `template_uuid` cascades on delete: removing a template wipes every
  assignment that pointed at it.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '154'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '153'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
