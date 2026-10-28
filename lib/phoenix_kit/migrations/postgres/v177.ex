defmodule PhoenixKit.Migrations.Postgres.V177 do
  @moduledoc """
  V177: `phoenix_kit_cat_item_attribute_sets` — the catalogue's item ↔
  attribute-set attachments (attribute-sets rework, replaces the single
  `phoenix_kit_cat_item_attribute_groups` assignment).

  A SET is a managed entities blueprint ("Ikea colors"); an item attaches
  any number of sets, ordered. `set_uuid` references
  `phoenix_kit_entities.uuid` WITHOUT an FK — deliberate, and load-bearing:
  the entities blueprint delete path consults the owning module's delete
  guard (`PhoenixKitEntities.Managed`), and the catalogue additionally
  cleans orphans off entities PubSub events. A hard FK would either
  cascade catalogue data on a blueprint delete or block entities' own
  lifecycle with a cross-module dependency — neither is this codebase's
  pattern for cross-module references (see V175's integration_uuid note).

  `data` (JSONB, default `{}`) is reserved per-attachment state. Known
  future keys (designed, not yet read by any code):

    * `"disabled_value_slugs"` — per-item value availability
    * `"selected_value_slug"`  — the item's current configuration

  Reserving the column now means those features land without another
  migration; readers must tolerate unknown keys.

  The old attribute tables (V103-era `cat_attribute_groups` /
  `cat_attributes` / `cat_attribute_values` / `cat_item_attribute_groups`)
  are NOT touched here — they go read-only during the dual-run and are
  dropped by a later version once the cutover completes.

  Filed as V176 originally; renumbered to V177 when upstream took V176 for
  the A002 FK-validation pass while this branch was still in review — the
  same dance that file's own moduledoc records for its V175 -> V176 move.
  No content changed beyond the version number and the COMMENT ON TABLE
  stamps. Every statement is IF-NOT-EXISTS idempotent, so an install that
  already ran this DDL as V176 (pre-renumber deploys) re-runs it as V177
  as a clean no-op.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '177'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '176'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
