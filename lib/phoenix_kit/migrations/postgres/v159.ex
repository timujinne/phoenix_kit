defmodule PhoenixKit.Migrations.Postgres.V159 do
  @moduledoc """
  V159: Publishing categories + post view counters
  (`phoenix_kit_publishing` module).

  ## phoenix_kit_publishing_categories

  Hierarchical, per-group taxonomy (WordPress-parity categories). The tree
  is a nullable `parent_uuid` self-FK — same shape as V103's catalogue
  categories; cycle/scope rules are context-layer responsibilities. `slug`
  is unique per group (not globally — two groups can both have "news").
  `name_i18n` carries per-language display names keyed by language code,
  mirroring the group-name convention in the groups table's `data` JSONB.

  Deleting a group cascades its categories; deleting a parent lifts its
  children to the root (`ON DELETE SET NULL`) rather than orphaning a
  subtree.

  ## phoenix_kit_publishing_post_categories

  Post↔category assignment (M:N — WordPress semantics: taxonomy is
  post-level, not per-version). Both sides cascade.

  ## phoenix_kit_publishing_post_views

  Per-day view rollups: one `(post_uuid, view_date)` row incremented in
  place. Totals are `SUM(count)`; time-series come free. Deduplication /
  bot filtering happen app-side before the increment — the table stores
  accepted counts only, no per-request rows and no reader PII.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '159'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '158'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
