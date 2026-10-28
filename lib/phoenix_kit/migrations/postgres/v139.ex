defmodule PhoenixKit.Migrations.Postgres.V139 do
  @moduledoc """
  V139: Dashboard-level `config` for the dashboards plugin.

  Adds a JSONB `config` column to `phoenix_kit_dashboards` for per-dashboard
  presentation settings — currently the layout mode (`"grid"` flow vs `"free"`
  pixel placement) and pixel-mode zoom. Read/written whole, like `layout`.

  All statements are idempotent (IF NOT EXISTS), safe to re-run.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '139'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '138'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
