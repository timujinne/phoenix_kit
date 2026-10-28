defmodule PhoenixKit.Migrations.Postgres.V218 do
  @moduledoc """
  V218: a sync connection's requests per minute default to 600.

  `phoenix_kit_sync_connections.rate_limit_requests_per_minute` was created with
  `DEFAULT 60` and nothing enforced it. The sync module now refuses a request over it
  (`0` means no limit), and a full sync of every table makes more than 60 requests in
  under a minute, so 60 would slow every full sync and fail tables on a peer that does
  not wait out the refusal.

  What the migration does:

    * sets the column default to 600, the sync module's own default;
    * raises every row still at exactly 60 to 600. No form, API or registration path
      ever wrote this field, so 60 is the old default nobody chose. A row set to 60 on
      purpose (only possible through a direct `Connections` call) cannot be told apart
      from it and is raised too; any other value, `0` included, is left alone.

  Running it again changes nothing: no row is left at 60, and the default is already 600.

  `down/1` restores the default of 60 and lowers no row: it cannot know which rows
  were raised and which were set to 600 on purpose.

  ## Locks

  `ALTER COLUMN … SET DEFAULT` changes the catalog only (no rewrite), then one
  update of the connections still at 60. Re-runnable.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '218'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '217'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
