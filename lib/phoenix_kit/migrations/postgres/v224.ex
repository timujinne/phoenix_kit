defmodule PhoenixKit.Migrations.Postgres.V224 do
  @moduledoc """
  V224: an index for one resource's activity.

  A page that shows what happened to particular records — the projects
  module's per-project Activity page and its History — reads the feed as

      WHERE resource_uuid IN ($1, …) ORDER BY inserted_at DESC LIMIT $n

  `phoenix_kit_activities` is indexed by module, action, actor, target,
  resource type and time, but not by `resource_uuid`. The planner can only
  walk the time index backwards filtering every row, or scan the module's
  whole history, so the page gets slower with every entry the site ever
  logged. One composite index answers it directly — the resource first, the
  time second, so each resource's newest entries are read in order and the
  `LIMIT` stops the scan:

      (resource_uuid, inserted_at)

  The name follows the table's existing `<table>_<columns>_index` indexes
  (`phoenix_kit_activities_actor_uuid_inserted_at_index`).

  ## Why not CONCURRENTLY

  Same reasoning as V167/V168/V193: a failed concurrent build leaves an
  INVALID index that `IF NOT EXISTS` then matches by name, turning the next
  run into a silent no-op. A plain build takes a SHARE lock on
  `phoenix_kit_activities`: reads continue, but every write to the feed — and
  every action that logs one — waits until the build ends. The lock is bounded
  by `lock_timeout`, so a long-running transaction makes the migration fail
  loudly instead of hanging. On a site with a very large activity log, run
  this migration in a quiet window.

  Additive only. The index name stays bare on CREATE (prefix-safe migration
  rules).
  """

  use Ecto.Migration

  def up(opts) do
    opts |> Map.get(:prefix, "public") |> prefix_str() |> up_statements() |> Enum.each(&execute/1)
  end

  @doc "Rolls V224 back: drops the index. Nothing is lost but speed."
  def down(opts) do
    opts
    |> Map.get(:prefix, "public")
    |> prefix_str()
    |> down_statements()
    |> Enum.each(&execute/1)
  end

  @doc false
  # The exact statements `up/1` runs, exposed so the migration test can run the
  # real SQL (a migration's `up/1` cannot run outside an Ecto.Migrator runner).
  # `p` is the schema prefix with its trailing dot.
  def up_statements(p) do
    [
      "SET lock_timeout = '5000ms'",
      """
      CREATE INDEX IF NOT EXISTS phoenix_kit_activities_resource_uuid_inserted_at_index
        ON #{p}phoenix_kit_activities USING btree (resource_uuid, inserted_at)
      """,
      # Session-level: `mix phoenix_kit.update` runs the chain in autocommit,
      # so without this the connection keeps the 5s cap after the migration
      # (and a fresh install's later versions inherit it). V163 does the same.
      "RESET lock_timeout",
      "COMMENT ON TABLE #{p}phoenix_kit IS '224'"
    ]
  end

  @doc false
  def down_statements(p) do
    [
      "DROP INDEX IF EXISTS #{p}phoenix_kit_activities_resource_uuid_inserted_at_index",
      "COMMENT ON TABLE #{p}phoenix_kit IS '223'"
    ]
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
