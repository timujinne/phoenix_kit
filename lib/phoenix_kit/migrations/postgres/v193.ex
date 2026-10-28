defmodule PhoenixKit.Migrations.Postgres.V193 do
  @moduledoc """
  V193: indexes for the AI spend caps.

  `phoenix_kit_ai`'s spend caps (`PhoenixKitAI.Budget.spent/3`) sum
  `cost_cents` over the trailing 24 hours of SUCCESSFUL requests, for one
  endpoint or one user:

      WHERE endpoint_uuid = $1 AND inserted_at >= $2 AND status = 'success'

  `phoenix_kit_ai_requests` only had single-column indexes, so the planner
  either walks one endpoint's (or user's) entire history to answer a one-day
  question, or combines two bitmaps. These two composite partial indexes
  answer it directly — equality column first, the time range second, only
  successful rows, and `cost_cents` carried in the index so the sum can be
  read from it:

      (endpoint_uuid, inserted_at) INCLUDE (cost_cents) WHERE status = 'success'
      (user_uuid,     inserted_at) INCLUDE (cost_cents) WHERE status = 'success'

  ## The predicate must stay a literal in the query

  A partial index is only used when the planner can prove the query's
  condition implies the index's. `status = 'success'` written as a literal
  does; `status = $1` does not once Postgres switches a prepared statement to
  a generic plan, and the index silently drops out of the plan — fast in a
  test, slow in production. `Budget.spent/3` writes the status as a literal
  for exactly this reason.

  No global `(inserted_at) WHERE status = 'success'` index: nothing queries a
  site-wide window today, and an unused index is write cost on the table every
  AI call inserts into.

  ## Why not CONCURRENTLY

  Same reasoning as V167/V168: a failed concurrent build leaves an INVALID
  index that `IF NOT EXISTS` then matches by name, turning the next run into a
  silent no-op. A plain build takes a SHARE lock (reads continue; inserts into
  this table wait for the build), bounded by `lock_timeout` so a long-running
  transaction makes the migration fail loudly instead of hanging. On a very
  large request log, run this migration in a quiet window.

  Additive only. Index names stay bare on CREATE (prefix-safe migration rules).

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '193'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '192'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
