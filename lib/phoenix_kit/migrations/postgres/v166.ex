defmodule PhoenixKit.Migrations.Postgres.V166 do
  @moduledoc """
  V166: frozen comment attribution — who a comment is FROM, at the time.

  Two problems, one row.

  ## The name has to be frozen

  A comment header used to render `user.email`, which on a public issue
  board published a full address next to every remark. Replacing it with a
  live name chain fixes the address but not the deeper issue: a name
  resolved at RENDER time rewrites history. Someone leaves, is renamed, or
  finally fills in their profile, and every comment they ever wrote is
  silently re-signed. `author_display_name` records what the world was
  shown when the comment was made.

  Null for every existing row, on purpose: a backfill would invent a
  history we do not have, so old rows keep resolving live and only new ones
  are pinned.

  ## Speaking for the project

  Someone answering on their employer's public board may be speaking as
  themselves or on behalf of the project, and those are different acts. The
  choice is stored, not recomputed: recomputing means a membership change
  retroactively alters who said what — and worse, un-masks somebody who
  deliberately posted under the project's name.

  **`user_uuid` is never cleared.** Posting as the project changes what the
  PUBLIC sees, and nothing else: internally the actual author stays on the
  row, so moderation, audit and "who actually said this" keep working. A
  shared voice with no accountable person behind it is how this feature
  goes wrong.

  `attributed_label` is frozen alongside `attributed_project_uuid` for the
  same reason prices are snapshotted on orders: the project may be renamed
  or deleted, and the comment should still say what it said.

  No FK on `attributed_project_uuid` — projects live in an optional
  package, exactly like the mention targets in V165.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '166'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '165'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
