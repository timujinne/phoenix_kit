defmodule PhoenixKit.Migrations.Postgres.V188 do
  @moduledoc """
  V188: the three uniqueness guarantees `phoenix_kit_user_connections`
  already believed it had.

  ## Why

  The module's schemas each declare a `unique_constraint/3` naming an index
  — `phoenix_kit_user_follows_unique_idx`,
  `phoenix_kit_user_blocks_unique_idx`,
  `phoenix_kit_user_connections_requester_recipient_uidx` — and none of the
  three has ever existed. `unique_constraint/3` only translates a database
  violation into a changeset error; with no index there is no violation, so
  the constraints were inert and the only guard was the module's
  read-then-write pre-check. Two concurrent follows, blocks or requests both
  pass that check and both insert, leaving a duplicate relationship no code
  path can produce deliberately and which every count then double-reports.

  ## What it does

  Removes existing duplicates, then creates the three unique indexes under
  exactly the names the schemas name, so those `unique_constraint/3` calls
  start working with no change to the module.

  ## Directed vs undirected, and why they differ

  Follows and blocks are DIRECTED. "A follows B" and "B follows A" are two
  different relationships, so their indexes are on the ordered pair and only
  an exact repeat of one direction is a duplicate.

  Connections are UNDIRECTED — one row represents one relationship, stored in
  whichever direction it was asked — so the index is on the unordered pair:

      (LEAST(requester_uuid, recipient_uuid),
       GREATEST(requester_uuid, recipient_uuid))

  An ordered index here would leave the race that actually matters open. Two
  users clicking "connect" on each other at the same moment both pass
  `request_connection/2`'s pre-check (`connected?/2` finds no accepted row,
  and each direction-specific pending lookup finds nothing) and both insert —
  one A→B row and one B→A row, which an ordered index permits. The damage is
  not cosmetic: the next request auto-accepts ONE of them and leaves the other
  as a live pending request between two already-connected users;
  `remove_connection/2` then deletes only the accepted row and leaves that
  ghost behind; and `get_accepted_connection/2` uses `Repo.one/1`, so a pair
  that ends up accepted twice raises `Ecto.MultipleResultsError`.

  The expression index is still reported under its own name in a `23505`, so
  the schema's existing `unique_constraint/3` keeps working unchanged — the
  field list only decides where the error is attached.

  Nothing legitimately needs both directions at once: a mutual request UPDATES
  the existing row to "accepted" rather than inserting a reverse one, and a
  removed connection deletes its row, freeing the pair for a later request.

  ## De-duplication

  Existing duplicates are removed first, or `CREATE UNIQUE INDEX` would fail.
  For follows and blocks the surviving row is the smallest `uuid`, which under
  UUIDv7's time ordering is the one written first. Connections rank
  "accepted" above "pending" before falling back to that rule, because the two
  can only coexist through the race being closed and the accepted row is the
  live relationship — dropping it for an older pending request would
  disconnect two connected users. The `*_history` tables are untouched and
  keep the full record either way.

  Rolling back drops the three indexes. It cannot bring back removed
  duplicates, which is correct: they were never valid.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '188'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '187'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
