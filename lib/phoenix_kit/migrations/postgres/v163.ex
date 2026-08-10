defmodule PhoenixKit.Migrations.Postgres.V163 do
  @moduledoc """
  V163: UUID primary-key integrity.

  Repairs any `phoenix_kit_*` table whose `uuid` column is the wrong type,
  nullable, or not the primary key — the state V40/V56/V74 are each supposed to
  make impossible, and which a production install reached anyway.

  ## The reported state

  On a database upgraded through the whole chain since V01,
  `phoenix_kit_email_events` had `uuid` as `character varying(255)`, nullable,
  no default, and the table had **no primary key at all**. 149 other tables were
  correct, so this was one table falling out of the conversion rather than a
  broken upgrade.

  ## Why the chain missed it, twice

  1. **V40's guard tests EXISTENCE, not TYPE.** An older release created that
     column as Ecto `:string`, so `unless column_exists?(table, :uuid, …)` was
     already true and V40 skipped the table wholesale — not just the `ADD
     COLUMN`, but the backfill, the `SET NOT NULL` and the unique index with it.
     The table *is* in V40's `@tables_to_migrate`; being listed did not help.

  2. **V56's type conversion shipped after some hosts had already passed V56.**
     `ensure_all_uuid_columns_native_type/2` — which converts exactly this
     varchar column — was added to V56 on 2026-03-02, seventeen days after V56
     itself (2026-02-13). A recorded version never re-runs, so every host that
     crossed V56 in that window kept the broken column permanently. V56's
     `NOT NULL` and index repairs also run off hardcoded table lists that
     `phoenix_kit_email_events` appears in none of.

  V74 then dropped the legacy bigint `id` but could not promote `uuid` to
  primary key — wrong type, nullable — and did not verify its own documented
  post-condition ("after V74, every PhoenixKit table has uuid as its PK").
  Nothing raised.

  ## Why this migration is catalog-driven

  Every previous attempt enumerated tables by hand, and this table was missing
  from every list. This one asks the catalog which tables are actually broken,
  so a table nobody remembered to list is repaired anyway — and so a table that
  is already correct is skipped without needing to be named.

  ## Large tables are deferred, not silently rewritten

  `ALTER COLUMN … TYPE uuid` rewrites the table under an `ACCESS EXCLUSIVE`
  lock, `SET NOT NULL` scans it under the same lock, and `ADD PRIMARY KEY`
  builds a unique index under it too. All three are O(rows), so the size limit
  gates the whole repair rather than only the rewrite — a keyless table needs no
  type change and would otherwise have had an index built over every row. On a
  big events table behind PgBouncer that is connection-pool exhaustion during
  `mix ecto.migrate`, not a pause, so above two million rows the table is left
  exactly as it was and logged with the command to run in a maintenance window.

  This migration never raises on the happy path. A library does not own its
  hosts' deploy runbooks, and turning a latent problem (one audit table without
  a PK, on a version where no schema maps to it) into a failed deploy across a
  fleet is a worse outcome than the problem. `mix phoenix_kit.doctor` is the
  loud channel and reports precisely what was deferred.
  """

  use Ecto.Migration

  require Logger

  alias PhoenixKit.Migrations.Postgres.Helpers
  alias PhoenixKit.Migrations.UUIDIntegrity

  # Above this, the rewrite is deferred to a maintenance window. ~2M rows is a
  # few seconds of exclusive lock on ordinary hardware; an order of magnitude
  # more is not. Override with `up(%{uuid_rewrite_row_limit: n})`.
  @rewrite_row_limit 2_000_000

  # A repair that cannot get its lock quickly is deferred, not waited on.
  @lock_timeout_ms 5_000

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    limit = Map.get(opts, :uuid_rewrite_row_limit, @rewrite_row_limit)

    # Repaired tables need the generator to exist even if V40 never reached them.
    Helpers.ensure_uuid_v7_function(prefix)

    # Fail fast rather than queue behind a long-running reader. The migration
    # `mix phoenix_kit.update` generates carries @disable_ddl_transaction — the
    # only path on which V163 has anything to do — so this is autocommit: without
    # a timeout an ALTER blocked by an open transaction waits forever and the
    # deploy hangs rather than erroring. (A fresh install runs the chain inside a
    # transaction, but reaches V163 with nothing broken to repair.)
    execute("SET lock_timeout = '#{@lock_timeout_ms}ms'")

    repo()
    |> UUIDIntegrity.broken_tables(prefix)
    |> Enum.each(&repair(&1, prefix, limit))

    execute("RESET lock_timeout")

    # ALWAYS recorded, even if a table above was skipped. The marker is the only
    # thing the chain consults, so failing to write it would make V163 re-run
    # forever — and, worse, a stale marker is how this codebase has previously
    # had migrations skipped permanently. Tables that did not get repaired are
    # logged and still reported by `mix phoenix_kit.doctor`; they are not lost.
    execute("COMMENT ON TABLE #{prefix_str(prefix)}phoenix_kit IS '163'")
  end

  # Irreversible by design. Rolling back would mean re-breaking a primary key —
  # recreating the reported defect on a healthy table — and the prior state is
  # not recoverable anyway: which rows held NULL uuids before the backfill is
  # not recorded. Only the version marker moves.
  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    execute("COMMENT ON TABLE #{prefix_str(prefix)}phoenix_kit IS '162'")
  end

  defp repair(%{name: name} = table, prefix, limit) do
    qualified = UUIDIntegrity.qualify(prefix, name)

    cond do
      # Checked BEFORE castability: `castable?/3` is a full-table
      # `count(*) … !~*` scan, so asking it first made the deferral path pay an
      # unbounded sequential scan on exactly the tables this limit exists to keep
      # out of `mix ecto.migrate`. Read-only, so not the ACCESS EXCLUSIVE outage
      # itself — but on a PgBouncer-fronted pool it pins a connection for minutes
      # before deciding to skip. `estimated_rows/3` reads the catalog.
      #
      # The guard covers EVERY repair class, not just the rewrite. `ALTER COLUMN
      # TYPE` rewrites the table, `SET NOT NULL` scans it, and `ADD PRIMARY KEY`
      # builds a unique index over it — all three under ACCESS EXCLUSIVE, all
      # three O(rows). Deferring only the rewrite left the worst case in: the
      # table that prompted this work is an events table, and had it been uuid-
      # typed-but-keyless it would have taken an index build over every row
      # during `mix ecto.migrate` — exactly the outage this limit exists to stop.
      too_big_or_unmeasured?(UUIDIntegrity.estimated_rows(repo(), prefix, name), limit) ->
        Logger.warning("""
        [PhoenixKit V163] #{name}: #{UUIDIntegrity.describe(table)} — but the \
        table is over #{limit} rows, or has never been analyzed so its size is \
        unknown. Skipped: the repair takes an ACCESS EXCLUSIVE lock for a full \
        pass over the table. Run this in a maintenance window, where the key can \
        be built CONCURRENTLY:
          mix phoenix_kit.repair_uuid #{name}
        That command reports the row count, and refuses with the offending values \
        if the column holds anything that is not a valid UUID — fix those first if \
        it does, because no repair can convert them.
        `mix phoenix_kit.doctor` will keep reporting it until you do.
        """)

      not UUIDIntegrity.castable?(repo(), qualified, table) ->
        # Aborting the migration over one table's bad data would strand every
        # other repair in this run, so this table is skipped and named.
        Logger.error("""
        [PhoenixKit V163] #{name}: the uuid column holds values that are not \
        valid UUIDs, so it cannot be converted. Left unchanged. Inspect with:
          SELECT uuid FROM #{qualified} WHERE uuid IS NOT NULL
           AND uuid !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' LIMIT 20;
        """)

      true ->
        warn_about_duplicates(qualified, table)
        run_isolated(qualified, prefix, table)
    end
  end

  # `:unknown` defers, exactly as an over-limit count does. The guard exists to
  # keep an unbounded ACCESS EXCLUSIVE pass out of `mix ecto.migrate`, and "we
  # never measured this table" is not evidence that the pass is bounded. The
  # cost of being wrong is asymmetric: deferring leaves the table unrepaired and
  # loudly reported by `doctor`, while proceeding can lock a large table for the
  # length of a deploy.
  defp too_big_or_unmeasured?(:unknown, _limit), do: true
  defp too_big_or_unmeasured?(rows, limit) when is_integer(rows), do: rows > limit

  # Deleting rows is the only destructive thing V163 does, so it is never
  # silent — an operator reading the deploy log sees the count before the
  # DELETE runs, not after.
  defp warn_about_duplicates(_qualified, %{has_pk: true}), do: :ok

  defp warn_about_duplicates(qualified, %{name: name}) do
    case UUIDIntegrity.duplicate_rows(repo(), qualified) do
      n when n > 0 ->
        Logger.warning("""
        [PhoenixKit V163] #{name}: #{n} row(s) share a uuid with another row and \
        will be DELETED — a primary key cannot be built over duplicates. One row \
        per uuid is kept.
        """)

      _ ->
        :ok
    end
  end

  # One table's failure must not take the rest of the run with it. Autocommit
  # means the statements already applied stay applied, and every prefix of the
  # sequence leaves the table further along than it started rather than
  # corrupted — so continuing is strictly better than aborting. The most likely
  # failure by far is `lock_not_available` from the timeout above, which means
  # "busy right now", not "broken".
  defp run_isolated(qualified, prefix, table) do
    qualified
    |> UUIDIntegrity.repair_statements(prefix, table)
    |> Enum.each(&execute/1)

    # `execute/1` only QUEUES a command; without this the statements are flushed
    # after `up/1` returns — outside the rescue below — and the isolation this
    # function exists for would silently never fire. `flush/0` runs everything
    # pending here, in scope, so a failure is caught and the next table proceeds.
    flush()
  rescue
    error ->
      Logger.error("""
      [PhoenixKit V163] #{table.name}: repair failed and was skipped — \
      #{Exception.message(error)}
      Other tables were not affected. Re-run with:
        mix phoenix_kit.repair_uuid #{table.name}
      """)
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
