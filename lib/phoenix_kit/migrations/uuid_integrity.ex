defmodule PhoenixKit.Migrations.UUIDIntegrity do
  @moduledoc """
  Finds and repairs `phoenix_kit_*` tables whose `uuid` column is not a proper
  primary key.

  The invariant the chain claims — every PhoenixKit table has a non-null `uuid`
  of type `uuid`, defaulted to `uuid_generate_v7()`, as its primary key — was
  violated on a production install, and by three separate migrations in
  sequence. See `PhoenixKit.Migrations.Postgres.V163` for how.

  ## Why the SQL lives here rather than in the migration

  Two callers need exactly the same repair with different execution and
  different risk appetite:

    * `V163` runs during `mix ecto.migrate`, inside a transaction, via
      `Ecto.Migration.execute/1`, and defers tables large enough that the
      rewrite's `ACCESS EXCLUSIVE` lock would be an outage.
    * `mix phoenix_kit.repair_uuid` runs when an operator chooses, outside a
      transaction, via the repo directly, with no size limit and with the index
      built `CONCURRENTLY` where that is possible.

  Writing the statements twice would guarantee they drift, and drift in a
  primary-key repair is how a table ends up half-fixed. This module owns the
  SQL; the callers own how and when it runs.

  ## Detection is catalog-driven

  `broken_tables/2` asks PostgreSQL which tables are actually wrong rather than
  consulting a hardcoded list. Every earlier attempt used a list, and the table
  that prompted this work was absent from all of them — including the list in
  the migration that was specifically written to repair its class of problem.
  """

  alias PhoenixKit.Migrations.Postgres.Helpers

  @uuid_regex "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

  @doc """
  Every `phoenix_kit_*` base table whose `uuid` column needs work.

  Returns maps of `%{name, type, nullable, has_pk}`. A table is included when
  the column is the wrong type, is nullable, or the table has no primary key —
  the predicate the earlier guards should have used. `column_exists?/3` is true
  for a `character varying` uuid, which is precisely why V40 skipped the table
  it was listed in.
  """
  def broken_tables(repo, prefix) do
    query = """
    SELECT c.table_name,
           c.data_type,
           c.is_nullable,
           EXISTS (
             SELECT 1
             FROM pg_constraint pc
             JOIN pg_class pcl ON pcl.oid = pc.conrelid
             JOIN pg_namespace pn ON pn.oid = pcl.relnamespace
             WHERE pcl.relname = c.table_name
               AND pn.nspname = c.table_schema
               AND pc.contype = 'p'
           ) AS has_pk
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_name = c.table_name
     AND t.table_schema = c.table_schema
    WHERE c.table_schema = $1
      AND c.table_name LIKE 'phoenix\\_kit\\_%'
      AND c.column_name = 'uuid'
      AND t.table_type = 'BASE TABLE'
    ORDER BY c.table_name
    """

    case repo.query(query, [prefix], log: false) do
      {:ok, %{rows: rows}} ->
        rows
        |> Enum.map(fn [name, type, nullable, has_pk] ->
          %{name: name, type: type, nullable: nullable == "YES", has_pk: has_pk}
        end)
        |> Enum.filter(&needs_repair?/1)

      {:error, _} ->
        []
    end
  end

  @doc """
  Whether this table's uuid column is not a proper primary key.

  `has_pk` is "the table has *a* primary key", not "the primary key is on
  `uuid`". A table keyed on some other column is therefore reported healthy
  once its uuid column is typed and non-null, even though uuid is still not the
  key. Promoting it would mean dropping the existing key, which this migration
  will not do unasked; no table in the chain is in that shape (V74 removed the
  last of the legacy `id` keys), so the gap is recorded rather than coded around.
  """
  def needs_repair?(%{type: type, nullable: nullable, has_pk: has_pk}) do
    type != "uuid" or nullable or not has_pk
  end

  @doc "Whether repairing this table requires rewriting it (a type change)."
  def rewrite_needed?(%{type: type}), do: type != "uuid"

  @doc """
  Human-readable summary of what is wrong with one table, for logs and output.
  """
  def describe(%{type: type, nullable: nullable, has_pk: has_pk}) do
    [
      if(type != "uuid", do: "type=#{type}"),
      if(nullable, do: "nullable"),
      if(not has_pk, do: "no primary key")
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(", ")
  end

  @doc """
  Whether every non-null value in the column can be cast to `uuid`.

  Checked BEFORE any DDL: `ALTER … USING uuid::uuid` aborts the surrounding
  transaction on the first malformed value, which in a migration means taking
  every other table's repair down with it.
  """
  def castable?(_repo, _qualified, %{type: "uuid"}), do: true

  def castable?(repo, qualified, _table) do
    sql = """
    SELECT count(*) FROM #{qualified}
     WHERE uuid IS NOT NULL AND uuid !~* '#{@uuid_regex}'
    """

    match?({:ok, %{rows: [[0]]}}, repo.query(sql, [], log: false))
  end

  @doc """
  Rows that de-duplication would DELETE, counted before any DDL runs.

  The delete in `repair_statements/4` is the only destructive step here, so both
  callers announce it rather than discovering it afterwards. `lower(uuid::text)`
  matches what the eventual cast to `uuid` collapses — two `varchar` rows
  differing only in case are one row after the rewrite — and works whatever the
  column's current type is.
  """
  def duplicate_rows(repo, qualified) do
    sql = """
    SELECT count(*) - count(DISTINCT lower(uuid::text))
    FROM #{qualified}
    WHERE uuid IS NOT NULL
    """

    case repo.query(sql, [], log: false) do
      {:ok, %{rows: [[n]]}} when is_integer(n) -> n
      _ -> 0
    end
  end

  @doc """
  Estimated row count, from the planner's statistics rather than a count(*).

  A sequential scan to decide whether to avoid an expensive operation is
  self-defeating. `reltuples` of -1 means "never analyzed" and is reported as 0,
  so an un-analyzed table is repaired rather than skipped — being wrong in that
  direction leaves the table correct.
  """
  def estimated_rows(repo, prefix, name) do
    # A name-based pg_class + pg_namespace JOIN, never `'schema.table'::regclass`:
    # regclass RAISES when the relation does not exist, which inside a migration
    # aborts the surrounding transaction and takes every other repair with it.
    # This is the chain's documented prefix-safety rule.
    sql = """
    SELECT COALESCE(NULLIF(c.reltuples, -1), 0)::bigint
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = $1 AND n.nspname = $2
    """

    case repo.query(sql, [name, prefix], log: false) do
      {:ok, %{rows: [[n]]}} -> n
      _ -> 0
    end
  end

  @doc """
  The ordered SQL statements that repair one table.

  Order is load-bearing and each step depends on the one before:

    1. **type** — before anything is built on the column, so the index and the
       primary key are built on `uuid`, not on the `varchar` it replaces.
    2. **default** — so rows inserted between here and the backfill get a value.
    3. **backfill** — before `SET NOT NULL`, or the constraint aborts on exactly
       the NULLs it exists to prevent.
    4. **NOT NULL** — before the primary key, which requires it.
    5. **de-duplicate** — a table that has run without a key can hold duplicate
       uuids, and `ADD PRIMARY KEY` aborts on them. Rows sharing a uuid are the
       same logical row twice; `ctid` picks one deterministically.
    6. **primary key** — last, once uniqueness and NOT NULL both hold.

  `concurrent_index: true` splits the key into a `CREATE UNIQUE INDEX
  CONCURRENTLY` plus `ADD PRIMARY KEY USING INDEX`, which holds the exclusive
  lock only for the attach rather than the whole build, and drops any leftover
  index of that name first so an interrupted run is retryable. It cannot run
  inside a transaction, so it is available to the mix task and not to the
  migration.
  """
  def repair_statements(qualified, prefix, table, opts \\ []) do
    # Helpers.uuid_v7_call/1 resolves the function's real schema, so the call
    # works regardless of the connecting role's search_path.
    uuid_v7 = Helpers.uuid_v7_call(prefix)
    concurrent? = Keyword.get(opts, :concurrent_index, false)

    type_stmt =
      if rewrite_needed?(table) do
        ["ALTER TABLE #{qualified} ALTER COLUMN uuid TYPE uuid USING uuid::uuid"]
      else
        []
      end

    common = [
      "ALTER TABLE #{qualified} ALTER COLUMN uuid SET DEFAULT #{uuid_v7}",
      "UPDATE #{qualified} SET uuid = #{uuid_v7} WHERE uuid IS NULL",
      "ALTER TABLE #{qualified} ALTER COLUMN uuid SET NOT NULL"
    ]

    type_stmt ++ common ++ pk_statements(qualified, prefix, table, concurrent?)
  end

  defp pk_statements(_qualified, _prefix, %{has_pk: true}, _concurrent?), do: []

  defp pk_statements(qualified, prefix, table, concurrent?) do
    dedupe = """
    DELETE FROM #{qualified} a USING #{qualified} b
     WHERE a.ctid < b.ctid AND a.uuid = b.uuid
    """

    # Built from the catalog name directly — parsing it back out of the quoted
    # qualified string would corrupt any name containing a dot or a quote.
    index_name = quote_ident("#{table.name}_uuid_pk_idx")

    if concurrent? do
      [
        dedupe,
        # An interrupted CONCURRENTLY build leaves an INVALID index behind. With
        # `IF NOT EXISTS` the retry would skip the rebuild and then fail on
        # `USING INDEX` — a table stuck permanently one statement from done. The
        # drop is unconditional so a retry starts from a known state; it is
        # CONCURRENTLY too, and qualified, per the chain's DROP INDEX rule.
        "DROP INDEX CONCURRENTLY IF EXISTS #{quote_ident(prefix)}.#{index_name}",
        "CREATE UNIQUE INDEX CONCURRENTLY #{index_name} ON #{qualified} (uuid)",
        "ALTER TABLE #{qualified} ADD PRIMARY KEY USING INDEX #{index_name}"
      ]
    else
      [dedupe, "ALTER TABLE #{qualified} ADD PRIMARY KEY (uuid)"]
    end
  end

  @doc """
  Fully-qualified, QUOTED table name.

  The prefix is validated upstream, but the table name comes from the catalog
  and is interpolated into DDL. Quoting it means a legal-but-unusual identifier
  — a space, a capital, a reserved word — produces valid SQL rather than a
  syntax error that aborts the run. PostgreSQL escapes an embedded quote by
  doubling it.
  """
  def qualify(prefix, name), do: "#{quote_ident(prefix)}.#{quote_ident(name)}"

  @doc false
  def quote_ident(ident), do: ~s("#{String.replace(ident, ~s("), ~s(""))}")
end
