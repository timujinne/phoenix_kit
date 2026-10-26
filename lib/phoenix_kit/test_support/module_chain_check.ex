defmodule PhoenixKit.TestSupport.ModuleChainCheck do
  @moduledoc """
  Proves that a module's own migration chain builds its tables without core,
  for use from the module's test suite.

  ## Why this exists

  Core's migration chain still creates tables that belong to modules
  (`PhoenixKit.Migrations.ModuleOwnedTables`). A module that adopted its
  tables re-declares them with `CREATE … IF NOT EXISTS`, but on every host
  core's chain runs first, so that DDL never actually runs: nothing shows
  whether it would build the same tables. This check makes it run. It is the
  proof each module needs before core can stop creating its tables
  (`dev_docs/plans/2026-10-25-module-table-ownership.md`, step 8).

  ## What it does

  In a scratch schema of its own:

    1. builds core's chain (`PhoenixKit.Migration.ensure_current/2`);
    2. runs the module's chain the way `mix phoenix_kit.update` does —
       `up(prefix: schema, version: current_version())` inside an
       `Ecto.Migrator` run — and records the module's tables: **today's
       install**, core's tables plus the module's changes on top;
    3. drops those tables and runs the module's chain again: **the module
       alone**;
    4. compares the two, table by table: columns (type, `NOT NULL`, default,
       identity, generated), indexes, constraints and triggers, each by name
       and definition. Definitions are compared in the canonical form
       `mix phoenix_kit.repair` uses, so two spellings Postgres stores for the
       same CHECK compare equal. Column order and comments are not compared.

  A chain that raises in either run is reported the same way: on a database
  where core no longer creates the module's tables, that migration would fail.

  The module's tables are the ones `ModuleOwnedTables` lists for its OTP
  application, plus every table its chain created in step 2, plus its
  `version_table/0` when it exports one. `:tables` replaces the first part.

  Returns `:ok`, or `{:error, report}` with one line per difference.

  ## Usage

  From an `async: false` test that does **not** check out a sandbox
  connection (use `ExUnit.Case`, not a `DataCase`): `Ecto.Migrator` runs on
  connections of its own, so the check puts a sandboxed repo in `:auto` mode
  while it runs and back in `:manual` afterwards, which is only safe once the
  async tests are done.

      defmodule MyModule.MigrationsBuildAloneTest do
        use ExUnit.Case, async: false

        @moduletag :integration

        test "the chain builds the module's tables without core" do
          assert :ok =
                   PhoenixKit.TestSupport.ModuleChainCheck.check(
                     MyModule.Test.Repo,
                     MyModule.Migrations
                   )
        end
      end

  Options:

    * `:tables` — the core-created tables to check, instead of what
      `ModuleOwnedTables` lists for the module's application
    * `:schema` — the scratch schema's name (default: a fresh `pkcc_*` name)
    * `:keep_schema` — leave the scratch schema in place, to inspect it

  Ships in `lib/` so modules reach it through Hex; never call it from
  application code.
  """

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Migrations.ModuleOwnedTables
  alias PhoenixKit.Migrations.Repair.Differ

  @columns_sql """
  SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
         pg_get_expr(d.adbin, d.adrelid), a.attidentity, a.attgenerated
  FROM pg_attribute a
  JOIN pg_class c ON c.oid = a.attrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  WHERE n.nspname = $1 AND c.relname = ANY($2) AND a.attnum > 0 AND NOT a.attisdropped
  """

  @indexes_sql """
  SELECT tablename, indexname, indexdef FROM pg_indexes
  WHERE schemaname = $1 AND tablename = ANY($2)
  """

  # NOT NULL constraints (`contype = 'n'`, Postgres 18) are compared as part
  # of each column instead.
  @constraints_sql """
  SELECT c.relname, con.conname, pg_get_constraintdef(con.oid)
  FROM pg_constraint con
  JOIN pg_class c ON c.oid = con.conrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = $1 AND c.relname = ANY($2) AND con.contype <> 'n'
  """

  @triggers_sql """
  SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid)
  FROM pg_trigger t
  JOIN pg_class c ON c.oid = t.tgrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = $1 AND c.relname = ANY($2) AND NOT t.tgisinternal
  """

  @labels %{columns: "column", indexes: "index", constraints: "constraint", triggers: "trigger"}

  @tables_sql """
  SELECT c.relname FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = $1 AND c.relkind IN ('r', 'p')
  """

  @doc """
  Builds `migrations`' tables both ways in a scratch schema and compares them.
  See the moduledoc.
  """
  @spec check(Ecto.Repo.t(), module(), keyword()) :: :ok | {:error, String.t()}
  def check(repo, migrations, opts \\ []) do
    Code.ensure_loaded!(migrations)
    schema = Keyword.get_lazy(opts, :schema, &scratch_schema/0)
    tables = Keyword.get_lazy(opts, :tables, fn -> owned_tables(migrations) end)

    with_auto_sandbox(repo, fn ->
      try do
        compare(repo, migrations, schema, tables)
      after
        unless opts[:keep_schema], do: query!(repo, ~s(DROP SCHEMA IF EXISTS "#{schema}" CASCADE))
      end
    end)
  end

  @doc """
  Builds core's chain, then the module's chain alone, in `schema`, and leaves
  it there. Returns `{:ok, tables}` with the module's table names, or
  `{:error, message}` when a chain fails.

  This is the build `check/3` compares, without the comparison: the input for
  generating the module's `ExpectedSchema` manifest
  (`dev_docs/squash/generate_module_manifest.exs`) and for checking a committed
  one with `PhoenixKit.Migrations.Repair`. The caller drops the schema.

  Takes the `:tables` option like `check/3`.
  """
  @spec build_alone(Ecto.Repo.t(), module(), String.t(), keyword()) ::
          {:ok, [String.t()]} | {:error, String.t()}
  def build_alone(repo, migrations, schema, opts \\ []) do
    Code.ensure_loaded!(migrations)
    tables = Keyword.get_lazy(opts, :tables, fn -> owned_tables(migrations) end)

    with_auto_sandbox(repo, fn ->
      query!(repo, ~s(DROP SCHEMA IF EXISTS "#{schema}" CASCADE))
      query!(repo, ~s(CREATE SCHEMA "#{schema}"))
      quietly(fn -> PhoenixKit.Migration.ensure_current(repo, prefix: schema, log: false) end)
      core_built = table_names(repo, schema)

      with :ok <- run_chain(repo, migrations, schema, "on top of core's tables") do
        created_by_chain = table_names(repo, schema) -- core_built
        tables = Enum.uniq(tables ++ created_by_chain ++ version_table(migrations))
        drop = Enum.map_join(tables, ", ", &~s("#{schema}"."#{&1}"))
        query!(repo, "DROP TABLE IF EXISTS #{drop} CASCADE")

        with :ok <- run_chain(repo, migrations, schema, "alone"), do: {:ok, tables}
      end
    end)
  end

  defp compare(repo, migrations, schema, tables) do
    query!(repo, ~s(DROP SCHEMA IF EXISTS "#{schema}" CASCADE))
    query!(repo, ~s(CREATE SCHEMA "#{schema}"))
    quietly(fn -> PhoenixKit.Migration.ensure_current(repo, prefix: schema, log: false) end)
    core_built = table_names(repo, schema)

    with :ok <- run_chain(repo, migrations, schema, "on top of core's tables") do
      created_by_chain = table_names(repo, schema) -- core_built
      tables = Enum.uniq(tables ++ created_by_chain ++ version_table(migrations))
      compare_alone(repo, migrations, schema, tables, snapshot(repo, schema, tables))
    end
  end

  defp compare_alone(repo, migrations, schema, tables, today) do
    drop = Enum.map_join(tables, ", ", &~s("#{schema}"."#{&1}"))
    query!(repo, "DROP TABLE IF EXISTS #{drop} CASCADE")

    with :ok <- run_chain(repo, migrations, schema, "alone") do
      alone = snapshot(repo, schema, tables)
      tables |> Enum.flat_map(&table_diff(&1, today[&1], alone[&1])) |> report(migrations)
    end
  end

  defp report([], _migrations), do: :ok

  defp report(lines, migrations) do
    {:error,
     "#{inspect(migrations)} does not build the same tables without core " <>
       "(today = core's chain, then the module's; alone = the module's chain only):\n" <>
       Enum.map_join(lines, "\n", &("  " <> &1))}
  end

  defp owned_tables(migrations) do
    case Application.get_application(migrations) do
      nil -> []
      app -> ModuleOwnedTables.tables_for(app)
    end
  end

  defp version_table(migrations) do
    if function_exported?(migrations, :version_table, 0),
      do: [migrations.version_table()],
      else: []
  end

  # Runs the module's chain the way the migration `mix phoenix_kit.update`
  # writes into a host does, under a unique version so Ecto never skips it.
  # A chain that raises is a finding, not a crash of the check.
  defp run_chain(repo, migrations, schema, run) do
    migrate(repo, migrations, schema)
    :ok
  rescue
    error -> chain_failed(migrations, run, Exception.message(error))
  catch
    :exit, reason -> chain_failed(migrations, run, Exception.format_exit(reason))
  end

  defp chain_failed(migrations, run, message) do
    {:error,
     "#{inspect(migrations)}'s chain fails when run #{run}:\n  " <>
       (message |> String.split("\n") |> Enum.take(12) |> Enum.join("\n  "))}
  end

  defp migrate(repo, migrations, schema) do
    name = Module.concat(__MODULE__, "Run#{System.unique_integer([:positive])}")

    contents =
      quote do
        use Ecto.Migration

        def up do
          unquote(migrations).up(
            prefix: unquote(schema),
            version: unquote(migrations).current_version()
          )
        end

        def down, do: :ok
      end

    {:module, ^name, _binary, _} = Module.create(name, contents, Macro.Env.location(__ENV__))

    try do
      quietly(fn ->
        Ecto.Migrator.up(repo, System.os_time(:microsecond), name, prefix: schema, log: false)
      end)
    after
      :code.purge(name)
      :code.delete(name)
    end
  end

  defp snapshot(repo, schema, tables) do
    present = repo |> rows(@tables_sql, [schema]) |> Enum.map(&hd/1) |> MapSet.new()

    columns =
      for [t, name, type, not_null, default, identity, generated] <-
            rows(repo, @columns_sql, [schema, tables]),
          do: {t, name, column(type, not_null, default, identity, generated)}

    kinds = %{
      columns: columns,
      indexes:
        for([t, name, def] <- rows(repo, @indexes_sql, [schema, tables]), do: {t, name, def}),
      constraints:
        for([t, name, def] <- rows(repo, @constraints_sql, [schema, tables]), do: {t, name, def}),
      triggers:
        for([t, name, def] <- rows(repo, @triggers_sql, [schema, tables]), do: {t, name, def})
    }

    Map.new(tables, fn table ->
      if MapSet.member?(present, table) do
        {table,
         Map.new(kinds, fn {kind, entries} ->
           {kind,
            for({^table, name, desc} <- entries, into: %{}, do: {name, unqualify(desc, schema)})}
         end)}
      else
        {table, :missing}
      end
    end)
  end

  defp column(type, not_null, default, identity, generated) do
    [
      type,
      not_null && "NOT NULL",
      default && !set?(generated) && "DEFAULT #{default}",
      set?(identity) && "IDENTITY #{identity}",
      set?(generated) && "GENERATED #{default}"
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.join(" ")
  end

  # `attidentity` / `attgenerated` are Postgres "char": unset reads as "" or a zero byte.
  defp set?(flag), do: flag not in [nil, "", <<0>>]

  defp table_diff(_table, :missing, :missing), do: []

  defp table_diff(table, :missing, _alone),
    do: ["#{table}: missing from today's install but created by the module's chain alone"]

  defp table_diff(table, _today, :missing),
    do: ["#{table}: the module's chain does not create it"]

  defp table_diff(table, today, alone) do
    for kind <- [:columns, :indexes, :constraints, :triggers],
        line <- entries_diff(table, kind, today[kind], alone[kind]),
        do: line
  end

  defp entries_diff(table, kind, today, alone) do
    label = Map.fetch!(@labels, kind)
    names = (Map.keys(today) ++ Map.keys(alone)) |> Enum.uniq() |> Enum.sort()

    Enum.flat_map(names, fn name ->
      case {Map.get(today, name), Map.get(alone, name)} do
        {same, same} -> []
        {desc, nil} -> ["#{table}: #{label} #{name} (#{desc}) — today only"]
        {nil, desc} -> ["#{table}: #{label} #{name} (#{desc}) — module's chain alone only"]
        {a, b} -> ["#{table}: #{label} #{name} — today: #{a}; alone: #{b}"]
      end
    end)
  end

  # Without the scratch schema's name, and in the canonical form repair's
  # differ compares, so two deparses of one expression are equal.
  defp unqualify(text, schema) do
    text
    |> String.replace(~s("#{schema}".), "")
    |> String.replace("#{schema}.", "")
    |> Differ.canonical_expression()
  end

  defp table_names(repo, schema), do: repo |> rows(@tables_sql, [schema]) |> Enum.map(&hd/1)

  defp rows(repo, sql, params), do: repo.query!(sql, params, log: false).rows

  defp query!(repo, sql), do: repo.query!(sql, [], log: false)

  # Unique across runs sharing a database, and within core's 20-byte prefix
  # cap. Postgres folds unquoted names to lower case; base 36 digits are upper.
  defp scratch_schema do
    n = System.os_time(:microsecond) * 1000 + rem(System.unique_integer([:positive]), 1000)
    "pkcc_" <> (n |> Integer.to_string(36) |> String.downcase() |> String.slice(-12, 12))
  end

  # Ecto.Migrator checks connections out on its own processes, which a
  # sandboxed repo in :manual mode refuses.
  defp with_auto_sandbox(repo, fun) do
    if repo.config()[:pool] == Sandbox do
      Sandbox.mode(repo, :auto)

      try do
        fun.()
      after
        Sandbox.mode(repo, :manual)
      end
    else
      fun.()
    end
  end

  # The migration runners print progress unconditionally.
  defp quietly(fun) do
    {:ok, device} = StringIO.open("")
    leader = Process.group_leader()
    Process.group_leader(self(), device)

    try do
      fun.()
    after
      Process.group_leader(self(), leader)
      StringIO.close(device)
    end
  end
end
