defmodule PhoenixKit.Migrations.ModuleOwnedTablesTest do
  @moduledoc """
  Holds `PhoenixKit.Migrations.ModuleOwnedTables` to core's chain: every table
  the chain creates is classified exactly once, and no core version after the
  last allowed one names a module's table in its code.

  The scan reads each version's parsed source, so a table named in a comment,
  a `@moduledoc` or a `@doc` does not count; a name in any string, sigil,
  interpolated SQL fragment or atom does.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Migrations.ExpectedSchema
  alias PhoenixKit.Migrations.ModuleOwnedTables

  @versions_dir Path.expand("../../../lib/phoenix_kit/migrations/postgres", __DIR__)
  @plan "dev_docs/plans/2026-10-25-module-table-ownership.md"

  describe "classification" do
    test "every table core's chain creates is core's or one module's, never both" do
      created = manifest_tables()
      core = MapSet.new(ModuleOwnedTables.core_tables())
      modules = MapSet.new(ModuleOwnedTables.module_tables())

      both = MapSet.intersection(core, modules)

      assert MapSet.size(both) == 0,
             "listed as core's and a module's: #{inspect(Enum.sort(both))}"

      unclassified = created |> MapSet.difference(core) |> MapSet.difference(modules)

      assert MapSet.size(unclassified) == 0, """
      core's chain creates tables nobody is listed as owning: #{inspect(Enum.sort(unclassified))}
      A table of core's own goes into `ModuleOwnedTables`' @core_tables. A module's
      table belongs in that module's own migration chain, not core's (#{@plan}).
      """

      unknown = core |> MapSet.union(modules) |> MapSet.difference(created)

      assert MapSet.size(unknown) == 0,
             "listed, but core's chain does not create them: #{inspect(Enum.sort(unknown))}"
    end

    test "no table is listed twice, under one owner or two" do
      tables = Enum.flat_map(ModuleOwnedTables.owners(), &elem(&1, 1))
      assert tables -- Enum.uniq(tables) == []
      assert ModuleOwnedTables.core_tables() -- Enum.uniq(ModuleOwnedTables.core_tables()) == []
    end

    test "owner/1 and tables_for/1 answer from the lists" do
      assert ModuleOwnedTables.owner("phoenix_kit_users") == :core
      assert ModuleOwnedTables.owner("phoenix_kit_comments") == :phoenix_kit_comments
      assert ModuleOwnedTables.owner("phoenix_kit_post_comments") == :phoenix_kit_posts
      assert ModuleOwnedTables.owner("phoenix_kit_no_such_table") == nil

      assert ModuleOwnedTables.tables_for(:phoenix_kit_sync) ==
               ~w(phoenix_kit_sync_connections phoenix_kit_sync_transfers)

      assert ModuleOwnedTables.tables_for(:phoenix_kit_no_such_app) == []
    end
  end

  describe "the manifest" do
    test "lists core's tables only: no object of a module's table remains" do
      module_tables = MapSet.new(ModuleOwnedTables.module_tables())
      objects = ExpectedSchema.objects("public")

      table_of = fn
        %{class: :table, check: {:catalog, %{name: name}}} -> name
        %{class: :seed, id: id} -> id |> String.split(":") |> Enum.at(1)
        %{check: {:catalog, %{table: table}}} -> table
        _ -> nil
      end

      offenders = for o <- objects, MapSet.member?(module_tables, table_of.(o)), do: o.id
      assert offenders == []

      sequences = for %{class: :sequence, check: {:catalog, %{name: n}}} <- objects, do: n

      assert Enum.filter(sequences, fn n ->
               Enum.any?(module_tables, &String.starts_with?(n, &1 <> "_"))
             end) == []

      for %{assert: sql} <- ExpectedSchema.data_invariants("public"),
          [name] <- Regex.scan(~r/phoenix_kit_[a-z0-9_]+/, sql) do
        refute MapSet.member?(module_tables, name), "an invariant still names #{name}"
      end
    end

    test "still lists every table of core's own" do
      listed =
        "public"
        |> ExpectedSchema.objects()
        |> Enum.flat_map(fn
          %{class: :table, check: {:catalog, %{name: name}}} -> [name]
          _ -> []
        end)

      assert Enum.sort(listed) == Enum.sort(ModuleOwnedTables.core_tables())
    end
  end

  describe "core versions after the last one allowed to touch a module's table" do
    test "name no module-owned table" do
      cutoff = ModuleOwnedTables.last_core_version_touching_module_tables()

      offenders =
        for {version, path} <- version_files(),
            version > cutoff,
            table <- module_tables_named_in(File.read!(path)),
            do: "V#{version} names #{table} (#{ModuleOwnedTables.owner(table)})"

      assert offenders == [], """
      #{Enum.join(offenders, "\n")}

      Since V#{cutoff}, core's migrations never create, change or drop a module's
      table. Put the change in the owning module's own migration chain (#{@plan}).
      """
    end

    test "the scan finds a version that does name one: V223 changes phoenix_kit_ai_requests" do
      {223, path} = Enum.find(version_files(), &match?({223, _}, &1))
      assert "phoenix_kit_ai_requests" in module_tables_named_in(File.read!(path))
    end

    test "the scan counts code and skips comments and docs" do
      source = ~S'''
      defmodule V999 do
        @moduledoc "Leaves phoenix_kit_comments alone."
        @doc "Nor phoenix_kit_staff_people."
        # phoenix_kit_referral_codes in a comment
        def up(%{prefix: p}) do
          execute("ALTER TABLE #{p}phoenix_kit_users ADD COLUMN x int")
          execute("CREATE INDEX phoenix_kit_comments_x_idx ON #{p}phoenix_kit_users (x)")
          execute(~s(ALTER TABLE "#{p}".phoenix_kit_sync_connections ADD COLUMN y int))
          alter table(:phoenix_kit_user_follows), do: add(:z, :integer)
        end
      end
      '''

      assert Enum.sort(module_tables_named_in(source)) ==
               ~w(phoenix_kit_sync_connections phoenix_kit_user_follows)
    end
  end

  defp manifest_tables, do: ExpectedSchema.created_table_names()

  defp version_files do
    @versions_dir
    |> Path.join("v*.ex")
    |> Path.wildcard()
    |> Enum.map(fn path ->
      {path |> Path.basename(".ex") |> String.trim_leading("v") |> String.to_integer(), path}
    end)
  end

  defp module_tables_named_in(source) do
    module_tables = MapSet.new(ModuleOwnedTables.module_tables())

    source
    |> Code.string_to_quoted!()
    |> code_literals()
    |> Enum.flat_map(&Regex.scan(~r/\bphoenix_kit_[a-z0-9_]+/, &1))
    |> List.flatten()
    |> Enum.filter(&MapSet.member?(module_tables, &1))
    |> Enum.uniq()
  end

  # Every string and atom in the code, leaving out the text of @moduledoc,
  # @doc and @typedoc (comments never reach the AST at all).
  defp code_literals(ast) do
    {_ast, literals} =
      Macro.prewalk(ast, [], fn
        {:@, _, [{doc, _, _}]}, acc when doc in [:moduledoc, :doc, :typedoc] -> {nil, acc}
        text, acc when is_binary(text) -> {text, [text | acc]}
        atom, acc when is_atom(atom) -> {atom, [Atom.to_string(atom) | acc]}
        node, acc -> {node, acc}
      end)

    literals
  end
end
