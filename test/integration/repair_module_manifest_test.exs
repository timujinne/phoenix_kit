defmodule PhoenixKit.Integration.RepairModuleManifestTest do
  @moduledoc """
  `PhoenixKit.Migrations.Repair` checks the tables a module supplies a manifest
  for (`PhoenixKit.Module.expected_schema/0`), after core's own pass.

  Core's manifest is replaced by an empty one so only the module pass has
  anything to say; the module is a two-object fixture with a fake migrations
  module whose recorded version the test sets.
  """

  use ExUnit.Case, async: false
  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Migrations.Repair
  alias PhoenixKit.Migrations.Repair.Report
  alias PhoenixKit.Test.Repo

  @prefix "pk_modman_test"
  @app :fake_module_app

  defmodule EmptyCore do
    @moduledoc false
    def objects(_prefix), do: []
    def data_invariants(_prefix), do: []
    def chain_hash, do: "empty"
  end

  defmodule Migrations do
    @moduledoc false
    def current_version, do: 2

    def migrated_version_runtime(_opts),
      do: Application.get_env(:phoenix_kit, :fake_module_version, 0)
  end

  defmodule Manifest do
    @moduledoc false
    def objects(prefix) do
      [
        %{
          id: "table:pk_fake_things",
          class: :table,
          since: 1,
          revisions: [{1, %{}}],
          presence: :required,
          check: {:catalog, %{kind: :table, name: "pk_fake_things"}},
          create: "CREATE TABLE IF NOT EXISTS #{prefix}.pk_fake_things ()",
          backfill: nil,
          owner: :fake_module_app
        },
        %{
          id: "column:pk_fake_things.label",
          class: :column,
          since: 1,
          revisions: [{1, %{type: "text", not_null: false, default: nil, pos: 1}}],
          presence: :required,
          check: {:catalog, %{kind: :column, table: "pk_fake_things", column: "label"}},
          create: "ALTER TABLE #{prefix}.pk_fake_things ADD COLUMN IF NOT EXISTS label text",
          backfill: nil,
          owner: :fake_module_app
        }
      ]
    end

    def data_invariants(_prefix), do: []
    def chain_hash, do: "fake"
  end

  @modules %{@app => %{manifest: Manifest, migrations: Migrations}}

  setup do
    Sandbox.mode(Repo, :auto)
    Application.put_env(:phoenix_kit, :expected_schema_module, EmptyCore)

    on_exit(fn ->
      try do
        Repo.query("DROP SCHEMA IF EXISTS #{@prefix} CASCADE", [])
      after
        Sandbox.mode(Repo, :manual)
        Application.delete_env(:phoenix_kit, :expected_schema_module)
        Application.delete_env(:phoenix_kit, :fake_module_version)
      end
    end)

    Repo.query("DROP SCHEMA IF EXISTS #{@prefix} CASCADE", [])
    Repo.query!("CREATE SCHEMA #{@prefix}", [])
    Repo.query!("CREATE TABLE #{@prefix}.phoenix_kit (id integer)", [])
    Repo.query!(~s(COMMENT ON TABLE #{@prefix}.phoenix_kit IS '142'), [])
    :ok
  end

  defp at_version(version), do: Application.put_env(:phoenix_kit, :fake_module_version, version)

  defp verify(modules \\ @modules) do
    {:ok, report} = Repair.verify(prefix: @prefix, repo: Repo, module_manifests: modules)
    report
  end

  test "a module at its chain head is checked, and its findings carry the app" do
    at_version(2)

    assert [
             %{kind: :missing, module: @app, object_id: "table:pk_fake_things", message: message},
             %{kind: :missing, module: @app, object_id: "column:pk_fake_things.label"}
           ] = verify() |> Report.findings()

    assert message =~ "fake_module_app: table:pk_fake_things"
  end

  test "repair creates what is missing, then the module verifies clean" do
    at_version(2)

    {:ok, repaired} = Repair.repair(prefix: @prefix, repo: Repo, module_manifests: @modules)
    assert Enum.all?(Report.findings(repaired), &(&1.kind == :repaired and &1.module == @app))

    assert [] = verify() |> Report.findings()
  end

  test "a module that is behind is reported, never checked" do
    at_version(1)

    assert [%{kind: :module_behind, severity: :info, module: @app, message: message}] =
             verify() |> Report.findings()

    assert message =~ "version 1"
    assert message =~ "chain is at 2"
  end

  test "a module that was never migrated is not mentioned" do
    at_version(0)

    assert [] = verify() |> Report.findings()
  end

  test "a module ahead of its code, or whose version cannot be read, is not checked" do
    at_version(3)

    assert [] = verify() |> Report.findings()
  end

  test "no manifests, no module findings" do
    at_version(2)

    assert [] = verify(%{}) |> Report.findings()
  end

  describe "ModuleRegistry.expected_schema_entry/1" do
    defmodule Supplier do
      @moduledoc false
      def expected_schema, do: PhoenixKit.Integration.RepairModuleManifestTest.Manifest
      def migration_module, do: PhoenixKit.Integration.RepairModuleManifestTest.Migrations
    end

    defmodule NoManifest do
      @moduledoc false
      def expected_schema, do: nil
      def migration_module, do: PhoenixKit.Integration.RepairModuleManifestTest.Migrations
    end

    defmodule NoChain do
      @moduledoc false
      def expected_schema, do: PhoenixKit.Integration.RepairModuleManifestTest.Manifest
      def migration_module, do: nil
    end

    defmodule Raises do
      @moduledoc false
      def expected_schema, do: raise("boom")
      def migration_module, do: nil
    end

    test "a manifest with a migrations module is usable" do
      assert {:ok, %{manifest: Manifest, migrations: Migrations}} =
               PhoenixKit.ModuleRegistry.expected_schema_entry(Supplier)
    end

    test "no manifest, no migrations module, a module without the exports, or a raise: left out" do
      for mod <- [NoManifest, NoChain, Raises] do
        assert :error = PhoenixKit.ModuleRegistry.expected_schema_entry(mod)
      end
    end

    test "core itself supplies none" do
      refute Map.has_key?(PhoenixKit.ModuleRegistry.all_expected_schemas(), :phoenix_kit)
    end
  end
end
