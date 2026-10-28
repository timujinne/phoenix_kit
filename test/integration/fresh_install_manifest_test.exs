defmodule PhoenixKit.Integration.FreshInstallManifestTest do
  @moduledoc """
  A database built from nothing by today's chain is what the `ExpectedSchema`
  manifest describes, and holds exactly core's tables
  (`PhoenixKit.Migrations.ModuleOwnedTables.core_tables/0`): since 3.0 no module's
  table is created by core.

  `hand_declared_manifest_test.exs` checks the manifest against the suite's
  own database, which has been migrated one version at a time since it was
  created; a fresh install takes a different path (the V135 baseline, then
  every delta in one run). This builds that path into a scratch schema and
  runs the real `Repair.verify/1` against it, so a fresh install that would
  have `mix phoenix_kit.repair` "fix" something fails here.

  Same sandbox handling as `prefix_migration_test.exs`: `Ecto.Migrator` runs
  on connections of its own, so the sandbox is in `:auto` mode for the test.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Migrations.ModuleOwnedTables
  alias PhoenixKit.Migrations.Postgres
  alias PhoenixKit.Migrations.Repair
  alias PhoenixKit.Migrations.Repair.Report
  alias PhoenixKit.Test.Repo

  @moduletag :integration
  @moduletag timeout: :timer.minutes(5)

  @schema "pk_fresh_install"

  setup do
    Sandbox.mode(Repo, :auto)

    on_exit(fn ->
      try do
        Repo.query!("DROP SCHEMA IF EXISTS #{@schema} CASCADE")
      after
        Sandbox.mode(Repo, :manual)
      end
    end)

    Repo.query!("DROP SCHEMA IF EXISTS #{@schema} CASCADE")
    Repo.query!("CREATE SCHEMA #{@schema}")

    capture_io(fn ->
      assert :ok = PhoenixKit.Migration.ensure_current(Repo, prefix: @schema, log: false)
    end)

    :ok
  end

  test "a fresh install verifies clean against the manifest" do
    %{rows: [[version]]} =
      Repo.query!("SELECT obj_description('#{@schema}.phoenix_kit'::regclass, 'pg_class')")

    assert version == to_string(Postgres.current_version())

    {:ok, report} = Repair.verify(prefix: @schema, repo: Repo)

    offenders =
      report
      |> Report.findings()
      |> Enum.filter(&(&1.severity in [:error, :repairable]))

    assert offenders == [], """
    A fresh install does not match the manifest — `mix phoenix_kit.repair` would \
    try to change it:

    #{Enum.map_join(offenders, "\n", &inspect/1)}
    """

    assert Report.exit_code(report) == 0
  end

  test "a fresh install holds exactly core's tables and none of a module's" do
    %{rows: rows} =
      Repo.query!(
        "SELECT tablename FROM pg_tables WHERE schemaname = $1 AND tablename LIKE 'phoenix_kit%'",
        [@schema]
      )

    built = rows |> List.flatten() |> MapSet.new()
    core = MapSet.new(ModuleOwnedTables.core_tables())
    modules = MapSet.new(ModuleOwnedTables.module_tables())

    assert MapSet.intersection(built, modules) == MapSet.new(),
           "core's chain created a module's table (each module's chain does that)"

    assert MapSet.difference(built, core) == MapSet.new()
    assert MapSet.difference(core, built) == MapSet.new()
  end
end
