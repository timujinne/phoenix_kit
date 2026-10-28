defmodule PhoenixKit.Integration.ModuleTablesUntouchedTest do
  @moduledoc """
  Core 3.0 never changes a module's table, even one that is already in the
  database when core is installed (a module installed first, a restore, a
  database upgraded from 2.x whose version marker is gone).

  `ModuleOwnedTablesTest` scans the migration sources for module table names,
  which cannot see the indirect paths (V163 repairs every broken `phoenix_kit_*`
  table the catalog reports, V176 validates a shared list of constraints). These
  tests run the chain against module tables that exist beforehand and check what
  happens to them. Same sandbox `:auto` mode as `PrefixMigrationTest`.
  """

  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Migrations.ModuleOwnedTables
  alias PhoenixKit.Migrations.Postgres
  alias PhoenixKit.Migrations.Postgres.V163
  alias PhoenixKit.Migrations.Postgres.V176
  alias PhoenixKit.Migrations.UUIDFKColumns
  alias PhoenixKit.Test.Repo

  @moduletag :integration
  @moduletag timeout: :timer.minutes(5)

  @schema "pk_mod_untouched"

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
    :ok
  end

  describe "a fresh core install over module tables that already exist" do
    test "V163 does not repair (and so cannot delete rows from) a module's table" do
      # Two rows sharing a uuid and no key: exactly what V163's repair would
      # "fix" by deleting one. Analyzed, so its size is known to the repair.
      Repo.query!("CREATE TABLE #{@schema}.phoenix_kit_email_events (uuid text, payload text)")
      uuid = Ecto.UUID.generate()

      for payload <- ["a", "b"] do
        Repo.query!("INSERT INTO #{@schema}.phoenix_kit_email_events VALUES ($1, $2)", [
          uuid,
          payload
        ])
      end

      Repo.query!("ANALYZE #{@schema}.phoenix_kit_email_events")

      ExUnit.CaptureIO.capture_io(fn ->
        assert :ok = PhoenixKit.Migration.ensure_current(Repo, prefix: @schema, log: false)
      end)

      assert %{rows: [[2]]} =
               Repo.query!("SELECT count(*) FROM #{@schema}.phoenix_kit_email_events")

      assert %{rows: [["text"]]} =
               Repo.query!(
                 "SELECT data_type FROM information_schema.columns " <>
                   "WHERE table_schema = $1 AND table_name = 'phoenix_kit_email_events' " <>
                   "AND column_name = 'uuid'",
                 [@schema]
               )
    end
  end

  describe "the shared lists V163 and V176 work from" do
    test "V163 keeps core's tables only" do
      tables = [%{name: "phoenix_kit_users"}, %{name: "phoenix_kit_email_events"}]
      tables = tables ++ [%{name: "phoenix_kit_someone_elses"}]

      assert V163.core_tables_only(tables) == [%{name: "phoenix_kit_users"}]
    end

    test "V176 validates constraints on core's tables only, and the list still has some" do
      constraints = V176.core_fk_constraints()

      assert constraints != []
      assert length(constraints) < length(UUIDFKColumns.fk_constraints())

      for {table, _uuid_fk, _ref_table, _ref_col, _on_delete} <- constraints do
        assert ModuleOwnedTables.owner(to_string(table)) == :core
      end
    end
  end

  describe "the upgrade gate against a real database" do
    test "a database below the minimum that holds module tables is refused, naming the bridge" do
      Repo.query!("CREATE TABLE #{@schema}.phoenix_kit (id int)")
      Repo.query!("COMMENT ON TABLE #{@schema}.phoenix_kit IS '224'")
      Repo.query!("CREATE TABLE #{@schema}.phoenix_kit_comments (uuid uuid, body text)")

      Repo.query!(
        "INSERT INTO #{@schema}.phoenix_kit_comments VALUES (gen_random_uuid(), 'keep')"
      )

      error =
        assert_raise PhoenixKit.Migrations.BelowFloorError, fn ->
          PhoenixKit.Migration.ensure_current(Repo, prefix: @schema, log: false)
        end

      assert error.db_version == 224
      assert error.floor == Postgres.minimum_version()
      assert Exception.message(error) =~ Postgres.bridge_version()

      assert %{rows: [["224"]]} =
               Repo.query!(
                 "SELECT obj_description('#{@schema}.phoenix_kit'::regclass, 'pg_class')"
               )

      assert %{rows: [[1]]} = Repo.query!("SELECT count(*) FROM #{@schema}.phoenix_kit_comments")
    end

    test "a database at the minimum is not refused, and its module tables are left alone" do
      Repo.query!("CREATE TABLE #{@schema}.phoenix_kit (id int)")
      Repo.query!("COMMENT ON TABLE #{@schema}.phoenix_kit IS '#{Postgres.current_version()}'")
      Repo.query!("CREATE TABLE #{@schema}.phoenix_kit_comments (uuid uuid, body text)")

      Repo.query!(
        "INSERT INTO #{@schema}.phoenix_kit_comments VALUES (gen_random_uuid(), 'keep')"
      )

      assert :ok = PhoenixKit.Migration.ensure_current(Repo, prefix: @schema, log: false)

      assert %{rows: [["keep"]]} = Repo.query!("SELECT body FROM #{@schema}.phoenix_kit_comments")
    end
  end
end
