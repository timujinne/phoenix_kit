defmodule PhoenixKit.TestSupport.ModuleChainCheckTest do
  @moduledoc """
  `PhoenixKit.TestSupport.ModuleChainCheck` against three fixture chains: one
  that builds a table of its own (passes), one that relies on core for its
  tables (the six modules with no chain today), and one whose adoption DDL
  is incomplete (the gap the check exists to surface).

  Each check builds core's chain into a scratch schema of its own, through
  `Ecto.Migrator` — so `ExUnit.Case`, not a sandboxed `DataCase`.
  """
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.TestSupport.ModuleChainCheck

  @moduletag :integration
  @moduletag timeout: :timer.minutes(3)

  @referral_tables ~w(phoenix_kit_referral_codes phoenix_kit_referral_code_usage)

  defmodule OwnTableChain do
    use Ecto.Migration

    def current_version, do: 1

    def up(opts) do
      p = Keyword.fetch!(opts, :prefix)

      execute("""
      CREATE TABLE IF NOT EXISTS "#{p}".phoenix_kit_mcc_fixture_items (
        uuid uuid PRIMARY KEY DEFAULT "#{p}".uuid_generate_v7(),
        user_uuid uuid NOT NULL REFERENCES "#{p}".phoenix_kit_users(uuid) ON DELETE CASCADE,
        name character varying(80) NOT NULL,
        quantity integer NOT NULL DEFAULT 0 CHECK (quantity >= 0),
        inserted_at timestamp(0) without time zone NOT NULL DEFAULT now()
      )
      """)

      execute(
        "CREATE INDEX IF NOT EXISTS phoenix_kit_mcc_fixture_items_name_idx " <>
          "ON \"#{p}\".phoenix_kit_mcc_fixture_items (name)"
      )
    end

    def down(_opts), do: :ok
  end

  defmodule NoChain do
    def current_version, do: 1
    def up(_opts), do: :ok
    def down(_opts), do: :ok
  end

  defmodule IncompleteAdoption do
    use Ecto.Migration

    def current_version, do: 1

    def up(opts) do
      p = Keyword.fetch!(opts, :prefix)

      execute("""
      CREATE TABLE IF NOT EXISTS "#{p}".phoenix_kit_referral_codes (
        uuid uuid PRIMARY KEY DEFAULT "#{p}".uuid_generate_v7(),
        code character varying(255) NOT NULL
      )
      """)
    end

    def down(_opts), do: :ok
  end

  test "a chain that builds its own table passes, and the scratch schema is removed" do
    schema = "pkcc_test_own"

    assert :ok = ModuleChainCheck.check(Repo, OwnTableChain, tables: [], schema: schema)

    assert %{rows: [[false]]} =
             Sandbox.unboxed_run(Repo, fn ->
               Repo.query!(
                 "SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)",
                 [schema]
               )
             end)
  end

  test "a module relying on core for its tables is reported, table by table" do
    assert {:error, report} = ModuleChainCheck.check(Repo, NoChain, tables: @referral_tables)

    assert report =~ "NoChain does not build the same tables without core"
    assert report =~ "phoenix_kit_referral_codes: the module's chain does not create it"
    assert report =~ "phoenix_kit_referral_code_usage: the module's chain does not create it"
  end

  test "adoption DDL that differs from what core builds is reported, column by column" do
    assert {:error, report} =
             ModuleChainCheck.check(Repo, IncompleteAdoption,
               tables: ["phoenix_kit_referral_codes"]
             )

    assert report =~ "phoenix_kit_referral_codes: column max_uses (integer NOT NULL) — today only"
    assert report =~ "phoenix_kit_referral_codes: column created_by_uuid"
    refute report =~ "column code "
    refute report =~ "phoenix_kit_referral_codes: the module's chain does not create it"
  end
end
