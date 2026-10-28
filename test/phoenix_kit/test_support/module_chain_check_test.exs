defmodule PhoenixKit.TestSupport.ModuleChainCheckTest do
  @moduledoc """
  `PhoenixKit.TestSupport.ModuleChainCheck` against a fixture chain that builds
  a table of its own (passes). The two cases that needed core to create a
  module's tables (a module with no chain, an incomplete adoption) went in core
  3.0, where core creates none: `check/3` can no longer see a difference, so
  what is left to prove is that a chain builds its tables on core's alone
  (`dev_docs/squash/rehearse_module_chains.exs`).

  Each check builds core's chain into a scratch schema of its own, through
  `Ecto.Migrator` — so `ExUnit.Case`, not a sandboxed `DataCase`.
  """
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.TestSupport.ModuleChainCheck

  @moduletag :integration
  @moduletag timeout: :timer.minutes(3)

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
end
