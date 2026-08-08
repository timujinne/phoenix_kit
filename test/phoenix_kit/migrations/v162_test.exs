defmodule PhoenixKit.Migrations.Postgres.V162Test do
  @moduledoc """
  Pins V162's schema state: the `payment_option_uuid` FK on
  `phoenix_kit_orders`, its `ON DELETE SET NULL` action, and its index.

  V162.up/down can't be invoked outside an `Ecto.Migrator` runner (they rely
  on `Ecto.Migration.execute/1`, which checks for a runner process) — same
  constraint as V161Test/V152Test/etc. The schema is verified at boot
  instead: `test_helper.exs` runs `ensure_current/2` (now through V162)
  before any test, so the assertions below pin the post-V162 shape.

  The delete action is the part worth pinning. `ON DELETE SET NULL` is a
  deliberate choice over the `RESTRICT` a plain `references/2` would give:
  deleting a payment option is an ordinary operator action, and it must
  neither be blocked by historical orders nor destroy them. A future
  refactor that reaches for Ecto's default would silently make deleting a
  used payment option impossible.
  """

  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Test.Repo

  # The FK's referenced table/column and its ON DELETE action, by referencing
  # column. Name-based `pg_class` + `pg_namespace` join rather than a
  # `'table'::regclass` cast, per the chain's prefix-safety rules.
  defp foreign_key(table, column) do
    %{rows: rows} =
      Repo.query!(
        """
        SELECT c.conname, ref.relname, refatt.attname, c.confdeltype
        FROM pg_constraint c
        JOIN pg_class src ON src.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = src.relnamespace
        JOIN pg_class ref ON ref.oid = c.confrelid
        JOIN pg_attribute att
          ON att.attrelid = c.conrelid AND att.attnum = c.conkey[1]
        JOIN pg_attribute refatt
          ON refatt.attrelid = c.confrelid AND refatt.attnum = c.confkey[1]
        WHERE c.contype = 'f'
          AND n.nspname = current_schema()
          AND src.relname = $1
          AND att.attname = $2
        """,
        [table, column]
      )

    case rows do
      [[name, ref_table, ref_column, delete_action]] ->
        %{name: name, references: {ref_table, ref_column}, on_delete: delete_action}

      [] ->
        nil
    end
  end

  defp column(table, column) do
    %{rows: rows} =
      Repo.query!(
        """
        SELECT udt_name, is_nullable
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = $1 AND column_name = $2
        """,
        [table, column]
      )

    case rows do
      [[udt_name, nullable]] -> %{type: udt_name, nullable: nullable}
      [] -> nil
    end
  end

  describe "phoenix_kit_orders.payment_option_uuid" do
    test "exists as a nullable uuid column" do
      assert %{type: "uuid", nullable: "YES"} =
               column("phoenix_kit_orders", "payment_option_uuid")
    end

    test "carries a foreign key to phoenix_kit_payment_options(uuid)" do
      assert %{references: {"phoenix_kit_payment_options", "uuid"}} =
               foreign_key("phoenix_kit_orders", "payment_option_uuid")
    end

    # 'n' = SET NULL, 'a' = NO ACTION, 'r' = RESTRICT, 'c' = CASCADE.
    test "deletes the option by nulling the link, not by restricting or cascading" do
      assert %{on_delete: "n"} = foreign_key("phoenix_kit_orders", "payment_option_uuid")
    end

    test "is indexed — the payment-options admin asks 'orders using this option'" do
      %{rows: rows} =
        Repo.query!(
          """
          SELECT indexname FROM pg_indexes
          WHERE schemaname = current_schema()
            AND tablename = 'phoenix_kit_orders'
            AND indexdef LIKE '%payment_option_uuid%'
          """,
          []
        )

      assert rows != [], "no index covers payment_option_uuid"
    end
  end

  describe "version marker" do
    test "phoenix_kit table comment is at or past V162" do
      %{rows: [[comment]]} =
        Repo.query!("SELECT obj_description('phoenix_kit'::regclass, 'pg_class')")

      # >= rather than ==: pinning the exact latest version breaks this test
      # every time a newer migration ships. What V162 owns is "the chain
      # reached at least me".
      assert String.to_integer(comment) >= 162
    end
  end
end
