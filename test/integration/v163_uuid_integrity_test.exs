defmodule PhoenixKit.Integration.V163UUIDIntegrityTest do
  @moduledoc """
  V163 repairs a state that no fresh install produces, so every test here has to
  MANUFACTURE the damage first. That is the point: the reported database was
  reached by an upgrade path that no longer exists in the tree, and the only way
  to prove the repair works is to recreate the shape it left behind —
  `character varying(255)` uuid, nullable, no default, no primary key.

  Each test builds its own scratch table rather than damaging a real PhoenixKit
  one, so a failure cannot corrupt the suite's schema for whatever runs next.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.UUIDIntegrity

  @prefix "public"

  setup do
    # `phoenix_kit_` prefix so discovery finds it; `zz_` so it sorts last and
    # cannot be confused with a real table.
    table = "phoenix_kit_zz_v163_#{System.unique_integer([:positive])}"
    on_exit(fn -> drop(table) end)
    {:ok, table: table}
  end

  defp repo, do: PhoenixKit.RepoHelper.repo()
  defp sql!(q, p \\ []), do: Repo.query!(q, p)
  defp drop(t), do: Repo.query("DROP TABLE IF EXISTS #{t}", [])

  # The reported shape, exactly.
  defp create_broken(table) do
    sql!("""
    CREATE TABLE #{table} (
      uuid character varying(255),
      payload text
    )
    """)
  end

  defp create_healthy(table) do
    sql!("""
    CREATE TABLE #{table} (
      uuid uuid PRIMARY KEY DEFAULT public.uuid_generate_v7(),
      payload text
    )
    """)
  end

  defp repair!(table) do
    tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))
    refute is_nil(tbl), "#{table} was not detected as broken"

    UUIDIntegrity.qualify(@prefix, table)
    |> UUIDIntegrity.repair_statements(@prefix, tbl)
    |> Enum.each(&sql!/1)
  end

  defp column(table) do
    %{rows: [[type, nullable, default]]} =
      sql!(
        """
        SELECT data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2 AND column_name = 'uuid'
        """,
        [@prefix, table]
      )

    %{type: type, nullable: nullable == "YES", default: default}
  end

  defp has_pk?(table) do
    %{rows: [[n]]} =
      sql!(
        """
        SELECT count(*) FROM pg_constraint pc
        JOIN pg_class pcl ON pcl.oid = pc.conrelid
        JOIN pg_namespace pn ON pn.oid = pcl.relnamespace
        WHERE pcl.relname = $1 AND pn.nspname = $2 AND pc.contype = 'p'
        """,
        [table, @prefix]
      )

    n > 0
  end

  describe "detection" do
    test "finds the reported shape", %{table: table} do
      create_broken(table)

      found = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))

      assert found.type == "character varying"
      assert found.nullable
      refute found.has_pk
    end

    test "a healthy table is NOT reported", %{table: table} do
      create_healthy(table)
      refute Enum.any?(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))
    end

    test "a correctly typed but PK-less table is still reported", %{table: table} do
      # The case the doctor's type check could never see: right type, no key.
      sql!("CREATE TABLE #{table} (uuid uuid NOT NULL, payload text)")

      found = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))
      assert found.type == "uuid"
      refute found.has_pk
    end

    test "every real phoenix_kit table in this database is already healthy" do
      # A canary: if the suite's own schema ever regresses into this state, the
      # scratch-table tests above would still pass and hide it.
      real =
        repo()
        |> UUIDIntegrity.broken_tables(@prefix)
        |> Enum.reject(&String.starts_with?(&1.name, "phoenix_kit_zz_"))

      assert real == [], "tables in a broken uuid state: #{inspect(Enum.map(real, & &1.name))}"
    end
  end

  describe "repair" do
    test "converts type, sets default, backfills, and adds the primary key", %{table: table} do
      create_broken(table)
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'kept')", [Ecto.UUID.generate()])
      sql!("INSERT INTO #{table} (uuid, payload) VALUES (NULL, 'null-uuid')")

      repair!(table)

      col = column(table)
      assert col.type == "uuid"
      refute col.nullable
      assert col.default =~ "uuid_generate_v7"
      assert has_pk?(table)

      # No row was lost and no uuid is null.
      %{rows: [[count]]} = sql!("SELECT count(*) FROM #{table}")
      assert count == 2
      %{rows: [[nulls]]} = sql!("SELECT count(*) FROM #{table} WHERE uuid IS NULL")
      assert nulls == 0
    end

    test "preserves the uuid values that were already there", %{table: table} do
      create_broken(table)
      existing = Ecto.UUID.generate()
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'keepme')", [existing])

      repair!(table)

      %{rows: [[stored]]} = sql!("SELECT uuid::text FROM #{table} WHERE payload = 'keepme'")
      assert stored == existing
    end

    test "de-duplicates before adding the key, keeping one row per uuid", %{table: table} do
      create_broken(table)
      dup = Ecto.UUID.generate()
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'a')", [dup])
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'b')", [dup])

      repair!(table)

      assert has_pk?(table)
      %{rows: [[count]]} = sql!("SELECT count(*) FROM #{table} WHERE uuid::text = $1", [dup])
      assert count == 1
    end

    test "is idempotent — a second pass is a no-op", %{table: table} do
      create_broken(table)
      sql!("INSERT INTO #{table} (uuid, payload) VALUES (NULL, 'x')")
      repair!(table)

      %{rows: [[before_count]]} = sql!("SELECT count(*) FROM #{table}")

      # After repair the table is no longer detected, which IS the idempotency:
      # nothing runs a second time.
      refute Enum.any?(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))

      %{rows: [[after_count]]} = sql!("SELECT count(*) FROM #{table}")
      assert before_count == after_count
      assert has_pk?(table)
    end

    test "a table that only lacks a key gets one without a rewrite", %{table: table} do
      sql!("CREATE TABLE #{table} (uuid uuid NOT NULL, payload text)")

      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1::text::uuid, 'x')", [
        Ecto.UUID.generate()
      ])

      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))
      refute UUIDIntegrity.rewrite_needed?(tbl), "a uuid-typed column must not be rewritten"

      repair!(table)
      assert has_pk?(table)
    end
  end

  describe "castability guard" do
    test "refuses a column holding values that are not UUIDs", %{table: table} do
      create_broken(table)
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ('not-a-uuid', 'bad')")

      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))
      qualified = UUIDIntegrity.qualify(@prefix, table)

      # Must be caught BEFORE any DDL: the cast would abort the surrounding
      # transaction and take every other table's repair down with it.
      refute UUIDIntegrity.castable?(repo(), qualified, tbl)
    end

    test "accepts a column whose values are all valid UUIDs", %{table: table} do
      create_broken(table)
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'ok')", [Ecto.UUID.generate()])

      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))
      assert UUIDIntegrity.castable?(repo(), UUIDIntegrity.qualify(@prefix, table), tbl)
    end

    test "a NULL-only column is castable", %{table: table} do
      create_broken(table)
      sql!("INSERT INTO #{table} (uuid, payload) VALUES (NULL, 'x')")

      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))
      assert UUIDIntegrity.castable?(repo(), UUIDIntegrity.qualify(@prefix, table), tbl)
    end
  end

  describe "identifier quoting" do
    test "an unusual but legal table name produces valid SQL", %{table: _t} do
      # Catalog-derived names are interpolated into DDL. An identifier with a
      # space or a capital must yield valid SQL rather than a syntax error that
      # aborts the whole run.
      odd = "phoenix_kit_zz_odd name_#{System.unique_integer([:positive])}"
      on_exit(fn -> Repo.query(~s|DROP TABLE IF EXISTS "#{odd}"|, []) end)
      sql!(~s|CREATE TABLE "#{odd}" (uuid character varying(255), payload text)|)

      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == odd))
      refute is_nil(tbl), "a quoted-identifier table must still be discovered"

      UUIDIntegrity.qualify(@prefix, odd)
      |> UUIDIntegrity.repair_statements(@prefix, tbl)
      |> Enum.each(&sql!/1)

      assert has_pk?(odd)
    end

    test "quote_ident doubles an embedded quote" do
      assert UUIDIntegrity.quote_ident(~s(a"b)) == ~s("a""b")
    end
  end

  describe "statement ordering" do
    test "the type change precedes the primary key", %{table: table} do
      create_broken(table)
      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))

      stmts = UUIDIntegrity.repair_statements(UUIDIntegrity.qualify(@prefix, table), @prefix, tbl)
      idx = fn frag -> Enum.find_index(stmts, &String.contains?(&1, frag)) end

      # A key built on the varchar would have to be rebuilt after the rewrite.
      assert idx.("TYPE uuid") < idx.("PRIMARY KEY")
      # SET NOT NULL aborts on the very NULLs the backfill exists to remove.
      assert idx.("WHERE uuid IS NULL") < idx.("SET NOT NULL")
      # The key requires NOT NULL to already hold.
      assert idx.("SET NOT NULL") < idx.("PRIMARY KEY")
    end

    test "concurrent_index splits the key into a CONCURRENTLY build plus attach",
         %{table: table} do
      create_broken(table)
      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))

      stmts =
        UUIDIntegrity.repair_statements(UUIDIntegrity.qualify(@prefix, table), @prefix, tbl,
          concurrent_index: true
        )

      assert Enum.any?(stmts, &String.contains?(&1, "CREATE UNIQUE INDEX CONCURRENTLY"))
      assert Enum.any?(stmts, &String.contains?(&1, "ADD PRIMARY KEY USING INDEX"))
      # CONCURRENTLY cannot run in a transaction, so the migration must not emit it.
      plain = UUIDIntegrity.repair_statements(UUIDIntegrity.qualify(@prefix, table), @prefix, tbl)
      refute Enum.any?(plain, &String.contains?(&1, "CONCURRENTLY"))
    end

    test "the concurrent build drops any leftover index first, so a retry works",
         %{table: table} do
      create_broken(table)
      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))

      stmts =
        UUIDIntegrity.repair_statements(UUIDIntegrity.qualify(@prefix, table), @prefix, tbl,
          concurrent_index: true
        )

      idx = fn frag -> Enum.find_index(stmts, &String.contains?(&1, frag)) end

      # An interrupted CONCURRENTLY build leaves an INVALID index. Without the
      # drop, `IF NOT EXISTS` would skip the rebuild and the attach would fail
      # on the invalid index — forever.
      assert idx.("DROP INDEX CONCURRENTLY IF EXISTS") < idx.("CREATE UNIQUE INDEX")
      refute Enum.any?(stmts, &String.contains?(&1, "CREATE UNIQUE INDEX CONCURRENTLY IF NOT"))

      # DROP INDEX is the one place the chain requires a schema-qualified name.
      drop = Enum.at(stmts, idx.("DROP INDEX"))
      assert String.contains?(drop, ~s("#{@prefix}"."#{table}_uuid_pk_idx"))
    end
  end

  describe "duplicate accounting" do
    test "counts the rows the de-duplicating DELETE would remove", %{table: table} do
      create_broken(table)
      dup = Ecto.UUID.generate()
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'a')", [dup])
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'b')", [dup])
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'c')", [Ecto.UUID.generate()])
      sql!("INSERT INTO #{table} (uuid, payload) VALUES (NULL, 'backfilled')")

      # Three rows survive de-duplication (one per uuid) plus the NULL, which
      # gets its own generated uuid — so exactly one row is deleted.
      assert UUIDIntegrity.duplicate_rows(repo(), UUIDIntegrity.qualify(@prefix, table)) == 1
    end

    test "case-differing varchar uuids collide once cast, and are counted", %{table: table} do
      create_broken(table)
      dup = Ecto.UUID.generate()
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'lower')", [dup])
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'upper')", [String.upcase(dup)])

      assert UUIDIntegrity.duplicate_rows(repo(), UUIDIntegrity.qualify(@prefix, table)) == 1
    end

    test "a clean table reports none", %{table: table} do
      create_broken(table)
      sql!("INSERT INTO #{table} (uuid, payload) VALUES ($1, 'x')", [Ecto.UUID.generate()])

      assert UUIDIntegrity.duplicate_rows(repo(), UUIDIntegrity.qualify(@prefix, table)) == 0
    end
  end

  describe "describe/1" do
    test "names every defect it found", %{table: table} do
      create_broken(table)
      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))

      assert UUIDIntegrity.describe(tbl) == "type=character varying, nullable, no primary key"
    end

    test "a keyless but correctly typed column reports only the missing key", %{table: table} do
      sql!("CREATE TABLE #{table} (uuid uuid NOT NULL, payload text)")
      tbl = Enum.find(UUIDIntegrity.broken_tables(repo(), @prefix), &(&1.name == table))

      assert UUIDIntegrity.describe(tbl) == "no primary key"
    end
  end
end
