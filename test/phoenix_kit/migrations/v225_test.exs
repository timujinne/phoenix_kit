defmodule PhoenixKit.Migrations.Postgres.V225Test do
  @moduledoc """
  V225's `phoenix_kit_files.short_code`, run as the real SQL: the column and its index, the
  backfill (every existing file gets one, none repeat), a re-run and a round trip, and that
  the manifest (`ExpectedSchema`) declares exactly what the chain builds.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.ExpectedSchema
  alias PhoenixKit.Migrations.Postgres.V225
  alias PhoenixKit.Migrations.Repair.Differ
  alias PhoenixKit.Migrations.Repair.Probe
  alias PhoenixKit.Test.Repo

  defp run(statements), do: Enum.each(statements, &Repo.query!/1)
  defp query(sql, params \\ []), do: Repo.query!(sql, params).rows

  defp marker do
    [[marker]] = query("SELECT obj_description('public.phoenix_kit'::regclass)")
    marker
  end

  # A file row with only what the table requires; `short_code` left to the migration.
  defp insert_file!(n) do
    [[uuid]] =
      query(
        """
        INSERT INTO phoenix_kit_files
          (original_file_name, file_name, file_path, mime_type, file_type, ext, file_checksum,
           user_file_checksum, size, status, inserted_at, updated_at)
        VALUES ($1, $1, $1, 'image/png', 'image', 'png', $2, $2, 1, 'active', now(), now())
        RETURNING uuid
        """,
        ["v225-#{n}.png", Ecto.UUID.generate()]
      )

    uuid
  end

  defp code_of(uuid),
    do: query("SELECT short_code FROM phoenix_kit_files WHERE uuid = $1", [uuid])

  describe "files.short_code" do
    test "the chain is at 225 or later, with a nullable varchar(12) and no default" do
      assert String.to_integer(marker()) >= 225

      assert [["character varying", 12, nil, "YES"]] =
               query("""
               SELECT data_type, character_maximum_length, column_default, is_nullable
               FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'phoenix_kit_files'
                 AND column_name = 'short_code'
               """)
    end

    test "the index is unique and partial" do
      assert [[def]] =
               query("""
               SELECT indexdef FROM pg_indexes
               WHERE schemaname = 'public' AND indexname = 'phoenix_kit_files_short_code_index'
               """)

      assert def =~ "CREATE UNIQUE INDEX"
      assert def =~ "short_code IS NOT NULL"
    end
  end

  describe "the migration" do
    test "gives every existing file an 8-character base58 code, and no two alike" do
      uuids = for n <- 1..40, do: insert_file!(n)

      run(V225.down_statements("public"))
      assert marker() == "224"
      run(V225.up_statements("public"))

      codes = for uuid <- uuids, do: code_of(uuid) |> hd() |> hd()
      assert Enum.all?(codes, &(is_binary(&1) and &1 =~ ~r/\A[1-9A-HJ-NP-Za-km-z]{8}\z/))
      assert codes |> Enum.uniq() |> length() == length(codes)

      assert [[0]] = query("SELECT count(*) FROM phoenix_kit_files WHERE short_code IS NULL")

      assert [[0]] =
               query("""
               SELECT count(*) FROM (SELECT short_code FROM phoenix_kit_files
                 GROUP BY 1 HAVING count(*) > 1) d
               """)
    end

    test "a code that two files drew is redrawn until none repeat" do
      [a, b] = for n <- 1..2, do: insert_file!(100 + n)
      run(V225.down_statements("public"))
      run(V225.up_statements("public"))

      query("UPDATE phoenix_kit_files SET short_code = 'sameSame' WHERE uuid = $1", [a])
      query("DROP INDEX phoenix_kit_files_short_code_index")
      query("UPDATE phoenix_kit_files SET short_code = 'sameSame' WHERE uuid = $1", [b])

      run(V225.up_statements("public"))

      refute hd(hd(code_of(a))) == hd(hd(code_of(b)))
    end

    test "running it again changes no code" do
      uuid = insert_file!(200)
      run(V225.down_statements("public"))
      run(V225.up_statements("public"))
      before = code_of(uuid)

      run(V225.up_statements("public"))

      assert code_of(uuid) == before
      assert String.to_integer(marker()) >= 225
    end

    test "rolls back and forward again" do
      run(V225.down_statements("public"))

      assert [] =
               query("""
               SELECT 1 FROM information_schema.columns
               WHERE table_name = 'phoenix_kit_files' AND column_name = 'short_code'
               """)

      assert marker() == "224"
      run(V225.up_statements("public"))
      assert marker() == "225"
    end
  end

  describe "the manifest" do
    defp declared_by_v225 do
      for %{since: 225} = object <- ExpectedSchema.objects("public"), do: object
    end

    defp newest_shape(%{revisions: revisions}) do
      {_version, shape} = Enum.max_by(revisions, fn {version, _} -> version end)
      shape
    end

    test "declares the column and its index" do
      assert [
               %{id: "column:phoenix_kit_files.short_code", class: :column},
               %{id: "index:phoenix_kit_files_short_code_index", class: :index}
             ] = declared_by_v225()
    end

    test "what it declares matches what the chain built" do
      snapshot = Probe.snapshot(Repo, "public")

      problems =
        for object <- declared_by_v225(),
            problem = problem(object, Probe.lookup(snapshot, object.check)),
            do: {object.id, problem}

      assert problems == []
    end

    defp problem(_object, nil), do: :missing

    defp problem(object, observed) do
      case Differ.compare(object.class, newest_shape(object), observed) do
        :match ->
          nil

        {:mismatch, _} = mismatch ->
          if Differ.deparse_text_only?(mismatch), do: nil, else: mismatch
      end
    end
  end
end
