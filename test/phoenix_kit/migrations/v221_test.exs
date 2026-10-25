defmodule PhoenixKit.Migrations.Postgres.V221Test do
  @moduledoc """
  V221's `phoenix_kit_users.country`, run as the real SQL: the column and its shape, the
  schema field, a re-run and a round trip, and that the manifest (`ExpectedSchema`)
  declares exactly what the chain builds.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.Fixtures, only: [user_fixture: 0]

  alias PhoenixKit.Migrations.ExpectedSchema
  alias PhoenixKit.Migrations.Postgres.V221
  alias PhoenixKit.Migrations.Repair.Differ
  alias PhoenixKit.Migrations.Repair.Probe
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth.User

  defp run(statements), do: Enum.each(statements, &Repo.query!/1)
  defp query(sql, params \\ []), do: Repo.query!(sql, params).rows

  defp marker do
    [[marker]] = query("SELECT obj_description('public.phoenix_kit'::regclass)")
    marker
  end

  describe "users.country" do
    test "the chain is at 221 or later, with a nullable varchar(2) and no default" do
      assert String.to_integer(marker()) >= 221

      assert [["character varying", 2, nil, "YES"]] =
               query("""
               SELECT data_type, character_maximum_length, column_default, is_nullable
               FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'phoenix_kit_users'
                 AND column_name = 'country'
               """)
    end

    test "a new user has no country, and the schema stores one" do
      user = user_fixture()
      assert %User{country: nil} = Repo.get!(User, user.uuid)

      {:ok, user} = user |> Ecto.Changeset.change(country: "DE") |> Repo.update()
      assert %User{country: "DE"} = Repo.get!(User, user.uuid)
    end

    test "nothing is copied from registration_country" do
      user = user_fixture()
      user |> Ecto.Changeset.change(registration_country: "EE") |> Repo.update!()

      # Recreate the pre-V221 shape with an existing GeoIP country, then apply
      # the migration. An empty database cannot prove that no backfill happens.
      run(V221.down_statements("public"))
      run(V221.up_statements("public"))

      assert %User{registration_country: "EE", country: nil} = Repo.get!(User, user.uuid)
    end
  end

  describe "the migration" do
    test "running it again changes nothing" do
      user = user_fixture()
      {:ok, user} = user |> Ecto.Changeset.change(country: "EE") |> Repo.update()

      run(V221.up_statements("public"))
      run(V221.up_statements("public"))

      assert %User{country: "EE"} = Repo.get!(User, user.uuid)
      assert String.to_integer(marker()) >= 221
    end

    test "rolls back and forward again" do
      run(V221.down_statements("public"))

      assert [] =
               query("""
               SELECT 1 FROM information_schema.columns
               WHERE table_name = 'phoenix_kit_users' AND column_name = 'country'
               """)

      assert marker() == "220"

      run(V221.up_statements("public"))

      assert [["country"]] =
               query("""
               SELECT column_name FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'phoenix_kit_users'
                 AND column_name = 'country'
               """)

      assert marker() == "221"
    end
  end

  describe "the manifest" do
    defp declared_by_v221 do
      for %{since: 221} = object <- ExpectedSchema.objects("public"), do: object
    end

    defp newest_shape(%{revisions: revisions}) do
      {_version, shape} = Enum.max_by(revisions, fn {version, _} -> version end)
      shape
    end

    test "declares the one column" do
      assert [%{id: "column:phoenix_kit_users.country", class: :column}] = declared_by_v221()
    end

    test "what it declares matches what the chain built" do
      snapshot = Probe.snapshot(Repo, "public")

      problems =
        for object <- declared_by_v221(),
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
