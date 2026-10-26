defmodule PhoenixKit.Migrations.Postgres.V224Test do
  @moduledoc """
  V224's `(resource_uuid, inserted_at)` index on `phoenix_kit_activities`, run as
  real SQL; proof that the query shape a per-resource feed uses can reach it; and
  that the manifest (`ExpectedSchema`) declares exactly what the chain builds.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.ExpectedSchema
  alias PhoenixKit.Migrations.Postgres.V224
  alias PhoenixKit.Migrations.Repair.Differ
  alias PhoenixKit.Migrations.Repair.Probe
  alias PhoenixKit.Test.Repo

  @index "phoenix_kit_activities_resource_uuid_inserted_at_index"

  defp run(statements), do: Enum.each(statements, &Repo.query!/1)

  defp present? do
    %{rows: rows} =
      Repo.query!(
        "SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1",
        [@index]
      )

    rows != []
  end

  # Name-based lookup, no `::regclass` cast.
  defp marker do
    %{rows: [[marker]]} =
      Repo.query!("""
      SELECT obj_description(c.oid, 'pg_class')
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relname = 'phoenix_kit' AND n.nspname = 'public'
      """)

    marker
  end

  describe "the migration" do
    test "the chain is at 224 or later and the index is there" do
      assert String.to_integer(marker()) >= 224
      assert present?()
    end

    test "down drops the index, up puts it back, and each stamps its marker" do
      run(V224.down_statements("public."))
      refute present?()
      assert marker() == "223"

      run(V224.up_statements("public."))
      assert present?()
      assert marker() == "224"
    end

    test "up leaves the connection's lock_timeout as it found it" do
      %{rows: [[before]]} = Repo.query!("SHOW lock_timeout")
      run(V224.up_statements("public."))
      assert %{rows: [[^before]]} = Repo.query!("SHOW lock_timeout")
    end

    test "up is re-runnable" do
      run(V224.up_statements("public."))
      run(V224.up_statements("public."))
      assert present?()
    end
  end

  # Whether the feed query reaches the index on a log shaped like a real one:
  # many resources, each with a handful of entries, so the few a page asks for
  # are a sliver of the table. (With a few hundred rows per resource the
  # planner rightly prefers walking `inserted_at` backwards until the LIMIT is
  # met — that is not the case this index is for.) Sequential and bitmap scans
  # are switched off inside the test's transaction (the sandbox rolls it back),
  # and the plan must name the index.
  describe "a per-resource feed reaches the index" do
    defp prepare_planner! do
      Repo.query!("""
      INSERT INTO phoenix_kit_activities (action, module, mode, resource_uuid, inserted_at)
      SELECT
        'thing.updated',
        'projects',
        'manual',
        ('00000000-0000-7000-8000-' || lpad(to_hex(g % 5000), 12, '0'))::uuid,
        now() - (g || ' minutes')::interval
      FROM generate_series(1, 20000) AS g
      """)

      Repo.query!("ANALYZE phoenix_kit_activities")
      Repo.query!("SET LOCAL enable_seqscan = off")
      Repo.query!("SET LOCAL enable_bitmapscan = off")
    end

    test "resource_uuid IN (…) ORDER BY inserted_at DESC LIMIT n" do
      prepare_planner!()

      %{rows: rows} =
        Repo.query!(
          """
          EXPLAIN SELECT uuid FROM phoenix_kit_activities
          WHERE resource_uuid = ANY($1) ORDER BY inserted_at DESC LIMIT 50
          """,
          [Enum.map(1..3, fn _ -> Ecto.UUID.dump!(Ecto.UUID.generate()) end)]
        )

      assert rows |> List.flatten() |> Enum.join("\n") =~ @index
    end
  end

  describe "the manifest" do
    defp declared_by_v224 do
      for %{since: 224} = object <- ExpectedSchema.objects("public"), do: object
    end

    defp newest_shape(%{revisions: revisions}) do
      {_version, shape} = Enum.max_by(revisions, fn {version, _} -> version end)
      shape
    end

    test "declares the one index" do
      assert [%{id: "index:" <> @index, class: :index}] = declared_by_v224()
    end

    test "what it declares matches what the chain built" do
      snapshot = Probe.snapshot(Repo, "public")

      problems =
        for object <- declared_by_v224(),
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
