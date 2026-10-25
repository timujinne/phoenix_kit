defmodule PhoenixKit.Migrations.Postgres.V222Test do
  @moduledoc """
  V222's binding of a confirmation to a person's live session, run as the real SQL: the
  `actor_user_uuid` column, its foreign key to the users (deleted with the user), the
  actor CHECK that now accepts a user, the `(actor_user_uuid, status)` index, a re-run and
  a round trip of the migration, and that the manifest (`ExpectedSchema`) declares exactly
  what the chain builds.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.Fixtures, only: [user_fixture: 0]

  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Migrations.ExpectedSchema
  alias PhoenixKit.Migrations.Postgres.V221
  alias PhoenixKit.Migrations.Postgres.V222
  alias PhoenixKit.Migrations.Repair.Differ
  alias PhoenixKit.Migrations.Repair.Probe

  @conf "phoenix_kit_api_confirmations"

  setup do
    KeyTestSupport.start_key_cache!()
    {user, _role} = KeyTestSupport.user_with(["settings"])

    {key, _token} =
      KeyTestSupport.create_key!(user, KeyTestSupport.scope_of(user), %{name: "v222", scopes: []})

    %{user: user, key: key}
  end

  defp run(statements), do: Enum.each(statements, &Repo.query!/1)
  defp query(sql, params \\ []), do: Repo.query!(sql, params).rows

  defp marker do
    [[marker]] = query("SELECT obj_description('public.phoenix_kit'::regclass)")
    marker
  end

  defp column? do
    query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'actor_user_uuid'",
      [@conf]
    ) != []
  end

  defp future, do: DateTime.utc_now() |> DateTime.add(120, :second) |> DateTime.truncate(:second)

  defp confirmation(overrides) do
    n = System.unique_integer([:positive])

    struct(
      Confirmation,
      Map.merge(
        %{
          kind: "token",
          tool: "testkit.write_item",
          input_hash: String.pad_leading(Integer.to_string(n, 16), 64, "0"),
          fingerprint: String.duplicate("a", 64),
          status: "unused",
          expires_at: future()
        },
        Map.new(overrides)
      )
    )
  end

  # A row of a session, inserted as SQL: the down test runs without the column, where the
  # schema cannot be used.
  defp insert_user_row!(user_uuid) do
    [[uuid]] =
      query(
        """
        INSERT INTO phoenix_kit_api_confirmations
          (kind, tool, input_hash, fingerprint, actor_user_uuid, status, expires_at)
        VALUES ('token', 'testkit.write_item', $1, $2, $3, 'unused', now() + interval '10 minutes')
        RETURNING uuid::text
        """,
        [String.duplicate("1", 64), String.duplicate("f", 64), Ecto.UUID.dump!(user_uuid)]
      )

    uuid
  end

  describe "phoenix_kit_api_confirmations.actor_user_uuid" do
    test "the chain is at 222 or later" do
      assert String.to_integer(marker()) >= 222
    end

    test "a row bound to a user alone is accepted and reads back", %{user: user} do
      row = Repo.insert!(confirmation(actor_user_uuid: user.uuid))

      assert %Confirmation{actor_user_uuid: user_uuid, actor_key_uuid: nil} =
               Repo.get!(Confirmation, row.uuid)

      assert user_uuid == user.uuid
    end

    test "a row with neither a key, a client token nor a user is still refused" do
      assert_raise Ecto.ConstraintError, ~r/phoenix_kit_api_confirmations_actor_check/, fn ->
        Repo.insert!(confirmation(%{}))
      end
    end

    test "the rows of a key and of a client token are still accepted", %{key: key} do
      assert %Confirmation{} = Repo.insert!(confirmation(actor_key_uuid: key.uuid))

      assert %Confirmation{} =
               Repo.insert!(confirmation(client_token_hash: String.duplicate("c", 43)))
    end

    test "a user that does not exist is refused by the foreign key" do
      assert_raise Ecto.ConstraintError,
                   ~r/phoenix_kit_api_confirmations_actor_user_uuid_fkey/,
                   fn -> Repo.insert!(confirmation(actor_user_uuid: UUIDv7.generate())) end
    end

    test "deleting the user deletes the user's rows, and only theirs", %{key: key} do
      user = user_fixture()
      mine = Repo.insert!(confirmation(actor_user_uuid: user.uuid))
      other = Repo.insert!(confirmation(actor_key_uuid: key.uuid))

      Repo.delete!(user)

      assert Repo.get(Confirmation, mine.uuid) == nil
      assert %Confirmation{} = Repo.get(Confirmation, other.uuid)
    end

    test "a user's lookup by status can use the new index", %{user: user} do
      Repo.insert!(confirmation(actor_user_uuid: user.uuid))

      plan =
        Repo.transaction(fn ->
          Repo.query!("SET LOCAL enable_seqscan = off")

          Repo.query!(
            "EXPLAIN SELECT uuid FROM phoenix_kit_api_confirmations WHERE actor_user_uuid = $1 AND status = 'unused'",
            [Ecto.UUID.dump!(user.uuid)]
          ).rows
          |> List.flatten()
          |> Enum.join("\n")
        end)

      assert {:ok, text} = plan
      assert text =~ "phoenix_kit_api_confirmations_actor_user_status_index"
    end
  end

  describe "the migration" do
    test "running it again changes nothing", %{user: user, key: key} do
      mine = Repo.insert!(confirmation(actor_user_uuid: user.uuid))
      keys = Repo.insert!(confirmation(actor_key_uuid: key.uuid))

      run(V222.up_statements("public"))
      run(V222.up_statements("public"))

      assert %Confirmation{} = Repo.get!(Confirmation, mine.uuid)
      assert %Confirmation{} = Repo.get!(Confirmation, keys.uuid)
      assert String.to_integer(marker()) >= 222
    end

    test "rolls back, a second time too, and forward again", %{user: user, key: key} do
      _session_row = insert_user_row!(user.uuid)
      keys = Repo.insert!(confirmation(actor_key_uuid: key.uuid))

      run(V222.down_statements("public"))

      refute column?()
      assert marker() == "221"
      # A session's row cannot exist without its column; the rows of keys stay.
      key_uuid = key.uuid

      assert [[^key_uuid]] =
               query("SELECT actor_key_uuid::text FROM phoenix_kit_api_confirmations")

      assert_raise Postgrex.Error, ~r/phoenix_kit_api_confirmations_actor_check/, fn ->
        query("""
        INSERT INTO phoenix_kit_api_confirmations (kind, tool, input_hash, fingerprint, status, expires_at)
        VALUES ('token', 't.x', 'h', 'f', 'unused', now())
        """)
      end

      run(V222.down_statements("public"))
      refute column?()
      assert marker() == "221"

      run(V222.up_statements("public"))

      assert column?()
      assert marker() == "222"
      assert %Confirmation{} = Repo.get!(Confirmation, keys.uuid)
      assert %Confirmation{} = Repo.insert!(confirmation(actor_user_uuid: user.uuid))
    end

    # A database that got these objects under another version number: the marker is put
    # back to 220 and the chain runs from there again, over objects that already exist.
    test "runs over its own objects after the marker went back to 220, and up, down, up",
         %{user: user, key: key} do
      mine = Repo.insert!(confirmation(actor_user_uuid: user.uuid))
      keys = Repo.insert!(confirmation(actor_key_uuid: key.uuid))
      query("COMMENT ON TABLE public.phoenix_kit IS '220'")

      run(V221.up_statements("public"))
      run(V222.up_statements("public"))

      assert marker() == "222"
      assert column?()
      assert %Confirmation{} = Repo.get!(Confirmation, mine.uuid)
      assert %Confirmation{} = Repo.get!(Confirmation, keys.uuid)

      assert [
               ["phoenix_kit_api_confirmations_actor_check"],
               ["phoenix_kit_api_confirmations_actor_user_uuid_fkey"]
             ] =
               query("""
               SELECT conname FROM pg_constraint
               WHERE conrelid = 'public.phoenix_kit_api_confirmations'::regclass
                 AND conname IN ('phoenix_kit_api_confirmations_actor_check',
                                 'phoenix_kit_api_confirmations_actor_user_uuid_fkey')
               ORDER BY conname
               """)

      assert [[1]] =
               query("""
               SELECT count(*)::int FROM pg_indexes
               WHERE schemaname = 'public'
                 AND indexname = 'phoenix_kit_api_confirmations_actor_user_status_index'
               """)

      run(V222.down_statements("public"))
      refute column?()
      assert marker() == "221"

      run(V222.up_statements("public"))
      assert column?()
      assert marker() == "222"
      assert %Confirmation{} = Repo.get!(Confirmation, keys.uuid)
      assert %Confirmation{} = Repo.insert!(confirmation(actor_user_uuid: user.uuid))
    end
  end

  describe "the manifest" do
    defp declared_by_v222 do
      for object <- ExpectedSchema.objects("public"),
          Enum.any?(object.revisions, fn {version, _shape} -> version == 222 end),
          do: object
    end

    defp newest_shape(%{revisions: revisions}) do
      {_version, shape} = Enum.max_by(revisions, fn {version, _} -> version end)
      shape
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

    test "declares the column, its foreign key and index, and reshapes the actor CHECK" do
      ids = declared_by_v222() |> Enum.map(& &1.id) |> Enum.sort()

      assert ids == [
               "column:phoenix_kit_api_confirmations.actor_user_uuid",
               "constraint:phoenix_kit_api_confirmations.phoenix_kit_api_confirmations_actor_check",
               "constraint:phoenix_kit_api_confirmations.phoenix_kit_api_confirmations_actor_user_uuid_fkey",
               "index:phoenix_kit_api_confirmations_actor_user_status_index"
             ]

      check =
        Enum.find(declared_by_v222(), &String.ends_with?(&1.id, "_actor_check"))

      assert [220, 222] = Enum.map(check.revisions, &elem(&1, 0))
      assert check.since == 220
    end

    test "every object it declares matches what the chain built" do
      assert declared_by_v222() != []
      snapshot = Probe.snapshot(Repo, "public")

      problems =
        for object <- declared_by_v222(),
            problem = problem(object, Probe.lookup(snapshot, object.check)),
            do: {object.id, problem}

      assert problems == []
    end

    test "every column of the table is declared, and nothing else is" do
      declared =
        for %{class: :column, id: "column:" <> rest} <- ExpectedSchema.objects("public"),
            [@conf, name] <- [String.split(rest, ".")],
            do: name

      actual =
        for [name] <-
              query(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1",
                [@conf]
              ),
            do: name

      assert Enum.sort(declared) == Enum.sort(actual)
    end
  end
end
