defmodule PhoenixKit.Modules.Storage.StoreNewInstanceFailureTest do
  @moduledoc """
  An upload whose original's instance cannot be recorded leaves nothing
  behind: not its row (a `processing` row without an instance would hold its
  own key against the cleanup, and linger), not its object.

  The failure is made without touching the code under test: the instance's
  `size` is read from the source file again after the object is stored, and
  an S3-compatible stub removes the source file when the object arrives, so
  that size is 0 and `create_file_instance/1` answers with a changeset.
  """
  use PhoenixKit.DataCase, async: false

  import Ecto.Query, only: [from: 2]

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.Bucket
  alias PhoenixKit.Modules.Storage.Libraries
  alias PhoenixKit.Modules.Storage.Profiles
  alias PhoenixKit.Users.Auth

  @buckets_cache :phoenix_kit_buckets_cache

  # A minimal S3: path-style `/<bucket>/<key>`, objects in an Agent. A PUT
  # removes the file the Agent names under `:vanish` once it has the bytes.
  defmodule StubS3 do
    @moduledoc false
    import Plug.Conn

    def init(store), do: store

    def call(conn, store) do
      [_bucket | key_parts] = conn.path_info
      key = Enum.join(key_parts, "/")

      case conn.method do
        "PUT" ->
          {:ok, body, conn} = read_all(conn, "")
          Agent.update(store, &Map.put(&1, key, body))
          if path = Agent.get(store, &Map.get(&1, :vanish)), do: File.rm(path)
          conn |> put_resp_header("etag", ~s("etag")) |> send_resp(200, "")

        "DELETE" ->
          Agent.update(store, &Map.delete(&1, key))
          send_resp(conn, 204, "")

        method when method in ["HEAD", "GET"] ->
          case Agent.get(store, &Map.get(&1, key)) do
            nil -> send_resp(conn, 404, "")
            body -> conn |> put_resp_header("etag", ~s("etag")) |> send_resp(200, body)
          end

        _ ->
          send_resp(conn, 405, "")
      end
    end

    defp read_all(conn, acc) do
      case read_body(conn) do
        {:ok, chunk, conn} -> {:ok, acc <> chunk, conn}
        {:more, chunk, conn} -> read_all(conn, acc <> chunk)
      end
    end
  end

  setup do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])

    # Only the stub's bucket takes writes.
    Repo.update_all(Bucket, set: [enabled: false])

    store = start_supervised!({Agent, fn -> %{} end})

    server =
      start_supervised!(
        {Bandit, plug: {StubS3, store}, ip: {127, 0, 0, 1}, port: 0, startup_log: false}
      )

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    {:ok, bucket} =
      Storage.create_bucket(%{
        name: "stub-s3-failure-#{n}",
        provider: "s3",
        endpoint: "http://127.0.0.1:#{port}",
        bucket_name: "pk",
        region: "us-east-1",
        access_key_id: "test-key",
        secret_access_key: "test-secret",
        enabled: true,
        priority: 0
      })

    # A cloud bucket is only used through a profile that wants a cloud copy.
    {:ok, profile} =
      Profiles.create_profile(%{
        name: "Stub S3 #{n}",
        copies_local: 0,
        copies_cloud: 1,
        min_copies_on_write: 1
      })

    Profiles.put_bucket(profile, bucket.uuid, %{})
    {:ok, library} = Libraries.create_system_library(%{name: "Stub S3 #{n}"})
    {:ok, library} = Profiles.set_library_profile(library, profile.uuid)

    start_supervised!(
      {Oban, name: Oban, repo: PhoenixKit.Test.Repo, testing: :manual, queues: [], plugins: []}
    )

    on_exit(fn -> :persistent_term.erase(@buckets_cache) end)

    {:ok, user} =
      Auth.register_user(%{
        "email" => "failing-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    %{n: n, store: store, user: user, library: library}
  end

  defp upload(ctx, opts) do
    content = "vanishing #{ctx.n}"
    sha = :sha256 |> :crypto.hash(content) |> Base.encode16(case: :lower)

    source =
      Path.join(System.tmp_dir!(), "pk_instance_failure_#{System.unique_integer([:positive])}")

    File.write!(source, content)
    on_exit(fn -> File.rm(source) end)

    Agent.update(ctx.store, &Map.put(&1, :vanish, source))

    opts = [library_uuid: ctx.library.uuid] ++ opts

    Storage.store_file_in_buckets(source, "document", ctx.user.uuid, sha, "txt", "a.txt", opts)
  end

  defp rows(ctx),
    do: Repo.aggregate(from(f in Storage.File, where: f.user_uuid == ^ctx.user.uuid), :count)

  defp objects(ctx), do: ctx.store |> Agent.get(&Map.delete(&1, :vanish)) |> Map.keys()

  for {name, opts} <- [{"a plain upload", []}, {"a `dedup: false` one", [dedup: false]}] do
    test "#{name} whose instance cannot be recorded leaves no row and no object", ctx do
      assert {:error, %Ecto.Changeset{errors: errors}} = upload(ctx, unquote(opts))

      assert Keyword.has_key?(errors, :size), "the instance was refused for its size"
      assert rows(ctx) == 0, "the failed upload's row is still there"
      assert objects(ctx) == [], "the failed upload's object is still there"
    end
  end
end
