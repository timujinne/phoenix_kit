defmodule PhoenixKit.Modules.Storage.StoreLargeFileTest do
  @moduledoc """
  A large file is stored from disk, never held in memory: `store_file_in_buckets/7`
  hashes it for its path key in chunks, copies it to the bucket as a stream, and
  the bytes that arrive are the bytes that were given. A video can be gigabytes;
  what storing one costs in memory must not depend on its size.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.Bucket
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.FileHash

  @buckets_cache :phoenix_kit_buckets_cache
  @mib 1_048_576

  setup do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])
    root = Path.join(System.tmp_dir!(), "pk_large_file_#{n}")
    source = Path.join(System.tmp_dir!(), "pk_large_src_#{n}.mp4")

    Repo.update_all(Bucket, set: [enabled: false])

    {:ok, _bucket} =
      Storage.create_bucket(%{
        name: "large-file-#{n}",
        provider: "local",
        endpoint: root,
        enabled: true,
        priority: 0
      })

    start_supervised!(
      {Oban, name: Oban, repo: PhoenixKit.Test.Repo, testing: :manual, queues: [], plugins: []}
    )

    on_exit(fn ->
      :persistent_term.erase(@buckets_cache)
      File.rm_rf(root)
      File.rm(source)
    end)

    {:ok, user} =
      Auth.register_user(%{
        "email" => "large-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    %{user: user, root: root, source: source}
  end

  defp write_large!(path, mib) do
    block = :crypto.strong_rand_bytes(@mib)

    File.open!(path, [:write, :raw, :binary], fn io ->
      for _ <- 1..mib, do: :ok = :file.write(io, block)
    end)
  end

  @tag timeout: 180_000
  test "storing a 160 MiB video costs a few chunks of memory, and the bytes arrive intact", ctx do
    write_large!(ctx.source, 160)
    {:ok, checksum} = FileHash.sha256(ctx.source)

    :erlang.garbage_collect()
    baseline = :erlang.memory(:binary)
    parent = self()

    sampler =
      spawn_link(fn ->
        loop = fn loop, peak ->
          receive do
            :stop -> send(parent, {:peak, peak})
          after
            2 -> loop.(loop, max(peak, :erlang.memory(:binary)))
          end
        end

        loop.(loop, baseline)
      end)

    result =
      Storage.store_file_in_buckets(
        ctx.source,
        "video",
        ctx.user.uuid,
        checksum,
        "mp4",
        "holiday.mp4",
        mime_type: "video/mp4"
      )

    send(sampler, :stop)
    peak = receive do: ({:peak, p} -> p)

    assert {:ok, file} = result

    # Nothing like the file's size was ever held at once.
    assert peak - baseline < 64 * @mib,
           "binary memory rose by #{div(peak - baseline, @mib)} MiB storing a 160 MiB file"

    # The stored original is the file that was given.
    [original | _] = Storage.list_file_instances(file.uuid)
    stored = Path.join(ctx.root, original.file_name)
    assert File.exists?(stored)
    assert File.stat!(stored).size == 160 * @mib
    assert {:ok, ^checksum} = FileHash.sha256(stored)
  end
end
