defmodule PhoenixKit.Modules.Storage.StoreWithoutDedupTest do
  @moduledoc """
  `store_file_in_buckets/7` with `dedup: false`: every upload is a row of its
  own, whatever the uploader or anybody else has stored before.

  The default is the dedup that has always been there — one row per uploader
  and library for the same bytes (`{:ok, file, :duplicate}` for the second
  upload) and a cross-user clone of an active file — and is pinned here too,
  so the option cannot change it.
  """
  use PhoenixKit.DataCase, async: false

  import Ecto.Query, only: [from: 2]

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.Bucket
  alias PhoenixKit.Modules.Storage.Libraries
  alias PhoenixKit.Modules.Storage.Manager
  alias PhoenixKit.Modules.Storage.VariantGenerator
  alias PhoenixKit.Users.Auth

  @buckets_cache :phoenix_kit_buckets_cache

  setup do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])
    root = Path.join(System.tmp_dir!(), "pk_no_dedup_#{n}")

    # Only this test's bucket: the seeded default one lives in the project
    # tree and outlasts the test.
    Repo.update_all(Bucket, set: [enabled: false])

    {:ok, _bucket} =
      Storage.create_bucket(%{
        name: "no-dedup-#{n}",
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
    end)

    %{n: n, alice: user!("alice", n), bob: user!("bob", n)}
  end

  defp user!(name, n) do
    {:ok, user} =
      Auth.register_user(%{
        "email" => "#{name}-nodedup-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    user
  end

  defp checksum(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  # What `store_file_in_buckets/7` answered, untouched.
  defp store(user, bytes, opts \\ [], name \\ "a.txt") do
    path =
      Path.join(System.tmp_dir!(), "pk_no_dedup_src_#{System.unique_integer([:positive])}.txt")

    File.write!(path, bytes)

    try do
      Storage.store_file_in_buckets(
        path,
        "document",
        user.uuid,
        checksum(bytes),
        "txt",
        name,
        opts
      )
    after
      File.rm(path)
    end
  end

  defp keys(file), do: file.uuid |> Storage.list_file_instances() |> Enum.map(& &1.file_name)

  defp exists?(key), do: Manager.file_exists?(key)

  # A file that finished processing: the only kind a cross-user upload clones.
  defp activate!(file) do
    Repo.update_all(from(f in Storage.File, where: f.uuid == ^file.uuid), set: [status: "active"])
    file
  end

  describe "the default" do
    test "the same uploader's second upload of the same bytes is the first one", ctx do
      assert {:ok, first} = store(ctx.alice, "same bytes #{ctx.n}")
      assert {:ok, second, :duplicate} = store(ctx.alice, "same bytes #{ctx.n}")

      assert second.uuid == first.uuid
    end

    test "`dedup: true` is the default spelled out", ctx do
      assert {:ok, first} = store(ctx.alice, "spelled out #{ctx.n}", dedup: true)
      assert {:ok, second, :duplicate} = store(ctx.alice, "spelled out #{ctx.n}", dedup: true)

      assert second.uuid == first.uuid
    end

    test "another uploader's upload of an active file is a clone of it", ctx do
      assert {:ok, donor} = store(ctx.alice, "donated #{ctx.n}")
      activate!(donor)

      assert {:ok, clone, :duplicate} = store(ctx.bob, "donated #{ctx.n}")
      assert clone.uuid != donor.uuid
      assert clone.user_uuid == ctx.bob.uuid
    end
  end

  describe "`dedup: false`, one uploader" do
    test "every upload of the same bytes is a row of its own, none a duplicate", ctx do
      assert {:ok, first} = store(ctx.alice, "again #{ctx.n}", dedup: false)
      assert {:ok, second} = store(ctx.alice, "again #{ctx.n}", dedup: false)
      assert {:ok, third} = store(ctx.alice, "again #{ctx.n}", dedup: false)

      assert first.uuid != second.uuid
      assert second.uuid != third.uuid
      assert first.uuid != third.uuid

      for file <- [first, second, third] do
        assert file.user_uuid == ctx.alice.uuid
        assert Storage.get_file(file.uuid)
        assert [_original] = Storage.list_file_instances(file.uuid)
      end
    end

    test "each row keeps the caller's own name and the real content checksum", ctx do
      bytes = "named #{ctx.n}"
      assert {:ok, first} = store(ctx.alice, bytes, [dedup: false], "request-1.txt")
      assert {:ok, second} = store(ctx.alice, bytes, [dedup: false], "request-2.txt")

      assert first.original_file_name == "request-1.txt"
      assert second.original_file_name == "request-2.txt"
      assert first.file_checksum == checksum(bytes)
      assert second.file_checksum == checksum(bytes)
    end

    test "a row's own data is its own: changing one leaves the other", ctx do
      assert {:ok, first} = store(ctx.alice, "metadata #{ctx.n}", dedup: false)
      assert {:ok, second} = store(ctx.alice, "metadata #{ctx.n}", dedup: false)

      {:ok, _} = Storage.update_file(first, %{original_file_name: "renamed.txt"})

      assert Storage.get_file(first.uuid).original_file_name == "renamed.txt"
      assert Storage.get_file(second.uuid).original_file_name == "a.txt"
    end

    test "the rows never take the uploader's dedup key, so a plain upload is not one of them",
         ctx do
      bytes = "keyless #{ctx.n}"
      assert {:ok, first} = store(ctx.alice, bytes, dedup: false)
      assert {:ok, second} = store(ctx.alice, bytes, dedup: false)

      key = Storage.calculate_user_file_checksum(ctx.alice.uuid, checksum(bytes))
      assert first.user_file_checksum != key
      assert second.user_file_checksum != key
      assert first.user_file_checksum != second.user_file_checksum
      refute Storage.get_file_by_user_checksum(key)

      # …and the next plain upload of the bytes is a new file with the usual key.
      assert {:ok, plain} = store(ctx.alice, bytes)
      assert plain.uuid not in [first.uuid, second.uuid]
      assert plain.user_file_checksum == key

      assert {:ok, again, :duplicate} = store(ctx.alice, bytes)
      assert again.uuid == plain.uuid
    end

    test "after a plain upload, `dedup: false` still adds a row and leaves the first alone",
         ctx do
      bytes = "mixed #{ctx.n}"
      assert {:ok, plain} = store(ctx.alice, bytes)
      assert {:ok, extra} = store(ctx.alice, bytes, dedup: false)

      assert extra.uuid != plain.uuid
      assert Storage.get_file(plain.uuid).user_file_checksum == plain.user_file_checksum
      assert {:ok, still, :duplicate} = store(ctx.alice, bytes)
      assert still.uuid == plain.uuid
    end

    test "concurrent uploads of the same bytes are all new rows", ctx do
      bytes = "racing #{ctx.n}"

      results =
        1..4
        |> Task.async_stream(fn _ -> store(ctx.alice, bytes, dedup: false) end,
          timeout: 30_000
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.all?(results, &match?({:ok, _file}, &1))
      uuids = Enum.map(results, fn {:ok, file} -> file.uuid end)
      assert length(Enum.uniq(uuids)) == 4
    end
  end

  describe "`dedup: false`, another uploader's copy" do
    test "an active file of somebody else is not cloned: the upload is a row of its own", ctx do
      assert {:ok, donor} = store(ctx.alice, "owned #{ctx.n}")
      activate!(donor)

      assert {:ok, own} = store(ctx.bob, "owned #{ctx.n}", dedup: false)

      assert own.uuid != donor.uuid
      assert own.user_uuid == ctx.bob.uuid
      assert own.file_checksum == donor.file_checksum
      # Stored and processed like a first upload, not copied from the donor.
      assert own.status == "processing"
      assert [_original] = Storage.list_file_instances(own.uuid)
    end

    test "the uploader's own earlier copy and somebody else's are both left alone", ctx do
      assert {:ok, alices} = store(ctx.alice, "both #{ctx.n}")
      activate!(alices)
      assert {:ok, bobs} = store(ctx.bob, "both #{ctx.n}", dedup: false)
      assert {:ok, bobs_again} = store(ctx.bob, "both #{ctx.n}", dedup: false)

      assert length(Enum.uniq([alices.uuid, bobs.uuid, bobs_again.uuid])) == 3
    end
  end

  describe "a plain upload after a `dedup: false` one" do
    test "clones an active such row like any active file, into a row of its own", ctx do
      bytes = "cloned later #{ctx.n}"
      assert {:ok, own} = store(ctx.alice, bytes, dedup: false)
      activate!(own)

      assert {:ok, by_bob, :duplicate} = store(ctx.bob, bytes)
      assert {:ok, by_alice, :duplicate} = store(ctx.alice, bytes)

      assert length(Enum.uniq([own.uuid, by_bob.uuid, by_alice.uuid])) == 3
      assert by_alice.user_file_checksum != own.user_file_checksum

      # The clones share the row's objects; deleting the row keeps them.
      [key] = keys(own)
      assert keys(by_bob) == [key]
      assert {:ok, _} = Storage.delete_file_completely(own)
      assert exists?(key)
      assert Storage.get_file(by_bob.uuid)
    end
  end

  describe "deleting one of several rows of the same bytes" do
    test "the others keep their instances and the stored object", ctx do
      assert {:ok, first} = store(ctx.alice, "shared object #{ctx.n}", dedup: false)
      assert {:ok, second} = store(ctx.alice, "shared object #{ctx.n}", dedup: false)

      [key] = keys(first)
      assert keys(second) == [key], "the rows' bytes are one content-addressed object"
      assert exists?(key)

      assert {:ok, _} = Storage.delete_file_completely(first)

      refute Storage.get_file(first.uuid)
      assert Storage.get_file(second.uuid)
      assert keys(second) == [key]
      assert exists?(key)
      assert {:ok, _path, _file, _instance} = Storage.retrieve_original(second.uuid)

      assert {:ok, _} = Storage.delete_file_completely(second)
      refute exists?(key), "the last row to name the object takes it with it"
    end

    test "the order of deletion does not matter", ctx do
      assert {:ok, first} = store(ctx.alice, "other order #{ctx.n}", dedup: false)
      assert {:ok, second} = store(ctx.alice, "other order #{ctx.n}", dedup: false)
      [key] = keys(first)

      assert {:ok, _} = Storage.delete_file_completely(second)
      assert exists?(key)
      assert Storage.get_file(first.uuid)
      assert [^key] = keys(first)

      assert {:ok, _} = Storage.delete_file_completely(first)
      refute exists?(key)
    end

    test "a row's name and folder are its own, and so is its deletion", ctx do
      assert {:ok, first} = store(ctx.alice, "per request #{ctx.n}", dedup: false)
      assert {:ok, second} = store(ctx.alice, "per request #{ctx.n}", dedup: false)
      {:ok, folder} = Storage.create_folder(%{name: "request-#{ctx.n}"})

      {:ok, _} = Storage.move_file_to_folder(second.uuid, folder.uuid)
      {:ok, _} = Storage.update_file(second, %{original_file_name: "second.txt"})

      assert Storage.get_file(first.uuid).folder_uuid == nil
      assert Storage.get_file(first.uuid).original_file_name == "a.txt"

      assert {:ok, _} = Storage.delete_file_completely(first)

      kept = Storage.get_file(second.uuid)
      assert kept.folder_uuid == folder.uuid
      assert kept.original_file_name == "second.txt"
    end

    test "with a plain upload of the same bytes among them", ctx do
      assert {:ok, plain} = store(ctx.alice, "with plain #{ctx.n}")
      assert {:ok, extra} = store(ctx.alice, "with plain #{ctx.n}", dedup: false)
      [key] = keys(plain)
      assert keys(extra) == [key]

      assert {:ok, _} = Storage.delete_file_completely(extra)
      assert exists?(key)
      assert Storage.get_file(plain.uuid)

      assert {:ok, _} = Storage.delete_file_completely(plain)
      refute exists?(key)
    end
  end

  describe "an upload that is still writing" do
    # `store_new_file_in_buckets/8` inserts the row, writes the object, and
    # only then records its instance. This is a row in that middle: the
    # object is on disk (another row of the same bytes put it there), the
    # row is `processing`, there is no instance yet.
    defp midway_upload!(first, ctx) do
      {:ok, midway} =
        Storage.create_file(%{
          file_name: first.file_name,
          original_file_name: "midway.txt",
          file_path: first.file_path,
          mime_type: first.mime_type,
          file_type: first.file_type,
          ext: first.ext,
          file_checksum: first.file_checksum,
          user_file_checksum: "nodedup:midway-#{ctx.n}",
          size: first.size,
          status: "processing",
          user_uuid: first.user_uuid
        })

      midway
    end

    defp record_original!(midway, key) do
      {:ok, _} =
        Storage.create_file_instance(%{
          variant_name: "original",
          file_name: key,
          mime_type: midway.mime_type,
          ext: midway.ext,
          checksum: midway.file_checksum,
          size: midway.size,
          processing_status: "completed",
          file_uuid: midway.uuid
        })
    end

    test "deleting another row of the same bytes leaves the object", ctx do
      assert {:ok, first} = store(ctx.alice, "midway #{ctx.n}", dedup: false)
      [key] = keys(first)
      midway = midway_upload!(first, ctx)

      assert {:ok, _} = Storage.delete_file_completely(first)
      assert exists?(key), "the upload that is writing the object loses it"

      # Once the instance is recorded the key is the row's by reference.
      record_original!(midway, key)
      assert exists?(key)
      assert {:ok, _} = Storage.delete_file_completely(midway)
      refute exists?(key)
    end

    test "delete_stored_objects/2 keeps the key unless the writer is the caller's own", ctx do
      assert {:ok, first} = store(ctx.alice, "own cleanup #{ctx.n}", dedup: false)
      [key] = keys(first)
      midway = midway_upload!(first, ctx)
      {:ok, _} = Storage.delete_file(first)

      assert :ok = Storage.delete_stored_objects([key])
      assert exists?(key)

      # A failed upload cleans up after itself: its own row is not "another".
      assert :ok = Storage.delete_stored_objects([key], exclude_file_uuids: [midway.uuid])
      refute exists?(key)
    end

    test "an old processing row holds nothing: nothing ever marks it failed", ctx do
      assert {:ok, first} = store(ctx.alice, "abandoned #{ctx.n}", dedup: false)
      [key] = keys(first)
      midway = midway_upload!(first, ctx)

      two_hours_ago = DateTime.add(DateTime.utc_now(), -2 * 3600) |> DateTime.truncate(:second)

      Repo.update_all(from(f in Storage.File, where: f.uuid == ^midway.uuid),
        set: [updated_at: two_hours_ago]
      )

      assert {:ok, _} = Storage.delete_file_completely(first)
      refute exists?(key)
    end

    test "a file's own processing row does not hold its instances' keys", ctx do
      assert {:ok, file} = store(ctx.alice, "own row #{ctx.n}", dedup: false)
      assert file.status == "processing"
      [key] = keys(file)

      assert :ok = Storage.remove_instances(file, Storage.list_file_instances(file.uuid))
      refute exists?(key)
    end

    test "ignore_uploads_of: ignores that file's upload and no other's", ctx do
      assert {:ok, first} = store(ctx.alice, "ignored #{ctx.n}", dedup: false)
      [key] = keys(first)
      mine = midway_upload!(first, ctx)
      {:ok, _} = Storage.delete_file(first)

      {:ok, theirs} =
        Storage.create_file(%{
          file_name: first.file_name,
          original_file_name: "theirs.txt",
          file_path: first.file_path,
          mime_type: first.mime_type,
          file_type: first.file_type,
          ext: first.ext,
          file_checksum: first.file_checksum,
          user_file_checksum: "nodedup:theirs-#{ctx.n}",
          size: first.size,
          status: "processing",
          user_uuid: first.user_uuid
        })

      assert :ok = Storage.delete_stored_objects([key], ignore_uploads_of: [mine.uuid])
      assert exists?(key), "another upload is still writing it"

      {:ok, _} = Storage.delete_file(theirs)
      assert :ok = Storage.delete_stored_objects([key], ignore_uploads_of: [mine.uuid])
      refute exists?(key)
    end

    # The variant job runs on a file that is still `processing`. Its own row,
    # which has no instance for the key being dropped, must not hold the key.
    defp prepared!(content) do
      path =
        Path.join(System.tmp_dir!(), "pk_no_dedup_variant_#{System.unique_integer([:positive])}")

      File.write!(path, content)
      path
    end

    test "a processing file's variant replaced under a new key loses the old object", ctx do
      assert {:ok, file} = store(ctx.alice, "republished #{ctx.n}", dedup: false)
      assert file.status == "processing"

      old_key = Path.join(file.file_path, "old-annotated.txt")
      {:ok, _} = Manager.store_file(prepared!("old"), path_prefix: old_key)

      {:ok, _} =
        Storage.create_file_instance(%{
          variant_name: "annotated",
          file_name: old_key,
          mime_type: "text/plain",
          ext: "txt",
          checksum: "old",
          size: 3,
          processing_status: "completed",
          file_uuid: file.uuid
        })

      assert {:ok, instance} =
               VariantGenerator.store_prepared_variant(
                 file,
                 "annotated",
                 prepared!("new"),
                 "txt",
                 "text/plain"
               )

      assert instance.file_name != old_key
      assert exists?(instance.file_name)
      refute exists?(old_key), "the file's own processing row held its replaced variant"
    end

    test "a variant dropped as stale loses its object though the file is processing", ctx do
      assert {:ok, file} = store(ctx.alice, "stale variant #{ctx.n}", dedup: false)
      assert file.status == "processing"
      variant_key = Path.join(file.file_path, "#{file.file_checksum}_annotated.txt")

      assert {:error, :stale_source} =
               VariantGenerator.store_prepared_variant(
                 file,
                 "annotated",
                 prepared!("stale"),
                 "txt",
                 "text/plain",
                 source_key: "not/the/original.txt"
               )

      refute exists?(variant_key), "the file's own processing row held its dropped variant"
    end
  end

  describe "what ignore_uploads_of: and exclude_file_uuids: are for" do
    test "a file that stays keeps its instances as references; one that goes does not", ctx do
      assert {:ok, file} = store(ctx.alice, "stays #{ctx.n}", dedup: false)
      [key] = keys(file)

      assert :ok = Storage.delete_stored_objects([key], ignore_uploads_of: [file.uuid])
      assert exists?(key), "the file stays: its instance still names the key"

      assert :ok = Storage.delete_stored_objects([key], exclude_file_uuids: [file.uuid])
      refute exists?(key)
    end
  end

  describe "inside a transaction of the caller's" do
    # Whether this session holds `lock_storage_paths/1`'s advisory lock for
    # `path`: `pg_advisory_xact_lock(hashtext(..))` shows in `pg_locks` as a
    # single bigint key, split into `classid` (high half) and `objid`.
    defp path_lock_held?(path) do
      %{rows: [[count]]} =
        Repo.query!(
          """
          SELECT count(*) FROM pg_locks
          WHERE locktype = 'advisory' AND objsubid = 1 AND pid = pg_backend_pid()
            AND ((classid::bigint << 32) | objid::bigint) =
                hashtext('phoenix_kit_storage_path:' || $1::text)::bigint
          """,
          [path]
        )

      count == 1
    end

    test "only a `dedup: false` upload takes the lock of the object's directory", ctx do
      assert {:ok, :done} =
               Repo.transaction(fn ->
                 assert {:ok, plain} = store(ctx.alice, "gate plain #{ctx.n}")
                 refute path_lock_held?(plain.file_path)

                 assert {:ok, locked} = store(ctx.alice, "gate false #{ctx.n}", dedup: false)
                 assert path_lock_held?(locked.file_path)
                 refute path_lock_held?(locked.file_path <> "-elsewhere")

                 :done
               end)
    end

    # An upload that cannot be recorded (no uploader) answers with its
    # changeset, as a plain `create_file/1` does.
    test "a plain upload that cannot be recorded leaves the transaction alone", ctx do
      assert {:ok, {:error, %Ecto.Changeset{}}} =
               Repo.transaction(fn -> store(%{uuid: nil}, "plain invalid #{ctx.n}") end)
    end

    test "so does a `dedup: false` one", ctx do
      assert {:ok, {:error, %Ecto.Changeset{}}} =
               Repo.transaction(fn ->
                 store(%{uuid: nil}, "keyless invalid #{ctx.n}", dedup: false)
               end)
    end

    # The database refuses this one (the uploader is gone), not the changeset:
    # a plain insert would leave the transaction aborted.
    test "a `dedup: false` upload the database refuses answers with its changeset", ctx do
      gone = %{uuid: UUIDv7.generate()}

      assert {:error, %Ecto.Changeset{}} = store(gone, "gone alone #{ctx.n}", dedup: false)
      assert {:error, %Ecto.Changeset{}} = store(gone, "gone plain #{ctx.n}")
    end

    test "and leaves a transaction of the caller's usable", ctx do
      assert {:ok, {:error, %Ecto.Changeset{}, :still_usable}} =
               Repo.transaction(fn ->
                 {:error, changeset} =
                   store(%{uuid: UUIDv7.generate()}, "gone in tx #{ctx.n}", dedup: false)

                 assert %{rows: [[1]]} = Repo.query!("SELECT 1")
                 {:error, changeset, :still_usable}
               end)
    end

    test "a `dedup: false` upload that can be recorded is one, and the transaction goes on",
         ctx do
      assert {:ok, {:ok, file}} =
               Repo.transaction(fn ->
                 store(ctx.alice, "in a transaction #{ctx.n}", dedup: false)
               end)

      assert Storage.get_file(file.uuid)
    end
  end

  describe "`dedup: false` into a library" do
    test "the rows share the library's keys, delete by reference, and dedup resumes", ctx do
      {:ok, library} = Libraries.create_system_library(%{name: "No dedup #{ctx.n}"})
      bytes = "in a library #{ctx.n}"
      opts = [library_uuid: library.uuid]

      assert {:ok, first} = store(ctx.alice, bytes, [dedup: false] ++ opts)
      assert {:ok, second} = store(ctx.alice, bytes, [dedup: false] ++ opts)

      assert first.uuid != second.uuid
      assert first.library_uuid == library.uuid
      assert second.library_uuid == library.uuid
      assert String.starts_with?(first.file_path, library.key_prefix <> "/")
      assert second.file_path == first.file_path
      [key] = keys(first)
      assert keys(second) == [key]

      library_key =
        Storage.calculate_user_file_checksum(ctx.alice.uuid, checksum(bytes), library.uuid)

      refute Storage.get_file_by_user_checksum(library_key)

      # A plain upload into the library is a row of its own with the usual
      # key, and the next one is that row again.
      assert {:ok, plain} = store(ctx.alice, bytes, opts)
      assert plain.uuid not in [first.uuid, second.uuid]
      assert plain.user_file_checksum == library_key
      assert {:ok, again, :duplicate} = store(ctx.alice, bytes, opts)
      assert again.uuid == plain.uuid

      for file <- [first, second] do
        assert {:ok, _} = Storage.delete_file_completely(file)
        assert exists?(key)
      end

      assert {:ok, _} = Storage.delete_file_completely(plain)
      refute exists?(key)
    end
  end
end
