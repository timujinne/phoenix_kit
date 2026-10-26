defmodule PhoenixKit.Modules.Storage.RelinkFileTest do
  @moduledoc """
  `Storage.relink_file/3` moves an existing record (a full copy in a library)
  onto its donor's stored objects by the rules of `link_copy/3`, keeping the
  record's uuid, library, folder, name and owner, and hands back the keys it
  no longer names; `Storage.delete_unreferenced_keys/1` then removes those
  that nobody names.

  Skipped when ImageMagick isn't installed.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.TestSupport.LinkCopyHelpers

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Manager, Profiles, Reconciler}

  @moduletag :tmp_dir

  unless imagemagick?(),
    do: @moduletag(skip: "ImageMagick (convert, identify) is not installed")

  setup %{tmp_dir: tmp} do
    if imagemagick?() do
      env = setup_storage(tmp)
      owner = user!("owner", env.n)
      sender = user!("sender", env.n)
      path = image!(tmp, "photo.jpg")
      donor = upload!(owner, path)
      target = library!(env.n)

      # What the module made before: a full copy, on keys of its own.
      snap = upload!(sender, path, library_uuid: target.uuid, dedup: false)

      Map.merge(env, %{
        owner: owner,
        sender: sender,
        donor: donor,
        target: target,
        snap: snap,
        path: path
      })
    else
      {:ok, skip: true}
    end
  end

  test "the snapshot is on keys of its own to begin with", ctx do
    assert ctx.snap.file_path != ctx.donor.file_path
    assert MapSet.disjoint?(key_set(ctx.snap), key_set(ctx.donor))
    assert ctx.snap.file_checksum == ctx.donor.file_checksum
  end

  describe "relinking" do
    test "names the donor's keys, answers the keys it left, and leaves them in the bucket", ctx do
      old_keys = key_set(ctx.snap)
      identity = identity(ctx.snap)
      before = object_count(ctx.root)

      assert {:ok, file, left} = Storage.relink_file(ctx.snap, ctx.donor, [])

      assert keys(file) == keys(ctx.donor)
      assert MapSet.new(left) == old_keys
      assert file.file_path == ctx.donor.file_path
      assert file.file_name == ctx.donor.file_name
      assert identity(reload(file)) == identity
      assert reload(file).placed_variant_revision == reload(ctx.donor).placed_variant_revision

      for inst <- instances(file) do
        donor_inst = instance(ctx.donor, inst.variant_name)
        assert inst.checksum == donor_inst.checksum
        assert location_set(inst) == location_set(donor_inst)
        assert MapSet.size(location_set(inst)) > 0
      end

      # Nothing is deleted unless asked: the objects are only unnamed now.
      assert Enum.all?(left, &exists?/1)
      assert object_count(ctx.root) == before
    end

    test "delete_unreferenced_keys/1 removes what nobody names, and only that", ctx do
      assert {:ok, file, left} = Storage.relink_file(ctx.snap, ctx.donor, [])

      # Another row that took one of the keys in the meantime.
      keeper = hd(left)
      other = upload!(ctx.owner, image!(ctx.tmp, "other.jpg", "blue"))

      {:ok, _} =
        Storage.create_file_instance(%{
          variant_name: "kept",
          file_name: keeper,
          mime_type: "image/jpeg",
          ext: "jpg",
          checksum: "x",
          size: 1,
          processing_status: "completed",
          file_uuid: other.uuid
        })

      assert :ok = Storage.delete_unreferenced_keys(left)

      assert exists?(keeper)
      refute Enum.any?(left -- [keeper], &exists?/1)
      assert all_keys_exist?(Map.values(keys(file)))
      assert all_keys_exist?(Map.values(keys(ctx.donor)))
      assert {:ok, _path, _} = Storage.retrieve_file(file.uuid)
    end

    test "delete_old: true deletes the unnamed keys after the commit", ctx do
      old_keys = key_set(ctx.snap)

      assert {:ok, file, left} = Storage.relink_file(ctx.snap, ctx.donor, delete_old: true)

      assert MapSet.new(left) == old_keys
      refute Enum.any?(left, &exists?/1)
      assert all_keys_exist?(Map.values(keys(file)))
    end

    test "a burned thumbnail of the record is dropped with its other variants", ctx do
      burned = burn!(ctx.snap, "thumbnail", ctx.tmp)
      snap = reload(ctx.snap)

      assert {:ok, file, left} = Storage.relink_file(snap, ctx.donor, [])

      assert burned.file_name in left
      assert instance(file, "thumbnail").spec_hash != nil
      assert keys(file) == keys(ctx.donor)
    end

    test "a donor's burned thumbnail is not taken; the record gets it made again", ctx do
      burn!(ctx.donor, "thumbnail", ctx.tmp)
      donor = reload(ctx.donor)
      jobs = length(queued_jobs(ctx.snap))

      assert {:ok, file, _left} = Storage.relink_file(ctx.snap, donor, [])

      refute Map.has_key?(keys(file), "thumbnail")
      assert reload(file).placed_variant_revision == 0
      assert length(queued_jobs(file)) == jobs

      assert :reconciled = Reconciler.reconcile_file(file)
      assert Map.has_key?(keys(reload(file)), "thumbnail")
    end

    test "is repeatable", ctx do
      assert {:ok, file, _} = Storage.relink_file(ctx.snap, ctx.donor, [])
      assert {:ok, again, []} = Storage.relink_file(file, ctx.donor, [])
      assert keys(again) == keys(ctx.donor)
      assert all_keys_exist?(Map.values(keys(again)))
    end
  end

  describe "refusals change nothing" do
    test "other bytes (checksum)", ctx do
      stranger = upload!(ctx.owner, image!(ctx.tmp, "stranger.jpg", "blue"))
      before = {keys(ctx.snap), identity(reload(ctx.snap))}

      assert {:error, :incompatible} = Storage.relink_file(ctx.snap, stranger, [])
      assert {keys(ctx.snap), identity(reload(ctx.snap))} == before
    end

    test "another size", ctx do
      row = from(f in Storage.File, where: f.uuid == ^ctx.snap.uuid)
      Repo.update_all(row, set: [size: ctx.snap.size + 1])
      before = keys(ctx.snap)

      assert {:error, :incompatible} = Storage.relink_file(reload(ctx.snap), ctx.donor, [])
      assert keys(ctx.snap) == before
    end

    test "a donor in the trash, or whose original is gone", ctx do
      before = keys(ctx.snap)

      :ok =
        Manager.delete_file(instance(ctx.donor, "original").file_name)

      assert {:error, :donor_unavailable} = Storage.relink_file(ctx.snap, ctx.donor, [])

      assert {:ok, _} = Storage.trash_file(ctx.donor)
      assert {:error, :donor_unavailable} = Storage.relink_file(ctx.snap, ctx.donor, [])
      assert keys(ctx.snap) == before
      assert all_keys_exist?(Map.values(before))
    end

    test "a donor that is gone", ctx do
      assert {:ok, _} = Storage.delete_file_completely(ctx.donor)
      before = keys(ctx.snap)

      assert {:error, :donor_changed} = Storage.relink_file(ctx.snap, ctx.donor, [])
      assert keys(ctx.snap) == before
    end

    test "a record onto itself", ctx do
      assert {:error, :incompatible} = Storage.relink_file(ctx.snap, ctx.snap, [])
    end

    test "a donor of another storage profile", ctx do
      {:ok, profile} = Profiles.create_profile(%{name: "Other #{ctx.n}"})
      {:ok, _} = Profiles.set_library_profile(ctx.target, profile.uuid)

      assert {:error, :incompatible} = Storage.relink_file(ctx.snap, ctx.donor, [])
    end
  end

  defp key_set(file), do: file |> keys() |> Map.values() |> MapSet.new()

  defp identity(file),
    do: Map.take(file, [:uuid, :library_uuid, :folder_uuid, :original_file_name, :user_uuid])

  defp location_set(instance) do
    Repo.all(
      from(l in Storage.FileLocation,
        where: l.file_instance_uuid == ^instance.uuid,
        select: {l.bucket_uuid, l.path}
      )
    )
    |> MapSet.new()
  end
end
