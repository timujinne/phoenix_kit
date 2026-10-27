defmodule PhoenixKit.Modules.Storage.PreparedVariantKeyTest do
  @moduledoc """
  `VariantGenerator.store_prepared_variant/6` (a burned or annotated
  thumbnail) never writes over an object another row names: its key goes
  through the same check a generated variant's does, so a file that shares
  its objects with another (a cross-user clone, a `link_copy/3`) cannot change
  the other's bytes by burning.

  Skipped when ImageMagick isn't installed.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.TestSupport.LinkCopyHelpers

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{AnnotationThumbnail, VariantGenerator}

  @moduletag :tmp_dir

  unless imagemagick?(),
    do: @moduletag(skip: "ImageMagick (convert, identify) is not installed")

  setup %{tmp_dir: tmp} do
    if imagemagick?() do
      env = setup_storage(tmp)
      owner = user!("owner", env.n)
      other = user!("other", env.n)
      path = image!(tmp, "photo.jpg")
      donor = upload!(owner, path)

      Map.merge(env, %{owner: owner, other: other, donor: donor, path: path})
    else
      {:ok, skip: true}
    end
  end

  defp link!(ctx) do
    target = library!(ctx.n)
    {:ok, copy} = Storage.link_copy(ctx.donor, ctx.other.uuid, library_uuid: target.uuid)
    copy
  end

  defp assert_untouched(file, variant, sha) do
    inst = instance(file, variant)
    assert exists?(inst.file_name)
    assert object_sha256(inst.file_name) == sha
  end

  test "the burn of a linked donor leaves the copy's thumbnail as it was", ctx do
    copy = link!(ctx)
    %{file_name: key, checksum: checksum} = instance(copy, "thumbnail")
    sha = object_sha256(key)

    burned = burn!(ctx.donor, "thumbnail", ctx.tmp)

    assert burned.file_name != key
    assert burned.checksum != checksum
    assert %{file_name: ^key, checksum: ^checksum} = instance(copy, "thumbnail")
    assert_untouched(copy, "thumbnail", sha)
    # The donor's own burn is what the donor serves.
    assert object_sha256(burned.file_name) != sha
  end

  test "the burn of a copy leaves the donor's thumbnail as it was", ctx do
    copy = link!(ctx)
    %{file_name: key} = instance(ctx.donor, "thumbnail")
    sha = object_sha256(key)

    burned = burn!(copy, "thumbnail", ctx.tmp)

    assert burned.file_name != key
    assert_untouched(ctx.donor, "thumbnail", sha)
    assert instance(ctx.donor, "thumbnail").file_name == key
  end

  test "the burn of a cross-user clone in the same library leaves the original's", ctx do
    sha_in = :sha256 |> :crypto.hash(File.read!(ctx.path)) |> Base.encode16(case: :lower)

    assert {:ok, clone, :duplicate} =
             Storage.store_file_in_buckets(
               ctx.path,
               "image",
               ctx.other.uuid,
               sha_in,
               "jpg",
               "p.jpg"
             )

    assert clone.uuid != ctx.donor.uuid
    assert keys(clone) == keys(ctx.donor)

    %{file_name: key} = instance(ctx.donor, "thumbnail")
    sha = object_sha256(key)

    burned = burn!(clone, "thumbnail", ctx.tmp)

    assert burned.file_name != key
    assert_untouched(ctx.donor, "thumbnail", sha)

    # And the other way round: the original burns, the clone's burn stays.
    clone_sha = object_sha256(burned.file_name)
    burn!(ctx.donor, "thumbnail", ctx.tmp, "blue")
    assert_untouched(clone, "thumbnail", clone_sha)
  end

  test "a file nobody shares with burns, and its generated object goes", ctx do
    %{file_name: key} = instance(ctx.donor, "thumbnail")

    burned = burn!(ctx.donor, "thumbnail", ctx.tmp)

    assert instance(ctx.donor, "thumbnail").file_name == burned.file_name
    assert exists?(burned.file_name)
    refute exists?(key)
  end

  test "burning again replaces the previous burn and leaves no object behind", ctx do
    first = burn!(ctx.donor, "thumbnail", ctx.tmp, "green")
    donor = reload(ctx.donor)
    count = object_count(ctx.root)

    second = burn!(donor, "thumbnail", ctx.tmp, "blue")

    assert second.checksum != first.checksum
    refute exists?(first.file_name)
    assert exists?(second.file_name)
    assert object_count(ctx.root) == count
  end

  test "an annotation thumbnail of a shared file does not reach the other", ctx do
    copy = link!(ctx)
    burn!(ctx.donor, "thumbnail_annotated", ctx.tmp)
    burn!(copy, "thumbnail_annotated", ctx.tmp, "blue")

    donor_inst = instance(ctx.donor, "thumbnail_annotated")
    copy_inst = instance(copy, "thumbnail_annotated")

    assert donor_inst.checksum != copy_inst.checksum
    assert object_sha256(donor_inst.file_name) == donor_inst.checksum
    assert object_sha256(copy_inst.file_name) == copy_inst.checksum
  end

  test "dropping the annotation thumbnail deletes its object, burn after burn", ctx do
    for color <- ~w(green blue red) do
      burned = burn!(reload(ctx.donor), "thumbnail_annotated", ctx.tmp, color)
      assert exists?(burned.file_name)

      assert {:ok, :removed} = AnnotationThumbnail.refresh(ctx.donor.uuid)

      assert instance(ctx.donor, "thumbnail_annotated") == nil
      refute exists?(burned.file_name)
    end
  end

  test "a burned slot's key is never the size's own name", ctx do
    first = burn!(ctx.donor, "thumbnail", ctx.tmp)
    second = burn!(reload(ctx.donor), "thumbnail", ctx.tmp, "blue")

    assert first.file_name != second.file_name
    assert first.file_name =~ ~r/_thumbnail_[0-9a-f-]{36}\.jpg$/
  end

  test "a prepared variant that cannot be published leaves no object behind", ctx do
    count = object_count(ctx.root)
    prepared = image!(ctx.tmp, "bad.jpg", "green")

    # A blank variant name is refused by the row, after the object is stored.
    assert {:error, _} =
             VariantGenerator.store_prepared_variant(ctx.donor, "", prepared, "jpg", "image/jpeg")

    assert object_count(ctx.root) == count
  end
end
