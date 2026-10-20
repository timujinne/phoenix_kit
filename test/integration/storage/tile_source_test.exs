defmodule PhoenixKit.Modules.Storage.TileSourceTest do
  @moduledoc """
  What deep-zoom tiles are cut from. An original libvips can read is used as it is.
  A HEIC, HEIF or AVIF (libvips has no HEVC decoder, so it cannot read a pixel of an
  iPhone's photo) is converted once to a full-resolution JPEG by ImageMagick, kept
  beside the tiles, and reused; a conversion of the wrong size is refused.

  This ImageMagick reads HEIC but cannot write it, so a HEIC fixture cannot be made
  here: the test stores a real JPEG and presents its original instance as a HEIC one.
  The conversion is the same command either way; it was run on a real iPhone HEIC to
  confirm libvips then decodes the result.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Bucket, ImageProcessor, Manager, TesseraAdapter, TileSource}
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.FileHash

  @buckets_cache :phoenix_kit_buckets_cache
  @width 640
  @height 480

  setup do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])
    root = Path.join(System.tmp_dir!(), "pk_tile_source_#{n}")
    src = Path.join(System.tmp_dir!(), "pk_tile_src_#{n}.jpg")

    Repo.update_all(Bucket, set: [enabled: false])

    {:ok, _bucket} =
      Storage.create_bucket(%{
        name: "tile-source-#{n}",
        provider: "local",
        endpoint: root,
        enabled: true,
        priority: 0
      })

    start_supervised!(
      {Oban, name: Oban, repo: PhoenixKit.Test.Repo, testing: :manual, queues: [], plugins: []}
    )

    {_, 0} =
      System.cmd("convert", ["-size", "#{@width}x#{@height}", "gradient:red-blue", src],
        stderr_to_stdout: true
      )

    {:ok, user} =
      Auth.register_user(%{
        "email" => "tile-source-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    {:ok, file} =
      Storage.store_file_in_buckets(
        src,
        "image",
        user.uuid,
        FileHash.sha256!(src),
        "jpg",
        "photo.jpg",
        mime_type: "image/jpeg"
      )

    on_exit(fn ->
      :persistent_term.erase(@buckets_cache)
      File.rm_rf(root)
      File.rm(src)
    end)

    original = Storage.get_file_instance_by_name(file.uuid, "original")

    source = %{
      file_uuid: file.uuid,
      base: "#{file.uuid}/v1/#{file.uuid}",
      width: @width,
      height: @height
    }

    %{photo: file, original: original, source: source}
  end

  defp as_heic(instance), do: %{instance | mime_type: "image/heic"}

  defp cached?(source),
    do: Manager.file_exists?(TesseraAdapter.destination_for(TileSource.key(source.base)))

  describe "convert?/1" do
    test "the types libvips cannot decode" do
      for mime <- ["image/heic", "image/heif", "image/avif", "IMAGE/HEIC"],
          do: assert(TileSource.convert?(%{mime_type: mime}))

      for mime <- ["image/jpeg", "image/png", "image/webp", "image/tiff", nil],
          do: refute(TileSource.convert?(%{mime_type: mime}))

      refute TileSource.convert?(nil)
    end
  end

  describe "an original libvips can read" do
    test "is used as it is, and nothing is kept", ctx do
      assert {:ok, path, cleanup} = TileSource.prepare(ctx.source, ctx.original)

      assert File.exists?(path)
      assert {:ok, {@width, @height}} = ImageProcessor.extract_dimensions(path)
      refute cached?(ctx.source)

      cleanup.()
      refute File.exists?(path)
    end
  end

  describe "a HEIC original" do
    test "is converted once to a full-resolution JPEG, kept, and reused", ctx do
      heic = as_heic(ctx.original)
      refute cached?(ctx.source)

      assert {:ok, path, cleanup} = TileSource.prepare(ctx.source, heic)
      assert Path.extname(path) == ".jpg"
      assert {:ok, {@width, @height}} = ImageProcessor.extract_dimensions(path)
      assert cached?(ctx.source)

      # A system-managed file of the original, so it goes with it.
      cleanup.()
      refute File.exists?(path)

      # The second request does not need the original any more: the kept JPEG is used.
      :ok = Manager.delete_file(ctx.original.file_name)
      refute Manager.file_exists?(ctx.original.file_name)

      assert {:ok, again, cleanup_again} = TileSource.prepare(ctx.source, heic)
      assert {:ok, {@width, @height}} = ImageProcessor.extract_dimensions(again)
      cleanup_again.()
      refute File.exists?(again)
    end

    test "a conversion of another size than the file's is refused and not kept", ctx do
      wrong = %{ctx.source | width: @width + 7}

      assert {:error, {:dimension_mismatch, {@width, @height}, {647, @height}}} =
               TileSource.prepare(wrong, as_heic(ctx.original))

      refute cached?(wrong)
    end

    test "an original that cannot be fetched is an error, and no temp file is left", ctx do
      :ok = Manager.delete_file(ctx.original.file_name)
      before = Path.wildcard(Path.join(System.tmp_dir!(), "tessera-*"))

      assert {:error, _reason} = TileSource.prepare(ctx.source, as_heic(ctx.original))

      assert Path.wildcard(Path.join(System.tmp_dir!(), "tessera-*")) -- before == []
    end
  end
end
