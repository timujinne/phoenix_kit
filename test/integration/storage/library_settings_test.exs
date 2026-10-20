defmodule PhoenixKit.Modules.Storage.LibrarySettingsTest do
  @moduledoc """
  A library's own settings (its JSON `settings` column): the one place their keys
  are named, what is refused, and the first of them — annotated thumbnails, on or
  off for one library, otherwise the site setting.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Storage.{AnnotationThumbnail, Libraries}
  alias PhoenixKit.Settings

  @key "storage_annotated_thumbnails_enabled"

  setup do
    on_exit(fn -> PhoenixKit.Cache.invalidate(:settings, @key) end)
    :ok
  end

  defp library!(name \\ "Library #{System.unique_integer([:positive])}") do
    {:ok, library} = Libraries.create_system_library(%{name: name})
    library
  end

  defp site_default(value), do: {:ok, _} = Settings.update_boolean_setting(@key, value)

  describe "put_setting/3 and setting/2" do
    test "a library has no value of its own until one is set" do
      library = library!()

      assert Libraries.setting(library, :annotated_thumbnails) == nil
      assert Libraries.setting(library.uuid, :annotated_thumbnails) == nil
    end

    test "sets, changes and removes a value" do
      library = library!()

      assert {:ok, updated} = Libraries.put_setting(library, :annotated_thumbnails, true)
      assert Libraries.setting(updated, :annotated_thumbnails) == true
      assert Libraries.setting(library.uuid, :annotated_thumbnails) == true

      assert {:ok, _} = Libraries.put_setting(library, :annotated_thumbnails, false)
      assert Libraries.setting(library.uuid, :annotated_thumbnails) == false

      assert {:ok, _} = Libraries.put_setting(library, :annotated_thumbnails, nil)
      assert Libraries.setting(library.uuid, :annotated_thumbnails) == nil
    end

    test "refuses an unknown key and a value of the wrong type, and changes nothing" do
      library = library!()

      assert {:error, :unknown_setting} = Libraries.put_setting(library, :purging, true)
      assert {:error, :unknown_setting} = Libraries.put_setting(library, :nope, 1)

      assert {:error, :invalid_value} =
               Libraries.put_setting(library, :annotated_thumbnails, "yes")

      assert Libraries.get_library(library.uuid).settings == %{}
    end

    test "leaves the other keys of the map alone, the purge marker included" do
      library = library!()

      {1, _} =
        PhoenixKit.RepoHelper.repo().update_all(
          Ecto.Query.from(l in PhoenixKit.Modules.Storage.Library,
            where: l.uuid == ^library.uuid
          ),
          set: [settings: %{"purging" => true, "other" => 1}]
        )

      assert {:ok, updated} = Libraries.put_setting(library, :annotated_thumbnails, true)
      assert %{"purging" => true, "other" => 1, "annotated_thumbnails" => true} = updated.settings

      assert {:ok, updated} = Libraries.put_setting(library, :annotated_thumbnails, nil)
      assert updated.settings == %{"purging" => true, "other" => 1}
    end

    test "Media (nil) is a library like another" do
      assert Libraries.setting(nil, :annotated_thumbnails) ==
               Libraries.setting(Libraries.media_uuid(), :annotated_thumbnails)
    end

    test "setting_among/2 answers for many libraries in one go" do
      on = library!()
      off = library!()
      none = library!()
      {:ok, _} = Libraries.put_setting(on, :annotated_thumbnails, true)
      {:ok, _} = Libraries.put_setting(off, :annotated_thumbnails, false)

      own =
        Libraries.setting_among([on.uuid, off.uuid, none.uuid, on.uuid], :annotated_thumbnails)

      assert own == %{to_string(on.uuid) => true, to_string(off.uuid) => false}
    end
  end

  describe "a module's own settings" do
    alias PhoenixKit.Modules.Storage.Library
    alias PhoenixKit.RepoHelper

    defp raw_settings(library), do: Libraries.get_library(library.uuid).settings

    defp store_raw!(library, settings) do
      {1, _} =
        RepoHelper.repo().update_all(
          Ecto.Query.from(l in Library, where: l.uuid == ^library.uuid),
          set: [settings: settings]
        )
    end

    test "a library has none until one is set, and Media is a library like another" do
      library = library!()
      assert Libraries.module_setting(library, "photos", "viewer") == nil
      assert Libraries.module_setting(library.uuid, "photos", "viewer") == nil

      assert Libraries.module_setting(nil, "photos", "viewer") ==
               Libraries.module_setting(Libraries.media_uuid(), "photos", "viewer")
    end

    test "sets, changes and removes a value, kept under the module's namespace" do
      library = library!()

      assert {:ok, updated} =
               Libraries.put_module_setting(library, "photos", "viewer", "photoswipe")

      assert Libraries.module_setting(updated, "photos", "viewer") == "photoswipe"
      assert Libraries.module_setting(library.uuid, "photos", "viewer") == "photoswipe"
      assert raw_settings(library) == %{"modules" => %{"photos" => %{"viewer" => "photoswipe"}}}

      assert {:ok, _} = Libraries.put_module_setting(library, "photos", "viewer", "classic")
      assert Libraries.module_setting(library.uuid, "photos", "viewer") == "classic"

      assert {:ok, _} = Libraries.put_module_setting(library, "photos", "viewer", nil)
      assert Libraries.module_setting(library.uuid, "photos", "viewer") == nil
    end

    test "takes a boolean, a number or a short string, and nothing else" do
      library = library!()

      for good <- [true, false, 0, 7, -3, 1.5, "", "text", String.duplicate("a", 255), "é"] do
        assert {:ok, _} = Libraries.put_module_setting(library, "photos", "value", good)
        assert Libraries.module_setting(library.uuid, "photos", "value") == good
      end

      for bad <- [String.duplicate("a", 256), <<255, 254>>, %{"a" => 1}, [1], :atom, {1}] do
        assert {:error, :invalid_value} =
                 Libraries.put_module_setting(library, "photos", "value", bad)
      end

      assert Libraries.module_setting(library.uuid, "photos", "value") == "é"
    end

    test "refuses a namespace or key that is not a lowercase word, and changes nothing" do
      library = library!()

      for bad <- ["", "Photos", "a-b", "a b", "1a", "a.b", String.duplicate("a", 33), nil, 1] do
        assert {:error, :invalid_namespace} = Libraries.put_module_setting(library, bad, "k", "v")
      end

      for bad <- ["", "Key", "k-1", "1k", "a.b", String.duplicate("a", 65), nil, :k] do
        assert {:error, :invalid_key} = Libraries.put_module_setting(library, "photos", bad, "v")
      end

      assert raw_settings(library) == %{}
      assert Libraries.module_setting(library, "Photos", "viewer") == nil
      assert Libraries.module_setting(library, nil, nil) == nil
    end

    test "one key does not disturb another, another module's, or core's own settings" do
      library = library!()
      {:ok, _} = Libraries.put_setting(library, :annotated_thumbnails, true)
      {:ok, _} = Libraries.put_module_setting(library, "photos", "viewer", "classic")
      {:ok, _} = Libraries.put_module_setting(library, "photos", "columns", 5)
      {:ok, _} = Libraries.put_module_setting(library, "shop", "layout", "wide")

      assert raw_settings(library) == %{
               "annotated_thumbnails" => true,
               "modules" => %{
                 "photos" => %{"viewer" => "classic", "columns" => 5},
                 "shop" => %{"layout" => "wide"}
               }
             }

      {:ok, _} = Libraries.put_setting(library, :deep_zoom, false)
      {:ok, _} = Libraries.put_setting(library, :annotated_thumbnails, nil)
      assert Libraries.module_setting(library.uuid, "photos", "viewer") == "classic"
      assert Libraries.module_setting(library.uuid, "shop", "layout") == "wide"
    end

    test "removing the last key leaves nothing behind, and the purge marker is kept" do
      library = library!()
      store_raw!(library, %{"purging" => true})
      {:ok, _} = Libraries.put_module_setting(library, "photos", "viewer", "classic")
      {:ok, _} = Libraries.put_module_setting(library, "shop", "layout", "wide")

      {:ok, _} = Libraries.put_module_setting(library, "photos", "viewer", nil)

      assert raw_settings(library) == %{
               "purging" => true,
               "modules" => %{"shop" => %{"layout" => "wide"}}
             }

      {:ok, _} = Libraries.put_module_setting(library, "shop", "layout", nil)
      assert raw_settings(library) == %{"purging" => true}

      # Removing what is not there is not an error.
      assert {:ok, _} = Libraries.put_module_setting(library, "photos", "viewer", nil)
      assert raw_settings(library) == %{"purging" => true}
    end

    test "settings that are not the shape of a module's read as none" do
      library = library!()

      for odd <- [
            %{"modules" => "x"},
            %{"modules" => %{"photos" => 1}},
            %{"modules" => %{"photos" => %{"viewer" => %{"a" => 1}}}},
            %{"modules" => %{"photos" => %{"viewer" => String.duplicate("a", 300)}}},
            %{"modules" => %{"photos" => %{"viewer" => nil}}}
          ] do
        store_raw!(library, odd)
        assert Libraries.module_setting(library.uuid, "photos", "viewer") == nil
      end
    end

    test "a library that is gone answers none, and refuses a write" do
      assert Libraries.module_setting(Ecto.UUID.generate(), "photos", "viewer") == nil
      assert Libraries.module_setting("not a uuid", "photos", "viewer") == nil

      library = library!()
      {:ok, _} = Libraries.delete_library(library)
      assert {:error, :not_found} = Libraries.put_module_setting(library, "photos", "viewer", "x")
    end

    test "core's own list does not name a module's key" do
      library = library!()
      assert {:error, :unknown_setting} = Libraries.put_setting(library, :viewer, "photoswipe")
    end
  end

  describe "annotated thumbnails for a library" do
    test "follow the site setting until the library chooses" do
      library = library!()

      site_default(false)
      refute AnnotationThumbnail.enabled_for?(library)
      refute AnnotationThumbnail.enabled_for?(library.uuid)

      site_default(true)
      assert AnnotationThumbnail.enabled_for?(library)
    end

    test "a library's own choice wins over the site setting, either way" do
      library = library!()

      site_default(false)
      {:ok, on} = Libraries.put_setting(library, :annotated_thumbnails, true)
      assert AnnotationThumbnail.enabled_for?(on)

      site_default(true)
      {:ok, off} = Libraries.put_setting(library, :annotated_thumbnails, false)
      refute AnnotationThumbnail.enabled_for?(off)
    end

    test "enabled_among/1 is the same rule for a page of files, Media included" do
      on = library!()
      off = library!()
      plain = library!()
      {:ok, _} = Libraries.put_setting(on, :annotated_thumbnails, true)
      {:ok, _} = Libraries.put_setting(off, :annotated_thumbnails, false)
      media = Libraries.media_uuid()

      site_default(false)

      enabled = AnnotationThumbnail.enabled_among([on.uuid, off.uuid, plain.uuid, nil])
      assert enabled == MapSet.new([to_string(on.uuid)])

      site_default(true)

      enabled = AnnotationThumbnail.enabled_among([on.uuid, off.uuid, plain.uuid, nil])
      assert enabled == MapSet.new([to_string(on.uuid), to_string(plain.uuid), media])
    end

    test "a file answers for its own library" do
      library = library!()
      {:ok, _} = Libraries.put_setting(library, :annotated_thumbnails, true)
      site_default(false)

      assert AnnotationThumbnail.enabled_for_file?(%{library_uuid: library.uuid})
      refute AnnotationThumbnail.enabled_for_file?(%{library_uuid: nil})
      refute AnnotationThumbnail.enabled_for_file_uuid?(Ecto.UUID.generate())
      refute AnnotationThumbnail.enabled_for_file_uuid?("not a uuid")
    end
  end

  describe "deep zoom for a library" do
    alias PhoenixKit.Modules.Storage.VariantSets

    test "follows its rendition profile's old flag until the library chooses" do
      {:ok, set} =
        VariantSets.create_variant_set(%{name: "Zoom #{System.unique_integer([:positive])}"})

      {:ok, library} =
        Libraries.create_system_library(%{
          name: "Zoomy #{System.unique_integer([:positive])}",
          variant_set_uuid: set.uuid
        })

      refute VariantSets.deep_zoom_for_library?(library.uuid)

      {:ok, _} = VariantSets.update_variant_set(set, %{generate_tiles: true})
      assert VariantSets.deep_zoom_for_library?(library.uuid)
    end

    test "a library's own choice wins over the set, either way" do
      {:ok, set} =
        VariantSets.create_variant_set(%{
          name: "Zoom #{System.unique_integer([:positive])}",
          generate_tiles: true
        })

      {:ok, library} =
        Libraries.create_system_library(%{
          name: "Zoomy #{System.unique_integer([:positive])}",
          variant_set_uuid: set.uuid
        })

      assert VariantSets.deep_zoom_for_library?(library.uuid)

      {:ok, _} = Libraries.put_setting(library, :deep_zoom, false)
      refute VariantSets.deep_zoom_for_library?(library.uuid)

      {:ok, _} = Libraries.put_setting(library, :deep_zoom, true)
      assert VariantSets.deep_zoom_for_library?(library.uuid)

      {:ok, _} = Libraries.put_setting(library, :deep_zoom, nil)
      assert VariantSets.deep_zoom_for_library?(library.uuid)
    end

    test "on for one library leaves another library on the same set alone" do
      {:ok, set} =
        VariantSets.create_variant_set(%{name: "Shared #{System.unique_integer([:positive])}"})

      {:ok, one} =
        Libraries.create_system_library(%{
          name: "One #{System.unique_integer([:positive])}",
          variant_set_uuid: set.uuid
        })

      {:ok, two} =
        Libraries.create_system_library(%{
          name: "Two #{System.unique_integer([:positive])}",
          variant_set_uuid: set.uuid
        })

      {:ok, _} = Libraries.put_setting(one, :deep_zoom, true)

      assert VariantSets.deep_zoom_for_library?(one.uuid)
      refute VariantSets.deep_zoom_for_library?(two.uuid)

      assert MapSet.equal?(
               VariantSets.tiles_among([one.uuid, two.uuid]),
               MapSet.new([to_string(one.uuid)])
             )

      assert VariantSets.tiles_anywhere?()
    end
  end

  describe "focus_crop_in_use?/0" do
    import Ecto.Query, only: [from: 2]

    alias PhoenixKit.Modules.Storage
    alias PhoenixKit.Modules.Storage.Dimension
    alias PhoenixKit.Modules.Storage.VariantSets

    # A fresh install's Default set carries the smart squares (V213);
    # this starts from a set with no subject crop.
    setup do
      Repo.delete_all(
        from d in Dimension, where: fragment("?->>'crop_mode' = 'focus'", d.options)
      )

      :ok
    end

    defp dimension!(name, attrs) do
      {:ok, dimension} =
        Storage.create_dimension(
          Map.merge(
            %{name: name, width: 200, height: 200, quality: 80, applies_to: "image"},
            attrs
          )
        )

      dimension
    end

    test "is false until a rendition crops around the subject" do
      refute VariantSets.focus_crop_in_use?()
    end

    test "is true for an enabled fixed box set to focus, and only then" do
      dimension!("box_middle", %{maintain_aspect_ratio: false, crop_mode: "center"})
      refute VariantSets.focus_crop_in_use?()

      # A rendition that keeps proportions is not cropped, whatever its mode says.
      dimension!("kept", %{maintain_aspect_ratio: true, crop_mode: "focus"})
      refute VariantSets.focus_crop_in_use?()

      focus = dimension!("box_focus", %{maintain_aspect_ratio: false, crop_mode: "focus"})
      assert VariantSets.focus_crop_in_use?()

      {:ok, _} = Storage.update_dimension(focus, %{enabled: false})
      refute VariantSets.focus_crop_in_use?()
    end
  end

  describe "heic_files_exist?/0" do
    alias PhoenixKit.Modules.Storage
    alias PhoenixKit.Users.Auth

    defp upload!(name, mime, ext) do
      n = System.unique_integer([:positive])

      {:ok, user} =
        Auth.register_user(%{
          "email" => "heic-#{n}@example.com",
          "password" => "ValidPassword123!"
        })

      {:ok, file} =
        Storage.create_file(%{
          original_file_name: name,
          file_name: name,
          file_path: "heic/#{n}",
          mime_type: mime,
          file_type: "image",
          ext: ext,
          file_checksum: Ecto.UUID.generate(),
          user_file_checksum: Ecto.UUID.generate(),
          size: 10,
          status: "active",
          user_uuid: user.uuid
        })

      file
    end

    test "is false until a HEIC or HEIF photo is here" do
      refute Storage.heic_files_exist?()

      upload!("a.jpg", "image/jpeg", "jpg")
      upload!("b.png", "image/png", "png")
      refute Storage.heic_files_exist?()
    end

    test "is true for either, by type or by extension" do
      upload!("c.heic", "image/heic", "heic")
      assert Storage.heic_files_exist?()
    end

    test "a HEIF photo counts too" do
      upload!("d.heif", "image/heif", "heif")
      assert Storage.heic_files_exist?()
    end

    test "a file whose browser type is vague still counts by its extension" do
      upload!("e.HEIC", "application/octet-stream", "heic")
      assert Storage.heic_files_exist?()
    end

    test "an extension is matched whatever its case (an iPhone names it IMG_1.HEIC)" do
      upload!("IMG_1.HEIC", "application/octet-stream", "HEIC")
      assert Storage.heic_files_exist?()
    end
  end
end
